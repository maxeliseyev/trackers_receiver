package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"trackers-receiver/internal/storage"
)

// WorkerPool управляет пулом горутин для обработки подключений
// Ограничивает количество одновременно обрабатываемых подключений
// Предотвращает создание неограниченного количества горутин
//
// Архитектура:
//
//	Incoming connections → Rate Limiter → Job Queue (buffered channel) → Workers (fixed pool) → Processing
//
// Для 100k+ одновременных трекеров:
//   - Workers: runtime.NumCPU() * 2 (например, 16 workers для 8 CPU)
//   - Queue size: 10000 (буфер для всплесков нагрузки)
//   - Rejected connections если очередь заполнена (backpressure)
//   - Rate limiting для защиты от DDoS
type WorkerPool struct {
	// Конфигурация
	workers   int // Количество worker горутин
	queueSize int // Размер очереди заданий
	storage   storage.QueueStorage
	config    *ConnectionConfig

	// Защита
	rateLimiter *RateLimiter // Rate limiting и IP blocking

	// Каналы
	jobs     chan Job      // Очередь заданий (подключений)
	shutdown chan struct{} // Сигнал для graceful shutdown
	done     chan struct{} // Сигнал что все workers завершились

	// Контекст для cancellation
	ctx    context.Context
	cancel context.CancelFunc

	// Синхронизация
	wg sync.WaitGroup // WaitGroup для ожидания завершения всех workers

	// Метрики (thread-safe через atomic)
	stats PoolStats
}

// Job представляет задание для worker'а
type Job struct {
	Conn       net.Conn  // TCP подключение от трекера
	ReceivedAt time.Time // Время получения подключения
}

// PoolStats статистика работы пула
type PoolStats struct {
	// Подключения
	TotalAccepted  atomic.Int64 // Всего принято подключений
	TotalRejected  atomic.Int64 // Всего отклонено (очередь заполнена)
	TotalProcessed atomic.Int64 // Всего обработано
	TotalFailed    atomic.Int64 // Всего упало с ошибкой

	// Производительность
	ActiveWorkers  atomic.Int32 // Текущее количество активных workers
	QueueLength    atomic.Int32 // Текущая длина очереди
	AvgQueueTimeMs atomic.Int64 // Среднее время в очереди (мс)

	// Время
	StartTime time.Time
}

// PoolConfig конфигурация worker pool
type PoolConfig struct {
	// Workers
	NumWorkers int // Количество workers (default: runtime.NumCPU() * 2)
	QueueSize  int // Размер очереди заданий (default: 10000)

	// Graceful shutdown
	ShutdownTimeout time.Duration // Таймаут для graceful shutdown (default: 30s)

	// Rate limiting
	RateLimiterConfig *RateLimiterConfig // Конфигурация rate limiter (nil = отключен)

	// Connection config
	ConnectionConfig *ConnectionConfig
}

// DefaultPoolConfig возвращает конфигурацию по умолчанию
func DefaultPoolConfig() *PoolConfig {
	return &PoolConfig{
		NumWorkers:        16,    // Для 8 CPU = 16 workers
		QueueSize:         10000, // Буфер для 10k подключений
		ShutdownTimeout:   30 * time.Second,
		RateLimiterConfig: DefaultRateLimiterConfig(), // Rate limiting включен по умолчанию
		ConnectionConfig:  DefaultConnectionConfig(),
	}
}

// NewWorkerPool создает новый пул workers
func NewWorkerPool(storage storage.QueueStorage, config *PoolConfig) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	pool := &WorkerPool{
		workers:   config.NumWorkers,
		queueSize: config.QueueSize,
		storage:   storage,
		config:    config.ConnectionConfig,
		jobs:      make(chan Job, config.QueueSize),
		shutdown:  make(chan struct{}),
		done:      make(chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
	}

	// Инициализируем rate limiter если задана конфигурация
	if config.RateLimiterConfig != nil {
		pool.rateLimiter = NewRateLimiter(config.RateLimiterConfig)
	}

	pool.stats.StartTime = time.Now()

	return pool
}

// Start запускает worker pool
// Создает фиксированное количество worker горутин
func (p *WorkerPool) Start() {
	// Запускаем workers
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker(i)
	}

	// Запускаем metrics updater (периодически обновляет метрики)
	go p.metricsUpdater()
}

// worker главная функция worker'а
// Бесконечный цикл: берет задание из очереди → обрабатывает → повторяет
func (p *WorkerPool) worker(id int) {
	defer p.wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			// Graceful shutdown - завершаем worker
			return

		case job, ok := <-p.jobs:
			if !ok {
				// Канал закрыт - завершаем worker
				return
			}

			// Обрабатываем подключение
			p.processJob(id, job)
		}
	}
}

// processJob обрабатывает одно подключение
func (p *WorkerPool) processJob(_ int, job Job) {
	// Увеличиваем счетчик активных workers
	p.stats.ActiveWorkers.Add(1)
	defer p.stats.ActiveWorkers.Add(-1)

	// Вычисляем время в очереди
	queueTime := time.Since(job.ReceivedAt)
	p.updateQueueTime(queueTime)

	// Создаем connection handler
	handler := NewConnectionHandler(job.Conn, p.storage, p.config)
	defer handler.Close()

	// Обрабатываем подключение
	if err := handler.Handle(); err != nil {
		p.stats.TotalFailed.Add(1)

		// Проверяем тип ошибки
		if isProtocolError(err) {
			// Protocol error - записываем в rate limiter
			if p.rateLimiter != nil {
				p.rateLimiter.RecordProtocolError(job.Conn)
			}
			// Protocol errors - нормально (атаки, сканеры, некорректные данные)
			// В production логировать на уровне DEBUG с structured logging
		} else {
			// Неожиданная системная ошибка (сеть, storage, etc)
			// В production логировать на уровне ERROR с structured logging
			// fmt.Printf("[ERROR] worker connection failed: %v (from %s)\n", err, job.Conn.RemoteAddr())
		}
	} else {
		p.stats.TotalProcessed.Add(1)
	}
}

// Submit добавляет подключение в очередь на обработку
// Возвращает ошибку если очередь заполнена (backpressure) или IP заблокирован
func (p *WorkerPool) Submit(conn net.Conn) error {
	// Сначала проверяем что pool не закрывается
	select {
	case <-p.ctx.Done():
		// Pool закрывается
		conn.Close()
		return fmt.Errorf("pool is shutting down")
	default:
		// Продолжаем
	}

	// Проверяем rate limiter
	if p.rateLimiter != nil {
		if !p.rateLimiter.Allow(conn) {
			// IP заблокирован rate limiter
			p.stats.TotalRejected.Add(1)
			conn.Close()
			return &PoolError{
				Code:    "RATE_LIMITED",
				Message: "connection rate limit exceeded or IP blocked",
				Workers: p.workers,
			}
		}
	}

	job := Job{
		Conn:       conn,
		ReceivedAt: time.Now(),
	}

	select {
	case p.jobs <- job:
		// Успешно добавили в очередь
		p.stats.TotalAccepted.Add(1)
		return nil

	default:
		// Очередь заполнена - отклоняем подключение
		p.stats.TotalRejected.Add(1)
		conn.Close()
		return &PoolError{
			Code:    "QUEUE_FULL",
			Message: "worker pool queue is full",
			Workers: p.workers,
			Queue:   len(p.jobs),
		}
	}
}

// Shutdown выполняет graceful shutdown пула
// Останавливает прием новых подключений и ждет завершения текущих
func (p *WorkerPool) Shutdown(ctx context.Context) error {
	// Сигнализируем о начале shutdown
	close(p.shutdown)

	// Останавливаем rate limiter
	if p.rateLimiter != nil {
		p.rateLimiter.Stop()
	}

	// Отменяем контекст - workers начнут завершаться
	p.cancel()

	// Закрываем канал jobs (больше не принимаем новые подключения)
	close(p.jobs)

	// Ждем завершения всех workers с таймаутом
	shutdownComplete := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(shutdownComplete)
	}()

	select {
	case <-shutdownComplete:
		// Все workers завершились
		close(p.done)
		return nil

	case <-ctx.Done():
		// Таймаут shutdown - форсируем завершение
		// Workers все еще работают, но мы больше не ждем
		close(p.done)
		return &PoolError{
			Code:    "SHUTDOWN_TIMEOUT",
			Message: "graceful shutdown timeout exceeded",
			Workers: p.workers,
		}
	}
}

// Wait ждет полного завершения пула
// Используется в тестах
func (p *WorkerPool) Wait() {
	<-p.done
}

// Stats возвращает текущую статистику пула
func (p *WorkerPool) Stats() *PoolStats {
	return &p.stats
}

// metricsUpdater периодически обновляет метрики
func (p *WorkerPool) metricsUpdater() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			// Обновляем длину очереди
			p.stats.QueueLength.Store(int32(len(p.jobs)))
		}
	}
}

// updateQueueTime обновляет среднее время в очереди
func (p *WorkerPool) updateQueueTime(queueTime time.Duration) {
	// Простое скользящее среднее (для production лучше использовать EWMA)
	currentAvg := p.stats.AvgQueueTimeMs.Load()
	newAvg := (currentAvg + queueTime.Milliseconds()) / 2
	p.stats.AvgQueueTimeMs.Store(newAvg)
}

// Health проверяет здоровье пула
func (p *WorkerPool) Health() error {
	// Проверяем что пул работает
	select {
	case <-p.done:
		return &PoolError{
			Code:    "POOL_STOPPED",
			Message: "worker pool is not running",
		}
	default:
		// Пул работает
	}

	// Проверяем что есть активные workers
	if p.stats.ActiveWorkers.Load() == 0 {
		// Если очередь пустая - это нормально
		if len(p.jobs) == 0 {
			return nil
		}
		// Если очередь не пустая но нет активных workers - проблема
		return &PoolError{
			Code:    "NO_ACTIVE_WORKERS",
			Message: "no active workers but queue is not empty",
			Queue:   len(p.jobs),
		}
	}

	// Проверяем что очередь не переполнена
	queueUsage := float64(len(p.jobs)) / float64(p.queueSize)
	if queueUsage > 0.9 {
		return &PoolError{
			Code:    "QUEUE_NEARLY_FULL",
			Message: fmt.Sprintf("queue is %.0f%% full", queueUsage*100),
			Queue:   len(p.jobs),
		}
	}

	return nil
}

// PoolError ошибка worker pool
type PoolError struct {
	Code    string
	Message string
	Workers int
	Queue   int
}

func (e *PoolError) Error() string {
	if e.Queue > 0 {
		return fmt.Sprintf("[%s] %s (workers=%d, queue=%d)", e.Code, e.Message, e.Workers, e.Queue)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// isProtocolError проверяет является ли ошибка ошибкой протокола
func isProtocolError(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*ProtocolError)
	return ok
}

// GetMetrics возвращает метрики в формате для Prometheus
func (p *WorkerPool) GetMetrics() map[string]any {
	uptime := time.Since(p.stats.StartTime).Seconds()

	metrics := map[string]any{
		// Подключения
		"pool_connections_accepted_total":  p.stats.TotalAccepted.Load(),
		"pool_connections_rejected_total":  p.stats.TotalRejected.Load(),
		"pool_connections_processed_total": p.stats.TotalProcessed.Load(),
		"pool_connections_failed_total":    p.stats.TotalFailed.Load(),

		// Workers
		"pool_workers_total":  p.workers,
		"pool_workers_active": p.stats.ActiveWorkers.Load(),

		// Очередь
		"pool_queue_size":        p.queueSize,
		"pool_queue_length":      p.stats.QueueLength.Load(),
		"pool_queue_time_avg_ms": p.stats.AvgQueueTimeMs.Load(),

		// Производительность
		"pool_uptime_seconds": uptime,
		"pool_throughput_qps": float64(p.stats.TotalProcessed.Load()) / uptime,

		// Здоровье
		"pool_rejection_rate": float64(p.stats.TotalRejected.Load()) / float64(p.stats.TotalAccepted.Load()+1),
		"pool_error_rate":     float64(p.stats.TotalFailed.Load()) / float64(p.stats.TotalProcessed.Load()+1),
	}

	// Добавляем метрики rate limiter если он включен
	if p.rateLimiter != nil {
		rlStats := p.rateLimiter.Stats()
		for key, value := range rlStats {
			metrics["ratelimit_"+key] = value
		}
	}

	return metrics
}
