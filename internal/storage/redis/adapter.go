package redis

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"trackers-receiver/internal/serialization"
	"trackers-receiver/internal/storage"
	"trackers-receiver/pkg/models"
)

// RedisStorage реализация storage.QueueStorage для Redis Lists
// Использует LPUSH для добавления в очереди (как в Python версии)
type RedisStorage struct {
	client     *redis.Client
	serializer *serialization.Serializer
	config     *Config

	// Статистика (thread-safe через atomic)
	stats struct {
		totalPushed atomic.Int64
		totalFailed atomic.Int64
		totalBytes  atomic.Int64
	}

	// Метрики производительности
	metrics struct {
		mu           sync.RWMutex
		latencies    []time.Duration // Последние N латентностей
		maxLatencies int             // Максимальное количество хранимых латентностей
	}

	// Здоровье
	health struct {
		mu        sync.RWMutex
		status    storage.HealthStatus
		lastError error
		lastCheck time.Time
	}
}

// Config конфигурация Redis storage
type Config struct {
	// Подключение
	Host     string
	Port     int
	Password string
	DB       int

	// Connection pool
	PoolSize     int
	MinIdleConns int
	MaxRetries   int

	// Timeouts
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// Очереди
	QueueMaxLengths map[string]int64 // Максимальная длина для каждой очереди

	// Метрики
	MaxLatencySamples int // Сколько латентностей хранить для расчета percentiles
}

// DefaultConfig возвращает конфигурацию по умолчанию
func DefaultConfig() *Config {
	return &Config{
		Host:     "localhost",
		Port:     6379,
		Password: "",
		DB:       0,

		PoolSize:     100,
		MinIdleConns: 10,
		MaxRetries:   3,

		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,

		QueueMaxLengths: map[string]int64{
			"charger":   2999999,
			"fasttrack": 2999999,
		},

		MaxLatencySamples: 1000,
	}
}

// NewRedisStorage создает новое Redis хранилище
func NewRedisStorage(config *Config) (*RedisStorage, error) {
	// Создаем Redis клиент
	client := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", config.Host, config.Port),
		Password:     config.Password,
		DB:           config.DB,
		PoolSize:     config.PoolSize,
		MinIdleConns: config.MinIdleConns,
		MaxRetries:   config.MaxRetries,
		DialTimeout:  config.DialTimeout,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
	})

	// Проверяем подключение
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	rs := &RedisStorage{
		client:     client,
		serializer: serialization.NewSerializer(),
		config:     config,
	}

	rs.metrics.maxLatencies = config.MaxLatencySamples
	rs.metrics.latencies = make([]time.Duration, 0, config.MaxLatencySamples)
	rs.health.status = storage.HealthStatusHealthy

	return rs, nil
}

// Push реализует storage.QueueStorage
func (rs *RedisStorage) Push(ctx context.Context, queue string, doc *models.Document) error {
	start := time.Now()

	// Сериализуем документ
	data, err := rs.serializer.Marshal(doc)
	if err != nil {
		rs.stats.totalFailed.Add(1)
		return storage.NewStorageError("Push", queue, fmt.Errorf("marshal failed: %w", err))
	}

	// Добавляем в Redis
	if err := rs.PushRaw(ctx, queue, data); err != nil {
		return err
	}

	// Обновляем метрики
	rs.recordLatency(time.Since(start))
	rs.stats.totalPushed.Add(1)
	rs.stats.totalBytes.Add(int64(len(data)))

	return nil
}

// PushBatch реализует storage.QueueStorage
func (rs *RedisStorage) PushBatch(ctx context.Context, queue string, docs []*models.Document) error {
	if len(docs) == 0 {
		return nil
	}

	start := time.Now()

	// Сериализуем все документы
	dataList := make([][]byte, 0, len(docs))
	for _, doc := range docs {
		data, err := rs.serializer.Marshal(doc)
		if err != nil {
			rs.stats.totalFailed.Add(1)
			return storage.NewStorageError("PushBatch", queue, fmt.Errorf("marshal failed: %w", err))
		}
		dataList = append(dataList, data)
	}

	// Используем pipeline для атомарной записи
	pipe := rs.client.Pipeline()

	for _, data := range dataList {
		pipe.LPush(ctx, queue, data)
	}

	// Обрезаем очередь если есть лимит
	if maxLen, ok := rs.config.QueueMaxLengths[queue]; ok {
		pipe.LTrim(ctx, queue, 0, maxLen-1)
	}

	// Выполняем pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		rs.stats.totalFailed.Add(int64(len(docs)))
		return storage.NewStorageError("PushBatch", queue, err)
	}

	// Обновляем метрики
	rs.recordLatency(time.Since(start))
	rs.stats.totalPushed.Add(int64(len(docs)))
	for _, data := range dataList {
		rs.stats.totalBytes.Add(int64(len(data)))
	}

	return nil
}

// PushRaw реализует storage.QueueStorage
func (rs *RedisStorage) PushRaw(ctx context.Context, queue string, data []byte) error {
	// LPUSH добавляет в начало списка (как в Python)
	if err := rs.client.LPush(ctx, queue, data).Err(); err != nil {
		rs.stats.totalFailed.Add(1)
		return storage.NewStorageError("PushRaw", queue, err)
	}

	// Обрезаем очередь если есть лимит
	if maxLen, ok := rs.config.QueueMaxLengths[queue]; ok {
		if err := rs.client.LTrim(ctx, queue, 0, maxLen-1).Err(); err != nil {
			// Trim failed - log but don't fail the operation
			// NOTE: Consider adding structured logging here when implementing zerolog/slog
		}
	}

	return nil
}

// Health реализует storage.QueueStorage
func (rs *RedisStorage) Health(ctx context.Context) error {
	rs.health.mu.Lock()
	defer rs.health.mu.Unlock()

	// Проверяем ping
	if err := rs.client.Ping(ctx).Err(); err != nil {
		rs.health.status = storage.HealthStatusUnhealthy
		rs.health.lastError = err
		rs.health.lastCheck = time.Now()
		return err
	}

	// Проверяем info (базовая информация о сервере)
	info, err := rs.client.Info(ctx, "server").Result()
	if err != nil {
		rs.health.status = storage.HealthStatusDegraded
		rs.health.lastError = err
		rs.health.lastCheck = time.Now()
		return err
	}

	// Если получили info - все ок
	_ = info
	rs.health.status = storage.HealthStatusHealthy
	rs.health.lastError = nil
	rs.health.lastCheck = time.Now()

	return nil
}

// Stats реализует storage.QueueStorage
func (rs *RedisStorage) Stats() *storage.Stats {
	rs.metrics.mu.RLock()
	defer rs.metrics.mu.RUnlock()

	rs.health.mu.RLock()
	defer rs.health.mu.RUnlock()

	stats := &storage.Stats{
		TotalPushed:   rs.stats.totalPushed.Load(),
		TotalFailed:   rs.stats.totalFailed.Load(),
		TotalBytes:    rs.stats.totalBytes.Load(),
		LastError:     rs.health.lastError,
		LastErrorTime: rs.health.lastCheck,
		HealthStatus:  rs.health.status,
		QueueSizes:    make(map[string]int64),
	}

	// Вычисляем метрики производительности
	if len(rs.metrics.latencies) > 0 {
		stats.AvgLatencyMs = rs.calculateAvgLatency()
		stats.P95LatencyMs = rs.calculatePercentile(0.95)
		stats.P99LatencyMs = rs.calculatePercentile(0.99)
	}

	// Получаем размеры очередей (лучше делать асинхронно)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	for queue := range rs.config.QueueMaxLengths {
		if size, err := rs.client.LLen(ctx, queue).Result(); err == nil {
			stats.QueueSizes[queue] = size
		}
	}

	// Вычисляем QPS
	if rs.stats.totalPushed.Load() > 0 {
		// Примерный QPS основан на последних N операциях
		// Для точного QPS нужен time-window counter
		stats.CurrentQPS = float64(len(rs.metrics.latencies)) / 10.0 // Грубая оценка
	}

	return stats
}

// Close реализует storage.QueueStorage
func (rs *RedisStorage) Close() error {
	return rs.client.Close()
}

// recordLatency записывает латентность операции
func (rs *RedisStorage) recordLatency(latency time.Duration) {
	rs.metrics.mu.Lock()
	defer rs.metrics.mu.Unlock()

	// Добавляем новую латентность
	rs.metrics.latencies = append(rs.metrics.latencies, latency)

	// Ограничиваем размер буфера (FIFO)
	if len(rs.metrics.latencies) > rs.metrics.maxLatencies {
		rs.metrics.latencies = rs.metrics.latencies[1:]
	}
}

// calculateAvgLatency вычисляет среднюю латентность
func (rs *RedisStorage) calculateAvgLatency() float64 {
	if len(rs.metrics.latencies) == 0 {
		return 0
	}

	var sum time.Duration
	for _, lat := range rs.metrics.latencies {
		sum += lat
	}

	return float64(sum.Milliseconds()) / float64(len(rs.metrics.latencies))
}

// calculatePercentile вычисляет перцентиль латентности
func (rs *RedisStorage) calculatePercentile(percentile float64) float64 {
	if len(rs.metrics.latencies) == 0 {
		return 0
	}

	// Копируем и сортируем
	sorted := make([]time.Duration, len(rs.metrics.latencies))
	copy(sorted, rs.metrics.latencies)

	// Простая bubble sort (для production лучше использовать sort.Slice)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i] > sorted[j] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// Вычисляем индекс перцентиля
	idx := int(float64(len(sorted)) * percentile)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}

	return float64(sorted[idx].Milliseconds())
}

// GetQueueLength возвращает текущую длину очереди
func (rs *RedisStorage) GetQueueLength(ctx context.Context, queue string) (int64, error) {
	return rs.client.LLen(ctx, queue).Result()
}

// ClearQueue очищает очередь (для тестов)
func (rs *RedisStorage) ClearQueue(ctx context.Context, queue string) error {
	return rs.client.Del(ctx, queue).Err()
}
