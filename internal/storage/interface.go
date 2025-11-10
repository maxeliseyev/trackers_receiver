package storage

import (
	"context"
	"time"

	"trackers-receiver/pkg/models"
)

// QueueStorage универсальный интерфейс для работы с очередями сообщений
// Поддерживает Redis (сейчас) и будущие реализации (RabbitMQ, Kafka)
//
// Дизайн принципы:
// 1. Простота - минимальный API для основных операций
// 2. Гибкость - легко добавить новые реализации
// 3. Производительность - поддержка batch операций
// 4. Наблюдаемость - встроенная статистика
type QueueStorage interface {
	// Push добавляет один документ в указанную очередь
	// queue - имя очереди ("charger", "fasttrack", и т.д.)
	// doc - документ для сохранения
	//
	// Возвращает ошибку если:
	// - Не удалось сериализовать документ
	// - Не удалось записать в очередь
	// - Превышен таймаут операции
	Push(ctx context.Context, queue string, doc *models.Document) error

	// PushBatch добавляет множество документов за одну операцию
	// Более эффективно чем N вызовов Push() для большинства реализаций
	//
	// Семантика:
	// - Redis: использует pipeline (все или ничего не гарантируется)
	// - RabbitMQ: использует транзакции (все или ничего)
	// - Kafka: использует batch send (все или ничего)
	PushBatch(ctx context.Context, queue string, docs []*models.Document) error

	// PushRaw добавляет сырые данные (уже сериализованные)
	// Используется для оптимизации когда сериализация уже выполнена
	PushRaw(ctx context.Context, queue string, data []byte) error

	// Health проверяет работоспособность хранилища
	// Используется для health check endpoints
	//
	// Возвращает nil если все ок, иначе ошибку с описанием проблемы
	Health(ctx context.Context) error

	// Stats возвращает статистику работы хранилища
	// Используется для мониторинга и отладки
	Stats() *Stats

	// Close закрывает соединение с хранилищем
	// После вызова Close() все операции будут возвращать ошибку
	Close() error
}

// Stats статистика работы хранилища
type Stats struct {
	// Операции
	TotalPushed      int64         // Всего успешно записано документов
	TotalFailed      int64         // Всего неудачных попыток
	TotalBytes       int64         // Всего байт записано
	CurrentQPS       float64       // Текущий QPS (queries per second)

	// Производительность
	AvgLatencyMs     float64       // Средняя латентность операций (мс)
	P95LatencyMs     float64       // 95-й перцентиль латентности (мс)
	P99LatencyMs     float64       // 99-й перцентиль латентности (мс)

	// Очереди (опционально, зависит от реализации)
	QueueSizes       map[string]int64 // Размеры очередей
	QueueLags        map[string]int64 // Отставание consumers

	// Здоровье
	LastError        error         // Последняя ошибка
	LastErrorTime    time.Time     // Время последней ошибки
	HealthStatus     HealthStatus  // Текущий статус здоровья
}

// HealthStatus статус здоровья хранилища
type HealthStatus int

const (
	HealthStatusUnknown HealthStatus = iota // Неизвестно (еще не проверяли)
	HealthStatusHealthy                     // Все ок
	HealthStatusDegraded                    // Работает, но есть проблемы
	HealthStatusUnhealthy                   // Не работает
)

func (h HealthStatus) String() string {
	switch h {
	case HealthStatusHealthy:
		return "healthy"
	case HealthStatusDegraded:
		return "degraded"
	case HealthStatusUnhealthy:
		return "unhealthy"
	default:
		return "unknown"
	}
}

// BatchConfig конфигурация для batch операций
type BatchConfig struct {
	// MaxBatchSize максимальное количество документов в одном batch
	MaxBatchSize int

	// FlushInterval максимальное время ожидания перед отправкой неполного batch
	FlushInterval time.Duration

	// MaxRetries максимальное количество повторных попыток при ошибке
	MaxRetries int

	// RetryDelay задержка между повторными попытками
	RetryDelay time.Duration
}

// DefaultBatchConfig возвращает конфигурацию по умолчанию
func DefaultBatchConfig() *BatchConfig {
	return &BatchConfig{
		MaxBatchSize:  1000,
		FlushInterval: 100 * time.Millisecond,
		MaxRetries:    3,
		RetryDelay:    100 * time.Millisecond,
	}
}

// StorageError стандартная ошибка хранилища
type StorageError struct {
	Op      string // Операция (Push, PushBatch, и т.д.)
	Queue   string // Имя очереди
	Err     error  // Исходная ошибка
	Retries int    // Количество попыток
}

func (e *StorageError) Error() string {
	if e.Queue != "" {
		return "storage." + e.Op + "[queue=" + e.Queue + "]: " + e.Err.Error()
	}
	return "storage." + e.Op + ": " + e.Err.Error()
}

func (e *StorageError) Unwrap() error {
	return e.Err
}

// NewStorageError создает новую ошибку хранилища
func NewStorageError(op, queue string, err error) *StorageError {
	return &StorageError{
		Op:    op,
		Queue: queue,
		Err:   err,
	}
}
