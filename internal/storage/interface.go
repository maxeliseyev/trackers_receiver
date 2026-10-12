package storage

import (
	"context"

	"trackers-receiver/pkg/models"
)

// QueueStorage is a sink for serialized documents grouped into named queues.
type QueueStorage interface {
	Push(ctx context.Context, queue string, doc *models.Document) error

	// PushBatch writes all docs in one round trip. It is not atomic: on error
	// some documents may already be in the queue.
	PushBatch(ctx context.Context, queue string, docs []*models.Document) error

	PushRaw(ctx context.Context, queue string, data []byte) error

	Health(ctx context.Context) error
	Stats() *Stats
	Close() error
}

type Stats struct {
	TotalPushed int64
	TotalFailed int64
	TotalBytes  int64

	AvgLatencyMs float64
	P95LatencyMs float64
	P99LatencyMs float64

	QueueSizes map[string]int64

	LastError    error
	HealthStatus HealthStatus
}

type HealthStatus int

const (
	HealthStatusUnknown HealthStatus = iota
	HealthStatusHealthy
	HealthStatusDegraded
	HealthStatusUnhealthy
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

type StorageError struct {
	Op    string
	Queue string
	Err   error
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

func NewStorageError(op, queue string, err error) *StorageError {
	return &StorageError{Op: op, Queue: queue, Err: err}
}
