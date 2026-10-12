package redis

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"trackers-receiver/internal/serialization"
	"trackers-receiver/internal/storage"
	"trackers-receiver/pkg/models"
)

const defaultLatencySamples = 1000

// RedisStorage implements storage.QueueStorage on top of Redis lists.
// Documents are LPUSHed, matching the Python receiver.
type RedisStorage struct {
	client     *redis.Client
	serializer *serialization.Serializer
	config     *Config

	totalPushed atomic.Int64
	totalFailed atomic.Int64
	totalBytes  atomic.Int64

	latencyMu    sync.Mutex
	latencies    []time.Duration
	maxLatencies int

	healthMu  sync.RWMutex
	status    storage.HealthStatus
	lastError error
}

type Config struct {
	Host     string
	Port     int
	Password string
	DB       int

	PoolSize     int
	MinIdleConns int
	MaxRetries   int

	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// QueueMaxLengths caps each listed queue with LTRIM after every push.
	QueueMaxLengths map[string]int64

	// MaxLatencySamples bounds the window used for latency percentiles.
	MaxLatencySamples int
}

func DefaultConfig() *Config {
	return &Config{
		Host:         "localhost",
		Port:         6379,
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
		MaxLatencySamples: defaultLatencySamples,
	}
}

func NewRedisStorage(config *Config) (*RedisStorage, error) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	maxLatencies := config.MaxLatencySamples
	if maxLatencies <= 0 {
		maxLatencies = defaultLatencySamples
	}

	return &RedisStorage{
		client:       client,
		serializer:   serialization.NewSerializer(),
		config:       config,
		latencies:    make([]time.Duration, 0, maxLatencies),
		maxLatencies: maxLatencies,
		status:       storage.HealthStatusHealthy,
	}, nil
}

func (rs *RedisStorage) Push(ctx context.Context, queue string, doc *models.Document) error {
	start := time.Now()

	data, err := rs.serializer.Marshal(doc)
	if err != nil {
		rs.totalFailed.Add(1)
		return storage.NewStorageError("Push", queue, err)
	}

	if err := rs.PushRaw(ctx, queue, data); err != nil {
		return err
	}

	rs.recordLatency(time.Since(start))
	rs.totalPushed.Add(1)
	rs.totalBytes.Add(int64(len(data)))
	return nil
}

func (rs *RedisStorage) PushBatch(ctx context.Context, queue string, docs []*models.Document) error {
	if len(docs) == 0 {
		return nil
	}

	start := time.Now()

	pipe := rs.client.Pipeline()
	var bytes int64
	for _, doc := range docs {
		data, err := rs.serializer.Marshal(doc)
		if err != nil {
			rs.totalFailed.Add(1)
			return storage.NewStorageError("PushBatch", queue, err)
		}
		pipe.LPush(ctx, queue, data)
		bytes += int64(len(data))
	}
	if maxLen, ok := rs.config.QueueMaxLengths[queue]; ok {
		pipe.LTrim(ctx, queue, 0, maxLen-1)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		rs.totalFailed.Add(int64(len(docs)))
		return storage.NewStorageError("PushBatch", queue, err)
	}

	rs.recordLatency(time.Since(start))
	rs.totalPushed.Add(int64(len(docs)))
	rs.totalBytes.Add(bytes)
	return nil
}

func (rs *RedisStorage) PushRaw(ctx context.Context, queue string, data []byte) error {
	pipe := rs.client.Pipeline()
	pipe.LPush(ctx, queue, data)
	if maxLen, ok := rs.config.QueueMaxLengths[queue]; ok {
		pipe.LTrim(ctx, queue, 0, maxLen-1)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		rs.totalFailed.Add(1)
		return storage.NewStorageError("PushRaw", queue, err)
	}
	return nil
}

func (rs *RedisStorage) Health(ctx context.Context) error {
	err := rs.client.Ping(ctx).Err()

	rs.healthMu.Lock()
	defer rs.healthMu.Unlock()
	rs.lastError = err
	if err != nil {
		rs.status = storage.HealthStatusUnhealthy
	} else {
		rs.status = storage.HealthStatusHealthy
	}
	return err
}

// Stats queries Redis for current queue lengths, so it costs a round trip per queue.
func (rs *RedisStorage) Stats() *storage.Stats {
	stats := &storage.Stats{
		TotalPushed: rs.totalPushed.Load(),
		TotalFailed: rs.totalFailed.Load(),
		TotalBytes:  rs.totalBytes.Load(),
		QueueSizes:  make(map[string]int64),
	}

	rs.healthMu.RLock()
	stats.LastError = rs.lastError
	stats.HealthStatus = rs.status
	rs.healthMu.RUnlock()

	rs.latencyMu.Lock()
	sorted := slices.Clone(rs.latencies)
	rs.latencyMu.Unlock()
	if len(sorted) > 0 {
		slices.Sort(sorted)
		var sum time.Duration
		for _, l := range sorted {
			sum += l
		}
		stats.AvgLatencyMs = durationMs(sum) / float64(len(sorted))
		stats.P95LatencyMs = durationMs(percentile(sorted, 0.95))
		stats.P99LatencyMs = durationMs(percentile(sorted, 0.99))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for queue := range rs.config.QueueMaxLengths {
		if size, err := rs.client.LLen(ctx, queue).Result(); err == nil {
			stats.QueueSizes[queue] = size
		}
	}

	return stats
}

func (rs *RedisStorage) Close() error {
	return rs.client.Close()
}

func (rs *RedisStorage) recordLatency(latency time.Duration) {
	rs.latencyMu.Lock()
	defer rs.latencyMu.Unlock()

	if len(rs.latencies) == rs.maxLatencies {
		copy(rs.latencies, rs.latencies[1:])
		rs.latencies = rs.latencies[:len(rs.latencies)-1]
	}
	rs.latencies = append(rs.latencies, latency)
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	idx := min(int(float64(len(sorted))*p), len(sorted)-1)
	return sorted[idx]
}

func durationMs(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func (rs *RedisStorage) GetQueueLength(ctx context.Context, queue string) (int64, error) {
	return rs.client.LLen(ctx, queue).Result()
}

// ClearQueue deletes the queue. Intended for tests.
func (rs *RedisStorage) ClearQueue(ctx context.Context, queue string) error {
	return rs.client.Del(ctx, queue).Err()
}
