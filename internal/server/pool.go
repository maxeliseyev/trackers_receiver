package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"trackers-receiver/internal/storage"
)

// WorkerPool serves accepted connections with a fixed number of goroutines.
// Each worker owns one connection for its whole lifetime, so at most
// NumWorkers trackers are served at once; the rest wait in the queue, and
// connections beyond QueueSize are rejected.
type WorkerPool struct {
	workers   int
	queueSize int
	storage   storage.QueueStorage
	config    *ConnectionConfig

	rateLimiter *RateLimiter // nil when disabled

	jobs chan Job
	done chan struct{} // closed once Shutdown returns

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// mu guards closed and active. Submit holds it for reading so that
	// Shutdown cannot run between its closed check and the send.
	mu     sync.RWMutex
	closed bool
	active map[net.Conn]struct{}

	stats PoolStats
}

type Job struct {
	Conn       net.Conn
	ReceivedAt time.Time
}

type PoolStats struct {
	TotalAccepted  atomic.Int64
	TotalRejected  atomic.Int64 // queue full or rate limited
	TotalProcessed atomic.Int64 // connections that ended without error
	TotalFailed    atomic.Int64

	ActiveWorkers  atomic.Int32
	AvgQueueTimeMs atomic.Int64 // exponential moving average, α = 1/2

	StartTime time.Time
}

type PoolConfig struct {
	NumWorkers int
	QueueSize  int

	// RateLimiterConfig enables per-IP rate limiting; nil disables it.
	RateLimiterConfig *RateLimiterConfig
	ConnectionConfig  *ConnectionConfig
}

func DefaultPoolConfig() *PoolConfig {
	return &PoolConfig{
		NumWorkers:        16,
		QueueSize:         10000,
		RateLimiterConfig: DefaultRateLimiterConfig(),
		ConnectionConfig:  DefaultConnectionConfig(),
	}
}

func NewWorkerPool(storage storage.QueueStorage, config *PoolConfig) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	pool := &WorkerPool{
		workers:   config.NumWorkers,
		queueSize: config.QueueSize,
		storage:   storage,
		config:    config.ConnectionConfig,
		jobs:      make(chan Job, config.QueueSize),
		done:      make(chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
		active:    make(map[net.Conn]struct{}),
	}
	if config.RateLimiterConfig != nil {
		pool.rateLimiter = NewRateLimiter(config.RateLimiterConfig)
	}
	pool.stats.StartTime = time.Now()

	return pool
}

func (p *WorkerPool) Start() {
	for range p.workers {
		p.wg.Add(1)
		go p.worker()
	}
}

func (p *WorkerPool) worker() {
	defer p.wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			return
		case job := <-p.jobs:
			p.processJob(job)
		}
	}
}

func (p *WorkerPool) processJob(job Job) {
	if !p.track(job.Conn) {
		job.Conn.Close()
		return
	}
	defer p.untrack(job.Conn)

	p.stats.ActiveWorkers.Add(1)
	defer p.stats.ActiveWorkers.Add(-1)

	p.updateQueueTime(time.Since(job.ReceivedAt))

	err := NewConnectionHandler(job.Conn, p.storage, p.config).Handle()
	if err == nil {
		p.stats.TotalProcessed.Add(1)
		return
	}

	p.stats.TotalFailed.Add(1)
	if pe, ok := err.(*ProtocolError); ok {
		if p.rateLimiter != nil {
			p.rateLimiter.RecordProtocolError(job.Conn)
		}
		log.Printf("[WARN] %v", pe)
		return
	}
	log.Printf("[ERROR] connection %s: %v", job.Conn.RemoteAddr(), err)
}

// track registers a connection for Shutdown to close. It returns false if the
// pool is already shutting down.
func (p *WorkerPool) track(conn net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.active[conn] = struct{}{}
	return true
}

func (p *WorkerPool) untrack(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.active, conn)
}

// Submit queues a connection. On error the connection has already been closed.
func (p *WorkerPool) Submit(conn net.Conn) error {
	if p.rateLimiter != nil && !p.rateLimiter.Allow(conn) {
		p.stats.TotalRejected.Add(1)
		conn.Close()
		return &PoolError{
			Code:    "RATE_LIMITED",
			Message: "connection rate limit exceeded or IP blocked",
			Workers: p.workers,
		}
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		conn.Close()
		return &PoolError{Code: "SHUTTING_DOWN", Message: "pool is shutting down"}
	}

	select {
	case p.jobs <- Job{Conn: conn, ReceivedAt: time.Now()}:
		p.stats.TotalAccepted.Add(1)
		return nil
	default:
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

// Shutdown stops accepting work, closes queued and active connections and
// waits for workers to exit or ctx to expire. Trackers resend unacknowledged
// data after reconnecting, so dropping connections loses nothing.
func (p *WorkerPool) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	p.closed = true
	for conn := range p.active {
		conn.Close()
	}
	p.mu.Unlock()

	if p.rateLimiter != nil {
		p.rateLimiter.Stop()
	}
	p.cancel()

	finished := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(finished)
	}()

	var err error
	select {
	case <-finished:
	case <-ctx.Done():
		err = &PoolError{
			Code:    "SHUTDOWN_TIMEOUT",
			Message: "graceful shutdown timeout exceeded",
			Workers: p.workers,
		}
	}

drain:
	for {
		select {
		case job := <-p.jobs:
			job.Conn.Close()
		default:
			break drain
		}
	}

	close(p.done)
	return err
}

// Wait blocks until Shutdown has returned.
func (p *WorkerPool) Wait() {
	<-p.done
}

func (p *WorkerPool) Stats() *PoolStats {
	return &p.stats
}

func (p *WorkerPool) updateQueueTime(queueTime time.Duration) {
	ms := queueTime.Milliseconds()
	for {
		old := p.stats.AvgQueueTimeMs.Load()
		if p.stats.AvgQueueTimeMs.CompareAndSwap(old, (old+ms)/2) {
			return
		}
	}
}

func (p *WorkerPool) Health() error {
	select {
	case <-p.done:
		return &PoolError{Code: "POOL_STOPPED", Message: "worker pool is not running"}
	default:
	}

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

// GetMetrics returns a flat snapshot of pool and rate limiter counters.
func (p *WorkerPool) GetMetrics() map[string]any {
	uptime := time.Since(p.stats.StartTime).Seconds()
	processed := p.stats.TotalProcessed.Load()
	accepted := p.stats.TotalAccepted.Load()

	metrics := map[string]any{
		"pool_connections_accepted_total":  accepted,
		"pool_connections_rejected_total":  p.stats.TotalRejected.Load(),
		"pool_connections_processed_total": processed,
		"pool_connections_failed_total":    p.stats.TotalFailed.Load(),

		"pool_workers_total":  p.workers,
		"pool_workers_active": p.stats.ActiveWorkers.Load(),

		"pool_queue_size":        p.queueSize,
		"pool_queue_length":      len(p.jobs),
		"pool_queue_time_avg_ms": p.stats.AvgQueueTimeMs.Load(),

		"pool_uptime_seconds": uptime,
		"pool_throughput_qps": float64(processed) / uptime,

		// +1 avoids division by zero before the first connection.
		"pool_rejection_rate": float64(p.stats.TotalRejected.Load()) / float64(accepted+1),
		"pool_error_rate":     float64(p.stats.TotalFailed.Load()) / float64(processed+1),
	}

	if p.rateLimiter != nil {
		for key, value := range p.rateLimiter.Stats() {
			metrics["ratelimit_"+key] = value
		}
	}

	return metrics
}
