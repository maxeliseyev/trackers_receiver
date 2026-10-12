package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"trackers-receiver/internal/storage"
)

// Server serves each tracker connection in its own goroutine. Connections
// beyond MaxConnections are closed right after accept.
type Server struct {
	storage     storage.QueueStorage
	connConfig  *ConnectionConfig
	maxConns    int
	rateLimiter *RateLimiter // nil when disabled

	mu     sync.Mutex
	closed bool
	active map[net.Conn]struct{}
	wg     sync.WaitGroup

	stats Stats
}

type Stats struct {
	TotalAccepted  atomic.Int64
	TotalRejected  atomic.Int64 // over the limit, rate limited or shutting down
	TotalProcessed atomic.Int64 // connections that ended without error
	TotalFailed    atomic.Int64
	StartTime      time.Time
}

type Config struct {
	MaxConnections int
	// RateLimiter enables per-IP rate limiting; nil disables it.
	RateLimiter *RateLimiterConfig
	Connection  *ConnectionConfig
}

func DefaultConfig() *Config {
	return &Config{
		MaxConnections: 10000,
		RateLimiter:    DefaultRateLimiterConfig(),
		Connection:     DefaultConnectionConfig(),
	}
}

func New(storage storage.QueueStorage, config *Config) *Server {
	s := &Server{
		storage:    storage,
		connConfig: config.Connection,
		maxConns:   config.MaxConnections,
		active:     make(map[net.Conn]struct{}),
	}
	if config.RateLimiter != nil {
		s.rateLimiter = NewRateLimiter(config.RateLimiter)
	}
	s.stats.StartTime = time.Now()
	return s
}

// Serve accepts connections until the listener is closed.
func (s *Server) Serve(listener net.Listener) {
	var backoff time.Duration
	for {
		conn, err := listener.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			// Typically EMFILE: wait for connections to close instead of spinning.
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			log.Printf("[ERROR] accept: %v; retrying in %v", err, backoff)
			time.Sleep(backoff)
			continue
		}
		backoff = 0

		if err := s.Submit(conn); err != nil {
			log.Printf("[WARN] reject %s: %v", conn.RemoteAddr(), err)
		}
	}
}

// Submit starts serving conn. On error the connection has already been closed.
func (s *Server) Submit(conn net.Conn) error {
	if s.rateLimiter != nil && !s.rateLimiter.Allow(conn) {
		return s.reject(conn, &ServerError{Code: "RATE_LIMITED", Message: "connection rate limit exceeded or IP blocked"})
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return s.reject(conn, &ServerError{Code: "SHUTTING_DOWN", Message: "server is shutting down"})
	}
	if len(s.active) >= s.maxConns {
		s.mu.Unlock()
		return s.reject(conn, &ServerError{
			Code:    "TOO_MANY_CONNECTIONS",
			Message: fmt.Sprintf("%d connections already active", s.maxConns),
		})
	}
	s.active[conn] = struct{}{}
	s.wg.Add(1)
	s.mu.Unlock()

	s.stats.TotalAccepted.Add(1)
	go s.serveConn(conn)
	return nil
}

func (s *Server) reject(conn net.Conn, err error) error {
	s.stats.TotalRejected.Add(1)
	conn.Close()
	return err
}

func (s *Server) serveConn(conn net.Conn) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		delete(s.active, conn)
		s.mu.Unlock()
	}()

	err := NewConnectionHandler(conn, s.storage, s.connConfig).Handle()
	if err == nil {
		s.stats.TotalProcessed.Add(1)
		return
	}

	s.stats.TotalFailed.Add(1)
	if pe, ok := err.(*ProtocolError); ok {
		if s.rateLimiter != nil {
			s.rateLimiter.RecordProtocolError(conn)
		}
		log.Printf("[WARN] %v", pe)
		return
	}
	if s.isClosed() {
		return // connection was closed by Shutdown
	}
	log.Printf("[ERROR] connection %s: %v", conn.RemoteAddr(), err)
}

// Shutdown stops accepting connections, closes the active ones and waits for
// their goroutines to finish or ctx to expire. Trackers resend unacknowledged
// data after reconnecting, so dropping connections loses nothing.
// The caller closes the listener.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	for conn := range s.active {
		conn.Close()
	}
	s.mu.Unlock()

	if s.rateLimiter != nil {
		s.rateLimiter.Stop()
	}

	finished := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(finished)
	}()

	select {
	case <-finished:
		return nil
	case <-ctx.Done():
		return &ServerError{Code: "SHUTDOWN_TIMEOUT", Message: "connections did not finish in time"}
	}
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Server) ActiveConnections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.active)
}

func (s *Server) Stats() *Stats {
	return &s.stats
}

func (s *Server) Health() error {
	s.mu.Lock()
	closed, active := s.closed, len(s.active)
	s.mu.Unlock()

	if closed {
		return &ServerError{Code: "STOPPED", Message: "server is not running"}
	}
	if usage := float64(active) / float64(s.maxConns); usage > 0.9 {
		return &ServerError{
			Code:    "NEAR_CONNECTION_LIMIT",
			Message: fmt.Sprintf("%d of %d connections in use", active, s.maxConns),
		}
	}
	return nil
}

type ServerError struct {
	Code    string
	Message string
}

func (e *ServerError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// GetMetrics returns a flat snapshot of server and rate limiter counters.
func (s *Server) GetMetrics() map[string]any {
	metrics := map[string]any{
		"connections_accepted_total":  s.stats.TotalAccepted.Load(),
		"connections_rejected_total":  s.stats.TotalRejected.Load(),
		"connections_processed_total": s.stats.TotalProcessed.Load(),
		"connections_failed_total":    s.stats.TotalFailed.Load(),
		"connections_active":          s.ActiveConnections(),
		"connections_max":             s.maxConns,
		"uptime_seconds":              time.Since(s.stats.StartTime).Seconds(),
	}

	if s.rateLimiter != nil {
		for key, value := range s.rateLimiter.Stats() {
			metrics["ratelimit_"+key] = value
		}
	}

	return metrics
}
