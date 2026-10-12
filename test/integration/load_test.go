package integration

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"trackers-receiver/internal/server"
	"trackers-receiver/internal/storage/redis"
)

// TestManyConcurrentConnections keeps every connection open until all of them
// have been answered, so it fails if the server can only serve a few at once.
func TestManyConcurrentConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	cfg := &redis.Config{
		Host:     "localhost",
		Port:     6379,
		Password: "",
		DB:       15,
		QueueMaxLengths: map[string]int64{
			"test_charger": 10000,
		},
	}

	storage, err := redis.NewRedisStorage(cfg)
	if err != nil {
		t.Skipf("Redis not available: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()
	storage.ClearQueue(ctx, "test_charger")

	srv := server.New(storage, &server.Config{
		MaxConnections: 1000,
		RateLimiter:    nil,
		Connection:     testConnectionConfig(),
	})
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()

	go srv.Serve(listener)

	time.Sleep(100 * time.Millisecond)

	const numConnections = 500
	packet := buildTestEGTSPacket()

	var answered, release sync.WaitGroup
	var wg sync.WaitGroup
	var mu sync.Mutex
	successCount := 0
	answered.Add(numConnections)
	release.Add(1)

	startTime := time.Now()
	for i := range numConnections {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok := false
			defer func() {
				if !ok {
					answered.Done()
				}
			}()

			conn, err := net.Dial("tcp", serverAddr)
			if err != nil {
				t.Logf("connection %d: dial: %v", i, err)
				return
			}
			defer conn.Close()

			conn.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := conn.Write(packet); err != nil {
				return
			}
			if _, err := conn.Read(make([]byte, 1024)); err != nil {
				t.Logf("connection %d: read: %v", i, err)
				return
			}

			mu.Lock()
			successCount++
			mu.Unlock()
			ok = true
			answered.Done()
			release.Wait()
		}()
	}

	answered.Wait()
	duration := time.Since(startTime)
	active := srv.ActiveConnections()
	release.Done()
	wg.Wait()

	t.Logf("%d/%d answered in %v, %d active at peak", successCount, numConnections, duration, active)

	if successCount != numConnections {
		t.Errorf("only %d of %d connections were answered", successCount, numConnections)
	}
	if active != numConnections {
		t.Errorf("ActiveConnections = %d while all clients were connected; expected %d", active, numConnections)
	}

	queueLen, err := storage.GetQueueLength(ctx, "test_charger")
	if err != nil {
		t.Fatalf("Failed to get queue length: %v", err)
	}
	if queueLen != numConnections {
		t.Errorf("Redis queue length = %d; expected %d", queueLen, numConnections)
	}
}

// TestRateLimiterIntegration tests rate limiter in real conditions
func TestRateLimiterIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping rate limiter test in short mode")
	}

	cfg := &redis.Config{
		Host:     "localhost",
		Port:     6379,
		Password: "",
		DB:       15,
		QueueMaxLengths: map[string]int64{
			"test_charger": 1000,
		},
	}

	storage, err := redis.NewRedisStorage(cfg)
	if err != nil {
		t.Skipf("Redis not available: %v", err)
	}
	defer storage.Close()

	rateLimiterConfig := &server.RateLimiterConfig{
		MaxConnectionsPerWindow: 5,
		WindowDuration:          2 * time.Second,
		BlockDuration:           5 * time.Second,
		WhitelistedIPs:          []string{},
		CleanupInterval:         1 * time.Minute,
	}

	srv := server.New(storage, &server.Config{
		MaxConnections: 10,
		RateLimiter:    rateLimiterConfig,
		Connection:     testConnectionConfig(),
	})
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()

	go srv.Serve(listener)

	time.Sleep(100 * time.Millisecond)

	// Try to connect 10 times rapidly from same IP
	packet := buildTestEGTSPacket()
	successCount := 0

	for i := 0; i < 10; i++ {
		conn, err := net.Dial("tcp", serverAddr)
		if err != nil {
			t.Logf("Connection %d failed: %v", i, err)
			continue
		}

		// A rate-limited connection is accepted by the kernel and then closed
		// by the server, so only a received response counts as success.
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Write(packet)
		if err == nil {
			_, err = conn.Read(make([]byte, 1024))
		}
		conn.Close()

		if err == nil {
			successCount++
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Logf("Rate limiter test: %d/%d connections succeeded", successCount, 10)

	// limit is 5 per window; the rest should be rate limited
	if successCount > 6 {
		t.Errorf("Rate limiter too permissive: %d connections succeeded (expected ~5)", successCount)
	}

	if successCount < 3 {
		t.Errorf("Rate limiter too strict: only %d connections succeeded", successCount)
	}

	stats := srv.Stats()
	metrics := srv.GetMetrics()

	t.Logf("Rejected: %d", stats.TotalRejected.Load())
	t.Logf("Rate limiter blocked: %v", metrics["ratelimit_total_blocked"])

	if stats.TotalRejected.Load() == 0 {
		t.Error("Expected some rejected connections due to rate limiting")
	}
}

// TestGracefulShutdownIntegration tests graceful shutdown with active connections
func TestGracefulShutdownIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping shutdown test in short mode")
	}

	cfg := &redis.Config{
		Host:     "localhost",
		Port:     6379,
		Password: "",
		DB:       15,
		QueueMaxLengths: map[string]int64{
			"test_charger": 1000,
		},
	}

	storage, err := redis.NewRedisStorage(cfg)
	if err != nil {
		t.Skipf("Redis not available: %v", err)
	}
	defer storage.Close()

	srv := server.New(storage, &server.Config{
		MaxConnections: 100,
		RateLimiter:    nil,
		Connection:     testConnectionConfig(),
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}

	serverAddr := listener.Addr().String()

	go srv.Serve(listener)

	time.Sleep(100 * time.Millisecond)

	clients := make([]net.Conn, 0, 10)
	for range 10 {
		conn, err := net.Dial("tcp", serverAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		clients = append(clients, conn)
	}
	deadline := time.Now().Add(time.Second)
	for srv.ActiveConnections() < len(clients) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}
	t.Logf("Shutdown with %d open connections took %v", len(clients), time.Since(start))
	listener.Close()

	for i, conn := range clients {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Errorf("client %d: connection still open after Shutdown", i)
		}
	}
}
