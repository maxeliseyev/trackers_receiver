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

// TestWorkerPoolUnderLoad tests worker pool behavior under high load
func TestWorkerPoolUnderLoad(t *testing.T) {
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

	poolConfig := &server.PoolConfig{
		NumWorkers:        4,
		QueueSize:         100,
		RateLimiterConfig: nil,
		ConnectionConfig:  server.DefaultConnectionConfig(),
	}

	pool := server.NewWorkerPool(storage, poolConfig)
	pool.Start()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		pool.Shutdown(shutdownCtx)
	}()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			pool.Submit(conn)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	numConnections := 200
	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	packet := buildTestEGTSPacket()

	startTime := time.Now()

	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			conn, err := net.Dial("tcp", serverAddr)
			if err != nil {
				t.Logf("Connection %d failed to dial: %v", id, err)
				return
			}
			defer conn.Close()

			conn.SetDeadline(time.Now().Add(10 * time.Second))

			_, err = conn.Write(packet)
			if err != nil {
				return
			}

			response := make([]byte, 1024)
			_, err = conn.Read(response)
			if err == nil {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}(i)

		// Small delay to avoid overwhelming the system
		if i%50 == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}

	wg.Wait()
	duration := time.Since(startTime)

	t.Logf("Load test completed:")
	t.Logf("  Total connections: %d", numConnections)
	t.Logf("  Successful: %d", successCount)
	t.Logf("  Duration: %v", duration)
	t.Logf("  Throughput: %.2f conn/sec", float64(numConnections)/duration.Seconds())

	stats := pool.Stats()
	t.Logf("Worker Pool Stats:")
	t.Logf("  Total Accepted: %d", stats.TotalAccepted.Load())
	t.Logf("  Total Rejected: %d", stats.TotalRejected.Load())
	t.Logf("  Total Processed: %d", stats.TotalProcessed.Load())
	t.Logf("  Total Failed: %d", stats.TotalFailed.Load())

	// We expect some rejections due to limited queue size
	if stats.TotalAccepted.Load() == 0 {
		t.Error("Expected some accepted connections")
	}

	time.Sleep(2 * time.Second)

	queueLen, err := storage.GetQueueLength(ctx, "test_charger")
	if err != nil {
		t.Fatalf("Failed to get queue length: %v", err)
	}

	t.Logf("Redis queue length: %d", queueLen)

	if queueLen == 0 {
		t.Error("Expected some data in Redis queue")
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

	poolConfig := &server.PoolConfig{
		NumWorkers:        2,
		QueueSize:         10,
		RateLimiterConfig: rateLimiterConfig,
		ConnectionConfig:  server.DefaultConnectionConfig(),
	}

	pool := server.NewWorkerPool(storage, poolConfig)
	pool.Start()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pool.Shutdown(shutdownCtx)
	}()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			pool.Submit(conn)
		}
	}()

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

		conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Write(packet)
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

	stats := pool.Stats()
	metrics := pool.GetMetrics()

	t.Logf("Pool rejected: %d", stats.TotalRejected.Load())
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

	poolConfig := &server.PoolConfig{
		NumWorkers:        2,
		QueueSize:         100,
		RateLimiterConfig: nil,
		ConnectionConfig:  server.DefaultConnectionConfig(),
	}

	pool := server.NewWorkerPool(storage, poolConfig)
	pool.Start()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}

	serverAddr := listener.Addr().String()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			pool.Submit(conn)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	var wg sync.WaitGroup
	packet := buildTestEGTSPacket()

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.Dial("tcp", serverAddr)
			if err != nil {
				return
			}
			defer conn.Close()
			conn.Write(packet)
			time.Sleep(500 * time.Millisecond)
		}()
	}

	time.Sleep(200 * time.Millisecond)

	shutdownStart := time.Now()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = pool.Shutdown(shutdownCtx)
	shutdownDuration := time.Since(shutdownStart)

	t.Logf("Shutdown completed in %v", shutdownDuration)

	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}

	listener.Close()

	wg.Wait()

	stats := pool.Stats()
	t.Logf("Final stats:")
	t.Logf("  Accepted: %d", stats.TotalAccepted.Load())
	t.Logf("  Processed: %d", stats.TotalProcessed.Load())
	t.Logf("  Failed: %d", stats.TotalFailed.Load())
}
