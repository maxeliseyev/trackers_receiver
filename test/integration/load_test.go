package integration

import (
	"context"
	"errors"
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
		// Dial sequentially: a burst of simultaneous dials overflows the kernel
		// accept backlog (128 on macOS) and gets reset before the server sees it.
		conn, err := net.Dial("tcp", serverAddr)
		if err != nil {
			t.Fatalf("connection %d: dial: %v", i, err)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			ok := false
			defer func() {
				if !ok {
					answered.Done()
				}
			}()
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

	// accepted reports whether the server kept a silent connection open.
	// A rate-limited one is accepted by the kernel and closed right away.
	accepted := func() bool {
		conn, err := net.Dial("tcp", serverAddr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, err = conn.Read(make([]byte, 1))
		var ne net.Error
		return errors.As(err, &ne) && ne.Timeout()
	}

	t.Run("UnknownIPIsLimited", func(t *testing.T) {
		n := 0
		for range 10 {
			if accepted() {
				n++
			}
		}
		if n != rateLimiterConfig.MaxConnectionsPerWindow {
			t.Errorf("%d of 10 connections accepted; expected %d", n, rateLimiterConfig.MaxConnectionsPerWindow)
		}
	})

	// The previous subtest got 127.0.0.1 blocked, so start a fresh server.
	t.Run("ValidTrafficLiftsLimit", func(t *testing.T) {
		srv.Shutdown(context.Background())
		listener.Close()

		srv = server.New(storage, &server.Config{
			MaxConnections: 10,
			RateLimiter:    rateLimiterConfig,
			Connection:     testConnectionConfig(),
		})
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		serverAddr = listener.Addr().String()
		go srv.Serve(listener)

		conn, err := net.Dial("tcp", serverAddr)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		conn.Write(buildTestEGTSPacket())
		if _, err := conn.Read(make([]byte, 1024)); err != nil {
			t.Fatalf("no response to a valid packet: %v", err)
		}
		conn.Close()

		for i := range 10 {
			if !accepted() {
				t.Fatalf("connection %d from a trusted IP was rejected", i)
			}
		}
	})
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
