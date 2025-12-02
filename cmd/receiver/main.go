package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"trackers-receiver/internal/config"
	"trackers-receiver/internal/server"
	"trackers-receiver/internal/storage/redis"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("The .env file was not found; default environment variables are being used.")
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Configuration loading error: %v", err)
	}

	// Print configuration for debugging
	fmt.Printf("=== Configuration ===\n")
	fmt.Printf("Port: %d\n", cfg.Server.Port)
	fmt.Printf("Read Timeout: %v\n", cfg.Server.ReadTimeout)
	fmt.Printf("Write Timeout: %v\n", cfg.Server.WriteTimeout)
	fmt.Printf("Max Connections: %d\n", cfg.Server.MaxConnections)
	fmt.Printf("Redis: %s\n", cfg.Redis.GetRedisAddr())
	fmt.Printf("Queue charger: %s (max %d)\n", cfg.Queue.ChargerName, cfg.Queue.ChargerMaxLen)
	fmt.Printf("Queue fasttrack: %s (max %d)\n", cfg.Queue.FasttrackName, cfg.Queue.FasttrackMaxLen)
	fmt.Printf("============================\n\n")

	// Initialize Redis storage
	redisConfig := &redis.Config{
		Host:     cfg.Redis.Host,
		Port:     cfg.Redis.Port,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
		PoolSize: 100,
		QueueMaxLengths: map[string]int64{
			cfg.Queue.ChargerName:   int64(cfg.Queue.ChargerMaxLen),
			cfg.Queue.FasttrackName: int64(cfg.Queue.FasttrackMaxLen),
		},
	}

	storage, err := redis.NewRedisStorage(redisConfig)
	if err != nil {
		log.Fatalf("Failed to initialize Redis storage: %v", err)
	}
	defer storage.Close()

	// Check Redis health
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := storage.Health(ctx); err != nil {
		log.Fatalf("Redis health check failed: %v", err)
	}
	fmt.Println("[INFO] Redis connection successful")

	// Configure Worker Pool
	numWorkers := max(4, min(32, runtime.NumCPU()*2))

	poolConfig := &server.PoolConfig{
		NumWorkers:       numWorkers,
		QueueSize:        10000,
		ShutdownTimeout:  30 * time.Second,
		ConnectionConfig: server.DefaultConnectionConfig(),
	}

	fmt.Printf("Worker Pool: %d workers, queue size: %d\n", poolConfig.NumWorkers, poolConfig.QueueSize)

	// Create and start Worker Pool
	pool := server.NewWorkerPool(storage, poolConfig)
	pool.Start()
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		if err := pool.Shutdown(shutdownCtx); err != nil {
			log.Printf("Warning: pool shutdown error: %v", err)
		}
	}()

	fmt.Println("[INFO] Worker pool started")

	// Create TCP listener
	fmt.Printf("Starting TCP server on %s...\n", cfg.Server.GetServerAddr())
	listener, err := server.Start(cfg.Server.GetServerAddr())
	if err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
	defer listener.Close()

	fmt.Println("[INFO] Server successfully started and waiting for connections...")

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Main accept loop
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				fmt.Printf("[ERROR] Error accepting connection: %v\n", err)
				continue
			}

			// Submit connection to worker pool
			if err := pool.Submit(conn); err != nil {
				fmt.Printf("[ERROR] Error submitting connection from %s: %v\n", conn.RemoteAddr(), err)
			}
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	fmt.Println("\n[INFO] Shutdown signal received, starting graceful shutdown...")

	// Close listener to stop accepting new connections
	listener.Close()

	fmt.Println("[INFO] Server shutdown complete")
}
