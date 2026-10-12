package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"trackers-receiver/internal/config"
	"trackers-receiver/internal/server"
	"trackers-receiver/internal/storage/redis"

	"github.com/joho/godotenv"
)

const shutdownTimeout = 30 * time.Second

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file, using environment only")
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Load config: %v", err)
	}

	storage, err := redis.NewRedisStorage(&redis.Config{
		Host:       cfg.Redis.Host,
		Port:       cfg.Redis.Port,
		Password:   cfg.Redis.Password,
		DB:         cfg.Redis.DB,
		PoolSize:   cfg.Redis.PoolSize,
		MaxRetries: cfg.Redis.MaxRetries,
		QueueMaxLengths: map[string]int64{
			cfg.Queue.ChargerName:   int64(cfg.Queue.ChargerMaxLen),
			cfg.Queue.FasttrackName: int64(cfg.Queue.FasttrackMaxLen),
		},
	})
	if err != nil {
		log.Fatalf("Init Redis storage: %v", err)
	}
	defer storage.Close()

	connConfig := server.DefaultConnectionConfig()
	connConfig.ReadTimeout = cfg.Server.ReadTimeout
	connConfig.WriteTimeout = cfg.Server.WriteTimeout
	connConfig.QueueCharger = cfg.Queue.ChargerName
	connConfig.QueueFasttrack = cfg.Queue.FasttrackName

	srvConfig := &server.Config{
		MaxConnections: cfg.Server.MaxConnections,
		Connection:     connConfig,
	}
	if rl := cfg.RateLimit; rl.Enabled {
		srvConfig.RateLimiter = &server.RateLimiterConfig{
			MaxConnectionsPerWindow: rl.MaxPerWindow,
			WindowDuration:          rl.Window,
			BlockDuration:           rl.BlockDuration,
			WhitelistedIPs:          rl.Whitelist,
			CleanupInterval:         time.Minute,
		}
		log.Printf("Rate limit: %d connections per %v per IP, first block %v, whitelist %v",
			rl.MaxPerWindow, rl.Window, rl.BlockDuration, rl.Whitelist)
	} else {
		log.Println("Rate limit disabled")
	}
	srv := server.New(storage, srvConfig)

	listener, err := net.Listen("tcp", cfg.Server.GetServerAddr())
	if err != nil {
		log.Fatalf("Listen on %s: %v", cfg.Server.GetServerAddr(), err)
	}

	log.Printf("Listening on %s, Redis %s, queues %s/%s",
		listener.Addr(), cfg.Redis.GetRedisAddr(), cfg.Queue.ChargerName, cfg.Queue.FasttrackName)

	go srv.Serve(listener)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down")
	listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Shutdown: %v", err)
	}
}
