package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Server ServerConfig
	Redis  RedisConfig
	Queue  QueueConfig
}

type ServerConfig struct {
	Port         int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	// MaxConnections caps how many accepted connections may wait for a worker.
	MaxConnections int
}

type RedisConfig struct {
	Host       string
	Port       int
	Password   string
	DB         int
	PoolSize   int
	MaxRetries int
}

type QueueConfig struct {
	ChargerName     string
	ChargerMaxLen   int
	FasttrackName   string
	FasttrackMaxLen int
}

func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Port:           getEnvAsInt("SERVER_PORT", 36000),
			ReadTimeout:    getEnvAsDuration("SERVER_READ_TIMEOUT", 600*time.Second),
			WriteTimeout:   getEnvAsDuration("SERVER_WRITE_TIMEOUT", 30*time.Second),
			MaxConnections: getEnvAsInt("SERVER_MAX_CONNECTIONS", 10000),
		},
		Redis: RedisConfig{
			Host:       getEnv("REDIS_HOST", "localhost"),
			Port:       getEnvAsInt("REDIS_PORT", 6379),
			Password:   getEnv("REDIS_PASSWORD", ""),
			DB:         getEnvAsInt("REDIS_DB", 0),
			PoolSize:   getEnvAsInt("REDIS_POOL_SIZE", 100),
			MaxRetries: getEnvAsInt("REDIS_MAX_RETRIES", 3),
		},
		Queue: QueueConfig{
			ChargerName:     getEnv("QUEUE_CHARGER_NAME", "charger"),
			ChargerMaxLen:   getEnvAsInt("QUEUE_CHARGER_MAX_LEN", 2999999),
			FasttrackName:   getEnv("QUEUE_FASTTRACK_NAME", "fasttrack"),
			FasttrackMaxLen: getEnvAsInt("QUEUE_FASTTRACK_MAX_LEN", 2999999),
		},
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d (should be 1-65535)", c.Server.Port)
	}

	if c.Server.ReadTimeout <= 0 || c.Server.WriteTimeout <= 0 {
		return fmt.Errorf("server timeouts must be positive")
	}

	if c.Server.MaxConnections < 1 {
		return fmt.Errorf("SERVER_MAX_CONNECTIONS must be positive")
	}

	if c.Redis.Host == "" {
		return fmt.Errorf("REDIS_HOST cannot be empty")
	}

	if c.Redis.Port < 1 || c.Redis.Port > 65535 {
		return fmt.Errorf("invalid Redis port: %d", c.Redis.Port)
	}

	if c.Queue.ChargerName == "" {
		return fmt.Errorf("charger queue name cannot be empty")
	}

	if c.Queue.FasttrackName == "" {
		return fmt.Errorf("fasttrack queue name cannot be empty")
	}

	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}

	return value
}

// getEnvAsDuration reads a whole number of seconds.
func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}

	seconds, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}

	return time.Duration(seconds) * time.Second
}

func (c *RedisConfig) GetRedisAddr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

func (c *ServerConfig) GetServerAddr() string {
	return fmt.Sprintf(":%d", c.Port)
}
