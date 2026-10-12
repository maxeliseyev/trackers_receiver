package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is read from the environment. Variables shared with the Python
// receiver (REDIS_HOST, REDIS_PORT, USE_HAPROXY, CONNECTION_TIMEOUT and the
// queue settings) keep its names and defaults, so existing deployments work
// unchanged.
type Config struct {
	Server    ServerConfig
	Redis     RedisConfig
	Queue     QueueConfig
	RateLimit RateLimitConfig
}

type ServerConfig struct {
	Port int
	// UseHAProxy expects a PROXY protocol header on every connection.
	UseHAProxy   bool
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	// MaxConnections caps concurrently served tracker connections.
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

// RateLimitConfig limits new connections per source IP. IPs that sent a valid
// packet within the last hour are exempt, so the limits only bite on unknown
// addresses; they are loose because a retranslator reconnecting after a restart
// is unknown too (production peak: 113 connections in 10 s from one IP).
type RateLimitConfig struct {
	Enabled       bool
	MaxPerWindow  int
	Window        time.Duration
	BlockDuration time.Duration // first block; doubles on each repeat
	// Whitelist must include any load balancer in front of the receiver,
	// otherwise all trackers appear to come from its address.
	Whitelist []string
}

func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Port:           getEnvAsInt("SERVER_PORT", 36000),
			UseHAProxy:     getEnvAsBool("USE_HAPROXY", false),
			ReadTimeout:    getEnvAsDuration("CONNECTION_TIMEOUT", 600*time.Second),
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
			ChargerName:     getEnv("CHARGER_QUEUE", "charger"),
			ChargerMaxLen:   getEnvAsInt("CHARGER_QUEUE_MAX_LEN", 99999),
			FasttrackName:   getEnv("FASTTRACK_QUEUE", "fasttrack"),
			FasttrackMaxLen: getEnvAsInt("FASTTRACK_QUEUE_MAX_LEN", 99999),
		},
		RateLimit: RateLimitConfig{
			Enabled:       getEnvAsBool("RATE_LIMIT_ENABLED", true),
			MaxPerWindow:  getEnvAsInt("RATE_LIMIT_MAX_PER_WINDOW", 300),
			Window:        getEnvAsDuration("RATE_LIMIT_WINDOW", 10*time.Second),
			BlockDuration: getEnvAsDuration("RATE_LIMIT_BLOCK_DURATION", time.Minute),
			Whitelist:     getEnvAsList("RATE_LIMIT_WHITELIST", []string{"127.0.0.1", "::1"}),
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

	if c.RateLimit.Enabled && (c.RateLimit.MaxPerWindow < 1 || c.RateLimit.Window <= 0 || c.RateLimit.BlockDuration <= 0) {
		return fmt.Errorf("rate limit settings must be positive")
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

func getEnvAsBool(key string, defaultValue bool) bool {
	value, err := strconv.ParseBool(os.Getenv(key))
	if err != nil {
		return defaultValue
	}
	return value
}

// getEnvAsList reads a comma-separated list. An empty variable yields the default.
func getEnvAsList(key string, defaultValue []string) []string {
	var list []string
	for item := range strings.SplitSeq(os.Getenv(key), ",") {
		if item = strings.TrimSpace(item); item != "" {
			list = append(list, item)
		}
	}
	if len(list) == 0 {
		return defaultValue
	}
	return list
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
