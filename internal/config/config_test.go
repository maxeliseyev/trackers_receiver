package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadDefaultConfig(t *testing.T) {
	clearEnv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Config loading failed: %v", err)
	}

	if cfg.Server.Port != 36000 {
		t.Errorf("Server.Port = %d; expected 36000", cfg.Server.Port)
	}

	if cfg.Server.ReadTimeout != 600*time.Second {
		t.Errorf("Server.ReadTimeout = %v; expected 600s", cfg.Server.ReadTimeout)
	}

	// Проверяем дефолтные значения Redis
	if cfg.Redis.Host != "localhost" {
		t.Errorf("Redis.Host = %s; expected localhost", cfg.Redis.Host)
	}

	if cfg.Redis.Port != 6379 {
		t.Errorf("Redis.Port = %d; expected 6379", cfg.Redis.Port)
	}

	// Проверяем дефолтные значения очередей
	if cfg.Queue.ChargerName != "charger" {
		t.Errorf("Queue.ChargerName = %s; expected charger", cfg.Queue.ChargerName)
	}

	if cfg.Queue.ChargerMaxLen != 2999999 {
		t.Errorf("Queue.ChargerMaxLen = %d; expected 2999999", cfg.Queue.ChargerMaxLen)
	}

	t.Log("Default configuration loaded successfully")
}

func TestLoadConfigFromEnv(t *testing.T) {
	clearEnv()

	os.Setenv("SERVER_PORT", "8080")
	os.Setenv("REDIS_HOST", "redis-server")
	os.Setenv("REDIS_PORT", "6380")
	os.Setenv("QUEUE_CHARGER_NAME", "test_charger")
	defer clearEnv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Config loading failed: %v", err)
	}

	// Проверяем, что значения загрузились из ENV
	if cfg.Server.Port != 8080 {
		t.Errorf("Server.Port = %d; expected 8080", cfg.Server.Port)
	}

	if cfg.Redis.Host != "redis-server" {
		t.Errorf("Redis.Host = %s; expected redis-server", cfg.Redis.Host)
	}

	if cfg.Redis.Port != 6380 {
		t.Errorf("Redis.Port = %d; expected 6380", cfg.Redis.Port)
	}

	if cfg.Queue.ChargerName != "test_charger" {
		t.Errorf("Queue.ChargerName = %s; expected test_charger", cfg.Queue.ChargerName)
	}

	t.Log("Configuration from ENV loaded successfully")
}

func TestValidateInvalidPort(t *testing.T) {
	clearEnv()

	os.Setenv("SERVER_PORT", "99999")
	defer clearEnv()

	_, err := Load()
	if err == nil {
		t.Fatal("Expected error for invalid port")
	}

	t.Logf("Invalid port error: %v", err)
}

func TestValidateEmptyRedisHost(t *testing.T) {
	clearEnv()

	// Empty string in ENV should return default value
	os.Setenv("REDIS_HOST", "")
	defer clearEnv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should use default "localhost"
	if cfg.Redis.Host != "localhost" {
		t.Errorf("Redis.Host = %s; expected localhost (default value)", cfg.Redis.Host)
	}

	t.Log("Empty REDIS_HOST correctly replaced with default value")
}

func TestGetRedisAddr(t *testing.T) {
	cfg := &RedisConfig{
		Host: "localhost",
		Port: 6379,
	}

	addr := cfg.GetRedisAddr()
	expected := "localhost:6379"

	if addr != expected {
		t.Errorf("GetRedisAddr() = %s; expected %s", addr, expected)
	}
}

func TestGetServerAddr(t *testing.T) {
	cfg := &ServerConfig{
		Port: 36000,
	}

	addr := cfg.GetServerAddr()
	expected := ":36000"

	if addr != expected {
		t.Errorf("GetServerAddr() = %s; expected %s", addr, expected)
	}
}

func clearEnv() {
	envVars := []string{
		"SERVER_PORT", "SERVER_READ_TIMEOUT", "SERVER_WRITE_TIMEOUT", "SERVER_MAX_CONNECTIONS",
		"REDIS_HOST", "REDIS_PORT", "REDIS_PASSWORD", "REDIS_DB", "REDIS_POOL_SIZE", "REDIS_MAX_RETRIES",
		"QUEUE_CHARGER_NAME", "QUEUE_CHARGER_MAX_LEN", "QUEUE_FASTTRACK_NAME", "QUEUE_FASTTRACK_MAX_LEN",
	}

	for _, key := range envVars {
		os.Unsetenv(key)
	}
}
