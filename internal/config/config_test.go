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

	if cfg.Redis.Host != "localhost" {
		t.Errorf("Redis.Host = %s; expected localhost", cfg.Redis.Host)
	}

	if cfg.Redis.Port != 6379 {
		t.Errorf("Redis.Port = %d; expected 6379", cfg.Redis.Port)
	}

	if cfg.Queue.ChargerName != "charger" {
		t.Errorf("Queue.ChargerName = %s; expected charger", cfg.Queue.ChargerName)
	}

	if cfg.Queue.ChargerMaxLen != 99999 {
		t.Errorf("Queue.ChargerMaxLen = %d; expected 99999", cfg.Queue.ChargerMaxLen)
	}

	if cfg.Server.UseHAProxy {
		t.Error("Server.UseHAProxy is on by default")
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	clearEnv()

	os.Setenv("SERVER_PORT", "8080")
	os.Setenv("REDIS_HOST", "redis-server")
	os.Setenv("REDIS_PORT", "6380")
	os.Setenv("CHARGER_QUEUE", "test_charger")
	os.Setenv("USE_HAPROXY", "true")
	os.Setenv("CONNECTION_TIMEOUT", "120")
	defer clearEnv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Config loading failed: %v", err)
	}

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

	if !cfg.Server.UseHAProxy {
		t.Error("Server.UseHAProxy = false; expected true")
	}

	if cfg.Server.ReadTimeout != 120*time.Second {
		t.Errorf("Server.ReadTimeout = %v; expected 2m", cfg.Server.ReadTimeout)
	}
}

func TestValidateInvalidPort(t *testing.T) {
	clearEnv()

	os.Setenv("SERVER_PORT", "99999")
	defer clearEnv()

	_, err := Load()
	if err == nil {
		t.Fatal("Expected error for invalid port")
	}
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

func TestRateLimitConfig(t *testing.T) {
	clearEnv()
	defer clearEnv()

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	rl := cfg.RateLimit
	if !rl.Enabled || rl.MaxPerWindow != 300 || rl.Window != 10*time.Second || rl.BlockDuration != time.Minute {
		t.Errorf("unexpected defaults: %+v", rl)
	}
	if len(rl.Whitelist) != 2 {
		t.Errorf("Whitelist = %v; expected loopback addresses", rl.Whitelist)
	}

	os.Setenv("RATE_LIMIT_ENABLED", "false")
	os.Setenv("RATE_LIMIT_WHITELIST", " 10.0.0.1, ,10.0.0.2 ")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RateLimit.Enabled {
		t.Error("RATE_LIMIT_ENABLED=false was ignored")
	}
	if got := cfg.RateLimit.Whitelist; len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "10.0.0.2" {
		t.Errorf("Whitelist = %q; expected [10.0.0.1 10.0.0.2]", got)
	}

	os.Setenv("RATE_LIMIT_ENABLED", "true")
	os.Setenv("RATE_LIMIT_MAX_PER_WINDOW", "0")
	if _, err := Load(); err == nil {
		t.Error("expected an error for RATE_LIMIT_MAX_PER_WINDOW=0")
	}
}

func clearEnv() {
	envVars := []string{
		"SERVER_PORT", "USE_HAPROXY", "CONNECTION_TIMEOUT", "SERVER_WRITE_TIMEOUT", "SERVER_MAX_CONNECTIONS",
		"REDIS_HOST", "REDIS_PORT", "REDIS_PASSWORD", "REDIS_DB", "REDIS_POOL_SIZE", "REDIS_MAX_RETRIES",
		"CHARGER_QUEUE", "CHARGER_QUEUE_MAX_LEN", "FASTTRACK_QUEUE", "FASTTRACK_QUEUE_MAX_LEN",
		"RATE_LIMIT_ENABLED", "RATE_LIMIT_MAX_PER_WINDOW", "RATE_LIMIT_WINDOW", "RATE_LIMIT_BLOCK_DURATION",
		"RATE_LIMIT_WHITELIST",
	}

	for _, key := range envVars {
		os.Unsetenv(key)
	}
}
