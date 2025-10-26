package config

import (
	"os"
	"testing"
	"time"
)

// TestLoadDefaultConfig проверяет загрузку конфигурации с дефолтными значениями
func TestLoadDefaultConfig(t *testing.T) {
	// Очищаем все ENV переменные перед тестом
	clearEnv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Не удалось загрузить конфигурацию: %v", err)
	}

	// Проверяем дефолтные значения сервера
	if cfg.Server.Port != 36000 {
		t.Errorf("Server.Port = %d; ожидалось 36000", cfg.Server.Port)
	}

	if cfg.Server.ReadTimeout != 600*time.Second {
		t.Errorf("Server.ReadTimeout = %v; ожидалось 600s", cfg.Server.ReadTimeout)
	}

	// Проверяем дефолтные значения Redis
	if cfg.Redis.Host != "localhost" {
		t.Errorf("Redis.Host = %s; ожидалось localhost", cfg.Redis.Host)
	}

	if cfg.Redis.Port != 6379 {
		t.Errorf("Redis.Port = %d; ожидалось 6379", cfg.Redis.Port)
	}

	// Проверяем дефолтные значения очередей
	if cfg.Queue.ChargerName != "charger" {
		t.Errorf("Queue.ChargerName = %s; ожидалось charger", cfg.Queue.ChargerName)
	}

	if cfg.Queue.ChargerMaxLen != 2999999 {
		t.Errorf("Queue.ChargerMaxLen = %d; ожидалось 2999999", cfg.Queue.ChargerMaxLen)
	}

	t.Log("Дефолтная конфигурация загружена успешно")
}

// TestLoadConfigFromEnv проверяет загрузку из переменных окружения
func TestLoadConfigFromEnv(t *testing.T) {
	// Очищаем переменные
	clearEnv()

	// Устанавливаем тестовые значения
	os.Setenv("SERVER_PORT", "8080")
	os.Setenv("REDIS_HOST", "redis-server")
	os.Setenv("REDIS_PORT", "6380")
	os.Setenv("QUEUE_CHARGER_NAME", "test_charger")
	defer clearEnv() // Очищаем после теста

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Не удалось загрузить конфигурацию: %v", err)
	}

	// Проверяем, что значения загрузились из ENV
	if cfg.Server.Port != 8080 {
		t.Errorf("Server.Port = %d; ожидалось 8080", cfg.Server.Port)
	}

	if cfg.Redis.Host != "redis-server" {
		t.Errorf("Redis.Host = %s; ожидалось redis-server", cfg.Redis.Host)
	}

	if cfg.Redis.Port != 6380 {
		t.Errorf("Redis.Port = %d; ожидалось 6380", cfg.Redis.Port)
	}

	if cfg.Queue.ChargerName != "test_charger" {
		t.Errorf("Queue.ChargerName = %s; ожидалось test_charger", cfg.Queue.ChargerName)
	}

	t.Log("Конфигурация из ENV загружена успешно")
}

// TestValidateInvalidPort проверяет валидацию неверного порта
func TestValidateInvalidPort(t *testing.T) {
	clearEnv()

	os.Setenv("SERVER_PORT", "99999") // Неверный порт
	defer clearEnv()

	_, err := Load()
	if err == nil {
		t.Fatal("Ожидалась ошибка валидации для неверного порта")
	}

	t.Logf("Правильно получена ошибка: %v", err)
}

// TestValidateEmptyRedisHost проверяет, что пустой REDIS_HOST использует дефолт
func TestValidateEmptyRedisHost(t *testing.T) {
	clearEnv()

	// Пустая строка в ENV должна вернуть дефолтное значение
	os.Setenv("REDIS_HOST", "")
	defer clearEnv()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Не ожидалась ошибка: %v", err)
	}

	// Должен использоваться дефолт "localhost"
	if cfg.Redis.Host != "localhost" {
		t.Errorf("Redis.Host = %s; ожидалось localhost (дефолтное значение)", cfg.Redis.Host)
	}

	t.Log("Пустой REDIS_HOST корректно заменён на дефолтное значение")
}

// TestGetRedisAddr проверяет форматирование адреса Redis
func TestGetRedisAddr(t *testing.T) {
	cfg := &RedisConfig{
		Host: "localhost",
		Port: 6379,
	}

	addr := cfg.GetRedisAddr()
	expected := "localhost:6379"

	if addr != expected {
		t.Errorf("GetRedisAddr() = %s; ожидалось %s", addr, expected)
	}
}

// TestGetServerAddr проверяет форматирование адреса сервера
func TestGetServerAddr(t *testing.T) {
	cfg := &ServerConfig{
		Port: 36000,
	}

	addr := cfg.GetServerAddr()
	expected := ":36000"

	if addr != expected {
		t.Errorf("GetServerAddr() = %s; ожидалось %s", addr, expected)
	}
}

// clearEnv очищает все ENV переменные, используемые в конфигурации
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
