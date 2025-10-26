package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config содержит все настройки приложения
type Config struct {
	Server ServerConfig
	Redis  RedisConfig
	Queue  QueueConfig
}

// ServerConfig - настройки TCP сервера
type ServerConfig struct {
	Port           int           // Порт для прослушивания
	ReadTimeout    time.Duration // Таймаут чтения
	WriteTimeout   time.Duration // Таймаут записи
	MaxConnections int           // Максимальное количество подключений
}

// RedisConfig - настройки подключения к Redis
type RedisConfig struct {
	Host       string // Хост Redis
	Port       int    // Порт Redis
	Password   string // Пароль (опционально)
	DB         int    // Номер базы данных
	PoolSize   int    // Размер пула подключений
	MaxRetries int    // Максимальное количество повторов
}

// QueueConfig - настройки очередей
type QueueConfig struct {
	ChargerName     string // Имя очереди charger
	ChargerMaxLen   int    // Максимальная длина очереди charger
	FasttrackName   string // Имя очереди fasttrack
	FasttrackMaxLen int    // Максимальная длина очереди fasttrack
}

// Load загружает конфигурацию из переменных окружения с дефолтными значениями
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

	// Валидация
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate проверяет корректность конфигурации
func (c *Config) Validate() error {
	// Проверка порта
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("неверный порт сервера: %d (должен быть 1-65535)", c.Server.Port)
	}

	// Проверка таймаутов
	if c.Server.ReadTimeout < 0 {
		return fmt.Errorf("таймаут чтения не может быть отрицательным")
	}

	// Проверка Redis
	if c.Redis.Host == "" {
		return fmt.Errorf("REDIS_HOST не может быть пустым")
	}

	if c.Redis.Port < 1 || c.Redis.Port > 65535 {
		return fmt.Errorf("неверный порт Redis: %d", c.Redis.Port)
	}

	// Проверка имён очередей
	if c.Queue.ChargerName == "" {
		return fmt.Errorf("имя очереди charger не может быть пустым")
	}

	if c.Queue.FasttrackName == "" {
		return fmt.Errorf("имя очереди fasttrack не может быть пустым")
	}

	return nil
}

// getEnv получает значение из переменной окружения или возвращает дефолтное
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvAsInt получает целое число из переменной окружения
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

// getEnvAsDuration получает duration из переменной окружения
// Принимает значение в секундах, например: SERVER_READ_TIMEOUT=600
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

// GetRedisAddr возвращает адрес Redis в формате "host:port"
func (c *RedisConfig) GetRedisAddr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// GetServerAddr возвращает адрес сервера в формате ":port"
func (c *ServerConfig) GetServerAddr() string {
	return fmt.Sprintf(":%d", c.Port)
}
