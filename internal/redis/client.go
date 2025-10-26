package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"trackers-receiver/internal/config"
)

// Client - обёртка над Redis клиентом для работы с очередями
type Client struct {
	client *redis.Client
	config *config.RedisConfig
}

// NewClient создаёт новый Redis клиент на основе конфигурации
func NewClient(cfg *config.RedisConfig) (*Client, error) {
	// Создаём клиент Redis
	rdb := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MaxRetries:   cfg.MaxRetries,
		DialTimeout:  5 * time.Second,  // Таймаут подключения
		ReadTimeout:  3 * time.Second,  // Таймаут чтения
		WriteTimeout: 3 * time.Second,  // Таймаут записи
	})

	// Проверяем подключение
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("не удалось подключиться к Redis: %w", err)
	}

	return &Client{
		client: rdb,
		config: cfg,
	}, nil
}

// PushToQueue добавляет данные в начало очереди Redis (LPUSH)
// Возвращает новую длину очереди после добавления
func (c *Client) PushToQueue(ctx context.Context, queueName string, data []byte) (int64, error) {
	// LPUSH добавляет элемент в начало списка
	length, err := c.client.LPush(ctx, queueName, data).Result()
	if err != nil {
		return 0, fmt.Errorf("ошибка при добавлении в очередь %s: %w", queueName, err)
	}

	return length, nil
}

// GetQueueLength возвращает текущую длину очереди
func (c *Client) GetQueueLength(ctx context.Context, queueName string) (int64, error) {
	length, err := c.client.LLen(ctx, queueName).Result()
	if err != nil {
		return 0, fmt.Errorf("ошибка при получении длины очереди %s: %w", queueName, err)
	}

	return length, nil
}

// TrimQueue обрезает очередь до максимальной длины (оставляет последние N элементов)
func (c *Client) TrimQueue(ctx context.Context, queueName string, maxLen int64) error {
	// LTRIM оставляет элементы от start до stop
	// Для ограничения очереди до maxLen элементов: 0 до maxLen-1
	err := c.client.LTrim(ctx, queueName, 0, maxLen-1).Err()
	if err != nil {
		return fmt.Errorf("ошибка при обрезке очереди %s: %w", queueName, err)
	}

	return nil
}

// Ping проверяет соединение с Redis
func (c *Client) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

// Close закрывает соединение с Redis
func (c *Client) Close() error {
	return c.client.Close()
}

// GetClient возвращает внутренний redis.Client (для продвинутого использования)
func (c *Client) GetClient() *redis.Client {
	return c.client
}
