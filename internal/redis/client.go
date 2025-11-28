package redis

import (
	"context"
	"fmt"
	"time"

	"trackers-receiver/internal/config"

	"github.com/redis/go-redis/v9"
)

type Client struct {
	client *redis.Client
	config *config.RedisConfig
}

func NewClient(cfg *config.RedisConfig) (*Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MaxRetries:   cfg.MaxRetries,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})

	// Chekcing connetion
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("Could not connect to Redis: %w", err)
	}

	return &Client{
		client: rdb,
		config: cfg,
	}, nil
}

// PushToQueue add data to start of Redis queue (LPUSH)
// Return new length of queue after adding
func (c *Client) PushToQueue(ctx context.Context, queueName string, data []byte) (int64, error) {
	length, err := c.client.LPush(ctx, queueName, data).Result()
	if err != nil {
		return 0, fmt.Errorf("Error adding to the queue %s: %w", queueName, err)
	}

	return length, nil
}

// GetQueueLength return current queue length
func (c *Client) GetQueueLength(ctx context.Context, queueName string) (int64, error) {
	length, err := c.client.LLen(ctx, queueName).Result()
	if err != nil {
		return 0, fmt.Errorf("Error with getting queue length %s: %w", queueName, err)
	}

	return length, nil
}

// TrimQueue trims the queue to its maximum length (leaves the last N elements)
func (c *Client) TrimQueue(ctx context.Context, queueName string, maxLen int64) error {
	err := c.client.LTrim(ctx, queueName, 0, maxLen-1).Err()
	if err != nil {
		return fmt.Errorf("Error with trimming the queue %s: %w", queueName, err)
	}

	return nil
}

func (c *Client) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

func (c *Client) Close() error {
	return c.client.Close()
}

func (c *Client) GetClient() *redis.Client {
	return c.client
}
