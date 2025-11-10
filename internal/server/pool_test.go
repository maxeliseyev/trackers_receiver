package server

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"trackers-receiver/internal/storage"
	"trackers-receiver/pkg/models"
)

// MockStorage для тестов
type MockStorage struct {
	pushCalls     int
	pushBatchCalls int
	mu            sync.Mutex
	delay         time.Duration
}

func (m *MockStorage) Push(ctx context.Context, queue string, doc *models.Document) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pushCalls++
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	return nil
}

func (m *MockStorage) PushBatch(ctx context.Context, queue string, docs []*models.Document) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pushBatchCalls++
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	return nil
}

func (m *MockStorage) PushRaw(ctx context.Context, queue string, data []byte) error {
	return nil
}

func (m *MockStorage) Health(ctx context.Context) error {
	return nil
}

func (m *MockStorage) Stats() *storage.Stats {
	return &storage.Stats{}
}

func (m *MockStorage) Close() error {
	return nil
}

func (m *MockStorage) GetCalls() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pushCalls, m.pushBatchCalls
}

// TestWorkerPoolBasic базовый тест worker pool
func TestWorkerPoolBasic(t *testing.T) {
	storage := &MockStorage{}
	config := &PoolConfig{
		NumWorkers:       2,
		QueueSize:        10,
		ShutdownTimeout:  5 * time.Second,
		ConnectionConfig: DefaultConnectionConfig(),
	}

	pool := NewWorkerPool(storage, config)
	pool.Start()
	defer pool.Shutdown(context.Background())

	// Проверяем что пул создан правильно
	if pool.workers != 2 {
		t.Errorf("Expected 2 workers, got %d", pool.workers)
	}

	if pool.queueSize != 10 {
		t.Errorf("Expected queue size 10, got %d", pool.queueSize)
	}

	// Даем время workers запуститься
	time.Sleep(100 * time.Millisecond)
}

// TestWorkerPoolSubmit тест добавления заданий
func TestWorkerPoolSubmit(t *testing.T) {
	storage := &MockStorage{}
	config := &PoolConfig{
		NumWorkers:       2,
		QueueSize:        5,
		ShutdownTimeout:  5 * time.Second,
		ConnectionConfig: DefaultConnectionConfig(),
	}

	pool := NewWorkerPool(storage, config)
	pool.Start()

	// Создаем mock соединения
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Добавляем задание
	err := pool.Submit(server)
	if err != nil {
		t.Errorf("Failed to submit job: %v", err)
	}

	// Проверяем метрики
	stats := pool.Stats()
	if stats.TotalAccepted.Load() != 1 {
		t.Errorf("Expected 1 accepted, got %d", stats.TotalAccepted.Load())
	}

	// Shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool.Shutdown(ctx)
}

// TestWorkerPoolQueueFull тест переполнения очереди
func TestWorkerPoolQueueFull(t *testing.T) {
	storage := &MockStorage{
		delay: 1 * time.Second, // Медленная обработка
	}
	config := &PoolConfig{
		NumWorkers:       1,
		QueueSize:        2, // Маленькая очередь
		ShutdownTimeout:  5 * time.Second,
		ConnectionConfig: DefaultConnectionConfig(),
	}

	pool := NewWorkerPool(storage, config)
	pool.Start()

	// Заполняем очередь
	var conns []net.Conn
	for i := 0; i < 5; i++ {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()
		conns = append(conns, server)

		err := pool.Submit(server)
		if i < 2 {
			// Первые 2 должны пройти (queue size = 2)
			if err != nil {
				t.Errorf("Job %d should be accepted: %v", i, err)
			}
		} else {
			// Следующие должны быть отклонены
			if err == nil {
				t.Errorf("Job %d should be rejected (queue full)", i)
			}
		}
	}

	// Проверяем метрики
	stats := pool.Stats()
	if stats.TotalRejected.Load() == 0 {
		t.Error("Expected some rejected connections")
	}

	// Shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool.Shutdown(ctx)
}

// TestWorkerPoolGracefulShutdown тест graceful shutdown
func TestWorkerPoolGracefulShutdown(t *testing.T) {
	storage := &MockStorage{}
	config := &PoolConfig{
		NumWorkers:       2,
		QueueSize:        10,
		ShutdownTimeout:  5 * time.Second,
		ConnectionConfig: DefaultConnectionConfig(),
	}

	pool := NewWorkerPool(storage, config)
	pool.Start()

	// Даем время запуститься
	time.Sleep(100 * time.Millisecond)

	// Shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	err := pool.Shutdown(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}

	// Shutdown должен быть быстрым (нет активных заданий)
	if elapsed > 1*time.Second {
		t.Errorf("Shutdown took too long: %v", elapsed)
	}

	// Проверяем что пул остановлен
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	err = pool.Submit(server)
	if err == nil {
		t.Error("Submit should fail after shutdown")
	}
}

// TestWorkerPoolConcurrent тест одновременной работы
func TestWorkerPoolConcurrent(t *testing.T) {
	storage := &MockStorage{}
	config := &PoolConfig{
		NumWorkers:       4,
		QueueSize:        100,
		ShutdownTimeout:  10 * time.Second,
		ConnectionConfig: DefaultConnectionConfig(),
	}

	pool := NewWorkerPool(storage, config)
	pool.Start()

	// Отправляем много подключений одновременно
	var wg sync.WaitGroup
	numConnections := 50

	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()

			err := pool.Submit(server)
			if err != nil {
				// Некоторые могут быть отклонены если очередь заполнится
				// Это нормально
			}
		}(i)
	}

	wg.Wait()

	// Проверяем метрики
	stats := pool.Stats()
	total := stats.TotalAccepted.Load() + stats.TotalRejected.Load()

	if total != int64(numConnections) {
		t.Errorf("Expected %d total connections, got %d", numConnections, total)
	}

	// Shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool.Shutdown(ctx)
}

// TestWorkerPoolStats тест статистики
func TestWorkerPoolStats(t *testing.T) {
	storage := &MockStorage{}
	config := DefaultPoolConfig()
	config.NumWorkers = 2
	config.QueueSize = 10

	pool := NewWorkerPool(storage, config)
	pool.Start()

	// Добавляем несколько заданий
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	pool.Submit(server)

	// Проверяем статистику
	stats := pool.Stats()

	if stats.StartTime.IsZero() {
		t.Error("Start time should be set")
	}

	if stats.TotalAccepted.Load() == 0 {
		t.Error("Expected some accepted connections")
	}

	// Проверяем метрики
	metrics := pool.GetMetrics()
	if metrics["pool_workers_total"] != 2 {
		t.Errorf("Expected 2 workers in metrics, got %v", metrics["pool_workers_total"])
	}

	// Shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool.Shutdown(ctx)
}

// TestWorkerPoolHealth тест health check
func TestWorkerPoolHealth(t *testing.T) {
	storage := &MockStorage{}
	config := DefaultPoolConfig()

	pool := NewWorkerPool(storage, config)
	pool.Start()

	// Здоровый пул
	err := pool.Health()
	if err != nil {
		t.Errorf("Healthy pool should pass health check: %v", err)
	}

	// Останавливаем пул
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool.Shutdown(ctx)
	pool.Wait()

	// Остановленный пул должен fail health check
	err = pool.Health()
	if err == nil {
		t.Error("Stopped pool should fail health check")
	}
}

// BenchmarkWorkerPoolSubmit бенчмарк добавления заданий
func BenchmarkWorkerPoolSubmit(b *testing.B) {
	storage := &MockStorage{}
	config := &PoolConfig{
		NumWorkers:       8,
		QueueSize:        10000,
		ShutdownTimeout:  10 * time.Second,
		ConnectionConfig: DefaultConnectionConfig(),
	}

	pool := NewWorkerPool(storage, config)
	pool.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		pool.Shutdown(ctx)
	}()

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			server, client := net.Pipe()
			pool.Submit(server)
			server.Close()
			client.Close()
		}
	})
}

// BenchmarkWorkerPoolThroughput бенчмарк throughput
func BenchmarkWorkerPoolThroughput(b *testing.B) {
	storage := &MockStorage{}
	config := &PoolConfig{
		NumWorkers:       16,
		QueueSize:        10000,
		ShutdownTimeout:  10 * time.Second,
		ConnectionConfig: DefaultConnectionConfig(),
	}

	pool := NewWorkerPool(storage, config)
	pool.Start()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		server, client := net.Pipe()
		pool.Submit(server)
		server.Close()
		client.Close()
	}

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool.Shutdown(ctx)
}
