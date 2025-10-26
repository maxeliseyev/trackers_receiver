package redis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"trackers-receiver/internal/config"
)

// setupTestRedis создаёт mock Redis сервер для тестирования
func setupTestRedis(t *testing.T) (*miniredis.Miniredis, *Client) {
	// Запускаем miniredis
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Не удалось запустить miniredis: %v", err)
	}

	// Создаём конфигурацию для подключения к miniredis
	cfg := &config.RedisConfig{
		Host:       mr.Host(),
		Port:       mr.Server().Addr().Port,
		Password:   "",
		DB:         0,
		PoolSize:   10,
		MaxRetries: 3,
	}

	// Создаём клиент
	client, err := NewClient(cfg)
	if err != nil {
		mr.Close()
		t.Fatalf("Не удалось создать Redis клиент: %v", err)
	}

	return mr, client
}

// TestNewClient проверяет создание нового клиента
func TestNewClient(t *testing.T) {
	mr, client := setupTestRedis(t)
	defer mr.Close()
	defer client.Close()

	// Проверяем, что клиент не nil
	if client == nil {
		t.Fatal("Клиент не должен быть nil")
	}

	// Проверяем подключение
	ctx := context.Background()
	err := client.Ping(ctx)
	if err != nil {
		t.Errorf("Ping не должен возвращать ошибку: %v", err)
	}

	t.Log("Redis клиент успешно создан и подключен")
}

// TestNewClientInvalidHost проверяет ошибку при неверном хосте
func TestNewClientInvalidHost(t *testing.T) {
	cfg := &config.RedisConfig{
		Host:       "invalid-host-12345",
		Port:       6379,
		Password:   "",
		DB:         0,
		PoolSize:   10,
		MaxRetries: 1,
	}

	_, err := NewClient(cfg)
	if err == nil {
		t.Fatal("Ожидалась ошибка при подключении к несуществующему хосту")
	}

	t.Logf("Правильно получена ошибка: %v", err)
}

// TestPushToQueue проверяет добавление данных в очередь
func TestPushToQueue(t *testing.T) {
	mr, client := setupTestRedis(t)
	defer mr.Close()
	defer client.Close()

	ctx := context.Background()
	queueName := "test_queue"
	testData := []byte("test message data")

	// Добавляем первое сообщение
	length, err := client.PushToQueue(ctx, queueName, testData)
	if err != nil {
		t.Fatalf("Ошибка при добавлении в очередь: %v", err)
	}

	// Длина очереди должна быть 1
	if length != 1 {
		t.Errorf("Длина очереди = %d; ожидалось 1", length)
	}

	// Добавляем второе сообщение
	length, err = client.PushToQueue(ctx, queueName, []byte("second message"))
	if err != nil {
		t.Fatalf("Ошибка при добавлении второго сообщения: %v", err)
	}

	// Длина очереди должна быть 2
	if length != 2 {
		t.Errorf("Длина очереди = %d; ожидалось 2", length)
	}

	t.Logf("Успешно добавлено 2 сообщения в очередь %s", queueName)
}

// TestGetQueueLength проверяет получение длины очереди
func TestGetQueueLength(t *testing.T) {
	mr, client := setupTestRedis(t)
	defer mr.Close()
	defer client.Close()

	ctx := context.Background()
	queueName := "test_queue_length"

	// Проверяем длину пустой очереди
	length, err := client.GetQueueLength(ctx, queueName)
	if err != nil {
		t.Fatalf("Ошибка при получении длины очереди: %v", err)
	}

	if length != 0 {
		t.Errorf("Длина пустой очереди = %d; ожидалось 0", length)
	}

	// Добавляем 3 элемента
	for i := 0; i < 3; i++ {
		_, err := client.PushToQueue(ctx, queueName, []byte("message"))
		if err != nil {
			t.Fatalf("Ошибка при добавлении сообщения: %v", err)
		}
	}

	// Проверяем длину
	length, err = client.GetQueueLength(ctx, queueName)
	if err != nil {
		t.Fatalf("Ошибка при получении длины очереди: %v", err)
	}

	if length != 3 {
		t.Errorf("Длина очереди = %d; ожидалось 3", length)
	}

	t.Log("Длина очереди определяется корректно")
}

// TestTrimQueue проверяет обрезку очереди до максимальной длины
func TestTrimQueue(t *testing.T) {
	mr, client := setupTestRedis(t)
	defer mr.Close()
	defer client.Close()

	ctx := context.Background()
	queueName := "test_queue_trim"

	// Добавляем 10 элементов
	for i := 0; i < 10; i++ {
		_, err := client.PushToQueue(ctx, queueName, []byte("message"))
		if err != nil {
			t.Fatalf("Ошибка при добавлении сообщения: %v", err)
		}
	}

	// Проверяем длину (должна быть 10)
	length, _ := client.GetQueueLength(ctx, queueName)
	if length != 10 {
		t.Errorf("Длина до обрезки = %d; ожидалось 10", length)
	}

	// Обрезаем до 5 элементов
	err := client.TrimQueue(ctx, queueName, 5)
	if err != nil {
		t.Fatalf("Ошибка при обрезке очереди: %v", err)
	}

	// Проверяем новую длину (должна быть 5)
	length, _ = client.GetQueueLength(ctx, queueName)
	if length != 5 {
		t.Errorf("Длина после обрезки = %d; ожидалось 5", length)
	}

	t.Log("Очередь успешно обрезана до 5 элементов")
}

// TestPushToQueueWithContext проверяет работу с контекстом и таймаутами
func TestPushToQueueWithContext(t *testing.T) {
	mr, client := setupTestRedis(t)
	defer mr.Close()
	defer client.Close()

	queueName := "test_queue_context"
	testData := []byte("test message")

	// Создаём контекст с таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Добавляем данные
	_, err := client.PushToQueue(ctx, queueName, testData)
	if err != nil {
		t.Fatalf("Ошибка при добавлении с контекстом: %v", err)
	}

	t.Log("Работа с контекстом выполнена успешно")
}

// TestPushMultipleQueues проверяет работу с несколькими очередями
func TestPushMultipleQueues(t *testing.T) {
	mr, client := setupTestRedis(t)
	defer mr.Close()
	defer client.Close()

	ctx := context.Background()

	// Добавляем в разные очереди
	queues := []string{"charger", "fasttrack", "test_queue"}

	for _, queueName := range queues {
		_, err := client.PushToQueue(ctx, queueName, []byte("data for "+queueName))
		if err != nil {
			t.Errorf("Ошибка при добавлении в очередь %s: %v", queueName, err)
		}
	}

	// Проверяем, что все очереди содержат по 1 элементу
	for _, queueName := range queues {
		length, err := client.GetQueueLength(ctx, queueName)
		if err != nil {
			t.Errorf("Ошибка при получении длины %s: %v", queueName, err)
		}

		if length != 1 {
			t.Errorf("Очередь %s имеет длину %d; ожидалось 1", queueName, length)
		}
	}

	t.Log("Работа с несколькими очередями выполнена успешно")
}

// TestClose проверяет закрытие соединения
func TestClose(t *testing.T) {
	mr, client := setupTestRedis(t)
	defer mr.Close()

	// Закрываем клиент
	err := client.Close()
	if err != nil {
		t.Errorf("Ошибка при закрытии клиента: %v", err)
	}

	// После закрытия операции должны падать с ошибкой
	ctx := context.Background()
	err = client.Ping(ctx)
	if err == nil {
		t.Error("Ping после закрытия должен возвращать ошибку")
	}

	t.Log("Закрытие соединения работает корректно")
}
