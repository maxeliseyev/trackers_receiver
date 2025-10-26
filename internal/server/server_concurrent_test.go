package server

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// TestConcurrentClients проверяет параллельную обработку нескольких клиентов
// Использует WaitGroup и Mutex для синхронизации
func TestConcurrentClients(t *testing.T) {
	// Запускаем сервер
	listener, err := Start(":0")
	if err != nil {
		t.Fatalf("Не удалось запустить сервер: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()
	t.Logf("Сервер запущен на: %s", serverAddr)

	// Количество одновременных клиентов для теста
	numClients := 5

	// Запускаем обработку подключений в фоне
	go AcceptConnections(listener, func(conn net.Conn) {
		defer conn.Close()

		// Читаем данные от клиента
		data, err := HandleClient(conn)
		if err != nil {
			return
		}

		// Отправляем эхо-ответ
		response := append([]byte("Echo: "), data...)
		SendResponse(conn, response)
	})

	// Даём серверу время запуститься
	time.Sleep(50 * time.Millisecond)

	// WaitGroup для ожидания всех клиентов
	var wg sync.WaitGroup

	// Счётчик успешных подключений (потокобезопасный через мьютекс)
	successCount := 0
	var mu sync.Mutex

	// Запускаем несколько клиентов одновременно
	for i := 0; i < numClients; i++ {
		wg.Add(1) // Добавляем задачу в WaitGroup

		// Запускаем каждого клиента в отдельной горутине
		go func(clientID int) {
			defer wg.Done() // Отмечаем задачу как выполненную

			// Подключаемся к серверу
			conn, err := net.Dial("tcp", serverAddr)
			if err != nil {
				t.Errorf("Клиент %d: не удалось подключиться: %v", clientID, err)
				return
			}
			defer conn.Close()

			// Отправляем уникальное сообщение
			message := []byte(fmt.Sprintf("Client %d", clientID))
			_, err = conn.Write(message)
			if err != nil {
				t.Errorf("Клиент %d: не удалось отправить данные: %v", clientID, err)
				return
			}

			// Закрываем запись, чтобы сервер получил EOF
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.CloseWrite()
			}

			// Читаем ответ
			buffer := make([]byte, 1024)
			n, err := conn.Read(buffer)
			if err != nil {
				t.Errorf("Клиент %d: не удалось прочитать ответ: %v", clientID, err)
				return
			}

			response := buffer[:n]
			expected := append([]byte("Echo: "), message...)

			// Проверяем ответ
			if !bytes.Equal(response, expected) {
				t.Errorf("Клиент %d: неверный ответ. Ожидалось: %q, Получено: %q", clientID, expected, response)
				return
			}

			t.Logf("Клиент %d: успешно обработан", clientID)

			// Увеличиваем счётчик успешных подключений
			mu.Lock()
			successCount++
			mu.Unlock()
		}(i)
	}

	// Ждём завершения всех клиентов
	wg.Wait()

	// Проверяем, что все клиенты обработаны
	if successCount != numClients {
		t.Errorf("Обработано клиентов: %d из %d", successCount, numClients)
	} else {
		t.Logf("Все %d клиентов успешно обработаны параллельно!", numClients)
	}
}

// TestConcurrentClientsWithChannel - та же функциональность, но с КАНАЛОМ вместо мьютекса
// Демонстрирует идиоматичный Go подход "share memory by communicating"
func TestConcurrentClientsWithChannel(t *testing.T) {
	// Запускаем сервер
	listener, err := Start(":0")
	if err != nil {
		t.Fatalf("Не удалось запустить сервер: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()
	t.Logf("Сервер запущен на: %s", serverAddr)

	numClients := 5

	// Запускаем обработку подключений
	go AcceptConnections(listener, func(conn net.Conn) {
		defer conn.Close()
		data, err := HandleClient(conn)
		if err != nil {
			return
		}
		response := append([]byte("Echo: "), data...)
		SendResponse(conn, response)
	})

	time.Sleep(50 * time.Millisecond)

	// КАНАЛ для сбора результатов вместо счётчика с мьютексом
	resultChan := make(chan bool, numClients)

	// Запускаем клиентов
	for i := 0; i < numClients; i++ {
		// Запускаем каждого клиента в горутине
		go func(clientID int) {
			// Подключаемся
			conn, err := net.Dial("tcp", serverAddr)
			if err != nil {
				t.Errorf("Клиент %d: не удалось подключиться: %v", clientID, err)
				resultChan <- false // Отправляем false в канал
				return
			}
			defer conn.Close()

			// Отправляем данные
			message := []byte(fmt.Sprintf("Client %d", clientID))
			_, err = conn.Write(message)
			if err != nil {
				t.Errorf("Клиент %d: не удалось отправить данные: %v", clientID, err)
				resultChan <- false
				return
			}

			// Закрываем запись
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.CloseWrite()
			}

			// Читаем ответ
			buffer := make([]byte, 1024)
			n, err := conn.Read(buffer)
			if err != nil {
				t.Errorf("Клиент %d: не удалось прочитать ответ: %v", clientID, err)
				resultChan <- false
				return
			}

			response := buffer[:n]
			expected := append([]byte("Echo: "), message...)

			// Проверяем ответ
			if !bytes.Equal(response, expected) {
				t.Errorf("Клиент %d: неверный ответ", clientID)
				resultChan <- false
				return
			}

			t.Logf("Клиент %d: успешно обработан", clientID)
			resultChan <- true // Отправляем true в канал
		}(i)
	}

	// Собираем результаты из канала
	successCount := 0
	for i := 0; i < numClients; i++ {
		if <-resultChan { // Читаем из канала (блокируется до получения)
			successCount++
		}
	}

	// Проверяем результат
	if successCount != numClients {
		t.Errorf("Обработано клиентов: %d из %d", successCount, numClients)
	} else {
		t.Logf("Все %d клиентов успешно обработаны (с использованием канала)!", numClients)
	}
}
