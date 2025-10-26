package server

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// TestStart проверяет запуск сервера
func TestStart(t *testing.T) {
	// Используем порт 0 - система автоматически выберет свободный порт
	address := ":0"

	// Запускаем сервер
	listener, err := Start(address)

	// Проверяем, что ошибки не было
	if err != nil {
		t.Fatalf("Не удалось запустить сервер: %v", err)
	}

	// Закрываем listener после теста
	defer listener.Close()

	// Проверяем, что listener не nil
	if listener == nil {
		t.Fatal("Listener не должен быть nil")
	}

	// Проверяем, что адрес установлен
	if listener.Addr() == nil {
		t.Fatal("Адрес listener не установлен")
	}

	t.Logf("Сервер успешно запущен на адресе: %s", listener.Addr())
}

// TestServerInvalidPort проверяет обработку неверного порта
func TestServerInvalidPort(t *testing.T) {
	// Пытаемся запустить сервер на недопустимом порту
	address := ":99999" // Порт > 65535

	_, err := Start(address)

	// Ожидаем ошибку
	if err == nil {
		t.Fatal("Ожидалась ошибка при запуске на неверном порту")
	}

	t.Logf("Правильно получена ошибка: %v", err)
}

// TestServerConnection проверяет подключение к серверу
func TestServerConnection(t *testing.T) {
	// Запускаем сервер на случайном порту
	listener, err := Start(":0")
	if err != nil {
		t.Fatalf("Не удалось запустить сервер: %v", err)
	}
	defer listener.Close()

	// Получаем адрес, на котором запущен сервер
	serverAddr := listener.Addr().String()
	t.Logf("Сервер запущен на: %s", serverAddr)

	// Запускаем обработчик подключений в отдельной горутине
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
	}()

	// Даём серверу время запуститься
	time.Sleep(100 * time.Millisecond)

	// Пытаемся подключиться к серверу
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("Не удалось подключиться к серверу: %v", err)
	}
	defer conn.Close()

	t.Log("Успешно подключились к серверу!")
}

// TestHandleClient проверяет чтение данных от клиента
func TestHandleClient(t *testing.T) {
	// Запускаем сервер
	listener, err := Start(":0")
	if err != nil {
		t.Fatalf("Не удалось запустить сервер: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Канал для передачи прочитанных данных из горутины
	dataChan := make(chan []byte, 1)

	// Запускаем обработку подключений
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Logf("Ошибка Accept: %v", err)
			return
		}
		defer conn.Close()

		// Вызываем функцию, которую мы НАПИШЕМ
		data, err := HandleClient(conn)
		if err != nil {
			t.Logf("Ошибка HandleClient: %v", err)
			return
		}

		// Отправляем данные в канал
		dataChan <- data
	}()

	// Даём серверу время запуститься
	time.Sleep(50 * time.Millisecond)

	// Подключаемся как клиент
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("Не удалось подключиться: %v", err)
	}
	defer conn.Close()

	// Отправляем тестовые данные
	testData := []byte("Hello from tracker!")
	n, err := conn.Write(testData)
	if err != nil {
		t.Fatalf("Не удалось отправить данные: %v", err)
	}
	t.Logf("Отправлено %d байт", n)

	// Закрываем соединение, чтобы сервер завершил чтение
	conn.Close()

	// Ждём получения данных с таймаутом
	select {
	case receivedData := <-dataChan:
		// Проверяем, что данные совпадают
		if !bytes.Equal(receivedData, testData) {
			t.Errorf("Данные не совпадают. Отправлено: %q, Получено: %q", testData, receivedData)
		} else {
			t.Logf("Успешно получены данные: %q", receivedData)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Таймаут ожидания данных от сервера")
	}
}

// TestSendResponse проверяет отправку ответа клиенту
func TestSendResponse(t *testing.T) {
	// Запускаем сервер
	listener, err := Start(":0")
	if err != nil {
		t.Fatalf("Не удалось запустить сервер: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Канал для передачи результата отправки
	errorChan := make(chan error, 1)

	// Запускаем обработку подключения
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errorChan <- err
			return
		}
		defer conn.Close()

		// Пытаемся отправить ответ клиенту
		responseData := []byte("OK: Data received!")
		err = SendResponse(conn, responseData)
		errorChan <- err
	}()

	// Даём серверу время запуститься
	time.Sleep(50 * time.Millisecond)

	// Подключаемся как клиент
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("Не удалось подключиться: %v", err)
	}
	defer conn.Close()

	// Читаем ответ от сервера
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatalf("Не удалось прочитать ответ: %v", err)
	}

	receivedData := buffer[:n]
	expectedData := []byte("OK: Data received!")

	// Проверяем, что данные совпадают
	if !bytes.Equal(receivedData, expectedData) {
		t.Errorf("Ответ не совпадает. Ожидалось: %q, Получено: %q", expectedData, receivedData)
	} else {
		t.Logf("Успешно получен ответ от сервера: %q", receivedData)
	}

	// Проверяем, что отправка на сервере прошла без ошибок
	select {
	case err := <-errorChan:
		if err != nil {
			t.Fatalf("Ошибка при отправке ответа на сервере: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Таймаут ожидания результата от сервера")
	}
}
