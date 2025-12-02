package server

import (
	"fmt"
	"io"
	"net"
)

// Start запускает TCP сервер на указанном адресе
// Возвращает listener или ошибку
func Start(address string) (net.Listener, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return listener, nil
}

// HandleClient читает данные от клиента
// Возвращает все прочитанные данные или ошибку
func HandleClient(conn net.Conn) ([]byte, error) {
	// io.ReadAll читает ВСЕ данные до закрытия соединения
	data, err := io.ReadAll(conn)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// SendResponse отправляет ответ клиенту
// Возвращает ошибку, если отправка не удалась
func SendResponse(conn net.Conn, data []byte) error {
	// conn.Write записывает данные в соединение
	_, err := conn.Write(data)
	if err != nil {
		return err
	}
	return nil
}

// HandlerFunc - тип функции для обработки соединения
type HandlerFunc func(conn net.Conn)

// AcceptConnections принимает подключения и обрабатывает каждое в отдельной горутине
// Это позволяет серверу обслуживать множество клиентов одновременно
func AcceptConnections(listener net.Listener, handler HandlerFunc) {
	for {
		// Accept() блокируется, пока не придёт новое подключение
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("[ERROR] Client connection error:", err)
			continue
		}

		fmt.Println("[INFO] New connection from:", conn.RemoteAddr())

		// Запускаем обработчик в отдельной горутине
		// Это позволяет серверу принимать новые подключения,
		// пока обрабатывается текущее
		go handler(conn)
	}
}

// HandleConnections обрабатывает входящие подключения
func HandleConnections(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("[ERROR] Client connection error:", err)
			continue
		}

		fmt.Println("[INFO] New connection from:", conn.RemoteAddr())
		conn.Close()
	}
}
