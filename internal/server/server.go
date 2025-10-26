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

// HandleConnections обрабатывает входящие подключения
func HandleConnections(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Ошибка при подключении клиента:", err)
			continue
		}

		fmt.Println("Новое подключение от:", conn.RemoteAddr())
		conn.Close()
	}
}
