package main

import (
	"fmt"
	"trackers-receiver/internal/server"
)

func main() {
	// Адрес и порт для прослушивания
	address := ":36000"

	fmt.Println("TCP Server запускается на порту 36000...")

	// Создаём TCP listener (слушатель)
	listener, err := server.Start(address)
	if err != nil {
		fmt.Println("Ошибка запуска сервера:", err)
		return
	}
	defer listener.Close()

	fmt.Println("Сервер успешно запущен и ожидает подключений...")

	// Обработка подключений
	server.HandleConnections(listener)
}
