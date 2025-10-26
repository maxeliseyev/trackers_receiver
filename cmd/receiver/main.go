package main

import (
	"fmt"
	"log"

	"github.com/joho/godotenv"
	"trackers-receiver/internal/config"
	"trackers-receiver/internal/server"
)

func main() {
	// Загружаем переменные окружения из .env файла
	// Если файл не найден - не критично, будут использованы системные ENV или дефолты
	err := godotenv.Load()
	if err != nil {
		log.Println("Файл .env не найден, используются системные переменные окружения")
	}

	// Загружаем конфигурацию
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Ошибка загрузки конфигурации: %v", err)
	}

	// Выводим конфигурацию для отладки
	fmt.Printf("=== Конфигурация сервера ===\n")
	fmt.Printf("Порт: %d\n", cfg.Server.Port)
	fmt.Printf("Таймаут чтения: %v\n", cfg.Server.ReadTimeout)
	fmt.Printf("Таймаут записи: %v\n", cfg.Server.WriteTimeout)
	fmt.Printf("Макс. подключений: %d\n", cfg.Server.MaxConnections)
	fmt.Printf("Redis: %s\n", cfg.Redis.GetRedisAddr())
	fmt.Printf("Очередь charger: %s (макс. %d)\n", cfg.Queue.ChargerName, cfg.Queue.ChargerMaxLen)
	fmt.Printf("Очередь fasttrack: %s (макс. %d)\n", cfg.Queue.FasttrackName, cfg.Queue.FasttrackMaxLen)
	fmt.Printf("============================\n\n")

	fmt.Printf("TCP Server запускается на %s...\n", cfg.Server.GetServerAddr())

	// Создаём TCP listener (слушатель)
	listener, err := server.Start(cfg.Server.GetServerAddr())
	if err != nil {
		log.Fatalf("Ошибка запуска сервера: %v", err)
	}
	defer listener.Close()

	fmt.Println("Сервер успешно запущен и ожидает подключений...")

	// Обработка подключений
	server.HandleConnections(listener)
}
