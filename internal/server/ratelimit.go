package server

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// RateLimiter управляет ограничением частоты запросов и блокировкой IP
// Защищает от:
//   - DDoS атак (слишком много подключений с одного IP)
//   - Port scanning (множественные подключения за короткий промежуток)
//   - Malicious trackers (повторяющиеся ошибки протокола)
//
// Архитектура:
//   - Sliding window rate limiting (окно в N секунд)
//   - Временная блокировка IP (exponential backoff)
//   - Автоматическая очистка старых записей
//   - Whitelist для доверенных IP (HAProxy, мониторинг)
type RateLimiter struct {
	// Конфигурация
	maxConnPerWindow int           // Максимум подключений за окно
	windowDuration   time.Duration // Размер окна (например, 10 секунд)
	blockDuration    time.Duration // Длительность блокировки

	// Whitelist IP адресов (не блокируются)
	whitelist map[string]bool

	// Tracking
	mu      sync.RWMutex
	clients map[string]*clientState // IP -> состояние клиента

	// Автоматическая очистка
	cleanupInterval time.Duration
	stopCleanup     chan struct{}

	// Метрики
	stats rateLimitStats
}

// clientState состояние одного IP адреса
type clientState struct {
	// Подключения
	connections []time.Time // Timestamps последних подключений (sliding window)

	// Блокировка
	blocked      bool      // Заблокирован ли IP
	blockedUntil time.Time // До какого времени заблокирован
	blockCount   int       // Сколько раз блокировали (для exponential backoff)

	// Ошибки протокола
	protocolErrors int       // Количество ошибок протокола
	lastError      time.Time // Время последней ошибки
}

// rateLimitStats статистика rate limiter
type rateLimitStats struct {
	totalBlocked   atomic.Int64 // Всего заблокировано подключений
	totalAllowed   atomic.Int64 // Всего разрешено подключений
	currentBlocked atomic.Int32 // Текущее количество заблокированных IP
	totalIPs       atomic.Int32 // Всего отслеживаемых IP
}

// RateLimiterConfig конфигурация rate limiter
type RateLimiterConfig struct {
	// Ограничения
	MaxConnectionsPerWindow int           // Максимум подключений за окно (default: 10)
	WindowDuration          time.Duration // Размер окна (default: 10s)
	BlockDuration           time.Duration // Длительность блокировки (default: 5m)

	// Whitelist
	WhitelistedIPs []string // IP адреса которые не блокируются

	// Очистка
	CleanupInterval time.Duration // Частота очистки старых записей (default: 1m)
}

// DefaultRateLimiterConfig возвращает конфигурацию по умолчанию
func DefaultRateLimiterConfig() *RateLimiterConfig {
	return &RateLimiterConfig{
		MaxConnectionsPerWindow: 10,
		WindowDuration:          10 * time.Second,
		BlockDuration:           5 * time.Minute,
		WhitelistedIPs:          []string{"127.0.0.1", "::1"},
		CleanupInterval:         1 * time.Minute,
	}
}

// NewRateLimiter создает новый rate limiter
func NewRateLimiter(config *RateLimiterConfig) *RateLimiter {
	rl := &RateLimiter{
		maxConnPerWindow: config.MaxConnectionsPerWindow,
		windowDuration:   config.WindowDuration,
		blockDuration:    config.BlockDuration,
		whitelist:        make(map[string]bool),
		clients:          make(map[string]*clientState),
		cleanupInterval:  config.CleanupInterval,
		stopCleanup:      make(chan struct{}),
	}

	// Добавляем whitelist
	for _, ip := range config.WhitelistedIPs {
		rl.whitelist[ip] = true
	}

	// Запускаем автоматическую очистку
	go rl.cleanupLoop()

	return rl
}

// Allow проверяет разрешено ли подключение от этого IP
// Возвращает true если разрешено, false если заблокирован
func (rl *RateLimiter) Allow(conn net.Conn) bool {
	// Извлекаем IP адрес
	ip := extractIP(conn.RemoteAddr())

	// Whitelist всегда разрешен
	if rl.isWhitelisted(ip) {
		rl.stats.totalAllowed.Add(1)
		return true
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Получаем или создаем состояние клиента
	state, exists := rl.clients[ip]
	if !exists {
		state = &clientState{
			connections: make([]time.Time, 0),
		}
		rl.clients[ip] = state
		rl.stats.totalIPs.Add(1)
	}

	// Проверяем не заблокирован ли IP
	if state.blocked {
		if now.Before(state.blockedUntil) {
			// Все еще заблокирован
			rl.stats.totalBlocked.Add(1)
			return false
		}
		// Блокировка истекла - сбрасываем состояние
		state.blocked = false
		state.connections = make([]time.Time, 0)
		state.protocolErrors = 0
		rl.stats.currentBlocked.Add(-1)
	}

	// Очищаем старые подключения (за пределами окна)
	state.connections = rl.cleanOldConnections(state.connections, now)

	// Проверяем превышен ли лимит
	if len(state.connections) >= rl.maxConnPerWindow {
		// Блокируем IP
		rl.blockIP(state, now)
		rl.stats.totalBlocked.Add(1)
		return false
	}

	// Добавляем новое подключение
	state.connections = append(state.connections, now)
	rl.stats.totalAllowed.Add(1)

	return true
}

// RecordProtocolError записывает ошибку протокола для IP
// Если слишком много ошибок - блокирует IP
func (rl *RateLimiter) RecordProtocolError(conn net.Conn) {
	ip := extractIP(conn.RemoteAddr())

	// Whitelist не блокируем за ошибки
	if rl.isWhitelisted(ip) {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	state, exists := rl.clients[ip]
	if !exists {
		state = &clientState{
			connections: make([]time.Time, 0),
		}
		rl.clients[ip] = state
		rl.stats.totalIPs.Add(1)
	}

	state.protocolErrors++
	state.lastError = now

	// Если более 5 ошибок за последние 60 секунд - блокируем
	if state.protocolErrors > 5 && now.Sub(state.lastError) < 60*time.Second {
		rl.blockIP(state, now)
	}
}

// blockIP блокирует IP адрес
func (rl *RateLimiter) blockIP(state *clientState, now time.Time) {
	state.blocked = true
	state.blockCount++

	// Exponential backoff: каждая следующая блокировка в 2 раза длиннее
	duration := rl.blockDuration * time.Duration(1<<uint(state.blockCount-1))

	// Максимум 24 часа
	if duration > 24*time.Hour {
		duration = 24 * time.Hour
	}

	state.blockedUntil = now.Add(duration)
	rl.stats.currentBlocked.Add(1)
}

// cleanOldConnections удаляет подключения за пределами окна
func (rl *RateLimiter) cleanOldConnections(connections []time.Time, now time.Time) []time.Time {
	cutoff := now.Add(-rl.windowDuration)

	// Находим первое подключение в пределах окна
	firstValid := 0
	for i, t := range connections {
		if t.After(cutoff) {
			firstValid = i
			break
		}
	}

	return connections[firstValid:]
}

// cleanupLoop периодически очищает старые записи
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.stopCleanup:
			return
		}
	}
}

// cleanup удаляет старые записи клиентов
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.windowDuration * 2) // Удаляем записи старше 2 окон

	for ip, state := range rl.clients {
		// Не удаляем заблокированные IP (пока блокировка активна)
		if state.blocked && now.Before(state.blockedUntil) {
			continue
		}

		// Удаляем IP без активности
		if len(state.connections) == 0 || state.connections[len(state.connections)-1].Before(cutoff) {
			delete(rl.clients, ip)
			rl.stats.totalIPs.Add(-1)

			if state.blocked {
				rl.stats.currentBlocked.Add(-1)
			}
		}
	}
}

// isWhitelisted проверяет находится ли IP в whitelist
func (rl *RateLimiter) isWhitelisted(ip string) bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	return rl.whitelist[ip]
}

// AddToWhitelist добавляет IP в whitelist
func (rl *RateLimiter) AddToWhitelist(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.whitelist[ip] = true
}

// RemoveFromWhitelist удаляет IP из whitelist
func (rl *RateLimiter) RemoveFromWhitelist(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.whitelist, ip)
}

// GetBlockedIPs возвращает список заблокированных IP
func (rl *RateLimiter) GetBlockedIPs() []string {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	now := time.Now()
	blocked := make([]string, 0)

	for ip, state := range rl.clients {
		if state.blocked && now.Before(state.blockedUntil) {
			blocked = append(blocked, ip)
		}
	}

	return blocked
}

// UnblockIP разблокирует IP адрес (для администрирования)
func (rl *RateLimiter) UnblockIP(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if state, exists := rl.clients[ip]; exists && state.blocked {
		state.blocked = false
		state.blockCount = 0
		state.connections = make([]time.Time, 0)
		state.protocolErrors = 0
		rl.stats.currentBlocked.Add(-1)
	}
}

// Stats возвращает статистику rate limiter
func (rl *RateLimiter) Stats() map[string]any {
	return map[string]any{
		"total_blocked":    rl.stats.totalBlocked.Load(),
		"total_allowed":    rl.stats.totalAllowed.Load(),
		"current_blocked":  rl.stats.currentBlocked.Load(),
		"total_ips":        rl.stats.totalIPs.Load(),
		"max_per_window":   rl.maxConnPerWindow,
		"window_duration":  rl.windowDuration.String(),
		"block_duration":   rl.blockDuration.String(),
	}
}

// Stop останавливает rate limiter
func (rl *RateLimiter) Stop() {
	close(rl.stopCleanup)
}

// extractIP извлекает IP адрес из net.Addr
func extractIP(addr net.Addr) string {
	// addr.String() возвращает "IP:port"
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		// Если не удалось разобрать - возвращаем как есть
		return addr.String()
	}
	return host
}
