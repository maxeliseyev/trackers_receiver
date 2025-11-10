package server

import (
	"net"
	"testing"
	"time"
)

// mockAddr реализует net.Addr для тестов
type mockAddr struct {
	network string
	address string
}

func (m *mockAddr) Network() string {
	return m.network
}

func (m *mockAddr) String() string {
	return m.address
}

// mockConn реализует net.Conn для тестов
type mockConn struct {
	remoteAddr net.Addr
}

func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return &mockAddr{network: "tcp", address: "localhost:36000"} }
func (m *mockConn) RemoteAddr() net.Addr               { return m.remoteAddr }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// newMockConn создает mock подключение с указанным IP
func newMockConn(ip string) net.Conn {
	return &mockConn{
		remoteAddr: &mockAddr{
			network: "tcp",
			address: ip + ":12345",
		},
	}
}

// TestRateLimiterBasic базовый тест rate limiter
func TestRateLimiterBasic(t *testing.T) {
	config := &RateLimiterConfig{
		MaxConnectionsPerWindow: 5,
		WindowDuration:          10 * time.Second,
		BlockDuration:           5 * time.Second,
		WhitelistedIPs:          []string{"127.0.0.1"},
		CleanupInterval:         1 * time.Minute,
	}

	rl := NewRateLimiter(config)
	defer rl.Stop()

	conn := newMockConn("192.168.1.1")

	// Первые 5 подключений должны пройти
	for i := 0; i < 5; i++ {
		if !rl.Allow(conn) {
			t.Errorf("Connection %d should be allowed", i)
		}
	}

	// 6-е подключение должно быть заблокировано
	if rl.Allow(conn) {
		t.Error("6th connection should be blocked")
	}

	// Проверяем статистику
	stats := rl.Stats()
	if stats["total_blocked"].(int64) != 1 {
		t.Errorf("Expected 1 blocked, got %d", stats["total_blocked"])
	}
	if stats["total_allowed"].(int64) != 5 {
		t.Errorf("Expected 5 allowed, got %d", stats["total_allowed"])
	}
}

// TestRateLimiterWhitelist тест whitelist
func TestRateLimiterWhitelist(t *testing.T) {
	config := &RateLimiterConfig{
		MaxConnectionsPerWindow: 3,
		WindowDuration:          10 * time.Second,
		BlockDuration:           5 * time.Second,
		WhitelistedIPs:          []string{"127.0.0.1"},
		CleanupInterval:         1 * time.Minute,
	}

	rl := NewRateLimiter(config)
	defer rl.Stop()

	conn := newMockConn("127.0.0.1")

	// Whitelisted IP должен быть всегда разрешен
	for i := 0; i < 100; i++ {
		if !rl.Allow(conn) {
			t.Errorf("Whitelisted IP should always be allowed (iteration %d)", i)
		}
	}

	// Проверяем что не было блокировок
	stats := rl.Stats()
	if stats["total_blocked"].(int64) != 0 {
		t.Error("Whitelisted IP should never be blocked")
	}
}

// TestRateLimiterSlidingWindow тест sliding window
func TestRateLimiterSlidingWindow(t *testing.T) {
	config := &RateLimiterConfig{
		MaxConnectionsPerWindow: 3,
		WindowDuration:          1 * time.Second,
		BlockDuration:           2 * time.Second,
		WhitelistedIPs:          []string{},
		CleanupInterval:         1 * time.Minute,
	}

	rl := NewRateLimiter(config)
	defer rl.Stop()

	conn := newMockConn("192.168.1.1")

	// Заполняем окно (3 подключения)
	for i := 0; i < 3; i++ {
		if !rl.Allow(conn) {
			t.Errorf("Connection %d should be allowed", i)
		}
	}

	// 4-е подключение блокируется
	if rl.Allow(conn) {
		t.Error("4th connection should be blocked")
	}

	// Ждем истечения окна
	time.Sleep(1100 * time.Millisecond)

	// IP заблокирован еще на 2 секунды
	if rl.Allow(conn) {
		t.Error("Connection should still be blocked")
	}

	// Ждем истечения блокировки
	time.Sleep(2 * time.Second)

	// Теперь должно быть разрешено
	if !rl.Allow(conn) {
		t.Error("Connection should be allowed after block expires")
	}
}

// TestRateLimiterProtocolErrors тест блокировки по ошибкам протокола
func TestRateLimiterProtocolErrors(t *testing.T) {
	config := DefaultRateLimiterConfig()
	rl := NewRateLimiter(config)
	defer rl.Stop()

	conn := newMockConn("192.168.1.1")

	// Записываем 10 ошибок протокола
	for i := 0; i < 10; i++ {
		rl.RecordProtocolError(conn)
	}

	// IP должен быть заблокирован
	if rl.Allow(conn) {
		t.Error("IP with many protocol errors should be blocked")
	}

	// Проверяем что IP в списке заблокированных
	blocked := rl.GetBlockedIPs()
	if len(blocked) == 0 {
		t.Error("Expected at least one blocked IP")
	}
}

// TestRateLimiterMultipleIPs тест с несколькими IP
func TestRateLimiterMultipleIPs(t *testing.T) {
	config := &RateLimiterConfig{
		MaxConnectionsPerWindow: 3,
		WindowDuration:          10 * time.Second,
		BlockDuration:           5 * time.Second,
		WhitelistedIPs:          []string{},
		CleanupInterval:         1 * time.Minute,
	}

	rl := NewRateLimiter(config)
	defer rl.Stop()

	// Три разных IP
	conn1 := newMockConn("192.168.1.1")
	conn2 := newMockConn("192.168.1.2")
	conn3 := newMockConn("192.168.1.3")

	// Каждый IP может сделать 3 подключения
	for i := 0; i < 3; i++ {
		if !rl.Allow(conn1) {
			t.Error("conn1 should be allowed")
		}
		if !rl.Allow(conn2) {
			t.Error("conn2 should be allowed")
		}
		if !rl.Allow(conn3) {
			t.Error("conn3 should be allowed")
		}
	}

	// Следующие подключения блокируются
	if rl.Allow(conn1) {
		t.Error("conn1 should be blocked")
	}
	if rl.Allow(conn2) {
		t.Error("conn2 should be blocked")
	}
	if rl.Allow(conn3) {
		t.Error("conn3 should be blocked")
	}

	// Проверяем статистику
	stats := rl.Stats()
	if stats["total_allowed"].(int64) != 9 {
		t.Errorf("Expected 9 allowed, got %d", stats["total_allowed"])
	}
	if stats["total_blocked"].(int64) != 3 {
		t.Errorf("Expected 3 blocked, got %d", stats["total_blocked"])
	}
	if stats["current_blocked"].(int32) != 3 {
		t.Errorf("Expected 3 currently blocked IPs, got %d", stats["current_blocked"])
	}
}

// TestRateLimiterUnblock тест разблокировки
func TestRateLimiterUnblock(t *testing.T) {
	config := &RateLimiterConfig{
		MaxConnectionsPerWindow: 2,
		WindowDuration:          10 * time.Second,
		BlockDuration:           10 * time.Minute, // Длинная блокировка
		WhitelistedIPs:          []string{},
		CleanupInterval:         1 * time.Minute,
	}

	rl := NewRateLimiter(config)
	defer rl.Stop()

	conn := newMockConn("192.168.1.1")

	// Блокируем IP
	for i := 0; i < 3; i++ {
		rl.Allow(conn)
	}

	// IP заблокирован
	if rl.Allow(conn) {
		t.Error("IP should be blocked")
	}

	// Разблокируем вручную
	rl.UnblockIP("192.168.1.1")

	// Теперь должно быть разрешено
	if !rl.Allow(conn) {
		t.Error("IP should be allowed after manual unblock")
	}
}

// TestRateLimiterCleanup тест очистки старых записей
func TestRateLimiterCleanup(t *testing.T) {
	config := &RateLimiterConfig{
		MaxConnectionsPerWindow: 3,
		WindowDuration:          100 * time.Millisecond,
		BlockDuration:           100 * time.Millisecond,
		WhitelistedIPs:          []string{},
		CleanupInterval:         200 * time.Millisecond,
	}

	rl := NewRateLimiter(config)
	defer rl.Stop()

	conn := newMockConn("192.168.1.1")

	// Делаем несколько подключений
	for i := 0; i < 2; i++ {
		rl.Allow(conn)
	}

	// Проверяем что IP отслеживается
	stats := rl.Stats()
	if stats["total_ips"].(int32) != 1 {
		t.Error("Expected 1 tracked IP")
	}

	// Ждем cleanup
	time.Sleep(500 * time.Millisecond)

	// Запускаем cleanup вручную
	rl.cleanup()

	// IP должен быть удален (нет активности > 2 окон)
	stats = rl.Stats()
	if stats["total_ips"].(int32) != 0 {
		t.Error("Expected 0 tracked IPs after cleanup")
	}
}

// TestRateLimiterExponentialBackoff тест exponential backoff
func TestRateLimiterExponentialBackoff(t *testing.T) {
	config := &RateLimiterConfig{
		MaxConnectionsPerWindow: 2,
		WindowDuration:          100 * time.Millisecond,
		BlockDuration:           200 * time.Millisecond,
		WhitelistedIPs:          []string{},
		CleanupInterval:         1 * time.Minute,
	}

	rl := NewRateLimiter(config)
	defer rl.Stop()

	conn := newMockConn("192.168.1.1")

	// Первая блокировка
	for i := 0; i < 3; i++ {
		rl.Allow(conn)
	}

	// Ждем истечения первой блокировки (200ms)
	time.Sleep(300 * time.Millisecond)

	// Блокируемся снова (вторая блокировка)
	for i := 0; i < 3; i++ {
		rl.Allow(conn)
	}

	// Первая блокировка: 200ms
	// Вторая блокировка: 400ms (exponential backoff)
	time.Sleep(300 * time.Millisecond)

	// Все еще заблокирован (400ms не прошло)
	if rl.Allow(conn) {
		t.Error("Should still be blocked (exponential backoff)")
	}

	// Ждем еще
	time.Sleep(200 * time.Millisecond)

	// Теперь разблокирован
	if !rl.Allow(conn) {
		t.Error("Should be unblocked after exponential backoff expires")
	}
}

// BenchmarkRateLimiterAllow бенчмарк Allow
func BenchmarkRateLimiterAllow(b *testing.B) {
	config := DefaultRateLimiterConfig()
	rl := NewRateLimiter(config)
	defer rl.Stop()

	conn := newMockConn("192.168.1.1")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rl.Allow(conn)
	}
}

// BenchmarkRateLimiterConcurrent бенчмарк параллельных Allow
func BenchmarkRateLimiterConcurrent(b *testing.B) {
	config := DefaultRateLimiterConfig()
	rl := NewRateLimiter(config)
	defer rl.Stop()

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		conn := newMockConn("192.168.1.1")
		for pb.Next() {
			rl.Allow(conn)
		}
	})
}
