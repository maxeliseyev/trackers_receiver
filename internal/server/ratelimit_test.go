package server

import (
	"net"
	"testing"
	"time"
)

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

func newMockConn(ip string) net.Conn {
	return &mockConn{
		remoteAddr: &mockAddr{
			network: "tcp",
			address: ip + ":12345",
		},
	}
}

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

	for i := 0; i < 5; i++ {
		if !rl.Allow(conn) {
			t.Errorf("Connection %d should be allowed", i)
		}
	}

	if rl.Allow(conn) {
		t.Error("6th connection should be blocked")
	}

	stats := rl.Stats()
	if stats["total_blocked"].(int64) != 1 {
		t.Errorf("Expected 1 blocked, got %d", stats["total_blocked"])
	}
	if stats["total_allowed"].(int64) != 5 {
		t.Errorf("Expected 5 allowed, got %d", stats["total_allowed"])
	}
}

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

	for i := 0; i < 100; i++ {
		if !rl.Allow(conn) {
			t.Errorf("Whitelisted IP should always be allowed (iteration %d)", i)
		}
	}

	stats := rl.Stats()
	if stats["total_blocked"].(int64) != 0 {
		t.Error("Whitelisted IP should never be blocked")
	}
}

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

	for i := 0; i < 3; i++ {
		if !rl.Allow(conn) {
			t.Errorf("Connection %d should be allowed", i)
		}
	}

	if rl.Allow(conn) {
		t.Error("4th connection should be blocked")
	}

	// let the window expire
	time.Sleep(1100 * time.Millisecond)

	// block (2s) is still active
	if rl.Allow(conn) {
		t.Error("Connection should still be blocked")
	}

	// let the block expire
	time.Sleep(2 * time.Second)

	if !rl.Allow(conn) {
		t.Error("Connection should be allowed after block expires")
	}
}

func TestRateLimiterProtocolErrors(t *testing.T) {
	config := DefaultRateLimiterConfig()
	rl := NewRateLimiter(config)
	defer rl.Stop()

	conn := newMockConn("192.168.1.1")

	for i := 0; i < 10; i++ {
		rl.RecordProtocolError(conn)
	}

	if rl.Allow(conn) {
		t.Error("IP with many protocol errors should be blocked")
	}

	blocked := rl.GetBlockedIPs()
	if len(blocked) == 0 {
		t.Error("Expected at least one blocked IP")
	}
}

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

	conn1 := newMockConn("192.168.1.1")
	conn2 := newMockConn("192.168.1.2")
	conn3 := newMockConn("192.168.1.3")

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

	if rl.Allow(conn1) {
		t.Error("conn1 should be blocked")
	}
	if rl.Allow(conn2) {
		t.Error("conn2 should be blocked")
	}
	if rl.Allow(conn3) {
		t.Error("conn3 should be blocked")
	}

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

func TestRateLimiterUnblock(t *testing.T) {
	config := &RateLimiterConfig{
		MaxConnectionsPerWindow: 2,
		WindowDuration:          10 * time.Second,
		BlockDuration:           10 * time.Minute, // long block
		WhitelistedIPs:          []string{},
		CleanupInterval:         1 * time.Minute,
	}

	rl := NewRateLimiter(config)
	defer rl.Stop()

	conn := newMockConn("192.168.1.1")

	for i := 0; i < 3; i++ {
		rl.Allow(conn)
	}

	if rl.Allow(conn) {
		t.Error("IP should be blocked")
	}

	rl.UnblockIP("192.168.1.1")

	if !rl.Allow(conn) {
		t.Error("IP should be allowed after manual unblock")
	}
}

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

	for i := 0; i < 2; i++ {
		rl.Allow(conn)
	}

	stats := rl.Stats()
	if stats["total_ips"].(int32) != 1 {
		t.Error("Expected 1 tracked IP")
	}

	time.Sleep(500 * time.Millisecond)

	rl.cleanup()

	// no activity for > 2 windows, so the entry is dropped
	stats = rl.Stats()
	if stats["total_ips"].(int32) != 0 {
		t.Error("Expected 0 tracked IPs after cleanup")
	}
}

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

	for i := 0; i < 3; i++ {
		rl.Allow(conn)
	}

	// first block (200ms) expires
	time.Sleep(300 * time.Millisecond)

	for i := 0; i < 3; i++ {
		rl.Allow(conn)
	}

	// first block: 200ms, second block: 400ms (exponential backoff)
	time.Sleep(300 * time.Millisecond)

	// still blocked: 400ms have not passed
	if rl.Allow(conn) {
		t.Error("Should still be blocked (exponential backoff)")
	}

	time.Sleep(200 * time.Millisecond)

	if !rl.Allow(conn) {
		t.Error("Should be unblocked after exponential backoff expires")
	}
}

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
