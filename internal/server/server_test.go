package server

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"trackers-receiver/internal/storage"
	"trackers-receiver/pkg/models"
)

type MockStorage struct {
	mu             sync.Mutex
	pushBatchCalls int
	pushed         map[string][]*models.Document
}

func (m *MockStorage) Push(ctx context.Context, queue string, doc *models.Document) error {
	return nil
}

func (m *MockStorage) PushBatch(ctx context.Context, queue string, docs []*models.Document) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pushBatchCalls++
	if m.pushed == nil {
		m.pushed = make(map[string][]*models.Document)
	}
	m.pushed[queue] = append(m.pushed[queue], docs...)
	return nil
}

func (m *MockStorage) documents(queue string) []*models.Document {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pushed[queue]
}

func (m *MockStorage) PushRaw(ctx context.Context, queue string, data []byte) error {
	return nil
}

func (m *MockStorage) Health(ctx context.Context) error {
	return nil
}

func (m *MockStorage) Stats() *storage.Stats {
	return &storage.Stats{}
}

func (m *MockStorage) Close() error {
	return nil
}

func newTestServer(t *testing.T, maxConns int) *Server {
	t.Helper()
	s := New(&MockStorage{}, &Config{
		MaxConnections: maxConns,
		Connection:     DefaultConnectionConfig(),
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.Shutdown(ctx)
	})
	return s
}

// pipeFrom is a net.Pipe whose server end reports the given remote IP.
func pipeFrom(ip string) (server, client net.Conn) {
	server, client = net.Pipe()
	return &addrConn{Conn: server, remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: 12345}}, client
}

type addrConn struct {
	net.Conn
	remote net.Addr
}

func (c *addrConn) RemoteAddr() net.Addr { return c.remote }

// waitFor polls cond until it holds or a second passes.
func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestCleanDisconnectCountsAsProcessed(t *testing.T) {
	s := newTestServer(t, 10)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go s.Serve(listener)

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return s.ActiveConnections() == 1 }, "connection was not served")

	client.Close()
	waitFor(t, func() bool { return s.ActiveConnections() == 0 }, "connection was not released")

	if got := s.Stats().TotalProcessed.Load(); got != 1 {
		t.Errorf("TotalProcessed = %d; expected 1", got)
	}
	if got := s.Stats().TotalFailed.Load(); got != 0 {
		t.Errorf("TotalFailed = %d; expected 0", got)
	}
}

func TestConnectionsAreServedConcurrently(t *testing.T) {
	const n = 100
	s := newTestServer(t, n)

	clients := make([]net.Conn, 0, n)
	for range n {
		serverConn, client := net.Pipe()
		clients = append(clients, client)
		if err := s.Submit(serverConn); err != nil {
			t.Fatalf("Submit: %v", err)
		}
	}
	if s.ActiveConnections() != n {
		t.Errorf("ActiveConnections = %d; expected %d", s.ActiveConnections(), n)
	}

	for _, c := range clients {
		c.Close()
	}
	waitFor(t, func() bool { return s.ActiveConnections() == 0 }, "connections were not released")
}

func TestMaxConnections(t *testing.T) {
	s := newTestServer(t, 2)

	for i := range 3 {
		serverConn, client := net.Pipe()
		defer client.Close()

		err := s.Submit(serverConn)
		if i < 2 && err != nil {
			t.Errorf("connection %d: unexpected error %v", i, err)
		}
		if i == 2 && err == nil {
			t.Error("connection over the limit was accepted")
		}
	}

	if got := s.Stats().TotalRejected.Load(); got != 1 {
		t.Errorf("TotalRejected = %d; expected 1", got)
	}
}

func TestRateLimitedSubmit(t *testing.T) {
	s := New(&MockStorage{}, &Config{
		MaxConnections: 10,
		RateLimiter: &RateLimiterConfig{
			MaxConnectionsPerWindow: 1,
			WindowDuration:          time.Minute,
			BlockDuration:           time.Minute,
			CleanupInterval:         time.Minute,
		},
		Connection: DefaultConnectionConfig(),
	})
	defer s.Shutdown(context.Background())

	first, firstClient := pipeFrom("10.0.0.1")
	defer firstClient.Close()
	second, secondClient := pipeFrom("10.0.0.1")
	defer secondClient.Close()
	if err := s.Submit(first); err != nil {
		t.Fatalf("first connection rejected: %v", err)
	}
	if err := s.Submit(second); err == nil {
		t.Error("second connection from the same IP was not rate limited")
	}
}

func TestShutdownClosesActiveConnections(t *testing.T) {
	s := newTestServer(t, 10)

	serverConn, client := net.Pipe()
	defer client.Close()
	if err := s.Submit(serverConn); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Error("client connection is still open after Shutdown")
	}
	if s.ActiveConnections() != 0 {
		t.Errorf("ActiveConnections = %d after Shutdown", s.ActiveConnections())
	}

	late, lateClient := net.Pipe()
	defer lateClient.Close()
	if err := s.Submit(late); err == nil {
		t.Error("Submit succeeded after Shutdown")
	}
}

func TestServeStopsWhenListenerCloses(t *testing.T) {
	s := newTestServer(t, 10)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		s.Serve(listener)
		close(done)
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitFor(t, func() bool { return s.ActiveConnections() == 1 }, "dialed connection was not served")

	listener.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Serve did not return after the listener was closed")
	}
}

func TestHealth(t *testing.T) {
	s := newTestServer(t, 10)

	if err := s.Health(); err != nil {
		t.Errorf("running server is unhealthy: %v", err)
	}

	s.Shutdown(context.Background())
	if err := s.Health(); err == nil {
		t.Error("stopped server reported healthy")
	}
}

func TestGetMetrics(t *testing.T) {
	s := newTestServer(t, 7)

	m := s.GetMetrics()
	if m["connections_max"] != 7 {
		t.Errorf("connections_max = %v; expected 7", m["connections_max"])
	}
	if m["connections_active"] != 0 {
		t.Errorf("connections_active = %v; expected 0", m["connections_active"])
	}
}

func BenchmarkSubmit(b *testing.B) {
	s := New(&MockStorage{}, &Config{
		MaxConnections: b.N + 1,
		Connection:     DefaultConnectionConfig(),
	})
	defer s.Shutdown(context.Background())

	for b.Loop() {
		serverConn, client := net.Pipe()
		s.Submit(serverConn)
		client.Close()
	}
}
