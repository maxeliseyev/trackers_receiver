package server

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"trackers-receiver/internal/egts"
)

func TestParseProxyHeader(t *testing.T) {
	tests := []struct {
		line string
		want string // "" for UNKNOWN, "error" for an error
	}{
		{"PROXY TCP4 192.168.0.1 192.168.0.11 56324 36000\r\n", "192.168.0.1:56324"},
		{"PROXY TCP6 2001:db8::1 2001:db8::2 4000 36000\r\n", "[2001:db8::1]:4000"},
		{"PROXY TCP4 192.168.0.1 192.168.0.11 56324 36000\n", "192.168.0.1:56324"},
		{"PROXY UNKNOWN\r\n", ""},
		{"PROXY UNKNOWN ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n", ""},
		{"PROXY TCP4 2001:db8::1 192.168.0.11 56324 36000\r\n", "error"},
		{"PROXY TCP4 192.168.0.1 192.168.0.11 70000 36000\r\n", "error"},
		{"PROXY TCP4 192.168.0.1\r\n", "error"},
		{"GET / HTTP/1.1\r\n", "error"},
	}
	for _, tt := range tests {
		addr, err := parseProxyHeader([]byte(tt.line))
		switch {
		case tt.want == "error":
			if err == nil {
				t.Errorf("%q: expected an error, got %v", tt.line, addr)
			}
		case err != nil:
			t.Errorf("%q: %v", tt.line, err)
		case tt.want == "" && addr != nil:
			t.Errorf("%q: got %v; expected no address", tt.line, addr)
		case tt.want != "" && (addr == nil || addr.String() != tt.want):
			t.Errorf("%q: got %v; expected %s", tt.line, addr, tt.want)
		}
	}
}

// The header and the first EGTS packet usually arrive in one segment; the
// packet must not be lost in the header reader's buffer.
func TestProxyProtocolConnection(t *testing.T) {
	s := New(&MockStorage{}, &Config{
		MaxConnections: 10,
		ProxyProtocol:  true,
		RateLimiter: &RateLimiterConfig{
			MaxConnectionsPerWindow: 1,
			WindowDuration:          time.Minute,
			BlockDuration:           time.Minute,
			CleanupInterval:         time.Minute,
		},
		Connection: DefaultConnectionConfig(),
	})
	defer s.Shutdown(context.Background())

	// Two clients behind the same balancer address are limited separately.
	for _, client := range []string{"10.0.0.1", "10.0.0.2"} {
		serverConn, conn := pipeFrom("192.168.0.100")
		defer conn.Close()
		s.Submit(serverConn)

		conn.SetDeadline(time.Now().Add(2 * time.Second))
		go conn.Write(append([]byte("PROXY TCP4 "+client+" 192.168.0.100 5000 36000\r\n"), emptyPacket(9)...))

		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("client %s: no response: %v", client, err)
		}
		if resp, err := egts.ParsePacket(buf[:n]); err != nil || resp.ResponsePacketID != 9 {
			t.Errorf("client %s: response %v, %v; expected a response to packet 9", client, resp, err)
		}
	}

	if got := s.rateLimiter.Stats()["total_ips"]; got != int32(2) {
		t.Errorf("rate limiter tracks %v IPs; expected the 2 client addresses", got)
	}
}

func TestProxyProtocolRejectsMissingHeader(t *testing.T) {
	s := newTestServer(t, 10)
	s.proxyProtocol = true

	serverConn, conn := net.Pipe()
	defer conn.Close()
	s.Submit(serverConn)

	conn.SetDeadline(time.Now().Add(time.Second))
	go conn.Write(emptyPacket(1))
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("read returned %v; expected the connection to be closed", err)
	}
	waitFor(t, func() bool { return s.Stats().TotalRejected.Load() == 1 }, "connection without a PROXY header was not rejected")
}
