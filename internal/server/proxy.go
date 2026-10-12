package server

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// maxProxyHeaderLength is the longest PROXY protocol v1 line, CRLF included.
const maxProxyHeaderLength = 107

const proxyPrefix = "PROXY "

// errNoProxyHeader means the peer closed the connection before sending
// anything, as HAProxy health checks do.
var errNoProxyHeader = errors.New("connection closed before the PROXY header")

// proxyConn is a connection received through a load balancer: RemoteAddr
// reports the client address from the PROXY header.
type proxyConn struct {
	net.Conn
	reader *bufio.Reader // may hold bytes that followed the header
	remote net.Addr
}

func (c *proxyConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *proxyConn) RemoteAddr() net.Addr       { return c.remote }

// readProxyHeader reads the PROXY protocol v1 line that HAProxy sends with
// "send-proxy" and returns conn with the client's address. For
// "PROXY UNKNOWN" the balancer's own address is kept.
func readProxyHeader(conn net.Conn, timeout time.Duration) (net.Conn, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	reader := bufio.NewReaderSize(conn, maxProxyHeaderLength)
	// Check the prefix first, so that a client connecting directly is
	// rejected at once instead of waiting for a line break.
	prefix, err := reader.Peek(len(proxyPrefix))
	if errors.Is(err, io.EOF) && len(prefix) == 0 {
		return nil, errNoProxyHeader
	}
	if err == nil && string(prefix) != proxyPrefix {
		err = fmt.Errorf("no PROXY header, got % X", prefix)
	}
	if err != nil {
		return nil, err
	}

	line, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return nil, fmt.Errorf("PROXY header longer than %d bytes", maxProxyHeaderLength)
	}
	if err != nil {
		return nil, fmt.Errorf("read PROXY header: %w", err)
	}

	remote, err := parseProxyHeader(line)
	if err != nil {
		return nil, err
	}
	if remote == nil {
		remote = conn.RemoteAddr()
	}
	return &proxyConn{Conn: conn, reader: reader, remote: remote}, nil
}

// parseProxyHeader parses "PROXY TCP4 <src> <dst> <srcport> <dstport>\r\n".
// It returns nil for "PROXY UNKNOWN".
func parseProxyHeader(line []byte) (net.Addr, error) {
	fields := strings.Fields(string(bytes.TrimRight(line, "\r\n")))
	if len(fields) < 2 || fields[0] != "PROXY" {
		return nil, fmt.Errorf("not a PROXY header: %q", line)
	}

	switch fields[1] {
	case "UNKNOWN":
		return nil, nil
	case "TCP4", "TCP6":
	default:
		return nil, fmt.Errorf("unsupported PROXY protocol %q", fields[1])
	}
	if len(fields) != 6 {
		return nil, fmt.Errorf("malformed PROXY header: %q", line)
	}

	ip := net.ParseIP(fields[2])
	port, err := strconv.ParseUint(fields[4], 10, 16)
	if ip == nil || err != nil || (fields[1] == "TCP4") != (ip.To4() != nil) {
		return nil, fmt.Errorf("malformed PROXY header: %q", line)
	}
	return &net.TCPAddr{IP: ip, Port: int(port)}, nil
}
