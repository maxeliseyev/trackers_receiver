package server

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxProtocolErrors   = 5
	protocolErrorWindow = 60 * time.Second
	maxBlockDuration    = 24 * time.Hour
)

// RateLimiter limits connections per IP over a sliding window and blocks
// offenders, doubling the block on each repeat. An IP is also blocked after
// more than maxProtocolErrors protocol errors within protocolErrorWindow.
type RateLimiter struct {
	maxConnPerWindow int
	windowDuration   time.Duration
	blockDuration    time.Duration

	// Read-only after construction.
	whitelist map[string]bool

	mu      sync.Mutex
	clients map[string]*clientState

	cleanupInterval time.Duration
	stopCleanup     chan struct{}

	totalBlocked   atomic.Int64 // rejected connection attempts
	totalAllowed   atomic.Int64
	currentBlocked atomic.Int32 // IPs currently blocked
	totalIPs       atomic.Int32 // IPs being tracked
}

type clientState struct {
	connections []time.Time // within the current window, oldest first

	blocked      bool
	blockedUntil time.Time
	blockCount   int

	protocolErrors int
	firstError     time.Time
}

type RateLimiterConfig struct {
	MaxConnectionsPerWindow int
	WindowDuration          time.Duration
	BlockDuration           time.Duration // first block; doubles on each repeat, capped at 24h
	WhitelistedIPs          []string
	CleanupInterval         time.Duration
}

func DefaultRateLimiterConfig() *RateLimiterConfig {
	return &RateLimiterConfig{
		MaxConnectionsPerWindow: 10,
		WindowDuration:          10 * time.Second,
		BlockDuration:           5 * time.Minute,
		WhitelistedIPs:          []string{"127.0.0.1", "::1"},
		CleanupInterval:         time.Minute,
	}
}

func NewRateLimiter(config *RateLimiterConfig) *RateLimiter {
	rl := &RateLimiter{
		maxConnPerWindow: config.MaxConnectionsPerWindow,
		windowDuration:   config.WindowDuration,
		blockDuration:    config.BlockDuration,
		whitelist:        make(map[string]bool, len(config.WhitelistedIPs)),
		clients:          make(map[string]*clientState),
		cleanupInterval:  config.CleanupInterval,
		stopCleanup:      make(chan struct{}),
	}
	for _, ip := range config.WhitelistedIPs {
		rl.whitelist[ip] = true
	}

	go rl.cleanupLoop()
	return rl
}

func (rl *RateLimiter) Allow(conn net.Conn) bool {
	ip := extractIP(conn.RemoteAddr())
	if rl.whitelist[ip] {
		rl.totalAllowed.Add(1)
		return true
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	state := rl.getState(ip)

	if state.blocked {
		if now.Before(state.blockedUntil) {
			rl.totalBlocked.Add(1)
			return false
		}
		rl.unblock(state)
	}

	state.connections = rl.dropExpired(state.connections, now)
	if len(state.connections) >= rl.maxConnPerWindow {
		rl.block(state, now)
		rl.totalBlocked.Add(1)
		return false
	}

	state.connections = append(state.connections, now)
	rl.totalAllowed.Add(1)
	return true
}

func (rl *RateLimiter) RecordProtocolError(conn net.Conn) {
	ip := extractIP(conn.RemoteAddr())
	if rl.whitelist[ip] {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	state := rl.getState(ip)

	if now.Sub(state.firstError) > protocolErrorWindow {
		state.protocolErrors = 0
		state.firstError = now
	}
	state.protocolErrors++

	if state.protocolErrors > maxProtocolErrors && !state.blocked {
		rl.block(state, now)
	}
}

// getState must be called with rl.mu held.
func (rl *RateLimiter) getState(ip string) *clientState {
	state, ok := rl.clients[ip]
	if !ok {
		state = &clientState{}
		rl.clients[ip] = state
		rl.totalIPs.Add(1)
	}
	return state
}

func (rl *RateLimiter) block(state *clientState, now time.Time) {
	state.blocked = true
	state.blockCount++
	duration := min(rl.blockDuration<<(state.blockCount-1), maxBlockDuration)
	if duration <= 0 { // shift overflow
		duration = maxBlockDuration
	}
	state.blockedUntil = now.Add(duration)
	rl.currentBlocked.Add(1)
}

// unblock clears an expired block but keeps blockCount, so the next block is longer.
func (rl *RateLimiter) unblock(state *clientState) {
	state.blocked = false
	state.connections = nil
	state.protocolErrors = 0
	rl.currentBlocked.Add(-1)
}

func (rl *RateLimiter) dropExpired(connections []time.Time, now time.Time) []time.Time {
	cutoff := now.Add(-rl.windowDuration)
	i := 0
	for i < len(connections) && !connections[i].After(cutoff) {
		i++
	}
	return connections[i:]
}

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

// cleanup forgets IPs that are not blocked and have been idle for two windows.
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-2 * rl.windowDuration)

	for ip, state := range rl.clients {
		if state.blocked && now.Before(state.blockedUntil) {
			continue
		}
		if len(state.connections) == 0 || state.connections[len(state.connections)-1].Before(cutoff) {
			delete(rl.clients, ip)
			rl.totalIPs.Add(-1)
			if state.blocked {
				rl.currentBlocked.Add(-1)
			}
		}
	}
}

func (rl *RateLimiter) GetBlockedIPs() []string {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	var blocked []string
	for ip, state := range rl.clients {
		if state.blocked && now.Before(state.blockedUntil) {
			blocked = append(blocked, ip)
		}
	}
	return blocked
}

// UnblockIP lifts a block and resets the backoff for the IP.
func (rl *RateLimiter) UnblockIP(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if state, ok := rl.clients[ip]; ok && state.blocked {
		rl.unblock(state)
		state.blockCount = 0
	}
}

func (rl *RateLimiter) Stats() map[string]any {
	return map[string]any{
		"total_blocked":   rl.totalBlocked.Load(),
		"total_allowed":   rl.totalAllowed.Load(),
		"current_blocked": rl.currentBlocked.Load(),
		"total_ips":       rl.totalIPs.Load(),
		"max_per_window":  rl.maxConnPerWindow,
		"window_duration": rl.windowDuration.String(),
		"block_duration":  rl.blockDuration.String(),
	}
}

func (rl *RateLimiter) Stop() {
	close(rl.stopCleanup)
}

func extractIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
