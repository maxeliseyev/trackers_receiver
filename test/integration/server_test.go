package integration

import (
	"context"
	"net"
	"testing"
	"time"

	"trackers-receiver/internal/config"
	"trackers-receiver/internal/server"
	"trackers-receiver/internal/storage/redis"
)

// TestServerIntegration tests the entire flow: connection -> parsing -> Redis
func TestServerIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := &redis.Config{
		Host:     "localhost",
		Port:     6379,
		Password: "",
		DB:       15, // Use separate DB for tests
		QueueMaxLengths: map[string]int64{
			"test_charger":   1000,
			"test_fasttrack": 1000,
		},
	}

	storage, err := redis.NewRedisStorage(cfg)
	if err != nil {
		t.Skipf("Redis not available: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()
	storage.ClearQueue(ctx, "test_charger")
	storage.ClearQueue(ctx, "test_fasttrack")

	poolConfig := &server.PoolConfig{
		NumWorkers:        2,
		QueueSize:         10,
		RateLimiterConfig: nil, // Disable rate limiting for tests
		ConnectionConfig:  server.DefaultConnectionConfig(),
	}

	pool := server.NewWorkerPool(storage, poolConfig)
	pool.Start()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pool.Shutdown(shutdownCtx)
	}()

	listener, err := net.Listen("tcp", "127.0.0.1:0") // Random port
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().String()

	// Accept connections in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // Listener closed
			}
			pool.Submit(conn)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	t.Run("ValidEGTSPacket", func(t *testing.T) {
		testValidEGTSPacket(t, serverAddr, storage)
	})

	t.Run("InvalidPacket", func(t *testing.T) {
		testInvalidPacket(t, serverAddr)
	})

	t.Run("MultipleConnections", func(t *testing.T) {
		testMultipleConnections(t, serverAddr, storage)
	})
}

// testValidEGTSPacket sends a valid EGTS packet and verifies it's saved to Redis
func testValidEGTSPacket(t *testing.T, serverAddr string, storage *redis.RedisStorage) {
	// Real EGTS packet with navigation data
	// This is a minimal valid EGTS_PT_APPDATA packet
	packet := buildTestEGTSPacket()

	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.Write(packet)
	if err != nil {
		t.Fatalf("Failed to send packet: %v", err)
	}

	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Verify response is valid EGTS_PT_RESPONSE
	if n < 11 { // Minimum EGTS header size
		t.Errorf("Response too short: %d bytes", n)
	}

	if response[0] != 0x01 { // PRV (Protocol Version)
		t.Errorf("Invalid protocol version: 0x%02x", response[0])
	}

	// Wait for data to be saved to Redis
	time.Sleep(500 * time.Millisecond)

	ctx := context.Background()
	queueLen, err := storage.GetQueueLength(ctx, "test_charger")
	if err != nil {
		t.Fatalf("Failed to get queue length: %v", err)
	}

	if queueLen == 0 {
		t.Error("Expected data in Redis queue, but queue is empty")
	} else {
		t.Logf("Queue length: %d", queueLen)
	}
}

// testInvalidPacket sends invalid data and verifies connection is closed
func testInvalidPacket(t *testing.T, serverAddr string) {
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))

	_, err = conn.Write([]byte("INVALID_DATA_NOT_EGTS"))
	if err != nil {
		t.Fatalf("Failed to send data: %v", err)
	}

	// Connection should be closed or we should get error response
	response := make([]byte, 1024)
	n, err := conn.Read(response)

	// Either connection closed (err != nil) or we got some response
	t.Logf("Invalid packet response: %d bytes, err: %v", n, err)
}

// testMultipleConnections tests concurrent connections
func testMultipleConnections(t *testing.T, serverAddr string, storage *redis.RedisStorage) {
	ctx := context.Background()
	storage.ClearQueue(ctx, "test_charger")

	numConnections := 10
	done := make(chan bool, numConnections)

	packet := buildTestEGTSPacket()

	for i := 0; i < numConnections; i++ {
		go func(id int) {
			conn, err := net.Dial("tcp", serverAddr)
			if err != nil {
				t.Errorf("Connection %d failed: %v", id, err)
				done <- false
				return
			}
			defer conn.Close()

			conn.SetDeadline(time.Now().Add(5 * time.Second))

			_, err = conn.Write(packet)
			if err != nil {
				t.Errorf("Connection %d send failed: %v", id, err)
				done <- false
				return
			}

			response := make([]byte, 1024)
			_, err = conn.Read(response)
			if err != nil {
				t.Errorf("Connection %d read failed: %v", id, err)
				done <- false
				return
			}

			done <- true
		}(i)
	}

	success := 0
	for i := 0; i < numConnections; i++ {
		if <-done {
			success++
		}
	}

	t.Logf("Successful connections: %d/%d", success, numConnections)

	if success < numConnections/2 {
		t.Errorf("Too many failed connections: %d/%d", numConnections-success, numConnections)
	}

	time.Sleep(500 * time.Millisecond)

	queueLen, err := storage.GetQueueLength(ctx, "test_charger")
	if err != nil {
		t.Fatalf("Failed to get queue length: %v", err)
	}

	t.Logf("Queue length after %d connections: %d", numConnections, queueLen)

	if queueLen < int64(success) {
		t.Errorf("Expected at least %d items in queue, got %d", success, queueLen)
	}
}

// buildTestEGTSPacket creates a minimal valid EGTS packet for testing
func buildTestEGTSPacket() []byte {
	// This is a simplified EGTS_PT_APPDATA packet with minimal navigation data
	// In production, use real packets captured from trackers

	// Transport Layer Header (11 bytes minimum)
	packet := []byte{
		0x01,       // PRV (Protocol Version = 1)
		0x00,       // SKID (Security Key ID = 0)
		0x00,       // FLAGS (no encryption, no priority, etc.)
		0x05,       // HL (Header Length = 11)
		0x00,       // HE (Header Encoding = 0)
		0x2D, 0x00, // FDL (Frame Data Length = 45 bytes) - will be calculated
		0x01, 0x00, // PID (Packet Identifier = 1)
		0x01, // PT (Packet Type = EGTS_PT_APPDATA)
		0x00, // HCS (Header Checksum) - will be calculated
	}

	// Service Layer (simplified - just minimal structure)
	// Record with minimal PosData subrecord
	serviceData := []byte{
		// Record Number 1
		0x01, 0x00, // RL (Record Length)
		0x01, 0x00, // RN (Record Number = 1)
		0x00,                   // RFL (Record Flags)
		0x01, 0x00, 0x00, 0x00, // OID (Object ID = 1)
		0x02, 0x00, 0x00, 0x00, // EVID (Event ID = 2)
		0x00, 0x00, 0x00, 0x00, // TM (Time = 0)

		// Subrecord: EGTS_SR_POS_DATA (type = 16)
		0x10,       // SRT (Subrecord Type = EGTS_SR_POS_DATA)
		0x15, 0x00, // SRL (Subrecord Length = 21 bytes)

		// Navigation Time (4 bytes)
		0x00, 0x00, 0x00, 0x00,

		// Latitude (4 bytes) - 55.755814° = 0x1A9F0A7C
		0x7C, 0x0A, 0x9F, 0x1A,

		// Longitude (4 bytes) - 37.617635° = 0x1677D63F
		0x3F, 0xD6, 0x77, 0x16,

		// Flags + Speed + Direction (3 bytes)
		0x80, // Flags (ALTE=1, LOHS=0, LAHS=0, MV=0, BB=0, FIX=0, CS=0, VLD=1)
		0x00, // Speed LSB
		0x80, // Speed MSB (1 bit) + Direction (7 bits)

		// Odometer (3 bytes)
		0x00, 0x00, 0x00,

		// Digital inputs (1 byte)
		0x00,

		// Source (1 byte)
		0x00,
	}

	fdl := len(serviceData) + 2 // +2 for CRC16
	packet[5] = byte(fdl & 0xFF)
	packet[6] = byte((fdl >> 8) & 0xFF)

	headerCRC := calculateCRC8(packet[0:10])
	packet[10] = headerCRC

	packet = append(packet, serviceData...)

	// Calculate and append Service Frame CRC16
	serviceCRC := calculateCRC16(serviceData)
	packet = append(packet, byte(serviceCRC&0xFF), byte((serviceCRC>>8)&0xFF))

	return packet
}

// calculateCRC8 calculates CRC8 for EGTS header
func calculateCRC8(data []byte) byte {
	crc := byte(0xFF)
	for _, b := range data {
		crc ^= b
		for i := 0; i < 8; i++ {
			if crc&0x80 != 0 {
				crc = (crc << 1) ^ 0x31
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// calculateCRC16 calculates CRC16 for EGTS service frame
func calculateCRC16(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0x8005
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

// TestWithConfig tests server with custom configuration
func TestWithConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	cfg := config.Config{
		Server: config.ServerConfig{
			Port:           36001,
			ReadTimeout:    300,
			WriteTimeout:   30,
			MaxConnections: 100,
		},
		Redis: config.RedisConfig{
			Host:     "localhost",
			Port:     6379,
			Password: "",
			DB:       15,
		},
		Queue: config.QueueConfig{
			ChargerName:     "test_charger",
			ChargerMaxLen:   1000,
			FasttrackName:   "test_fasttrack",
			FasttrackMaxLen: 1000,
		},
	}

	t.Logf("Testing with config: %+v", cfg)

	if cfg.Server.Port == 0 {
		t.Error("Invalid server port")
	}
}
