package integration

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"trackers-receiver/internal/egts"
	"trackers-receiver/internal/server"
	"trackers-receiver/internal/storage/redis"
	"trackers-receiver/internal/utils"
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
		ConnectionConfig:  testConnectionConfig(),
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

	resp, err := egts.ParsePacket(response[:n])
	if err != nil {
		t.Fatalf("Invalid response: %v", err)
	}
	if resp.Header.PacketType != egts.PtResponse {
		t.Errorf("Response packet type = %d, want %d", resp.Header.PacketType, egts.PtResponse)
	}
	if len(resp.Records) != 1 {
		t.Errorf("Response confirms %d records, want 1", len(resp.Records))
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

	// The server drops connections that don't start with an EGTS header.
	if n, err := conn.Read(make([]byte, 1024)); err == nil {
		t.Errorf("Expected connection to be closed, got %d bytes", n)
	}
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

func testConnectionConfig() *server.ConnectionConfig {
	cfg := server.DefaultConnectionConfig()
	cfg.QueueCharger = "test_charger"
	cfg.QueueFasttrack = "test_fasttrack"
	return cfg
}

// buildTestEGTSPacket builds an EGTS_PT_APPDATA packet with one record
// holding a single SR_POS_DATA (Moscow, 60 km/h, course 300).
func buildTestEGTSPacket() []byte {
	lat, lon := 55.755814, 37.617635
	posData := make([]byte, 21)
	binary.LittleEndian.PutUint32(posData[0:], 500_000_000)                // NTM, seconds since 2010-01-01
	binary.LittleEndian.PutUint32(posData[4:], uint32(lat/90*0xFFFFFFFF))  // LAT
	binary.LittleEndian.PutUint32(posData[8:], uint32(lon/180*0xFFFFFFFF)) // LONG
	posData[12] = 0x13                                                     // FLG: MV, FIX, VLD
	binary.LittleEndian.PutUint16(posData[13:], 1<<15|600)                 // SPD: DIRH, 60.0 km/h
	posData[15] = 0x2C                                                     // DIR: 300 = 0x100 | 0x2C

	subRecord := []byte{egts.SrPosData, byte(len(posData)), 0x00}
	subRecord = append(subRecord, posData...)

	record := binary.LittleEndian.AppendUint16(nil, uint16(len(subRecord))) // RL
	record = binary.LittleEndian.AppendUint16(record, 1)                    // RN
	record = append(record, 0x01)                                           // RFL: OBFE
	record = binary.LittleEndian.AppendUint32(record, 1)                    // OID
	record = append(record, egts.EgtsTeleDataService, egts.EgtsTeleDataService)
	record = append(record, subRecord...)

	header := []byte{
		egts.ProtocolVersion,
		0x00, // SKID
		0x00, // flags
		egts.MinHeaderLength,
		0x00, // HE
		0, 0, // FDL
		0x01, 0x00, // PID
		egts.PtAppdata,
	}
	binary.LittleEndian.PutUint16(header[5:], uint16(len(record)))
	header = append(header, utils.CRC8(header))

	packet := append(header, record...)
	return binary.LittleEndian.AppendUint16(packet, utils.CRC16(record))
}

// TestBuildTestEGTSPacket checks the fixture itself, so a broken fixture is
// caught without Redis.
func TestBuildTestEGTSPacket(t *testing.T) {
	packet, err := egts.ParsePacket(buildTestEGTSPacket())
	if err != nil {
		t.Fatalf("fixture does not parse: %v", err)
	}
	if len(packet.Records) != 1 || packet.Records[0].ObjectID != 1 || len(packet.Records[0].SubRecords) != 1 {
		t.Fatalf("unexpected structure: %+v", packet.Records)
	}

	pos, err := egts.GetPositionData(packet.Records[0].SubRecords[0])
	if err != nil {
		t.Fatal(err)
	}
	if pos.Speed != 60 || pos.Course != 300 || pos.Latitude < 55.75 || pos.Latitude > 55.76 ||
		pos.Longitude < 37.61 || pos.Longitude > 37.62 {
		t.Errorf("unexpected position: %+v", pos)
	}
}
