// Package parity checks that the documents match those of the Python receiver.
//
// The test runs the Python receiver's own code (with the network and Redis
// stubbed out) on the same packets and compares the documents as the
// consumers see them, decoded with its utils/pack.py. It needs uv and a
// checkout of the Python receiver:
//
//	PYTHON_RECEIVER_SRC=/path/to/gazpromneft_receiver/src go test ./test/parity
//
// PARITY_PACKETS_CSV adds real packets: a ';'-separated CSV with the packet
// hex in the "Полный EGTS-пакет hex (без TCP/IP заголовков)" column.
package parity

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"trackers-receiver/internal/egts"
	"trackers-receiver/internal/serialization"
	"trackers-receiver/internal/server"
	"trackers-receiver/internal/storage"
	"trackers-receiver/pkg/models"
)

type parityCase struct {
	Name    string   `json:"name"`
	Address [2]any   `json:"address"`
	Packets []string `json:"packets"`
	GoDocs  []string `json:"go_docs"`
}

var clientAddr = &net.TCPAddr{IP: net.IPv4(10, 1, 2, 3), Port: 5555}

func TestParityWithPythonReceiver(t *testing.T) {
	src := os.Getenv("PYTHON_RECEIVER_SRC")
	if src == "" {
		t.Skip("PYTHON_RECEIVER_SRC is not set")
	}
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv is not installed")
	}

	cases := syntheticCases()
	if path := os.Getenv("PARITY_PACKETS_CSV"); path != "" {
		cases = append(cases, csvCases(t, path)...)
	}
	for i := range cases {
		cases[i].Address = [2]any{clientAddr.IP.String(), clientAddr.Port}
		cases[i].GoDocs = runGoReceiver(t, cases[i].Packets)
	}

	input, err := json.Marshal(map[string]any{"cases": cases})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("uv", "run", "--quiet", "--no-project", "--with", "msgpack", "--with", "arrow",
		"python", "python_receiver.py", src)
	cmd.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("Python receiver: %v\n%s", err, stderr.String())
	}

	var diffs map[string][]string
	if err := json.Unmarshal(output, &diffs); err != nil {
		t.Fatalf("Python receiver output: %v\n%s", err, output)
	}
	documents := 0
	for _, c := range cases {
		documents += len(c.GoDocs)
		if len(c.GoDocs) == 0 {
			t.Errorf("%s: no documents", c.Name)
		}
		for _, d := range diffs[c.Name] {
			t.Errorf("%s: %s", c.Name, d)
		}
	}
	t.Logf("compared %d documents in %d cases", documents, len(cases))
}

// runGoReceiver sends the packets over one connection and returns the
// documents pushed to the charger queue, msgpack-encoded and hex-encoded.
func runGoReceiver(t *testing.T, packets []string) []string {
	t.Helper()
	serverConn, client := net.Pipe()
	defer client.Close()
	stor := &capture{}
	go server.NewConnectionHandler(&tcpConn{serverConn}, stor, server.DefaultConnectionConfig()).Handle()

	var data []byte
	for _, p := range packets {
		b, err := hex.DecodeString(p)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, b...)
	}
	client.SetDeadline(time.Now().Add(5 * time.Second))
	go client.Write(data)

	// Documents are stored before the packet is answered, so they are all
	// there once every packet has its response.
	for responses := 0; responses < len(packets); {
		header := make([]byte, egts.MinHeaderLength)
		if _, err := io.ReadFull(client, header); err != nil {
			t.Fatalf("read response: %v", err)
		}
		body := make([]byte, egts.PacketSize(egts.MinHeaderLength, binary.LittleEndian.Uint16(header[5:]))-len(header))
		if _, err := io.ReadFull(client, body); err != nil {
			t.Fatalf("read response: %v", err)
		}
		if header[9] == egts.PtResponse {
			responses++
		}
	}
	return stor.documents()
}

// tcpConn reports a fixed TCP client address.
type tcpConn struct{ net.Conn }

func (tcpConn) RemoteAddr() net.Addr { return clientAddr }

type capture struct {
	mu   sync.Mutex
	docs []string
}

func (c *capture) PushBatch(_ context.Context, queue string, docs []*models.Document) error {
	if queue != server.DefaultConnectionConfig().QueueCharger {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, d := range docs {
		b, err := serialization.NewSerializer().Marshal(d)
		if err != nil {
			return err
		}
		c.docs = append(c.docs, hex.EncodeToString(b))
	}
	return nil
}

func (c *capture) documents() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.docs
}

func (c *capture) Push(ctx context.Context, queue string, doc *models.Document) error {
	return c.PushBatch(ctx, queue, []*models.Document{doc})
}
func (c *capture) PushRaw(context.Context, string, []byte) error { return errors.New("not supported") }
func (c *capture) Health(context.Context) error                  { return nil }
func (c *capture) Stats() *storage.Stats                         { return &storage.Stats{} }
func (c *capture) Close() error                                  { return nil }

func csvCases(t *testing.T, path string) []parityCase {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(data, []byte("\uFEFF"))))
	r.Comma = ';'
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatal(err)
	}

	column := -1
	for i, name := range rows[0] {
		if strings.HasPrefix(name, "Полный EGTS-пакет hex") {
			column = i
		}
	}
	if column < 0 {
		t.Fatalf("%s: no packet hex column", path)
	}

	var cases []parityCase
	seen := map[string]bool{}
	for i, row := range rows[1:] {
		packet := strings.ToLower(strings.Join(strings.Fields(row[column]), ""))
		if packet == "" || seen[packet] {
			continue
		}
		seen[packet] = true
		cases = append(cases, parityCase{Name: "csv row " + strconv.Itoa(i+2), Packets: []string{packet}})
	}
	return cases
}
