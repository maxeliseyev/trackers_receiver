package server

import (
	"net"
	"testing"
	"time"

	"trackers-receiver/internal/egts"
	"trackers-receiver/internal/utils"
)

// emptyPacket is an EGTS_PT_APPDATA with FDL = 0, which trackers send as a
// keepalive. It has no frame data and therefore no SFRCS.
func emptyPacket(pid uint16) []byte {
	h := []byte{egts.ProtocolVersion, 0, 0, egts.MinHeaderLength, 0, 0, 0, byte(pid), byte(pid >> 8), egts.PtAppdata}
	return append(h, utils.CRC8(h))
}

func TestEmptyPacketsAreAcknowledged(t *testing.T) {
	serverConn, client := net.Pipe()
	defer client.Close()

	go NewConnectionHandler(serverConn, &MockStorage{}, DefaultConnectionConfig()).Handle()

	client.SetDeadline(time.Now().Add(2 * time.Second))
	go func() {
		client.Write(append(emptyPacket(1), emptyPacket(2)...))
	}()

	for _, pid := range []uint16{1, 2} {
		buf := make([]byte, 64)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("no response to packet %d: %v", pid, err)
		}
		resp, err := egts.ParsePacket(buf[:n])
		if err != nil {
			t.Fatalf("invalid response to packet %d: %v", pid, err)
		}
		if resp.ResponsePacketID != pid || resp.ProcessingResult != egts.ProcessingResultOK {
			t.Errorf("response RPID=%d PR=%d; expected RPID=%d PR=0", resp.ResponsePacketID, resp.ProcessingResult, pid)
		}
	}
}
