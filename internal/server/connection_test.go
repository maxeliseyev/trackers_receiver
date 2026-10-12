package server

import (
	"encoding/binary"
	"io"
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

func subRecord(srt uint8, data []byte) []byte {
	return append([]byte{srt, byte(len(data)), byte(len(data) >> 8)}, data...)
}

// record builds a record with OID set, so RFL = OBFE.
func record(rn uint16, oid uint32, service uint8, subRecords ...[]byte) []byte {
	var rd []byte
	for _, sr := range subRecords {
		rd = append(rd, sr...)
	}
	r := []byte{byte(len(rd)), byte(len(rd) >> 8), byte(rn), byte(rn >> 8), 0x01,
		byte(oid), byte(oid >> 8), byte(oid >> 16), byte(oid >> 24), service, service}
	return append(r, rd...)
}

func appdataPacket(pid uint16, records ...[]byte) []byte {
	var frame []byte
	for _, r := range records {
		frame = append(frame, r...)
	}
	h := []byte{egts.ProtocolVersion, 0, 0, egts.MinHeaderLength, 0, byte(len(frame)), byte(len(frame) >> 8), byte(pid), byte(pid >> 8), egts.PtAppdata}
	p := append(h, utils.CRC8(h))
	p = append(p, frame...)
	crc := utils.CRC16(frame)
	return append(p, byte(crc), byte(crc>>8))
}

func posData(ntm uint32) []byte {
	d := make([]byte, 21)
	binary.LittleEndian.PutUint32(d, ntm)
	return subRecord(egts.SrPosData, d)
}

// readServerPacket reads one whole packet sent by the server.
func readServerPacket(t *testing.T, r io.Reader) *egts.Packet {
	t.Helper()
	header := make([]byte, egts.MinHeaderLength)
	if _, err := io.ReadFull(r, header); err != nil {
		t.Fatalf("read header: %v", err)
	}
	fdl := binary.LittleEndian.Uint16(header[5:])
	raw := make([]byte, egts.PacketSize(egts.MinHeaderLength, fdl))
	copy(raw, header)
	if _, err := io.ReadFull(r, raw[egts.MinHeaderLength:]); err != nil {
		t.Fatalf("read body: %v", err)
	}
	p, err := egts.ParsePacket(raw)
	if err != nil {
		t.Fatalf("invalid packet from server: %v", err)
	}
	return p
}

func TestAppdataProcessing(t *testing.T) {
	serverConn, client := net.Pipe()
	defer client.Close()
	stor := &MockStorage{}
	go NewConnectionHandler(serverConn, stor, DefaultConnectionConfig()).Handle()

	identity := make([]byte, 5+15)
	binary.LittleEndian.PutUint32(identity, 42) // TID
	identity[4] = 0x40                          // IMEIE
	copy(identity[5:], "123456789012345")

	packet := appdataPacket(77,
		record(1, 1000, egts.EgtsAuthService, subRecord(egts.SrTermIdentity, identity)),
		// Two positions in one record, each followed by its own EXT_POS_DATA.
		record(2, 1000, egts.EgtsTeleDataService,
			posData(100), subRecord(egts.SrExtPosData, []byte{0x04, 150, 0}),
			posData(200), subRecord(egts.SrExtPosData, []byte{0x04, 250, 0})),
		// No position: still has to be confirmed.
		record(3, 1000, egts.EgtsTeleDataService, subRecord(egts.SrStateData, make([]byte, 5))),
		record(4, 1000, egts.EgtsCommandsService),
	)

	client.SetDeadline(time.Now().Add(2 * time.Second))
	go client.Write(packet)

	resp := readServerPacket(t, client)
	if resp.Header.PacketType != egts.PtResponse || resp.ResponsePacketID != 77 || resp.ProcessingResult != egts.ProcessingResultOK {
		t.Fatalf("PT = %d, RPID = %d, PR = %d; expected a successful response to packet 77",
			resp.Header.PacketType, resp.ResponsePacketID, resp.ProcessingResult)
	}
	wantServices := []uint8{egts.EgtsAuthService, egts.EgtsTeleDataService, egts.EgtsTeleDataService, egts.EgtsCommandsService}
	if len(resp.Records) != len(wantServices) {
		t.Fatalf("%d records confirmed; expected %d", len(resp.Records), len(wantServices))
	}
	for i, r := range resp.Records {
		crn := binary.LittleEndian.Uint16(r.SubRecords[0].Data)
		if crn != uint16(i+1) || r.SourceServiceType != wantServices[i] {
			t.Errorf("confirmation %d: CRN = %d, SST = %d; expected %d and %d", i, crn, r.SourceServiceType, i+1, wantServices[i])
		}
	}

	result := readServerPacket(t, client)
	if result.Header.PacketType != egts.PtAppdata || len(result.Records) != 1 {
		t.Fatalf("PT = %d with %d records after the response; expected EGTS_SR_RESULT_CODE", result.Header.PacketType, len(result.Records))
	}
	if sr := result.Records[0].SubRecords; len(sr) != 1 || sr[0].Type != egts.SrResultCode || sr[0].Data[0] != egts.ProcessingResultOK {
		t.Errorf("subrecords %+v; expected EGTS_SR_RESULT_CODE with RCD 0", sr)
	}
	if result.Header.PacketID == resp.Header.PacketID {
		t.Errorf("response and result code share PID %d", resp.Header.PacketID)
	}

	docs := stor.documents(DefaultConnectionConfig().QueueCharger)
	if len(docs) != 2 {
		t.Fatalf("%d documents stored; expected one per SR_POS_DATA", len(docs))
	}
	for i, wantPDOP := range []uint16{2, 3} {
		d := docs[i]
		if d.IMEI != "123456789012345" || d.Client != 1000 {
			t.Errorf("document %d: IMEI = %q, client = %d", i, d.IMEI, d.Client)
		}
		if d.NavData.PDOP == nil || *d.NavData.PDOP != wantPDOP {
			t.Errorf("document %d: PDOP = %v; expected %d", i, d.NavData.PDOP, wantPDOP)
		}
	}
}
