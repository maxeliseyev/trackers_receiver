package egts

import (
	"encoding/binary"
	"testing"
)

func TestBuildResponseRoundTrip(t *testing.T) {
	data, err := NewResponseBuilder(0x1234).BuildResponse(ProcessingResultOK, []uint16{7, 8}, RecordStatusOK)
	if err != nil {
		t.Fatal(err)
	}

	packet, err := ParsePacket(data)
	if err != nil {
		t.Fatalf("response does not parse: %v", err)
	}

	if packet.Header.PacketType != PtResponse {
		t.Errorf("PacketType = %d; expected %d", packet.Header.PacketType, PtResponse)
	}
	if packet.ResponsePacketID != 0x1234 {
		t.Errorf("ResponsePacketID = 0x%04X; expected 0x1234", packet.ResponsePacketID)
	}
	if packet.ProcessingResult != ProcessingResultOK {
		t.Errorf("ProcessingResult = %d; expected %d", packet.ProcessingResult, ProcessingResultOK)
	}
	if len(packet.Records) != 2 {
		t.Fatalf("got %d records; expected 2", len(packet.Records))
	}

	for i, want := range []uint16{7, 8} {
		sr := packet.Records[i].SubRecords
		if len(sr) != 1 || sr[0].Type != SrRecordResponse || len(sr[0].Data) != 3 {
			t.Fatalf("record %d: unexpected subrecords %+v", i, sr)
		}
		if crn := binary.LittleEndian.Uint16(sr[0].Data); crn != want {
			t.Errorf("record %d: CRN = %d; expected %d", i, crn, want)
		}
	}
}

func TestBuildErrorResponseHasNoRecords(t *testing.T) {
	data, err := NewResponseBuilder(1).BuildErrorResponse(ProcessingResultUnsupportedType)
	if err != nil {
		t.Fatal(err)
	}

	packet, err := ParsePacket(data)
	if err != nil {
		t.Fatalf("response does not parse: %v", err)
	}
	if packet.ProcessingResult != ProcessingResultUnsupportedType || len(packet.Records) != 0 {
		t.Errorf("PR = %d, records = %d; expected %d and 0",
			packet.ProcessingResult, len(packet.Records), ProcessingResultUnsupportedType)
	}
}
