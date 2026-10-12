package egts

import (
	"encoding/binary"
	"testing"
)

func TestBuildResponseRoundTrip(t *testing.T) {
	confirmations := []RecordConfirmation{
		{RecordNumber: 7, SourceServiceType: EgtsAuthService, RecipientServiceType: EgtsAuthService},
		{RecordNumber: 8, SourceServiceType: EgtsTeleDataService, RecipientServiceType: EgtsTeleDataService, Status: ProcessingResultIncDataForm},
	}
	packet, err := ParsePacket(BuildResponse(5, 0x1234, ProcessingResultOK, confirmations))
	if err != nil {
		t.Fatalf("response does not parse: %v", err)
	}

	if packet.Header.PacketType != PtResponse || packet.Header.PacketID != 5 {
		t.Errorf("PT = %d, PID = %d; expected %d and 5", packet.Header.PacketType, packet.Header.PacketID, PtResponse)
	}
	if packet.ResponsePacketID != 0x1234 || packet.ProcessingResult != ProcessingResultOK {
		t.Errorf("RPID = 0x%04X, PR = %d; expected 0x1234 and 0", packet.ResponsePacketID, packet.ProcessingResult)
	}
	if len(packet.Records) != len(confirmations) {
		t.Fatalf("got %d records; expected %d", len(packet.Records), len(confirmations))
	}

	for i, want := range confirmations {
		r := packet.Records[i]
		if r.SourceServiceType != want.RecipientServiceType || r.RecipientServiceType != want.SourceServiceType {
			t.Errorf("record %d: SST/RST = %d/%d; expected the confirmed record's services swapped", i, r.SourceServiceType, r.RecipientServiceType)
		}
		sr := r.SubRecords
		if len(sr) != 1 || sr[0].Type != SrRecordResponse || len(sr[0].Data) != 3 {
			t.Fatalf("record %d: unexpected subrecords %+v", i, sr)
		}
		if crn, rst := binary.LittleEndian.Uint16(sr[0].Data), sr[0].Data[2]; crn != want.RecordNumber || rst != want.Status {
			t.Errorf("record %d: CRN = %d, RST = %d; expected %d and %d", i, crn, rst, want.RecordNumber, want.Status)
		}
	}
}

func TestBuildErrorResponseHasNoRecords(t *testing.T) {
	packet, err := ParsePacket(BuildResponse(1, 1, ProcessingResultUnsupportedType, nil))
	if err != nil {
		t.Fatalf("response does not parse: %v", err)
	}
	if packet.ProcessingResult != ProcessingResultUnsupportedType || len(packet.Records) != 0 {
		t.Errorf("PR = %d, records = %d; expected %d and 0",
			packet.ProcessingResult, len(packet.Records), ProcessingResultUnsupportedType)
	}
}

func TestBuildResultCode(t *testing.T) {
	packet, err := ParsePacket(BuildResultCode(3, 3, ProcessingResultOK))
	if err != nil {
		t.Fatalf("result code does not parse: %v", err)
	}
	if packet.Header.PacketType != PtAppdata || len(packet.Records) != 1 {
		t.Fatalf("PT = %d, records = %d; expected APPDATA with one record", packet.Header.PacketType, len(packet.Records))
	}
	r := packet.Records[0]
	if r.SourceServiceType != EgtsAuthService || r.RecipientServiceType != EgtsAuthService {
		t.Errorf("SST/RST = %d/%d; expected the auth service", r.SourceServiceType, r.RecipientServiceType)
	}
	if len(r.SubRecords) != 1 || r.SubRecords[0].Type != SrResultCode || len(r.SubRecords[0].Data) != 1 || r.SubRecords[0].Data[0] != ProcessingResultOK {
		t.Errorf("unexpected subrecords %+v; expected one EGTS_SR_RESULT_CODE with RCD 0", r.SubRecords)
	}
}
