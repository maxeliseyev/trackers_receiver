package egts

import (
	"bytes"
	"encoding/binary"

	"trackers-receiver/internal/utils"
)

// Processing result codes (EGTS_PC_*).
const (
	ProcessingResultOK               = 0   // EGTS_PC_OK
	ProcessingResultInProgress       = 1   // EGTS_PC_IN_PROGRESS
	ProcessingResultUnsupportedProto = 128 // EGTS_PC_UNS_PROTOCOL
	ProcessingResultDecryptError     = 129 // EGTS_PC_DECRYPT_ERROR
	ProcessingResultHeaderError      = 131 // EGTS_PC_PROC_DENIED
	ProcessingResultIncHeaderForm    = 132 // EGTS_PC_INC_HEADERFORM
	ProcessingResultIncDataForm      = 133 // EGTS_PC_INC_DATAFORM
	ProcessingResultUnsupportedType  = 134 // EGTS_PC_UNS_TYPE
	ProcessingResultNeedParamsError  = 135 // EGTS_PC_NOTEN_PARAMS
	ProcessingResultDBError          = 136 // EGTS_PC_DBE_ERROR
	ProcessingResultSSE              = 137 // EGTS_PC_SSE_ERROR
	ProcessingResultRecordError      = 138 // EGTS_PC_REC_ERROR
	ProcessingResultTfldError        = 139 // EGTS_PC_FLD_ERROR
)

// RFL of records sent by the platform: RSOD, the recipient is on the terminal side.
const platformRecordFlags = 0x40

// RecordConfirmation is one EGTS_SR_RECORD_RESPONSE: the confirmed record's
// number and services, and the result of processing it.
type RecordConfirmation struct {
	RecordNumber         uint16
	SourceServiceType    uint8 // SST of the confirmed record
	RecipientServiceType uint8 // RST of the confirmed record
	Status               uint8
}

// ConfirmRecord confirms r with status.
func ConfirmRecord(r *Record, status uint8) RecordConfirmation {
	return RecordConfirmation{
		RecordNumber:         r.RecordNumber,
		SourceServiceType:    r.SourceServiceType,
		RecipientServiceType: r.RecipientServiceType,
		Status:               status,
	}
}

// BuildResponse builds an EGTS_PT_RESPONSE with packet ID pid that answers
// packet rpid. Records are confirmed only when processingResult is OK.
func BuildResponse(pid, rpid uint16, processingResult uint8, records []RecordConfirmation) []byte {
	frame := bytes.NewBuffer(make([]byte, 0, 3+len(records)*13))
	binary.Write(frame, binary.LittleEndian, rpid)
	frame.WriteByte(processingResult)

	if processingResult == ProcessingResultOK {
		for _, rc := range records {
			// The response comes from the service that received the record,
			// so its source and recipient are swapped.
			var srd [3]byte
			binary.LittleEndian.PutUint16(srd[:], rc.RecordNumber)
			srd[2] = rc.Status
			writeRecord(frame, rc.RecordNumber, rc.RecipientServiceType, rc.SourceServiceType, SrRecordResponse, srd[:])
		}
	}
	return buildPacket(pid, PtResponse, frame.Bytes())
}

// BuildResultCode builds an EGTS_PT_APPDATA carrying EGTS_SR_RESULT_CODE,
// which the platform sends after the terminal has identified itself.
func BuildResultCode(pid, recordNumber uint16, code uint8) []byte {
	frame := bytes.NewBuffer(make([]byte, 0, 13))
	writeRecord(frame, recordNumber, EgtsAuthService, EgtsAuthService, SrResultCode, []byte{code})
	return buildPacket(pid, PtAppdata, frame.Bytes())
}

// writeRecord writes a record RL(2) RN(2) RFL(1) SST(1) RST(1) holding a
// single subrecord SRT(1) SRL(2) SRD.
func writeRecord(buf *bytes.Buffer, rn uint16, sst, rst, srt uint8, srd []byte) {
	binary.Write(buf, binary.LittleEndian, uint16(3+len(srd)))
	binary.Write(buf, binary.LittleEndian, rn)
	buf.WriteByte(platformRecordFlags)
	buf.WriteByte(sst)
	buf.WriteByte(rst)

	buf.WriteByte(srt)
	binary.Write(buf, binary.LittleEndian, uint16(len(srd)))
	buf.Write(srd)
}

// buildPacket wraps frame data in an 11-byte transport header with all flags
// cleared, followed by SFRCS.
func buildPacket(pid uint16, packetType uint8, frame []byte) []byte {
	buf := bytes.NewBuffer(make([]byte, 0, MinHeaderLength+len(frame)+2))

	var h [MinHeaderLength]byte
	h[0] = ProtocolVersion
	h[3] = MinHeaderLength
	binary.LittleEndian.PutUint16(h[5:], uint16(len(frame)))
	binary.LittleEndian.PutUint16(h[7:], pid)
	h[9] = packetType
	h[10] = utils.CRC8(h[:10])
	buf.Write(h[:])

	if len(frame) > 0 {
		buf.Write(frame)
		binary.Write(buf, binary.LittleEndian, utils.CRC16(frame))
	}
	return buf.Bytes()
}
