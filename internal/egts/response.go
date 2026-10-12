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

const RecordStatusOK = 0

// ResponseBuilder builds EGTS_PT_RESPONSE packets acknowledging one incoming packet.
type ResponseBuilder struct {
	packetID uint16
}

func NewResponseBuilder(packetID uint16) *ResponseBuilder {
	return &ResponseBuilder{packetID: packetID}
}

func (rb *ResponseBuilder) BuildErrorResponse(processingResult uint8) ([]byte, error) {
	return rb.BuildResponse(processingResult, nil, 0)
}

// BuildResponse builds a response packet. When processingResult is OK, every
// record number gets an EGTS_SR_RECORD_RESPONSE with recordStatus.
func (rb *ResponseBuilder) BuildResponse(processingResult uint8, recordNumbers []uint16, recordStatus uint8) ([]byte, error) {
	sfd := rb.buildServiceFrameData(processingResult, recordNumbers, recordStatus)

	buf := bytes.NewBuffer(make([]byte, 0, MinHeaderLength+len(sfd)+2))
	rb.writeHeader(buf, uint16(len(sfd)))
	buf.Write(sfd)
	binary.Write(buf, binary.LittleEndian, utils.CRC16(sfd))

	return buf.Bytes(), nil
}

// writeHeader writes an 11-byte transport header with all flags cleared.
func (rb *ResponseBuilder) writeHeader(buf *bytes.Buffer, frameDataLength uint16) {
	var h [MinHeaderLength]byte
	h[0] = ProtocolVersion
	h[3] = MinHeaderLength
	binary.LittleEndian.PutUint16(h[5:], frameDataLength)
	binary.LittleEndian.PutUint16(h[7:], rb.packetID)
	h[9] = PtResponse
	h[10] = utils.CRC8(h[:10])
	buf.Write(h[:])
}

// buildServiceFrameData builds RPID(2) PR(1) followed by one record per confirmed record number.
func (rb *ResponseBuilder) buildServiceFrameData(processingResult uint8, recordNumbers []uint16, recordStatus uint8) []byte {
	buf := bytes.NewBuffer(make([]byte, 0, 3+len(recordNumbers)*13))
	binary.Write(buf, binary.LittleEndian, rb.packetID)
	buf.WriteByte(processingResult)

	if processingResult == ProcessingResultOK {
		for _, rn := range recordNumbers {
			writeRecordResponse(buf, rn, recordStatus)
		}
	}
	return buf.Bytes()
}

// writeRecordResponse writes a record RL(2) RN(2) RFL(1) SST(1) RST(1) holding
// one EGTS_SR_RECORD_RESPONSE subrecord: SRT(1) SRL(2) CRN(2) RST(1).
func writeRecordResponse(buf *bytes.Buffer, recordNumber uint16, recordStatus uint8) {
	const subRecordLen = 6

	binary.Write(buf, binary.LittleEndian, uint16(subRecordLen))
	binary.Write(buf, binary.LittleEndian, recordNumber)
	buf.WriteByte(0x40) // RFL: RSOD
	buf.WriteByte(EgtsAuthService)
	buf.WriteByte(EgtsAuthService)

	buf.WriteByte(SrRecordResponse)
	binary.Write(buf, binary.LittleEndian, uint16(3))
	binary.Write(buf, binary.LittleEndian, recordNumber)
	buf.WriteByte(recordStatus)
}
