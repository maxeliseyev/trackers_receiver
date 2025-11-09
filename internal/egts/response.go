package egts

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"trackers-receiver/internal/utils"
)

// ResponseBuilder строит ответы EGTS для отправки трекерам
type ResponseBuilder struct {
	packetID uint16 // ID исходного пакета
}

// NewResponseBuilder создает новый builder для ответов
func NewResponseBuilder(packetID uint16) *ResponseBuilder {
	return &ResponseBuilder{
		packetID: packetID,
	}
}

// ProcessingResult коды результата обработки пакета
const (
	ProcessingResultOK                = 0   // EGTS_PC_OK - успешно обработано
	ProcessingResultInProgress        = 1   // EGTS_PC_IN_PROGRESS - в процессе
	ProcessingResultUnsupportedProto  = 128 // EGTS_PC_UNS_PROTOCOL - неподдерживаемый протокол
	ProcessingResultDecryptError      = 129 // EGTS_PC_DECRYPT_ERROR - ошибка расшифровки
	ProcessingResultHeaderError       = 131 // EGTS_PC_PROC_DENIED - ошибка обработки
	ProcessingResultIncHeaderForm     = 132 // EGTS_PC_INC_HEADERFORM - некорректный заголовок
	ProcessingResultIncDataForm       = 133 // EGTS_PC_INC_DATAFORM - некорректные данные
	ProcessingResultUnsupportedType   = 134 // EGTS_PC_UNS_TYPE - неподдерживаемый тип
	ProcessingResultNeedParamsError   = 135 // EGTS_PC_NOTEN_PARAMS - недостаточно параметров
	ProcessingResultDBError           = 136 // EGTS_PC_DBE_ERROR - ошибка БД
	ProcessingResultSSE               = 137 // EGTS_PC_SSE_ERROR - ошибка источника
	ProcessingResultRecordError       = 138 // EGTS_PC_REC_ERROR - ошибка записи
	ProcessingResultTfldError         = 139 // EGTS_PC_FLD_ERROR - ошибка поля
)

// RecordStatus коды статуса обработки записи
const (
	RecordStatusOK            = 0   // EGTS_PC_OK - успешно
	RecordStatusNoError       = 1   // Нет ошибок (альтернативный код)
	RecordStatusHeaderError   = 131 // Ошибка заголовка
	RecordStatusDataError     = 132 // Ошибка данных
	RecordStatusUnsupported   = 134 // Неподдерживаемый тип
)

// BuildSuccessResponse создает успешный ответ для пакета с записями
// Подтверждает обработку всех записей из исходного пакета
func (rb *ResponseBuilder) BuildSuccessResponse(recordNumbers []uint16) ([]byte, error) {
	return rb.BuildResponse(ProcessingResultOK, recordNumbers, RecordStatusOK)
}

// BuildErrorResponse создает ответ с ошибкой обработки пакета
func (rb *ResponseBuilder) BuildErrorResponse(processingResult uint8) ([]byte, error) {
	return rb.BuildResponse(processingResult, nil, 0)
}

// BuildResponse создает EGTS_PT_RESPONSE пакет
// processingResult - результат обработки пакета (EGTS_PC_*)
// recordNumbers - номера успешно обработанных записей
// recordStatus - статус обработки записей
func (rb *ResponseBuilder) BuildResponse(processingResult uint8, recordNumbers []uint16, recordStatus uint8) ([]byte, error) {
	// Строим Service Frame Data для EGTS_PT_RESPONSE
	sfData, err := rb.buildServiceFrameData(processingResult, recordNumbers, recordStatus)
	if err != nil {
		return nil, fmt.Errorf("failed to build service frame data: %w", err)
	}

	// Строим Transport Layer Header
	header := rb.buildTransportHeader(uint16(len(sfData)))

	// Вычисляем CRC16 для Service Frame Data
	crc16 := utils.CRC16(sfData)

	// Собираем полный пакет
	buf := bytes.NewBuffer(make([]byte, 0, int(header.HeaderLength)+len(sfData)+2))

	// Записываем заголовок
	if err := rb.writeHeader(buf, header); err != nil {
		return nil, fmt.Errorf("failed to write header: %w", err)
	}

	// Записываем Service Frame Data
	buf.Write(sfData)

	// Записываем CRC16
	binary.Write(buf, binary.LittleEndian, crc16)

	return buf.Bytes(), nil
}

// buildTransportHeader создает заголовок Transport Layer для ответа
func (rb *ResponseBuilder) buildTransportHeader(frameDataLength uint16) *PacketHeader {
	header := &PacketHeader{
		ProtocolVersion: ProtocolVersion, // 0x01
		SecurityKeyID:   0,
		Prefix:          0,
		Route:           0,
		EncryptionAlg:   0,
		Compression:     0,
		Priority:        0,
		HeaderLength:    11, // Минимальная длина без опциональных полей
		HeaderEncoding:  0,
		FrameDataLength: frameDataLength,
		PacketID:        rb.packetID,
		PacketType:      PtResponse, // 0 - EGTS_PT_RESPONSE
	}

	return header
}

// writeHeader записывает заголовок в буфер
func (rb *ResponseBuilder) writeHeader(buf *bytes.Buffer, header *PacketHeader) error {
	// PRV - Protocol Version
	buf.WriteByte(header.ProtocolVersion)

	// SKID - Security Key ID
	buf.WriteByte(header.SecurityKeyID)

	// FLAGS - объединенные флаги (1 байт)
	flags := (header.Prefix << 6) |
		(header.Route << 5) |
		(header.EncryptionAlg << 3) |
		(header.Compression << 2) |
		header.Priority
	buf.WriteByte(flags)

	// HL - Header Length
	buf.WriteByte(header.HeaderLength)

	// HE - Header Encoding
	buf.WriteByte(header.HeaderEncoding)

	// FDL - Frame Data Length (2 байта, little-endian)
	binary.Write(buf, binary.LittleEndian, header.FrameDataLength)

	// PID - Packet ID (2 байта, little-endian)
	binary.Write(buf, binary.LittleEndian, header.PacketID)

	// PT - Packet Type
	buf.WriteByte(header.PacketType)

	// HCS - Header CheckSum (CRC8)
	// Вычисляем CRC8 для всех данных заголовка кроме самого HCS
	headerData := buf.Bytes()[buf.Len()-10:] // Последние 10 байт (заголовок без CRC)
	crc8 := utils.CRC8(headerData)
	buf.WriteByte(crc8)

	return nil
}

// buildServiceFrameData создает Service Frame Data для EGTS_PT_RESPONSE
// Формат согласно ГОСТ Р 54619-2011:
// - RPID (2 байта) - Response Packet ID (ID подтверждаемого пакета)
// - PR (1 байт) - Processing Result (результат обработки)
// - Records[] - массив записей с подтверждениями (опционально)
func (rb *ResponseBuilder) buildServiceFrameData(processingResult uint8, recordNumbers []uint16, recordStatus uint8) ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 256))

	// RPID - Response Packet ID (2 байта)
	binary.Write(buf, binary.LittleEndian, rb.packetID)

	// PR - Processing Result (1 байт)
	buf.WriteByte(processingResult)

	// Если есть записи для подтверждения, добавляем их
	if len(recordNumbers) > 0 && processingResult == ProcessingResultOK {
		for _, recordNumber := range recordNumbers {
			// Создаем запись с подзаписью EGTS_SR_RECORD_RESPONSE
			recordData, err := rb.buildRecordResponse(recordNumber, recordStatus)
			if err != nil {
				return nil, fmt.Errorf("failed to build record response for RN=%d: %w", recordNumber, err)
			}
			buf.Write(recordData)
		}
	}

	return buf.Bytes(), nil
}

// buildRecordResponse создает Service Layer Record с подзаписью EGTS_SR_RECORD_RESPONSE
// Формат Record:
// - RL (2 байта) - Record Length
// - RN (2 байта) - Record Number (номер подтверждаемой записи)
// - RFL (1 байт) - Record Flags
// - SST (1 байт) - Source Service Type (EGTS_AUTH_SERVICE или EGTS_TELEDATA_SERVICE)
// - RST (1 байт) - Recipient Service Type
// - RecordData - подзапись EGTS_SR_RECORD_RESPONSE
func (rb *ResponseBuilder) buildRecordResponse(recordNumber uint16, recordStatus uint8) ([]byte, error) {
	// Подзапись EGTS_SR_RECORD_RESPONSE:
	// - SRT (1 байт) = 0 (EGTS_SR_RECORD_RESPONSE)
	// - SRL (2 байта) = 3 (длина данных подзаписи)
	// - CRN (2 байта) - Confirmed Record Number
	// - RST (1 байт) - Record Status
	subRecordData := bytes.NewBuffer(make([]byte, 0, 6))
	subRecordData.WriteByte(SrRecordResponse)                     // SRT = 0
	binary.Write(subRecordData, binary.LittleEndian, uint16(3))   // SRL = 3
	binary.Write(subRecordData, binary.LittleEndian, recordNumber) // CRN
	subRecordData.WriteByte(recordStatus)                         // RST

	// Длина данных записи (без заголовка Record)
	recordDataLength := uint16(subRecordData.Len())

	// Строим запись
	recordBuf := bytes.NewBuffer(make([]byte, 0, 64))

	// RL - Record Length (2 байта)
	binary.Write(recordBuf, binary.LittleEndian, recordDataLength)

	// RN - Record Number (2 байта) - используем тот же номер что и подтверждаемая запись
	binary.Write(recordBuf, binary.LittleEndian, recordNumber)

	// RFL - Record Flags (1 байт)
	// Биты:
	// - SSOD (бит 0) = 0 (Structure Source On Device)
	// - RSOD (бит 1) = 1 (Record Source On Device)
	// - GRP (бит 2) = 0 (Group)
	// - RPP (биты 3-4) = 00 (Route Priority)
	// - TMFE (бит 5) = 0 (Time Field Exists)
	// - EVFE (бит 6) = 0 (Event ID Field Exists)
	// - OBFE (бит 7) = 0 (Object ID Field Exists)
	// Итого: 0b01000000 = 0x40
	recordBuf.WriteByte(0x40)

	// SST - Source Service Type (1 байт) - EGTS_AUTH_SERVICE
	recordBuf.WriteByte(EgtsAuthService)

	// RST - Recipient Service Type (1 байт) - EGTS_AUTH_SERVICE
	recordBuf.WriteByte(EgtsAuthService)

	// Record Data (подзапись)
	recordBuf.Write(subRecordData.Bytes())

	return recordBuf.Bytes(), nil
}

// BuildEmptyResponse создает минимальный ответ без подтверждения записей
// Используется когда нужно просто подтвердить получение пакета
func (rb *ResponseBuilder) BuildEmptyResponse() ([]byte, error) {
	return rb.BuildResponse(ProcessingResultOK, nil, 0)
}

// ResponseInfo содержит информацию о построенном ответе (для логирования)
type ResponseInfo struct {
	PacketID          uint16
	ProcessingResult  uint8
	RecordCount       int
	TotalBytes        int
	HeaderCRC         uint8
	FrameDataCRC      uint16
}

// GetResponseInfo извлекает информацию из построенного ответа
func GetResponseInfo(responseData []byte) (*ResponseInfo, error) {
	if len(responseData) < MinHeaderLength {
		return nil, fmt.Errorf("response too short: %d bytes", len(responseData))
	}

	info := &ResponseInfo{
		TotalBytes: len(responseData),
	}

	// Читаем PacketID из заголовка (offset 7-8)
	info.PacketID = binary.LittleEndian.Uint16(responseData[7:9])

	// Читаем HeaderCRC (последний байт заголовка)
	headerLength := responseData[3]
	info.HeaderCRC = responseData[headerLength-1]

	// Читаем Processing Result из Service Frame Data (offset headerLength+2)
	if len(responseData) > int(headerLength)+2 {
		info.ProcessingResult = responseData[headerLength+2]
	}

	// Читаем FrameDataCRC (последние 2 байта пакета)
	info.FrameDataCRC = binary.LittleEndian.Uint16(responseData[len(responseData)-2:])

	return info, nil
}
