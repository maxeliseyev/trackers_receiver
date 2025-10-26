package egts

import (
	"testing"
	"time"
)

// TestParsePacketInsufficientData проверяет обработку недостаточных данных
func TestParsePacketInsufficientData(t *testing.T) {
	// Слишком короткие данные (меньше минимального заголовка)
	shortData := []byte{0x01, 0x00, 0x00}

	_, err := ParsePacket(shortData)
	if err == nil {
		t.Fatal("Ожидалась ошибка при парсинге коротких данных")
	}

	t.Logf("Правильно получена ошибка: %v", err)
}

// TestParseHeaderBasic проверяет базовый парсинг заголовка
func TestParseHeaderBasic(t *testing.T) {
	// Создаём минимальный валидный заголовок EGTS
	// PRV=0x01, SKID=0x00, FLAGS=0x00, HL=0x0B (11 байт), HE=0x00
	// FDL=0x0005 (5 байт данных), PID=0x0001, PT=0x01 (APPDATA)
	headerData := []byte{
		0x01,       // PRV - Protocol Version
		0x00,       // SKID - Security Key ID
		0x00,       // FLAGS (PRF=00, RTE=0, ENA=00, CMP=0, PR=00)
		0x0B,       // HL - Header Length (11 байт)
		0x00,       // HE - Header Encoding
		0x05, 0x00, // FDL - Frame Data Length (5 байт) - little endian
		0x01, 0x00, // PID - Packet ID (1) - little endian
		0x01,       // PT - Packet Type (APPDATA)
		0x00,       // HCS - Header Check Sum (упрощенно)
	}

	header, err := parseHeader(headerData)
	if err != nil {
		t.Fatalf("Ошибка парсинга заголовка: %v", err)
	}

	// Проверяем поля
	if header.ProtocolVersion != 0x01 {
		t.Errorf("ProtocolVersion = %d; ожидалось 1", header.ProtocolVersion)
	}

	if header.HeaderLength != 0x0B {
		t.Errorf("HeaderLength = %d; ожидалось 11", header.HeaderLength)
	}

	if header.FrameDataLength != 0x0005 {
		t.Errorf("FrameDataLength = %d; ожидалось 5", header.FrameDataLength)
	}

	if header.PacketID != 0x0001 {
		t.Errorf("PacketID = %d; ожидалось 1", header.PacketID)
	}

	if header.PacketType != PtAppdata {
		t.Errorf("PacketType = %d; ожидалось %d", header.PacketType, PtAppdata)
	}

	t.Log("Заголовок успешно распарсен")
}

// TestParsePacketWithEmptyRecords проверяет пакет без записей
func TestParsePacketWithEmptyRecords(t *testing.T) {
	// Создаём пакет с пустыми данными фрейма
	packetData := []byte{
		0x01,       // PRV
		0x00,       // SKID
		0x00,       // FLAGS
		0x0B,       // HL
		0x00,       // HE
		0x00, 0x00, // FDL = 0 (нет данных)
		0x01, 0x00, // PID
		0x01,       // PT
		0x00,       // HCS
	}

	packet, err := ParsePacket(packetData)
	if err != nil {
		t.Fatalf("Ошибка парсинга пакета: %v", err)
	}

	if packet.Header == nil {
		t.Fatal("Header не должен быть nil")
	}

	if len(packet.Records) != 0 {
		t.Errorf("Количество записей = %d; ожидалось 0", len(packet.Records))
	}

	t.Log("Пакет без записей успешно распарсен")
}

// TestParseSubRecordsEmpty проверяет парсинг пустых подзаписей
func TestParseSubRecordsEmpty(t *testing.T) {
	emptyData := []byte{}

	subRecords, err := parseSubRecords(emptyData)
	if err != nil {
		t.Fatalf("Ошибка при парсинге пустых подзаписей: %v", err)
	}

	if len(subRecords) != 0 {
		t.Errorf("Количество подзаписей = %d; ожидалось 0", len(subRecords))
	}

	t.Log("Пустые подзаписи обработаны корректно")
}

// TestParseSubRecordBasic проверяет базовый парсинг подзаписи
func TestParseSubRecordBasic(t *testing.T) {
	// Создаём простую подзапись
	// SRT=16 (SR_POS_DATA), SRL=5, SRD=[1,2,3,4,5]
	subRecordData := []byte{
		0x10,       // SRT - Subrecord Type (SR_POS_DATA = 16)
		0x05, 0x00, // SRL - Subrecord Length (5 байт) - little endian
		0x01, 0x02, 0x03, 0x04, 0x05, // SRD - данные (5 байт)
	}

	subRecords, err := parseSubRecords(subRecordData)
	if err != nil {
		t.Fatalf("Ошибка парсинга подзаписи: %v", err)
	}

	if len(subRecords) != 1 {
		t.Fatalf("Количество подзаписей = %d; ожидалось 1", len(subRecords))
	}

	sr := subRecords[0]

	if sr.Type != SrPosData {
		t.Errorf("Type = %d; ожидалось %d", sr.Type, SrPosData)
	}

	if sr.Length != 5 {
		t.Errorf("Length = %d; ожидалось 5", sr.Length)
	}

	if len(sr.Data) != 5 {
		t.Errorf("Длина данных = %d; ожидалось 5", len(sr.Data))
	}

	expectedData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	for i, b := range sr.Data {
		if b != expectedData[i] {
			t.Errorf("Data[%d] = %d; ожидалось %d", i, b, expectedData[i])
		}
	}

	t.Log("Подзапись успешно распарсена")
}

// TestParseMultipleSubRecords проверяет парсинг нескольких подзаписей
func TestParseMultipleSubRecords(t *testing.T) {
	// Создаём две подзаписи
	subRecordsData := []byte{
		// Первая подзапись
		0x10,       // SRT
		0x03, 0x00, // SRL = 3
		0xAA, 0xBB, 0xCC, // Данные

		// Вторая подзапись
		0x11,       // SRT (SR_EXT_POS_DATA = 17)
		0x02, 0x00, // SRL = 2
		0xDD, 0xEE, // Данные
	}

	subRecords, err := parseSubRecords(subRecordsData)
	if err != nil {
		t.Fatalf("Ошибка парсинга подзаписей: %v", err)
	}

	if len(subRecords) != 2 {
		t.Fatalf("Количество подзаписей = %d; ожидалось 2", len(subRecords))
	}

	// Проверяем первую подзапись
	if subRecords[0].Type != 0x10 {
		t.Errorf("Первая подзапись Type = %d; ожидалось 16", subRecords[0].Type)
	}

	if len(subRecords[0].Data) != 3 {
		t.Errorf("Первая подзапись длина = %d; ожидалось 3", len(subRecords[0].Data))
	}

	// Проверяем вторую подзапись
	if subRecords[1].Type != 0x11 {
		t.Errorf("Вторая подзапись Type = %d; ожидалось 17", subRecords[1].Type)
	}

	if len(subRecords[1].Data) != 2 {
		t.Errorf("Вторая подзапись длина = %d; ожидалось 2", len(subRecords[1].Data))
	}

	t.Log("Несколько подзаписей успешно распарсены")
}

// TestGetPositionDataInvalidType проверяет ошибку при неверном типе подзаписи
func TestGetPositionDataInvalidType(t *testing.T) {
	// Подзапись с неверным типом
	subRecord := &SubRecord{
		Type:   SrExtPosData, // Не SR_POS_DATA
		Length: 5,
		Data:   []byte{1, 2, 3, 4, 5},
	}

	_, err := GetPositionData(subRecord)
	if err == nil {
		t.Fatal("Ожидалась ошибка при неверном типе подзаписи")
	}

	t.Logf("Правильно получена ошибка: %v", err)
}

// TestGetPositionDataInsufficientData проверяет ошибку при недостаточных данных
func TestGetPositionDataInsufficientData(t *testing.T) {
	// Подзапись с недостаточным количеством данных
	subRecord := &SubRecord{
		Type:   SrPosData,
		Length: 5, // Слишком мало (минимум 21 байт)
		Data:   []byte{1, 2, 3, 4, 5},
	}

	_, err := GetPositionData(subRecord)
	if err == nil {
		t.Fatal("Ожидалась ошибка при недостаточных данных")
	}

	t.Logf("Правильно получена ошибка: %v", err)
}

// TestGetPositionDataBasic проверяет извлечение данных позиции
func TestGetPositionDataBasic(t *testing.T) {
	// Создаём минимальные данные SR_POS_DATA (21 байт)
	posData := make([]byte, 21)

	// Navigation Time (4 байта) = 1000 секунд с 2010-01-01
	posData[0] = 0xE8 // 1000 в little-endian
	posData[1] = 0x03
	posData[2] = 0x00
	posData[3] = 0x00

	// Latitude (4 байта) - ~45° северной широты
	// lat_raw = 45.0 * 0xFFFFFFFF / 90.0 = 2147483647
	lat := uint32(0x7FFFFFFF) // ~45 градусов
	posData[4] = byte(lat)
	posData[5] = byte(lat >> 8)
	posData[6] = byte(lat >> 16)
	posData[7] = byte(lat >> 24)

	// Longitude (4 байта) - ~90° восточной долготы
	// lon_raw = 90.0 * 0xFFFFFFFF / 180.0 = 2147483647
	lon := uint32(0x7FFFFFFF) // ~90 градусов
	posData[8] = byte(lon)
	posData[9] = byte(lon >> 8)
	posData[10] = byte(lon >> 16)
	posData[11] = byte(lon >> 24)

	// Flags (1 байт) - valid=1, fix=1 (2D), lat/lon valid
	// VLD=1 (бит 0), FIX=1 (бит 1), LAHS=1 (бит 5), LOHS=1 (бит 6)
	posData[12] = 0x63 // 0b01100011

	// Speed (2 байта) - формат: биты 2-15 = скорость*10
	// Скорость 50 км/ч = 500 (0x1F4)
	// SPD = 500 << 2 = 2000 (0x07D0)
	spd := uint16(500 << 2) // 50 км/ч в формате EGTS
	posData[13] = byte(spd)
	posData[14] = byte(spd >> 8)

	// Direction (1 байт) - младшие 8 бит направления
	// Направление 180 градусов = 0xB4 (младшие 8 бит), старший бит в SPD[0]
	posData[15] = 0xB4

	// Odometer (3 байта) - 1000 декаметров = 100000 метров
	// 1000 = 0x03E8
	posData[16] = 0xE8
	posData[17] = 0x03
	posData[18] = 0x00

	// Digital Inputs (1 байт)
	posData[19] = 0x0F

	// Source (1 байт)
	posData[20] = 0x01

	subRecord := &SubRecord{
		Type:   SrPosData,
		Length: 21,
		Data:   posData,
	}

	pos, err := GetPositionData(subRecord)
	if err != nil {
		t.Fatalf("Ошибка извлечения данных позиции: %v", err)
	}

	// Проверяем NavigationTime (1000 секунд после 2010-01-01)
	expectedTime := time.Date(2010, 1, 1, 0, 16, 40, 0, time.UTC) // +1000 секунд
	if !pos.NavigationTime.Equal(expectedTime) {
		t.Errorf("NavigationTime = %v; ожидалось %v", pos.NavigationTime, expectedTime)
	}

	// Широта должна быть около 45 градусов
	if pos.Latitude < 44.9 || pos.Latitude > 45.1 {
		t.Errorf("Latitude = %.6f; ожидалось ~45.0", pos.Latitude)
	}

	// Долгота должна быть около 90 градусов
	if pos.Longitude < 89.9 || pos.Longitude > 90.1 {
		t.Errorf("Longitude = %.6f; ожидалось ~90.0", pos.Longitude)
	}

	// Проверяем флаги
	if !pos.Valid {
		t.Error("Valid должен быть true")
	}

	if pos.Fix != 1 {
		t.Errorf("Fix = %d; ожидалось 1", pos.Fix)
	}

	if !pos.LatitudeValid {
		t.Error("LatitudeValid должен быть true")
	}

	if !pos.LongitudeValid {
		t.Error("LongitudeValid должен быть true")
	}

	// Скорость = (500 << 2) >> 2 / 10 = 500 / 10 = 50 км/ч
	if pos.Speed != 50 {
		t.Errorf("Speed = %d; ожидалось 50", pos.Speed)
	}

	// Направление = 0xB4 = 180 градусов (младшие 8 бит, старший бит = 0)
	if pos.Course != 180 {
		t.Errorf("Course = %d; ожидалось 180", pos.Course)
	}

	// Одометр = 1000 декаметров * 100 = 100000 метров
	if pos.Odometer != 100000 {
		t.Errorf("Odometer = %d; ожидалось 100000", pos.Odometer)
	}

	// Digital Inputs
	if pos.DigitalInputs != 0x0F {
		t.Errorf("DigitalInputs = 0x%02X; ожидалось 0x0F", pos.DigitalInputs)
	}

	// Source
	if pos.Source != 0x01 {
		t.Errorf("Source = 0x%02X; ожидалось 0x01", pos.Source)
	}

	t.Logf("Данные позиции: Lat=%.6f, Lon=%.6f, Speed=%d км/ч, Course=%d°, Odometer=%d м",
		pos.Latitude, pos.Longitude, pos.Speed, pos.Course, pos.Odometer)
	t.Log("Данные позиции успешно извлечены")
}

// TestConstants проверяет константы EGTS
func TestConstants(t *testing.T) {
	if ProtocolVersion != 0x01 {
		t.Errorf("ProtocolVersion = %d; ожидалось 1", ProtocolVersion)
	}

	if MinHeaderLength != 11 {
		t.Errorf("MinHeaderLength = %d; ожидалось 11", MinHeaderLength)
	}

	if SrPosData != 16 {
		t.Errorf("SR_POS_DATA = %d; ожидалось 16", SrPosData)
	}

	t.Log("Константы EGTS корректны")
}
