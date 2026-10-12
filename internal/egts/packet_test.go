package egts

import (
	"testing"
	"time"

	"trackers-receiver/internal/utils"
)

func TestParsePacketInsufficientData(t *testing.T) {
	shortData := []byte{0x01, 0x00, 0x00}

	_, err := ParsePacket(shortData)
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestParseHeaderBasic(t *testing.T) {
	// PRV=0x01, SKID=0x00, FLAGS=0x00, HL=0x0B (11 bytes), HE=0x00
	// FDL=0x0005 (5 bytes), PID=0x0001, PT=0x01 (APPDATA)
	headerData := []byte{
		0x01,       // PRV - Protocol Version
		0x00,       // SKID - Security Key ID
		0x00,       // FLAGS (PRF=00, RTE=0, ENA=00, CMP=0, PR=00)
		0x0B,       // HL - Header Length (11 bytes)
		0x00,       // HE - Header Encoding
		0x05, 0x00, // FDL - Frame Data Length (5), little endian
		0x01, 0x00, // PID - Packet ID (1) - little endian
		0x01, // PT - Packet Type (APPDATA)
		0x00, // HCS - Header Check Sum (dummy)
	}

	header, err := parseHeader(headerData)
	if err != nil {
		t.Fatalf("parseHeader failed: %v", err)
	}

	if header.ProtocolVersion != 0x01 {
		t.Errorf("ProtocolVersion = %d; expected 1", header.ProtocolVersion)
	}

	if header.HeaderLength != 0x0B {
		t.Errorf("HeaderLength = %d; expected 11", header.HeaderLength)
	}

	if header.FrameDataLength != 0x0005 {
		t.Errorf("FrameDataLength = %d; expected 5", header.FrameDataLength)
	}

	if header.PacketID != 0x0001 {
		t.Errorf("PacketID = %d; expected 1", header.PacketID)
	}

	if header.PacketType != PtAppdata {
		t.Errorf("PacketType = %d; expected %d", header.PacketType, PtAppdata)
	}
}

func TestParsePacketWithEmptyRecords(t *testing.T) {
	headerWithoutCRC := []byte{
		0x01,       // PRV
		0x00,       // SKID
		0x00,       // FLAGS
		0x0B,       // HL
		0x00,       // HE
		0x00, 0x00, // FDL = 0 (no data)
		0x01, 0x00, // PID
		0x01, // PT
	}

	headerCRC := utils.CRC8(headerWithoutCRC)

	// With FDL = 0 there is no frame data and no SFRCS.
	packetData := append(headerWithoutCRC, headerCRC)

	packet, err := ParsePacket(packetData)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}

	if packet.Header == nil {
		t.Fatal("Header must not be nil")
	}

	if len(packet.Records) != 0 {
		t.Errorf("Records count = %d; expected 0", len(packet.Records))
	}
}

func TestParseSubRecordsEmpty(t *testing.T) {
	emptyData := []byte{}

	subRecords, err := parseSubRecords(emptyData)
	if err != nil {
		t.Fatalf("parseSubRecords failed: %v", err)
	}

	if len(subRecords) != 0 {
		t.Errorf("SubRecords count = %d; expected 0", len(subRecords))
	}
}

func TestParseSubRecordBasic(t *testing.T) {
	// SRT=16 (SR_POS_DATA), SRL=5, SRD=[1,2,3,4,5]
	subRecordData := []byte{
		0x10,       // SRT - Subrecord Type (SR_POS_DATA = 16)
		0x05, 0x00, // SRL - Subrecord Length (5), little endian
		0x01, 0x02, 0x03, 0x04, 0x05, // SRD - data (5 bytes)
	}

	subRecords, err := parseSubRecords(subRecordData)
	if err != nil {
		t.Fatalf("parseSubRecords failed: %v", err)
	}

	if len(subRecords) != 1 {
		t.Fatalf("SubRecords count = %d; expected 1", len(subRecords))
	}

	sr := subRecords[0]

	if sr.Type != SrPosData {
		t.Errorf("Type = %d; expected %d", sr.Type, SrPosData)
	}

	if sr.Length != 5 {
		t.Errorf("Length = %d; expected 5", sr.Length)
	}

	if len(sr.Data) != 5 {
		t.Errorf("Data length = %d; expected 5", len(sr.Data))
	}

	expectedData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	for i, b := range sr.Data {
		if b != expectedData[i] {
			t.Errorf("Data[%d] = %d; expected %d", i, b, expectedData[i])
		}
	}
}

func TestParseMultipleSubRecords(t *testing.T) {
	subRecordsData := []byte{
		0x10,       // SRT
		0x03, 0x00, // SRL = 3
		0xAA, 0xBB, 0xCC, // data

		0x11,       // SRT (SR_EXT_POS_DATA = 17)
		0x02, 0x00, // SRL = 2
		0xDD, 0xEE, // data
	}

	subRecords, err := parseSubRecords(subRecordsData)
	if err != nil {
		t.Fatalf("parseSubRecords failed: %v", err)
	}

	if len(subRecords) != 2 {
		t.Fatalf("SubRecords count = %d; expected 2", len(subRecords))
	}

	if subRecords[0].Type != 0x10 {
		t.Errorf("first Type = %d; expected 16", subRecords[0].Type)
	}

	if len(subRecords[0].Data) != 3 {
		t.Errorf("first Data length = %d; expected 3", len(subRecords[0].Data))
	}

	if subRecords[1].Type != 0x11 {
		t.Errorf("second Type = %d; expected 17", subRecords[1].Type)
	}

	if len(subRecords[1].Data) != 2 {
		t.Errorf("second Data length = %d; expected 2", len(subRecords[1].Data))
	}
}

func TestGetPositionDataInvalidType(t *testing.T) {
	subRecord := &SubRecord{
		Type:   SrExtPosData, // not SR_POS_DATA
		Length: 5,
		Data:   []byte{1, 2, 3, 4, 5},
	}

	_, err := GetPositionData(subRecord)
	if err == nil {
		t.Fatal("expected error for wrong subrecord type")
	}
}

func TestGetPositionDataInsufficientData(t *testing.T) {
	subRecord := &SubRecord{
		Type:   SrPosData,
		Length: 5, // too short (minimum 21 bytes)
		Data:   []byte{1, 2, 3, 4, 5},
	}

	_, err := GetPositionData(subRecord)
	if err == nil {
		t.Fatal("expected error for insufficient data")
	}
}

func TestGetPositionDataBasic(t *testing.T) {
	// Minimal SR_POS_DATA (21 bytes)
	posData := make([]byte, 21)

	// Navigation Time (4 bytes) = 1000 seconds since 2010-01-01
	posData[0] = 0xE8 // 1000, little endian
	posData[1] = 0x03
	posData[2] = 0x00
	posData[3] = 0x00

	// Latitude (4 bytes) - ~45 degrees north
	// lat_raw = 45.0 * 0xFFFFFFFF / 90.0 = 2147483647
	lat := uint32(0x7FFFFFFF) // ~45 degrees
	posData[4] = byte(lat)
	posData[5] = byte(lat >> 8)
	posData[6] = byte(lat >> 16)
	posData[7] = byte(lat >> 24)

	// Longitude (4 bytes) - ~90 degrees east
	// lon_raw = 90.0 * 0xFFFFFFFF / 180.0 = 2147483647
	lon := uint32(0x7FFFFFFF) // ~90 degrees
	posData[8] = byte(lon)
	posData[9] = byte(lon >> 8)
	posData[10] = byte(lon >> 16)
	posData[11] = byte(lon >> 24)

	// Flags: VLD=1 (bit 0), FIX=1 (bit 1), northern/eastern hemisphere
	posData[12] = 0x03

	// SPD: speed in 0.1 km/h in bits 0-13, DIRH and ALTS clear
	spd := uint16(500) // 50 km/h
	posData[13] = byte(spd)
	posData[14] = byte(spd >> 8)

	// Direction (1 byte) - low 8 bits of direction
	// Direction 180 degrees = 0xB4 (low 8 bits), 9th bit is DIRH
	posData[15] = 0xB4

	// Odometer (3 bytes) - 1000 * 0.1 km = 100000 meters
	// 1000 = 0x03E8
	posData[16] = 0xE8
	posData[17] = 0x03
	posData[18] = 0x00

	// Digital Inputs (1 byte)
	posData[19] = 0x0F

	// Source (1 byte)
	posData[20] = 0x01

	subRecord := &SubRecord{
		Type:   SrPosData,
		Length: 21,
		Data:   posData,
	}

	pos, err := GetPositionData(subRecord)
	if err != nil {
		t.Fatalf("GetPositionData failed: %v", err)
	}

	expectedTime := time.Date(2010, 1, 1, 0, 16, 40, 0, time.UTC) // +1000 seconds
	if !pos.NavigationTime.Equal(expectedTime) {
		t.Errorf("NavigationTime = %v; expected %v", pos.NavigationTime, expectedTime)
	}

	if pos.Latitude < 44.9 || pos.Latitude > 45.1 {
		t.Errorf("Latitude = %.6f; expected ~45.0", pos.Latitude)
	}

	if pos.Longitude < 89.9 || pos.Longitude > 90.1 {
		t.Errorf("Longitude = %.6f; expected ~90.0", pos.Longitude)
	}

	if !pos.Valid {
		t.Error("Valid must be true")
	}

	if pos.Fix != 1 {
		t.Errorf("Fix = %d; expected 1", pos.Fix)
	}

	if pos.Speed != 50 {
		t.Errorf("Speed = %d; expected 50", pos.Speed)
	}

	if pos.Course != 180 {
		t.Errorf("Course = %d; expected 180", pos.Course)
	}

	if pos.Odometer != 100000 {
		t.Errorf("Odometer = %d; expected 100000", pos.Odometer)
	}

	if pos.DigitalInputs != 0x0F {
		t.Errorf("DigitalInputs = 0x%02X; expected 0x0F", pos.DigitalInputs)
	}

	if pos.Source != 0x01 {
		t.Errorf("Source = 0x%02X; expected 0x01", pos.Source)
	}

	t.Logf("Position: Lat=%.6f, Lon=%.6f, Speed=%d km/h, Course=%d, Odometer=%d m",
		pos.Latitude, pos.Longitude, pos.Speed, pos.Course, pos.Odometer)
}

func TestConstants(t *testing.T) {
	if ProtocolVersion != 0x01 {
		t.Errorf("ProtocolVersion = %d; expected 1", ProtocolVersion)
	}

	if MinHeaderLength != 11 {
		t.Errorf("MinHeaderLength = %d; expected 11", MinHeaderLength)
	}

	if SrPosData != 16 {
		t.Errorf("SR_POS_DATA = %d; expected 16", SrPosData)
	}
}

func TestParseRecordWithOptionalFields(t *testing.T) {
	// RFL = 0x07 (TMFE=1, EVFE=1, OBFE=1)
	recordData := []byte{
		0x01, 0x00, // Record Length (RL) = 1 byte of data
		0x01, 0x00, // Record Number (RN) = 1
		0x07, // RFL
		// Object ID (4 bytes, OBFE=1)
		0x78, 0x56, 0x34, 0x12, // OID = 0x12345678
		// Event ID (4 bytes, EVFE=1)
		0xEF, 0xCD, 0xAB, 0x89, // EVID = 0x89ABCDEF
		// Time (4 bytes, TMFE=1)
		0x10, 0x00, 0x00, 0x00, // TM = 16 seconds since EGTS epoch
		// SourceServiceType (1 byte)
		0x01, // SST = EGTS_AUTH_SERVICE
		// RecipientServiceType (1 byte)
		0x02, // RST = EGTS_TELEDATA_SERVICE
		// Service Data (1 byte per RL)
		0xFF, // subrecord data
	}

	headerWithoutCRC := []byte{
		0x01,                       // PRV
		0x00,                       // SKID
		0x00,                       // FLAGS
		0x0B,                       // HL
		0x00,                       // HE
		byte(len(recordData)),      // FDL (low byte)
		byte(len(recordData) >> 8), // FDL (high byte)
		0x01, 0x00,                 // PID
		0x01, // PT (EGTS_PT_APPDATA)
	}

	headerCRC := utils.CRC8(headerWithoutCRC)
	packetData := append(headerWithoutCRC, headerCRC)
	packetData = append(packetData, recordData...)

	bodyCRC := utils.CRC16(recordData)
	packetData = append(packetData, byte(bodyCRC), byte(bodyCRC>>8))

	packet, err := ParsePacket(packetData)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}

	if len(packet.Records) != 1 {
		t.Fatalf("Records count = %d; expected 1", len(packet.Records))
	}

	record := packet.Records[0]

	if record.RecordFlags != 0x07 {
		t.Errorf("RecordFlags = 0x%02X; expected 0x07", record.RecordFlags)
	}

	if record.ObjectID != 0x12345678 {
		t.Errorf("ObjectID = 0x%08X; expected 0x12345678", record.ObjectID)
	}

	if record.EventID != 0x89ABCDEF {
		t.Errorf("EventID = 0x%08X; expected 0x89ABCDEF", record.EventID)
	}

	if record.Time != 16 {
		t.Errorf("Time = %d; expected 16", record.Time)
	}
}

func TestParseRecordWithoutOptionalFields(t *testing.T) {
	// RFL = 0b00000000 = 0x00 (all flags clear)
	recordData := []byte{
		0x01, 0x00, // Record Length (RL) = 1 byte of data
		0x02, 0x00, // Record Number (RN) = 2
		0x00, // Record Flags (RFL) = 0x00 (flags clear)
		// no OID, EVID, TM (flags clear)
		// SourceServiceType (1 byte)
		0x01, // SST = EGTS_AUTH_SERVICE
		// RecipientServiceType (1 byte)
		0x02, // RST = EGTS_TELEDATA_SERVICE
		// Service Data (1 byte per RL)
		0xAA, // subrecord data
	}

	headerWithoutCRC := []byte{
		0x01,                       // PRV
		0x00,                       // SKID
		0x00,                       // FLAGS
		0x0B,                       // HL
		0x00,                       // HE
		byte(len(recordData)),      // FDL (low byte)
		byte(len(recordData) >> 8), // FDL (high byte)
		0x01, 0x00,                 // PID
		0x01, // PT (EGTS_PT_APPDATA)
	}

	headerCRC := utils.CRC8(headerWithoutCRC)
	packetData := append(headerWithoutCRC, headerCRC)
	packetData = append(packetData, recordData...)

	bodyCRC := utils.CRC16(recordData)
	packetData = append(packetData, byte(bodyCRC), byte(bodyCRC>>8))

	packet, err := ParsePacket(packetData)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}

	if len(packet.Records) != 1 {
		t.Fatalf("Records count = %d; expected 1", len(packet.Records))
	}

	record := packet.Records[0]

	if record.RecordFlags != 0x00 {
		t.Errorf("RecordFlags = 0x%02X; expected 0x00", record.RecordFlags)
	}

	if record.ObjectID != 0 {
		t.Errorf("ObjectID = 0x%08X; expected 0x00000000", record.ObjectID)
	}

	if record.EventID != 0 {
		t.Errorf("EventID = 0x%08X; expected 0x00000000", record.EventID)
	}

	if record.Time != 0 {
		t.Errorf("Time = %d; expected 0", record.Time)
	}
}

func TestParseRecordPartialOptionalFields(t *testing.T) {
	// RFL = 0x01 (OBFE only)
	recordData := []byte{
		0x01, 0x00, // Record Length (RL) = 1 byte of data
		0x03, 0x00, // Record Number (RN) = 3
		0x01, // RFL
		// Object ID (4 bytes, OBFE=1)
		0x11, 0x22, 0x33, 0x44, // OID = 0x44332211
		// no EVID, TM (flags clear)
		// SourceServiceType (1 byte)
		0x01, // SST = EGTS_AUTH_SERVICE
		// RecipientServiceType (1 byte)
		0x02, // RST = EGTS_TELEDATA_SERVICE
		// Service Data (1 byte per RL)
		0xBB, // subrecord data
	}

	headerWithoutCRC := []byte{
		0x01,                       // PRV
		0x00,                       // SKID
		0x00,                       // FLAGS
		0x0B,                       // HL
		0x00,                       // HE
		byte(len(recordData)),      // FDL (low byte)
		byte(len(recordData) >> 8), // FDL (high byte)
		0x01, 0x00,                 // PID
		0x01, // PT (EGTS_PT_APPDATA)
	}

	headerCRC := utils.CRC8(headerWithoutCRC)
	packetData := append(headerWithoutCRC, headerCRC)
	packetData = append(packetData, recordData...)

	bodyCRC := utils.CRC16(recordData)
	packetData = append(packetData, byte(bodyCRC), byte(bodyCRC>>8))

	packet, err := ParsePacket(packetData)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}

	if len(packet.Records) != 1 {
		t.Fatalf("Records count = %d; expected 1", len(packet.Records))
	}

	record := packet.Records[0]

	if record.RecordFlags != 0x01 {
		t.Errorf("RecordFlags = 0x%02X; expected 0x01", record.RecordFlags)
	}

	if record.ObjectID != 0x44332211 {
		t.Errorf("ObjectID = 0x%08X; expected 0x44332211", record.ObjectID)
	}

	if record.EventID != 0 {
		t.Errorf("EventID = 0x%08X; expected 0x00000000", record.EventID)
	}

	if record.Time != 0 {
		t.Errorf("Time = %d; expected 0", record.Time)
	}
}

func TestGetPositionDataSpeedBits(t *testing.T) {
	data := make([]byte, 24)
	data[12] = 0x80 // ALTE
	// DIRH=1, ALTS=1, speed 1234 (123.4 km/h)
	spd := uint16(1)<<15 | uint16(1)<<14 | 1234
	data[13] = byte(spd)
	data[14] = byte(spd >> 8)
	data[15] = 0x2C // course 300 = 0x100 | 0x2C
	data[21] = 0x96 // altitude 150
	pos, err := GetPositionData(&SubRecord{Type: SrPosData, Length: 24, Data: data})
	if err != nil {
		t.Fatal(err)
	}

	if pos.Speed != 123 {
		t.Errorf("Speed = %d; expected 123", pos.Speed)
	}
	if pos.Course != 300 {
		t.Errorf("Course = %d; expected 300", pos.Course)
	}
	if pos.Altitude == nil || *pos.Altitude != -150 {
		t.Errorf("Altitude = %v; expected -150", pos.Altitude)
	}
}

func TestGetPositionDataHemisphere(t *testing.T) {
	data := make([]byte, 21)
	lat := uint32(0x7FFFFFFF) // ~45 degrees
	lon := uint32(0x7FFFFFFF) // ~90 degrees
	for i := range 4 {
		data[4+i] = byte(lat >> (8 * i))
		data[8+i] = byte(lon >> (8 * i))
	}
	data[12] = 0x60 // LOHS=1, LAHS=1

	pos, err := GetPositionData(&SubRecord{Type: SrPosData, Length: 21, Data: data})
	if err != nil {
		t.Fatal(err)
	}

	if pos.Latitude > -44.9 || pos.Latitude < -45.1 {
		t.Errorf("Latitude = %.6f; expected ~-45.0", pos.Latitude)
	}
	if pos.Longitude > -89.9 || pos.Longitude < -90.1 {
		t.Errorf("Longitude = %.6f; expected ~-90.0", pos.Longitude)
	}
	if pos.ExtraDOP != 0x60 {
		t.Errorf("ExtraDOP = 0x%02X; expected 0x60", pos.ExtraDOP)
	}
}

// 3-byte fields are unsigned: values with the top bit set must not turn negative.
func TestThreeByteFieldsAreUnsigned(t *testing.T) {
	data := make([]byte, 21)
	data[16], data[17], data[18] = 0x00, 0x00, 0x90 // ODM 0x900000 = 943718.4 km
	pos, err := GetPositionData(&SubRecord{Type: SrPosData, Length: 21, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	if pos.Odometer != 0x900000*100 {
		t.Errorf("Odometer = %d; expected %d", pos.Odometer, 0x900000*100)
	}

	counter, err := GetCounterData(&SubRecord{Type: SrAbsCntrData, Length: 4, Data: []byte{1, 0xFF, 0xFF, 0xFF}})
	if err != nil {
		t.Fatal(err)
	}
	if counter.CounterValue != 0xFFFFFF {
		t.Errorf("CounterValue = %d; expected %d", counter.CounterValue, 0xFFFFFF)
	}

	analog, err := GetAbsAnalogSensorData(&SubRecord{Type: SrAbsAnSensData, Length: 4, Data: []byte{2, 0x00, 0x00, 0x80}})
	if err != nil {
		t.Fatal(err)
	}
	if analog.SensorValue != 0x800000 {
		t.Errorf("SensorValue = %d; expected %d", analog.SensorValue, 0x800000)
	}
}

func TestGetLiquidLevelDataFlags(t *testing.T) {
	tests := []struct {
		name      string
		flags     byte
		llsd      []byte
		sensor    uint8
		errorFlag uint8
		mm, l     *uint32
	}{
		{"uncalibrated", 0x05, []byte{100, 0, 0, 0}, 5, 0, ptr(uint32(100)), nil},
		{"litres", 0x20 | 0x01, []byte{100, 0, 0, 0}, 1, 0, nil, ptr(uint32(1000))},
		{"error", 0x40 | 0x02, []byte{0, 0, 0, 0}, 2, 1, ptr(uint32(0)), nil},
		{"raw data", 0x08, []byte{0x34, 0x12}, 0, 0, ptr(uint32(0x1234)), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := append([]byte{tt.flags, 0, 0}, tt.llsd...)
			liquid, err := GetLiquidLevelData(&SubRecord{Type: SrLiquidLevel, Length: uint16(len(data)), Data: data})
			if err != nil {
				t.Fatal(err)
			}
			if liquid.NavDataNumber != tt.sensor || liquid.SensorErrorStatus != tt.errorFlag {
				t.Errorf("LLSN = %d, LLSEF = %d; expected %d and %d", liquid.NavDataNumber, liquid.SensorErrorStatus, tt.sensor, tt.errorFlag)
			}
			if !equalPtr(liquid.LevelMM, tt.mm) || !equalPtr(liquid.LevelL, tt.l) {
				t.Errorf("LevelMM = %v, LevelL = %v; expected %v and %v", deref(liquid.LevelMM), deref(liquid.LevelL), deref(tt.mm), deref(tt.l))
			}
		})
	}
}

func TestGetExtPosData(t *testing.T) {
	// VFE HFE PFE SFE NSFE, VDOP 1.5, HDOP 0.9, PDOP 1.75, 12 satellites, NS GLONASS|GPS
	data := []byte{0x1F, 150, 0, 90, 0, 175, 0, 12, 0x03, 0x00}
	ext, err := GetExtPosData(&SubRecord{Type: SrExtPosData, Length: uint16(len(data)), Data: data})
	if err != nil {
		t.Fatal(err)
	}
	if deref(ext.VDOP) != 150 || deref(ext.HDOP) != 90 || deref(ext.PDOP) != 175 {
		t.Errorf("VDOP/HDOP/PDOP = %d/%d/%d; expected 150/90/175", deref(ext.VDOP), deref(ext.HDOP), deref(ext.PDOP))
	}
	if deref(ext.Satellites) != 12 || deref(ext.NavigationSystems) != 0x03 {
		t.Errorf("SAT = %d, NS = %d; expected 12 and 3", deref(ext.Satellites), deref(ext.NavigationSystems))
	}
}

func ptr[T any](v T) *T { return &v }

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

func equalPtr[T comparable](a, b *T) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
