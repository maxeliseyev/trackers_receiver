// Package egts parses and builds EGTS (GOST R 54619-2011) transport packets.
package egts

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"trackers-receiver/internal/utils"
)

const (
	ProtocolVersion = 0x01

	MinHeaderLength = 11

	// Packet types (PT).
	PtResponse           = 0
	PtAppdata            = 1
	PtSignedAppdata      = 2
	PtAppdataWithRecords = 3

	// Service types (SST/RST).
	EgtsAuthService     = 1
	EgtsTeleDataService = 2
	EgtsCommandsService = 4

	// Subrecord types (SRT). Numbers are scoped to a service, so a subrecord
	// must be interpreted according to the record's service type.
	SrRecordResponse = 0 // any service

	// EGTS_AUTH_SERVICE.
	SrTermIdentity = 1
	SrResultCode   = 9

	// EGTS_TELEDATA_SERVICE.
	SrPosData       = 16
	SrExtPosData    = 17
	SrAdSensorsData = 18
	SrCountersData  = 19
	SrStateData     = 20
	SrAbsAnSensData = 24
	SrAbsCntrData   = 25
	SrLiquidLevel   = 27
	SrPassengers    = 28
)

var (
	ErrHeaderCRC = errors.New("header CRC8 mismatch")
	ErrBodyCRC   = errors.New("frame data CRC16 mismatch")
)

// PacketHeader is the transport layer header. Field comments give the GOST names.
type PacketHeader struct {
	ProtocolVersion  uint8  // PRV
	SecurityKeyID    uint8  // SKID
	Prefix           uint8  // PRF
	Route            uint8  // RTE
	EncryptionAlg    uint8  // ENA
	Compression      uint8  // CMP
	Priority         uint8  // PR
	HeaderLength     uint8  // HL
	HeaderEncoding   uint8  // HE
	FrameDataLength  uint16 // FDL
	PacketID         uint16 // PID
	PacketType       uint8  // PT
	PeerAddress      uint16 // PRA, present only when RTE=1 (not parsed yet)
	RecipientAddress uint16 // RCA, present only when RTE=1 (not parsed yet)
	TimeToLive       uint8  // TTL, present only when RTE=1 (not parsed yet)
	HeaderCheckSum   uint8  // HCS
}

type Packet struct {
	Header *PacketHeader

	// Set only for EGTS_PT_RESPONSE, whose frame data starts with RPID and PR.
	ResponsePacketID uint16
	ProcessingResult uint8

	Records []*Record
	Raw     []byte
}

// Record is a service layer record (SDR).
type Record struct {
	RecordLength         uint16 // RL
	RecordNumber         uint16 // RN
	RecordFlags          uint8  // RFL
	ObjectID             uint32 // OID
	EventID              uint32 // EVID
	Time                 uint32 // TM
	SourceServiceType    uint8  // SST
	RecipientServiceType uint8  // RST
	RecordData           []byte // RD
	SubRecords           []*SubRecord
}

type SubRecord struct {
	Type   uint8  // SRT
	Length uint16 // SRL
	Data   []byte // SRD
}

// ParsePacket parses and validates a complete packet. CRC failures are
// reported as errors wrapping ErrHeaderCRC or ErrBodyCRC.
func ParsePacket(data []byte) (*Packet, error) {
	header, err := parseHeader(data)
	if err != nil {
		return nil, err
	}

	headerWithoutCRC := data[:header.HeaderLength-1]
	if !utils.ValidateCRC8(headerWithoutCRC, header.HeaderCheckSum) {
		return nil, fmt.Errorf("%w: expected 0x%02X, got 0x%02X",
			ErrHeaderCRC, utils.CRC8(headerWithoutCRC), header.HeaderCheckSum)
	}

	size := PacketSize(header.HeaderLength, header.FrameDataLength)
	if len(data) < size {
		return nil, fmt.Errorf("packet truncated: got %d bytes, expected %d", len(data), size)
	}

	frameStart := int(header.HeaderLength)
	frameEnd := frameStart + int(header.FrameDataLength)
	frameData := data[frameStart:frameEnd]
	if len(frameData) > 0 {
		receivedCRC16 := binary.LittleEndian.Uint16(data[frameEnd:])
		if !utils.ValidateCRC16(frameData, receivedCRC16) {
			return nil, fmt.Errorf("%w: expected 0x%04X, got 0x%04X",
				ErrBodyCRC, utils.CRC16(frameData), receivedCRC16)
		}
	}

	packet := &Packet{Header: header, Raw: data}

	if header.PacketType == PtResponse {
		if len(frameData) < 3 {
			return nil, fmt.Errorf("response frame truncated: %d bytes", len(frameData))
		}
		packet.ResponsePacketID = binary.LittleEndian.Uint16(frameData)
		packet.ProcessingResult = frameData[2]
		frameData = frameData[3:]
	}

	packet.Records, err = parseRecords(frameData)
	if err != nil {
		return nil, fmt.Errorf("parse records: %w", err)
	}

	return packet, nil
}

// PacketSize returns the full packet length. SFRCS (the frame data CRC16) is
// present only when there is frame data, so an empty packet is just the header.
func PacketSize(headerLength uint8, frameDataLength uint16) int {
	size := int(headerLength) + int(frameDataLength)
	if frameDataLength > 0 {
		size += 2
	}
	return size
}

func parseHeader(data []byte) (*PacketHeader, error) {
	if len(data) < MinHeaderLength {
		return nil, fmt.Errorf("header truncated: %d bytes, need at least %d", len(data), MinHeaderLength)
	}

	flags := data[2]
	header := &PacketHeader{
		ProtocolVersion: data[0],
		SecurityKeyID:   data[1],
		Prefix:          flags >> 6 & 0x03,
		Route:           flags >> 5 & 0x01,
		EncryptionAlg:   flags >> 3 & 0x03,
		Compression:     flags >> 2 & 0x01,
		Priority:        flags & 0x03,
		HeaderLength:    data[3],
		HeaderEncoding:  data[4],
		FrameDataLength: binary.LittleEndian.Uint16(data[5:]),
		PacketID:        binary.LittleEndian.Uint16(data[7:]),
		PacketType:      data[9],
	}

	if header.HeaderLength < MinHeaderLength || int(header.HeaderLength) > len(data) {
		return nil, fmt.Errorf("invalid header length %d (have %d bytes)", header.HeaderLength, len(data))
	}

	// TODO: when RTE=1 the header carries PRA, RCA and TTL (5 bytes) before HCS.
	// They are skipped for now; HCS is always the last byte of the header.
	header.HeaderCheckSum = data[header.HeaderLength-1]

	return header, nil
}

func parseRecords(data []byte) ([]*Record, error) {
	var records []*Record
	offset := 0

	// RL + RN + RFL + SST + RST is the smallest possible record header.
	for offset+7 <= len(data) {
		record := &Record{
			RecordLength: binary.LittleEndian.Uint16(data[offset:]),
			RecordNumber: binary.LittleEndian.Uint16(data[offset+2:]),
			RecordFlags:  data[offset+4],
		}
		pos := offset + 5

		// RFL: SSOD(7) RSOD(6) GRP(5) RPP(4-3) TMFE(2) EVFE(1) OBFE(0).
		optional := []struct {
			present bool
			dst     *uint32
			name    string
		}{
			{record.RecordFlags&0x01 != 0, &record.ObjectID, "OID"},
			{record.RecordFlags&0x02 != 0, &record.EventID, "EVID"},
			{record.RecordFlags&0x04 != 0, &record.Time, "TM"},
		}
		for _, f := range optional {
			if !f.present {
				continue
			}
			if pos+4 > len(data) {
				return nil, fmt.Errorf("record %d: truncated %s", record.RecordNumber, f.name)
			}
			*f.dst = binary.LittleEndian.Uint32(data[pos:])
			pos += 4
		}

		if pos+2 > len(data) {
			return nil, fmt.Errorf("record %d: truncated SST/RST", record.RecordNumber)
		}
		record.SourceServiceType = data[pos]
		record.RecipientServiceType = data[pos+1]
		pos += 2

		end := pos + int(record.RecordLength)
		if end > len(data) {
			return nil, fmt.Errorf("record %d: length %d exceeds frame (%d bytes left)",
				record.RecordNumber, record.RecordLength, len(data)-pos)
		}
		record.RecordData = data[pos:end]

		subRecords, err := parseSubRecords(record.RecordData)
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", record.RecordNumber, err)
		}
		record.SubRecords = subRecords

		records = append(records, record)
		offset = end
	}

	return records, nil
}

func parseSubRecords(data []byte) ([]*SubRecord, error) {
	var subRecords []*SubRecord
	offset := 0

	for offset+3 <= len(data) {
		sr := &SubRecord{
			Type:   data[offset],
			Length: binary.LittleEndian.Uint16(data[offset+1:]),
		}
		start := offset + 3
		end := start + int(sr.Length)
		if end > len(data) {
			return nil, fmt.Errorf("subrecord type %d at offset %d: length %d exceeds record (%d bytes left)",
				sr.Type, offset, sr.Length, len(data)-start)
		}
		sr.Data = data[start:end]

		subRecords = append(subRecords, sr)
		offset = end
	}

	return subRecords, nil
}

// EGTS timestamps count seconds from 2010-01-01 00:00:00 UTC.
var egtsEpoch = time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)

// uint24 decodes a 3-byte little-endian unsigned integer. GOST has no signed
// 3-byte fields: where a sign exists (ALT) it is carried by a separate flag.
func uint24(data []byte) uint32 {
	return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16
}

func checkSubRecord(sr *SubRecord, want uint8, minLen int, name string) error {
	if sr.Type != want {
		return fmt.Errorf("unexpected subrecord type %d, want %d (%s)", sr.Type, want, name)
	}
	if len(sr.Data) < minLen {
		return fmt.Errorf("%s truncated: %d bytes, need at least %d", name, len(sr.Data), minLen)
	}
	return nil
}

type PositionData struct {
	NavigationTime time.Time
	Latitude       float64 // degrees
	Longitude      float64 // degrees
	Speed          int     // km/h
	Course         int     // degrees
	Odometer       uint32  // metres
	Altitude       *int32  // metres, nil when ALTE=0
	DigitalInputs  uint8
	Source         uint8

	// FLG bits.
	Valid         bool  // VLD
	Fix           uint8 // FIX
	SouthLatitude bool  // LAHS
	WestLongitude bool  // LOHS
	AltitudeValid bool  // ALTE
	Moving        bool  // MV
	ExtraDOP      uint8 // VLD<<7 | LOHS<<6 | LAHS<<5, as the Python receiver encoded it
}

// GetPositionData decodes EGTS_SR_POS_DATA.
//
// Layout: NTM(4) LAT(4) LONG(4) FLG(1) SPD(2) DIR(1) ODM(3) DIN(1) SRC(1) [ALT(3)].
func GetPositionData(sr *SubRecord) (*PositionData, error) {
	if err := checkSubRecord(sr, SrPosData, 21, "SR_POS_DATA"); err != nil {
		return nil, err
	}
	d := sr.Data

	ntm := binary.LittleEndian.Uint32(d[0:])
	lat := binary.LittleEndian.Uint32(d[4:])
	lon := binary.LittleEndian.Uint32(d[8:])
	flags := d[12]
	spd := binary.LittleEndian.Uint16(d[13:])
	dir := d[15]

	pos := &PositionData{
		NavigationTime: egtsEpoch.Add(time.Duration(ntm) * time.Second),
		Latitude:       float64(lat) * 90.0 / 0xFFFFFFFF,
		Longitude:      float64(lon) * 180.0 / 0xFFFFFFFF,
		AltitudeValid:  flags&0x80 != 0,
		WestLongitude:  flags&0x40 != 0,
		SouthLatitude:  flags&0x20 != 0,
		Moving:         flags&0x10 != 0,
		Fix:            flags >> 1 & 0x01,
		Valid:          flags&0x01 != 0,
		DigitalInputs:  d[19],
		Source:         d[20],
	}
	pos.ExtraDOP = flags&0x01<<7 | flags&0x40 | flags&0x20

	// LAT and LONG are unsigned magnitudes; the hemisphere comes from FLG.
	if pos.SouthLatitude {
		pos.Latitude = -pos.Latitude
	}
	if pos.WestLongitude {
		pos.Longitude = -pos.Longitude
	}

	// SPD: DIRH(15) ALTS(14) speed in 0.1 km/h (13-0). DIRH is the 9th bit
	// of the course; DIR holds the lower 8.
	// Rounded half to even, like Python's round() in the previous receiver.
	pos.Speed = int(math.RoundToEven(float64(spd&0x3FFF) / 10.0))
	pos.Course = int(spd>>15)<<8 | int(dir)

	// ODM is in units of 0.1 km.
	pos.Odometer = uint24(d[16:19]) * 100

	if pos.AltitudeValid && len(d) >= 24 {
		alt := int32(uint24(d[21:24]))
		if spd>>14&0x01 != 0 {
			alt = -alt
		}
		pos.Altitude = &alt
	}

	return pos, nil
}

// ExtPosData holds EGTS_SR_EXT_POS_DATA. DOP values are raw (multiplied by 100).
type ExtPosData struct {
	VDOP              *uint16
	HDOP              *uint16
	PDOP              *uint16
	Satellites        *uint8
	NavigationSystems *uint16 // NS, a bit mask of GLONASS, GPS, Galileo etc.
}

// StateData holds EGTS_SR_STATE_DATA. Voltages are in units of 0.1 V.
type StateData struct {
	State              uint8 // ST
	MainPowerVoltage   uint8 // MPSV
	BackupBatVoltage   uint8 // BBV
	InternalBatVoltage uint8 // IBV
	StateFlags         uint8
}

type TermIdentity struct {
	TerminalID     uint32
	HomeDispatcher *uint16
	IMEI           []byte // as transmitted, NUL padding included; nil when absent
	IMSI           []byte
	LanguageCode   string
	NetworkID      []byte
	BufferSize     *uint16
	MSISDN         string
}

type ADSensorsData struct {
	DigitalInputsOutputs map[string]uint8  // "adio_<byte>_<bit>"
	DigitalOutputs       map[string]uint8  // "dout_<bit>"
	AnalogSensors        map[string]uint32 // "ans_<n>"
}

type LiquidLevelData struct {
	SensorFlags       uint8
	ModuleAddress     uint16
	LevelMM           *uint32
	LevelL            *uint32 // the raw value multiplied by 10, as the Python receiver stored it
	NavDataNumber     uint8   // LLSN, the sensor number
	SensorErrorStatus uint8   // LLSEF
}

type CounterData struct {
	CounterNumber uint8
	CounterValue  uint32
	CounterTime   *time.Time // set for counter 105, whose value is a Unix timestamp
}

type AbsAnalogSensorData struct {
	SensorNumber uint8
	SensorValue  uint32
}

// GetExtPosData decodes EGTS_SR_EXT_POS_DATA. Fields cut off by a short
// subrecord are left nil.
func GetExtPosData(sr *SubRecord) (*ExtPosData, error) {
	if err := checkSubRecord(sr, SrExtPosData, 1, "SR_EXT_POS_DATA"); err != nil {
		return nil, err
	}

	extPos := &ExtPosData{}
	r := bytes.NewReader(sr.Data[1:])
	flags := sr.Data[0]

	// Bits 0..4: VFE, HFE, PFE, SFE, NSFE.
	if flags&0x01 != 0 {
		extPos.VDOP = readUint16(r)
	}
	if flags&0x02 != 0 {
		extPos.HDOP = readUint16(r)
	}
	if flags&0x04 != 0 {
		extPos.PDOP = readUint16(r)
	}
	if flags&0x08 != 0 {
		if b, err := r.ReadByte(); err == nil {
			extPos.Satellites = &b
		}
	}
	if flags&0x10 != 0 {
		extPos.NavigationSystems = readUint16(r)
	}

	return extPos, nil
}

func GetStateData(sr *SubRecord) (*StateData, error) {
	if err := checkSubRecord(sr, SrStateData, 5, "SR_STATE_DATA"); err != nil {
		return nil, err
	}
	d := sr.Data
	return &StateData{
		State:              d[0],
		MainPowerVoltage:   d[1],
		BackupBatVoltage:   d[2],
		InternalBatVoltage: d[3],
		StateFlags:         d[4],
	}, nil
}

// GetTermIdentity decodes EGTS_SR_TERM_IDENTITY. Optional fields cut off by a
// short subrecord are left empty.
func GetTermIdentity(sr *SubRecord) (*TermIdentity, error) {
	if err := checkSubRecord(sr, SrTermIdentity, 5, "SR_TERM_IDENTITY"); err != nil {
		return nil, err
	}

	identity := &TermIdentity{TerminalID: binary.LittleEndian.Uint32(sr.Data)}
	flags := sr.Data[4]
	r := bytes.NewReader(sr.Data[5:])

	// FLG: MNE(7) BSE(6) NIDE(5) SSRA(4) LNGCE(3) IMSIE(2) IMEIE(1) HDIDE(0).
	// SSRA selects the authentication mode and has no field.
	if flags&0x01 != 0 {
		identity.HomeDispatcher = readUint16(r)
	}
	if flags&0x02 != 0 {
		identity.IMEI = readBytes(r, 15)
	}
	if flags&0x04 != 0 {
		identity.IMSI = readBytes(r, 16)
	}
	if flags&0x08 != 0 {
		identity.LanguageCode = readString(r, 3)
	}
	if flags&0x20 != 0 {
		identity.NetworkID = readBytes(r, 3)
	}
	if flags&0x40 != 0 {
		identity.BufferSize = readUint16(r)
	}
	if flags&0x80 != 0 {
		identity.MSISDN = readString(r, 15)
	}

	return identity, nil
}

func readUint16(r *bytes.Reader) *uint16 {
	var buf [2]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil
	}
	v := binary.LittleEndian.Uint16(buf[:])
	return &v
}

func readBytes(r *bytes.Reader, n int) []byte {
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil
	}
	return buf
}

// readString reads a fixed-width, NUL-padded string field.
func readString(r *bytes.Reader, n int) string {
	return string(bytes.TrimRight(readBytes(r, n), "\x00"))
}

// GetADSensorsData decodes EGTS_SR_AD_SENSORS_DATA.
//
// Layout: DIOE(1) DOUT(1) ASFE(1), then one ADIO byte per bit set in DIOE,
// then one 3-byte ANS value per bit set in ASFE.
func GetADSensorsData(sr *SubRecord) (*ADSensorsData, error) {
	if err := checkSubRecord(sr, SrAdSensorsData, 3, "SR_AD_SENSORS_DATA"); err != nil {
		return nil, err
	}

	sensors := &ADSensorsData{
		DigitalInputsOutputs: make(map[string]uint8),
		DigitalOutputs:       make(map[string]uint8),
		AnalogSensors:        make(map[string]uint32),
	}

	dioe, dout, asfe := sr.Data[0], sr.Data[1], sr.Data[2]
	r := bytes.NewReader(sr.Data[3:])

	for i := range 8 {
		sensors.DigitalOutputs[fmt.Sprintf("dout_%d", i)] = dout >> i & 0x01
	}

	for i := range 8 {
		if dioe>>i&0x01 == 0 {
			continue
		}
		adio, err := r.ReadByte()
		if err != nil {
			break
		}
		for j := range 8 {
			sensors.DigitalInputsOutputs[fmt.Sprintf("adio_%d_%d", i, j)] = adio >> j & 0x01
		}
	}

	for i := range 8 {
		if asfe>>i&0x01 == 0 {
			continue
		}
		var ans [3]byte
		if _, err := io.ReadFull(r, ans[:]); err != nil {
			break
		}
		sensors.AnalogSensors[fmt.Sprintf("ans_%d", i)] = uint24(ans[:])
	}

	return sensors, nil
}

// GetLiquidLevelData decodes EGTS_SR_LIQUID_LEVEL_SENSOR.
//
// Layout: FLG(1) MADDR(2) LLSD(4, or the rest of the subrecord when RDF=1).
// FLG: LLSEF(6) LLSVU(5-4) RDF(3) LLSN(2-0).
func GetLiquidLevelData(sr *SubRecord) (*LiquidLevelData, error) {
	if err := checkSubRecord(sr, SrLiquidLevel, 3, "SR_LIQUID_LEVEL_SENSOR"); err != nil {
		return nil, err
	}

	liquid := &LiquidLevelData{
		SensorFlags:   sr.Data[0],
		ModuleAddress: binary.LittleEndian.Uint16(sr.Data[1:]),
	}
	flags := liquid.SensorFlags
	liquid.NavDataNumber = flags & 0x07
	liquid.SensorErrorStatus = flags >> 6 & 0x01
	unit := flags >> 4 & 0x03
	llsd := sr.Data[3:]

	var level uint32
	if flags&0x08 == 0 {
		if len(llsd) < 4 {
			return nil, fmt.Errorf("SR_LIQUID_LEVEL_SENSOR truncated: %d bytes of LLSD, need 4", len(llsd))
		}
		level = binary.LittleEndian.Uint32(llsd)
	} else {
		n := len(llsd)
		if n == 0 || n > 8 {
			return nil, fmt.Errorf("SR_LIQUID_LEVEL_SENSOR: %d bytes of raw LLSD", n)
		}
		for i := range min(n, 4) {
			level |= uint32(llsd[i]) << (8 * i)
		}
	}

	switch unit {
	case 0, 1:
		liquid.LevelMM = &level
	case 2:
		litres := level * 10
		liquid.LevelL = &litres
	}

	return liquid, nil
}

func GetCounterData(sr *SubRecord) (*CounterData, error) {
	if err := checkSubRecord(sr, SrAbsCntrData, 4, "SR_ABS_CNTR_DATA"); err != nil {
		return nil, err
	}

	counter := &CounterData{
		CounterNumber: sr.Data[0],
		CounterValue:  uint24(sr.Data[1:4]),
	}
	if counter.CounterNumber == 105 {
		ts := time.Unix(int64(counter.CounterValue), 0)
		counter.CounterTime = &ts
	}

	return counter, nil
}

func GetAbsAnalogSensorData(sr *SubRecord) (*AbsAnalogSensorData, error) {
	if err := checkSubRecord(sr, SrAbsAnSensData, 4, "SR_ABS_AN_SENS_DATA"); err != nil {
		return nil, err
	}
	return &AbsAnalogSensorData{
		SensorNumber: sr.Data[0],
		SensorValue:  uint24(sr.Data[1:4]),
	}, nil
}
