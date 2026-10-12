package parity

import (
	"encoding/binary"
	"encoding/hex"

	"trackers-receiver/internal/egts"
	"trackers-receiver/internal/utils"
)

// syntheticCases cover every subrecord both receivers store. They avoid the
// inputs on which the receivers differ on purpose (see README).
func syntheticCases() []parityCase {
	identity := le(uint32(42), byte(0x06)) // TID, IMSIE | IMEIE
	identity = append(identity, "861230043907626"...)
	identity = append(identity, "250990123456789\x00"...)

	adSensors := []byte{
		0x01, 0x81, 0x05, // DIOE, DOUT, ASFE
		0xA5,             // ADIO 0
		0x10, 0x20, 0x30, // ANS 0
		0xFF, 0xFF, 0xFF, // ANS 2
	}

	teledata := packet(2,
		record(1, 1000,
			pos(500000000, 0x93, 1<<15|1<<14|125, 0x10, 0x900000, 0x05, 150),
			sub(egts.SrExtPosData, le(byte(0x1F), uint16(150), uint16(90), uint16(175), byte(12), uint16(3))),
			sub(egts.SrStateData, []byte{2, 120, 40, 41, 0x01}),
			sub(egts.SrLiquidLevel, le(byte(0x61), uint16(0), uint32(1234))), // sensor 1, litres, error
			sub(egts.SrLiquidLevel, le(byte(0x02), uint16(7), uint32(300))),  // sensor 2, uncalibrated
			sub(egts.SrAdSensorsData, adSensors),
			sub(egts.SrAbsAnSensData, []byte{1, 0x01, 0x00, 0x80}),
			sub(egts.SrAbsAnSensData, []byte{3, 7, 0, 0}),
			sub(egts.SrAbsCntrData, []byte{100, 5, 0, 0}),
			sub(egts.SrAbsCntrData, append([]byte{105}, le24(1700000000&0xFFFFFF)...)),
			sub(egts.SrAbsCntrData, []byte{7, 99, 0, 0}),
			sub(egts.SrAbsCntrData, []byte{110, 0x09, 0x03, 0}),
			// A second, earlier position in the same record.
			pos(499999990, 0x03, 600, 200, 1000, 0, 0),
			sub(egts.SrExtPosData, le(byte(0x02), uint16(250))),
		),
		record(2, 1000, pos(500000010, 0x01, 135, 0, 0, 0, 0)),
	)

	return []parityCase{
		{
			Name: "identified terminal",
			Packets: []string{
				packet(1, authRecord(1, sub(egts.SrTermIdentity, identity))),
				teledata,
			},
		},
		{
			Name:    "no identity and no OID",
			Packets: []string{packet(7, record(1, 0, pos(500000000, 0x01, 1000, 90, 5, 1, 0)))},
		},
	}
}

// pos builds EGTS_SR_POS_DATA at 55.75 N 37.62 E; ALT is appended when FLG has ALTE.
func pos(ntm uint32, flg byte, spd uint16, dir byte, odm uint32, din byte, alt uint32) []byte {
	lat, lon := 55.75, 37.62
	d := le(ntm, uint32(lat/90*0xFFFFFFFF), uint32(lon/180*0xFFFFFFFF), flg, spd, dir)
	d = append(d, le24(odm)...)
	d = append(d, din, 0)
	if flg&0x80 != 0 {
		d = append(d, le24(alt)...)
	}
	return sub(egts.SrPosData, d)
}

func sub(srt byte, data []byte) []byte {
	return append(le(srt, uint16(len(data))), data...)
}

// record builds an EGTS_TELEDATA_SERVICE record, with OID when oid is not 0.
func record(rn uint16, oid uint32, subRecords ...[]byte) []byte {
	return serviceRecord(rn, oid, egts.EgtsTeleDataService, subRecords...)
}

func authRecord(rn uint16, subRecords ...[]byte) []byte {
	return serviceRecord(rn, 0, egts.EgtsAuthService, subRecords...)
}

func serviceRecord(rn uint16, oid uint32, service byte, subRecords ...[]byte) []byte {
	var rd []byte
	for _, sr := range subRecords {
		rd = append(rd, sr...)
	}
	r := le(uint16(len(rd)), rn)
	if oid != 0 {
		r = append(r, 0x01)
		r = append(r, le(oid)...)
	} else {
		r = append(r, 0x00)
	}
	r = append(r, service, service)
	return append(r, rd...)
}

// packet builds an EGTS_PT_APPDATA and returns it hex-encoded.
func packet(pid uint16, records ...[]byte) string {
	var frame []byte
	for _, r := range records {
		frame = append(frame, r...)
	}
	h := le(byte(egts.ProtocolVersion), byte(0), byte(0), byte(egts.MinHeaderLength), byte(0),
		uint16(len(frame)), pid, byte(egts.PtAppdata))
	p := append(h, utils.CRC8(h))
	p = append(p, frame...)
	p = append(p, le(utils.CRC16(frame))...)
	return hex.EncodeToString(p)
}

// le encodes fixed-size values in little-endian order.
func le(values ...any) []byte {
	var b []byte
	for _, v := range values {
		b, _ = binary.Append(b, binary.LittleEndian, v)
	}
	return b
}

func le24(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16)}
}
