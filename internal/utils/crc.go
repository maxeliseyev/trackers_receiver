// Package utils implements the checksums used by EGTS (GOST R 54619-2011).
package utils

// CRC-8: poly 0x31, init 0xFF, no reflection, xorout 0x00. Check("123456789") = 0xF7.
var crc8Table [256]uint8

// CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection, xorout 0x0000. Check("123456789") = 0x29B1.
var crc16Table [256]uint16

func init() {
	for i := range 256 {
		c8 := uint8(i)
		c16 := uint16(i) << 8
		for range 8 {
			if c8&0x80 != 0 {
				c8 = c8<<1 ^ 0x31
			} else {
				c8 <<= 1
			}
			if c16&0x8000 != 0 {
				c16 = c16<<1 ^ 0x1021
			} else {
				c16 <<= 1
			}
		}
		crc8Table[i] = c8
		crc16Table[i] = c16
	}
}

// CRC8 computes the EGTS transport header checksum (HCS).
func CRC8(data []byte) uint8 {
	crc := uint8(0xFF)
	for _, b := range data {
		crc = crc8Table[crc^b]
	}
	return crc
}

// CRC16 computes the EGTS frame data checksum (SFRCS).
func CRC16(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc = crc<<8 ^ crc16Table[byte(crc>>8)^b]
	}
	return crc
}

func ValidateCRC8(data []byte, expected uint8) bool {
	return CRC8(data) == expected
}

func ValidateCRC16(data []byte, expected uint16) bool {
	return CRC16(data) == expected
}
