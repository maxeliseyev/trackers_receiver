package utils

import (
	"testing"
)

func TestCRC8(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected uint8
	}{
		{
			name:     "Test vector: 123456789",
			data:     []byte("123456789"),
			expected: 0xF7,
		},
		{
			name:     "Empty data",
			data:     []byte{},
			expected: 0xFF, // initial value
		},
		{
			name:     "EGTS header example (no CRC)",
			data:     []byte{0x01, 0x00, 0x00, 0x0B, 0x00, 0x03, 0x00, 0x01, 0x00, 0x01},
			expected: 0, // no known reference value; result is only logged
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CRC8(tt.data)
			if tt.name != "EGTS header example (no CRC)" {
				if result != tt.expected {
					t.Errorf("CRC8(%v) = 0x%02X, expected 0x%02X", tt.data, result, tt.expected)
				}
			} else {
				t.Logf("CRC8 for EGTS header example: 0x%02X", result)
			}
		})
	}
}

func TestCRC16(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected uint16
	}{
		{
			name:     "Test vector: 123456789",
			data:     []byte("123456789"),
			expected: 0x29B1,
		},
		{
			name:     "Empty data",
			data:     []byte{},
			expected: 0xFFFF, // initial value
		},
		{
			name:     "EGTS packet body example (no CRC)",
			data:     []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
			expected: 0, // no known reference value; result is only logged
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CRC16(tt.data)
			if tt.name != "EGTS packet body example (no CRC)" {
				if result != tt.expected {
					t.Errorf("CRC16(%v) = 0x%04X, expected 0x%04X", tt.data, result, tt.expected)
				}
			} else {
				t.Logf("CRC16 for EGTS packet body example: 0x%04X", result)
			}
		})
	}
}

func TestValidateCRC8(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected uint8
		valid    bool
	}{
		{
			name:     "Valid CRC8",
			data:     []byte("123456789"),
			expected: 0xF7,
			valid:    true,
		},
		{
			name:     "Invalid CRC8",
			data:     []byte("123456789"),
			expected: 0x00,
			valid:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateCRC8(tt.data, tt.expected)
			if result != tt.valid {
				t.Errorf("ValidateCRC8() = %v, expected %v", result, tt.valid)
			}
		})
	}
}

func TestValidateCRC16(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected uint16
		valid    bool
	}{
		{
			name:     "Valid CRC16",
			data:     []byte("123456789"),
			expected: 0x29B1,
			valid:    true,
		},
		{
			name:     "Invalid CRC16",
			data:     []byte("123456789"),
			expected: 0x0000,
			valid:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateCRC16(tt.data, tt.expected)
			if result != tt.valid {
				t.Errorf("ValidateCRC16() = %v, expected %v", result, tt.valid)
			}
		})
	}
}

func BenchmarkCRC8(b *testing.B) {
	data := []byte("123456789")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CRC8(data)
	}
}

func BenchmarkCRC16(b *testing.B) {
	data := []byte("123456789")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CRC16(data)
	}
}

func BenchmarkCRC8LargeData(b *testing.B) {
	data := make([]byte, 1024) // 1KB
	for i := range data {
		data[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CRC8(data)
	}
}

func BenchmarkCRC16LargeData(b *testing.B) {
	data := make([]byte, 1024) // 1KB
	for i := range data {
		data[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CRC16(data)
	}
}
