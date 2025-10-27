package utils

// CRC8 и CRC16 для протокола EGTS
// На основе спецификации ГОСТ Р 54619-2011

// CRC8 таблица для быстрого вычисления
// Полином: 0x31 (x^8 + x^5 + x^4 + 1)
// Начальное значение: 0xFF
// XOR Out: 0x00
var crc8Table [256]uint8

// CRC16 таблица для быстрого вычисления (CRC-16-CCITT)
// Полином: 0x1021 (x^16 + x^12 + x^5 + 1)
// Начальное значение: 0xFFFF
// XOR Out: 0x0000
var crc16Table [256]uint16

// init генерирует таблицы CRC при инициализации пакета
func init() {
	// Генерация CRC8 таблицы
	generateCRC8Table()

	// Генерация CRC16 таблицы
	generateCRC16Table()
}

// generateCRC8Table генерирует таблицу для быстрого вычисления CRC8
func generateCRC8Table() {
	const poly uint8 = 0x31

	for i := 0; i < 256; i++ {
		crc := uint8(i)
		for j := 0; j < 8; j++ {
			if (crc & 0x80) != 0 {
				crc = (crc << 1) ^ poly
			} else {
				crc = crc << 1
			}
		}
		crc8Table[i] = crc
	}
}

// generateCRC16Table генерирует таблицу для быстрого вычисления CRC16
func generateCRC16Table() {
	const poly uint16 = 0x1021

	for i := 0; i < 256; i++ {
		crc := uint16(i) << 8
		for j := 0; j < 8; j++ {
			if (crc & 0x8000) != 0 {
				crc = (crc << 1) ^ poly
			} else {
				crc = crc << 1
			}
		}
		crc16Table[i] = crc
	}
}

// CRC8 вычисляет CRC8 для данных (для заголовка EGTS Transport Layer)
// Полином: 0x31
// Начальное значение: 0xFF
// XOR Out: 0x00
// Тестовое значение: CRC8("123456789") = 0xF7
func CRC8(data []byte) uint8 {
	crc := uint8(0xFF) // Начальное значение

	for _, b := range data {
		crc = crc8Table[crc^b]
	}

	return crc
}

// CRC16 вычисляет CRC16-CCITT для данных (для тела пакета EGTS)
// Полином: 0x1021
// Начальное значение: 0xFFFF
// XOR Out: 0x0000
// Тестовое значение: CRC16("123456789") = 0x29B1
func CRC16(data []byte) uint16 {
	crc := uint16(0xFFFF) // Начальное значение

	for _, b := range data {
		crc = (crc << 8) ^ crc16Table[((crc>>8)^uint16(b))&0xFF]
	}

	return crc
}

// ValidateCRC8 проверяет CRC8 заголовка EGTS пакета
// data - данные заголовка БЕЗ последнего байта (CRC)
// expected - ожидаемое значение CRC (последний байт заголовка)
func ValidateCRC8(data []byte, expected uint8) bool {
	calculated := CRC8(data)
	return calculated == expected
}

// ValidateCRC16 проверяет CRC16 тела EGTS пакета
// data - данные тела БЕЗ последних 2 байт (CRC)
// expected - ожидаемое значение CRC (последние 2 байта тела)
func ValidateCRC16(data []byte, expected uint16) bool {
	calculated := CRC16(data)
	return calculated == expected
}
