package egts

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// Константы EGTS протокола
const (
	// Версия протокола EGTS
	ProtocolVersion = 0x01

	// Минимальная длина заголовка пакета
	MinHeaderLength = 11

	// Типы пакетов EGTS
	PtResponse           = 0  // EGTS_PT_RESPONSE - подтверждение
	PtAppdata            = 1  // EGTS_PT_APPDATA - данные приложения
	PtSignedAppdata      = 2  // EGTS_PT_SIGNED_APPDATA - подписанные данные
	PtAppdataWithRecords = 3  // EGTS_PT_APPDATA_WITH_RECORDS - данные с записями

	// Сервисы EGTS
	EgtsAuthService     = 1  // EGTS_AUTH_SERVICE - авторизация
	EgtsTeleDataService = 2  // EGTS_TELEDATA_SERVICE - телематические данные
	EgtsCommandsService = 4  // EGTS_COMMANDS_SERVICE - команды

	// Типы подзаписей (subrecords) для телематических данных
	SrPosData        = 16 // EGTS_SR_POS_DATA - данные о позиции
	SrExtPosData     = 17 // EGTS_SR_EXT_POS_DATA - расширенные данные о позиции
	SrAdSensorsData  = 18 // EGTS_SR_AD_SENSORS_DATA - данные аналоговых датчиков
	SrCountersData   = 19 // EGTS_SR_COUNTERS_DATA - данные счётчиков
	SrStateData      = 20 // EGTS_SR_STATE_DATA - данные состояния
	SrLiquidLevel    = 27 // EGTS_SR_LIQUID_LEVEL_SENSOR - уровень жидкости
	SrPassengers     = 28 // EGTS_SR_PASSENGERS - количество пассажиров
)

// PacketHeader представляет заголовок EGTS пакета
// Согласно спецификации EGTS Transport Layer
type PacketHeader struct {
	ProtocolVersion  uint8  // PRV - версия протокола (должна быть 0x01)
	SecurityKeyID    uint8  // SKID - идентификатор ключа безопасности
	Prefix           uint8  // PREFIX - префикс (не используется, всегда 0x00)
	Route            uint8  // ROUTE - маршрутизация (не используется, всегда 0x00)
	EncryptionAlg    uint8  // EA - алгоритм шифрования
	Compression      uint8  // CMP - сжатие
	Priority         uint8  // PR - приоритет
	HeaderLength     uint8  // HL - длина заголовка в байтах
	HeaderEncoding   uint8  // HE - кодировка заголовка
	FrameDataLength  uint16 // FDL - длина данных фрейма
	PacketID         uint16 // PID - идентификатор пакета
	PacketType       uint8  // PT - тип пакета
	PeerAddress      uint16 // PRA - адрес получателя (опционально)
	RecipientAddress uint16 // RCA - адрес отправителя (опционально)
	TimeToLive       uint8  // TTL - время жизни (опционально)
	HeaderCheckSum   uint8  // HCS - контрольная сумма заголовка
}

// Packet представляет полный EGTS пакет
type Packet struct {
	Header  *PacketHeader
	Records []*Record // Записи в пакете
	Raw     []byte    // Сырые данные пакета
}

// Record представляет запись EGTS (Service Frame Data Record)
type Record struct {
	RecordLength       uint16      // RL - длина данных записи
	RecordNumber       uint16      // RN - номер записи
	RecordFlags        uint8       // RFL - флаги записи
	ObjectID           uint32      // OID - идентификатор объекта (опционально)
	EventID            uint32      // EVID - идентификатор события (опционально)
	Time               uint32      // TM - время (опционально)
	SourceServiceType  uint8       // SST - тип сервиса источника
	RecipientServiceType uint8     // RST - тип сервиса получателя
	RecordData         []byte      // RD - данные записи
	SubRecords         []*SubRecord // Подзаписи
}

// SubRecord представляет подзапись EGTS
type SubRecord struct {
	Type   uint8  // SRT - тип подзаписи
	Length uint16 // SRL - длина данных подзаписи
	Data   []byte // SRD - данные подзаписи
}

// ParsePacket разбирает EGTS пакет из байтового массива
func ParsePacket(data []byte) (*Packet, error) {
	if len(data) < MinHeaderLength {
		return nil, fmt.Errorf("недостаточно данных для заголовка: %d байт (минимум %d)", len(data), MinHeaderLength)
	}

	packet := &Packet{
		Raw: data,
	}

	// Парсим заголовок
	header, err := parseHeader(data)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга заголовка: %w", err)
	}
	packet.Header = header

	// Парсим записи
	recordsData := data[header.HeaderLength : uint16(header.HeaderLength)+header.FrameDataLength]
	records, err := parseRecords(recordsData)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга записей: %w", err)
	}
	packet.Records = records

	return packet, nil
}

// parseHeader разбирает заголовок EGTS пакета
func parseHeader(data []byte) (*PacketHeader, error) {
	reader := bytes.NewReader(data)

	header := &PacketHeader{}

	// Читаем базовые поля заголовка
	if err := binary.Read(reader, binary.LittleEndian, &header.ProtocolVersion); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.LittleEndian, &header.SecurityKeyID); err != nil {
		return nil, err
	}

	// Читаем флаги (1 байт объединяет несколько полей)
	var flags uint8
	if err := binary.Read(reader, binary.LittleEndian, &flags); err != nil {
		return nil, err
	}

	// Разбираем флаги
	header.Prefix = (flags >> 6) & 0x03
	header.Route = (flags >> 5) & 0x01
	header.EncryptionAlg = (flags >> 3) & 0x03
	header.Compression = (flags >> 2) & 0x01
	header.Priority = flags & 0x03

	if err := binary.Read(reader, binary.LittleEndian, &header.HeaderLength); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.LittleEndian, &header.HeaderEncoding); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.LittleEndian, &header.FrameDataLength); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.LittleEndian, &header.PacketID); err != nil {
		return nil, err
	}

	if err := binary.Read(reader, binary.LittleEndian, &header.PacketType); err != nil {
		return nil, err
	}

	// Опциональные поля зависят от флагов
	// Пока пропускаем их для простоты

	// Контрольная сумма заголовка (последний байт заголовка)
	if int(header.HeaderLength) <= len(data) {
		header.HeaderCheckSum = data[header.HeaderLength-1]
	}

	return header, nil
}

// parseRecords разбирает записи из данных фрейма
func parseRecords(data []byte) ([]*Record, error) {
	var records []*Record
	offset := 0

	for offset < len(data) {
		if offset+7 > len(data) { // Минимальный размер записи
			break
		}

		record := &Record{}
		reader := bytes.NewReader(data[offset:])

		// RecordLength (2 байта)
		if err := binary.Read(reader, binary.LittleEndian, &record.RecordLength); err != nil {
			return nil, err
		}

		// RecordNumber (2 байта)
		if err := binary.Read(reader, binary.LittleEndian, &record.RecordNumber); err != nil {
			return nil, err
		}

		// RecordFlags (1 байт)
		if err := binary.Read(reader, binary.LittleEndian, &record.RecordFlags); err != nil {
			return nil, err
		}

		// Пропускаем разбор опциональных полей для простоты

		// SourceServiceType (1 байт)
		if err := binary.Read(reader, binary.LittleEndian, &record.SourceServiceType); err != nil {
			return nil, err
		}

		// RecipientServiceType (1 байт)
		if err := binary.Read(reader, binary.LittleEndian, &record.RecipientServiceType); err != nil {
			return nil, err
		}

		// RecordData
		headerSize := 7 // Минимальный размер без опциональных полей
		dataStart := offset + headerSize
		dataEnd := dataStart + int(record.RecordLength)

		if dataEnd > len(data) {
			return nil, fmt.Errorf("некорректная длина записи")
		}

		record.RecordData = data[dataStart:dataEnd]

		// Парсим подзаписи
		subRecords, err := parseSubRecords(record.RecordData)
		if err != nil {
			return nil, fmt.Errorf("ошибка парсинга подзаписей: %w", err)
		}
		record.SubRecords = subRecords

		records = append(records, record)
		offset = dataEnd
	}

	return records, nil
}

// parseSubRecords разбирает подзаписи из данных записи
func parseSubRecords(data []byte) ([]*SubRecord, error) {
	var subRecords []*SubRecord
	offset := 0

	for offset < len(data) {
		if offset+3 > len(data) { // Минимальный размер подзаписи
			break
		}

		subRecord := &SubRecord{}
		reader := bytes.NewReader(data[offset:])

		// Type (1 байт)
		if err := binary.Read(reader, binary.LittleEndian, &subRecord.Type); err != nil {
			return nil, err
		}

		// Length (2 байта)
		if err := binary.Read(reader, binary.LittleEndian, &subRecord.Length); err != nil {
			return nil, err
		}

		// Data
		dataStart := offset + 3
		dataEnd := dataStart + int(subRecord.Length)

		if dataEnd > len(data) {
			return nil, fmt.Errorf("некорректная длина подзаписи")
		}

		subRecord.Data = data[dataStart:dataEnd]

		subRecords = append(subRecords, subRecord)
		offset = dataEnd
	}

	return subRecords, nil
}

// EGTS эпоха времени (2010-01-01 00:00:00 UTC)
var egtsEpoch = time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)

// convert3BytesToInt конвертирует 3 байта (little-endian) в int32
func convert3BytesToInt(data []byte) int32 {
	if len(data) != 3 {
		return 0
	}
	// Расширяем до 4 байт с учетом знака
	val := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16
	// Проверяем знаковый бит (23-й бит)
	if val&0x800000 != 0 {
		// Отрицательное число - расширяем знак
		val |= 0xFF000000
	}
	return int32(val)
}

// GetPositionData извлекает данные о позиции из подзаписи SR_POS_DATA
func GetPositionData(subRecord *SubRecord) (*PositionData, error) {
	if subRecord.Type != SrPosData {
		return nil, fmt.Errorf("неверный тип подзаписи: %d (ожидался %d)", subRecord.Type, SrPosData)
	}

	if len(subRecord.Data) < 21 { // Минимальный размер SR_POS_DATA
		return nil, fmt.Errorf("недостаточно данных для SR_POS_DATA: %d байт (минимум 21)", len(subRecord.Data))
	}

	pos := &PositionData{}
	reader := bytes.NewReader(subRecord.Data)

	// 1. Navigation Time (4 байта) - секунды с 2010-01-01 00:00:00 UTC
	var ntm uint32
	binary.Read(reader, binary.LittleEndian, &ntm)
	pos.NavigationTime = egtsEpoch.Add(time.Duration(ntm) * time.Second)

	// 2. Latitude (4 байта)
	var lat uint32
	binary.Read(reader, binary.LittleEndian, &lat)
	pos.Latitude = float64(lat) * 90.0 / 0xFFFFFFFF

	// 3. Longitude (4 байта)
	var lon uint32
	binary.Read(reader, binary.LittleEndian, &lon)
	pos.Longitude = float64(lon) * 180.0 / 0xFFFFFFFF

	// 4. Flags (1 байт) - битовые флаги
	var flags uint8
	binary.Read(reader, binary.LittleEndian, &flags)

	// Разбираем флаги (биты 7-0):
	// Бит 7 (ALTH): наличие высоты
	// Бит 6 (LOHS): достоверность долготы
	// Бит 5 (LAHS): достоверность широты
	// Бит 4 (MV): движение
	// Бит 3 (BB): от резервной батареи
	// Бит 2 (CS): система координат
	// Бит 1 (FIX): метод определения (2D/3D)
	// Бит 0 (VLD): валидность данных
	pos.AltitudeValid = (flags & 0x80) != 0  // бит 7
	pos.LongitudeValid = (flags & 0x40) != 0 // бит 6
	pos.LatitudeValid = (flags & 0x20) != 0  // бит 5
	pos.Moving = (flags & 0x10) != 0         // бит 4
	pos.Fix = (flags >> 1) & 0x01            // бит 1
	pos.Valid = (flags & 0x01) != 0          // бит 0

	// Вычисляем extra_dop (для совместимости с Python)
	// extra_dop = VLD(бит0) + LOHS(бит1) + LAHS(бит2) + 00000
	vld := uint8(0)
	if pos.Valid {
		vld = 1
	}
	lohs := uint8(0)
	if pos.LongitudeValid {
		lohs = 1
	}
	lahs := uint8(0)
	if pos.LatitudeValid {
		lahs = 1
	}
	pos.ExtraDOP = (vld << 7) | (lohs << 6) | (lahs << 5)

	// 5. Speed (2 байта) - НЕ вся скорость!
	// Биты 15-14: не используются в скорости
	// Бит 1: знак высоты (если высота присутствует)
	// Бит 0: старший бит направления (9-й бит)
	// Биты 2-15: скорость * 10 (в десятых км/ч)
	var spd uint16
	binary.Read(reader, binary.LittleEndian, &spd)

	// Извлекаем скорость из битов 2-15
	speedRaw := (spd >> 2) & 0x3FFF // 14 бит
	pos.Speed = int(math.Round(float64(speedRaw) / 10.0))

	// 6. Direction (1 байт) - младшие 8 бит направления
	var dir uint8
	binary.Read(reader, binary.LittleEndian, &dir)

	// Курс = 9 бит: старший бит из SPD[0] + 8 бит DIR
	courseHiBit := (spd & 0x01) << 8 // Бит 0 из SPD -> бит 8 курса
	pos.Course = int(courseHiBit | uint16(dir))

	// 7. Odometer (3 байта) - в декаметрах, нужно * 100 для метров
	var odmBytes [3]byte
	reader.Read(odmBytes[:])
	odmRaw := convert3BytesToInt(odmBytes[:])
	pos.Odometer = uint32(odmRaw) * 100 // декаметры -> метры

	// 8. Digital Inputs (1 байт)
	binary.Read(reader, binary.LittleEndian, &pos.DigitalInputs)

	// 9. Source (1 байт)
	binary.Read(reader, binary.LittleEndian, &pos.Source)

	// 10. Altitude (3 байта, опционально) - идет ПОСЛЕ основных 21 байта
	if pos.AltitudeValid && len(subRecord.Data) >= 24 {
		var altBytes [3]byte
		copy(altBytes[:], subRecord.Data[21:24])
		altRaw := convert3BytesToInt(altBytes[:])

		// Знак высоты берется из бита 1 SPD
		altSign := (spd >> 1) & 0x01
		if altSign == 0 {
			// Положительная высота
			pos.Altitude = &altRaw
		} else {
			// Отрицательная высота
			negAlt := -altRaw
			pos.Altitude = &negAlt
		}
	}

	return pos, nil
}

// PositionData содержит данные о позиции из EGTS SR_POS_DATA
type PositionData struct {
	NavigationTime time.Time // Время навигационных данных (с эпохи 2010-01-01)
	Latitude       float64   // Широта в градусах
	Longitude      float64   // Долгота в градусах
	Speed          int       // Скорость в км/ч (округленная)
	Course         int       // Курс в градусах (0-511, 9 бит)
	Odometer       uint32    // Одометр в метрах
	Altitude       *int32    // Высота в дециметрах (опционально)
	DigitalInputs  uint8     // Цифровые входы (DIN)
	Source         uint8     // Источник данных (SRC)

	// Флаги
	Valid          bool  // Валидность данных GPS (VLD)
	Fix            uint8 // Тип фиксации (2D/3D)
	LatitudeValid  bool  // Достоверность широты (LAHS)
	LongitudeValid bool  // Достоверность долготы (LOHS)
	AltitudeValid  bool  // Наличие высоты (ALTH)
	Moving         bool  // Движение (MV)
	ExtraDOP       uint8 // Extra DOP для совместимости
}
