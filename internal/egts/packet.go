package egts

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"trackers-receiver/internal/utils"
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

	// Типы подзаписей AUTH_SERVICE
	SrRecordResponse = 0 // EGTS_SR_RECORD_RESPONSE - ответ на запись
	SrTermIdentity   = 1 // EGTS_SR_TERM_IDENTITY - идентификация терминала

	// Типы подзаписей (subrecords) для телематических данных
	SrPosData         = 16 // EGTS_SR_POS_DATA - данные о позиции
	SrExtPosData      = 17 // EGTS_SR_EXT_POS_DATA - расширенные данные о позиции
	SrAdSensorsData   = 18 // EGTS_SR_AD_SENSORS_DATA - данные аналоговых датчиков
	SrCountersData    = 19 // EGTS_SR_COUNTERS_DATA - данные счётчиков
	SrStateData       = 20 // EGTS_SR_STATE_DATA - данные состояния
	SrAbsAnSensData   = 24 // EGTS_SR_ABS_AN_SENS_DATA - абсолютные аналоговые датчики
	SrAbsCntrData     = 25 // EGTS_SR_ABS_CNTR_DATA - абсолютные счетчики
	SrLiquidLevel     = 27 // EGTS_SR_LIQUID_LEVEL_SENSOR - уровень жидкости
	SrPassengers      = 28 // EGTS_SR_PASSENGERS - количество пассажиров
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

	// Валидация CRC8 заголовка
	// Заголовок без последнего байта (CRC)
	headerWithoutCRC := data[:header.HeaderLength-1]
	if !utils.ValidateCRC8(headerWithoutCRC, header.HeaderCheckSum) {
		return nil, fmt.Errorf("неверная контрольная сумма CRC8 заголовка: ожидалось 0x%02X, получено 0x%02X",
			utils.CRC8(headerWithoutCRC), header.HeaderCheckSum)
	}

	// Проверяем что достаточно данных для тела пакета
	expectedLength := uint16(header.HeaderLength) + header.FrameDataLength + 2 // +2 для CRC16
	if len(data) < int(expectedLength) {
		return nil, fmt.Errorf("недостаточно данных для пакета: получено %d байт, ожидалось %d", len(data), expectedLength)
	}

	// Валидация CRC16 тела пакета
	// Тело без последних 2 байт (CRC16)
	frameData := data[header.HeaderLength : uint16(header.HeaderLength)+header.FrameDataLength]
	crc16Offset := uint16(header.HeaderLength) + header.FrameDataLength
	receivedCRC16 := binary.LittleEndian.Uint16(data[crc16Offset : crc16Offset+2])

	if !utils.ValidateCRC16(frameData, receivedCRC16) {
		return nil, fmt.Errorf("неверная контрольная сумма CRC16 тела: ожидалось 0x%04X, получено 0x%04X",
			utils.CRC16(frameData), receivedCRC16)
	}

	// Парсим записи
	records, err := parseRecords(frameData)
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

	// TODO: Опциональные поля Transport Layer Header (зависят от флага Route)
	// Согласно спецификации EGTS (ГОСТ Р 54619-2011), если флаг RTE (Route) установлен,
	// то после базовых полей заголовка следуют дополнительные поля:
	// - PRA (2 байта) - Peer Address (адрес получателя)
	// - RCA (2 байта) - Recipient Address (адрес отправителя)
	// - TTL (1 байт) - Time To Live (время жизни пакета)
	//
	// Пример из Python кода (oldproject/src/protocols/egts/__init__.py:187-193):
	//   if self.tl_rte:
	//       self.tl_pra, self.tl_rca, self.tl_ttl = unpack('<HHB', data[:5])
	//       cur_idx = 5
	//
	// Для реализации нужно:
	// 1. Проверить флаг Route (header.Route == 1)
	// 2. Прочитать 5 дополнительных байт (PRA, RCA, TTL)
	// 3. Учесть эти байты при вычислении позиции HCS (Header CheckSum)
	// 4. Обновить структуру PacketHeader с корректными значениями
	//
	// ВАЖНО: Эти поля должны быть прочитаны ПЕРЕД контрольной суммой заголовка (HCS),
	// так как HCS находится на позиции (HeaderLength - 1), и длина заголовка увеличивается
	// при наличии этих опциональных полей.
	//
	// Приоритет: СРЕДНИЙ (эти поля используются редко, в основном для маршрутизации через
	// промежуточные серверы, но для полной совместимости с протоколом их нужно реализовать)

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
		currentPos := offset

		// RecordLength (2 байта)
		record.RecordLength = binary.LittleEndian.Uint16(data[currentPos:])
		currentPos += 2

		// RecordNumber (2 байта)
		record.RecordNumber = binary.LittleEndian.Uint16(data[currentPos:])
		currentPos += 2

		// RecordFlags (1 байт)
		record.RecordFlags = data[currentPos]
		currentPos += 1

		// Разбираем флаги Record (RFL)
		// Биты (от старшего к младшему):
		// Бит 7 (OBFE): Object ID Field Exists
		// Бит 6 (EVFE): Event ID Field Exists
		// Бит 5 (TMFE): Time Field Exists
		// Биты 4-3 (RPP): Route Priority
		// Бит 2 (GRP): Group flag
		// Бит 1 (RSOD): Record Source On Device
		// Бит 0 (SSOD): Structure Source On Device
		obfe := (record.RecordFlags >> 7) & 0x01 // Бит 7
		evfe := (record.RecordFlags >> 6) & 0x01 // Бит 6
		tmfe := (record.RecordFlags >> 5) & 0x01 // Бит 5

		// Object ID (4 байта, опционально)
		if obfe == 1 {
			if currentPos+4 > len(data) {
				return nil, fmt.Errorf("недостаточно данных для OID")
			}
			record.ObjectID = binary.LittleEndian.Uint32(data[currentPos:])
			currentPos += 4
		}

		// Event ID (4 байта, опционально)
		if evfe == 1 {
			if currentPos+4 > len(data) {
				return nil, fmt.Errorf("недостаточно данных для EVID")
			}
			record.EventID = binary.LittleEndian.Uint32(data[currentPos:])
			currentPos += 4
		}

		// Time (4 байта, опционально)
		if tmfe == 1 {
			if currentPos+4 > len(data) {
				return nil, fmt.Errorf("недостаточно данных для TM")
			}
			record.Time = binary.LittleEndian.Uint32(data[currentPos:])
			currentPos += 4
		}

		// SourceServiceType (1 байт)
		if currentPos >= len(data) {
			return nil, fmt.Errorf("недостаточно данных для SST")
		}
		record.SourceServiceType = data[currentPos]
		currentPos += 1

		// RecipientServiceType (1 байт)
		if currentPos >= len(data) {
			return nil, fmt.Errorf("недостаточно данных для RST")
		}
		record.RecipientServiceType = data[currentPos]
		currentPos += 1

		// RecordData
		dataStart := currentPos
		dataEnd := dataStart + int(record.RecordLength)

		if dataEnd > len(data) {
			return nil, fmt.Errorf("некорректная длина записи: dataEnd=%d > len(data)=%d", dataEnd, len(data))
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

// ExtPosData содержит расширенные данные о позиции из EGTS SR_EXT_POS_DATA
type ExtPosData struct {
	VDOP       *uint16 // Vertical Dilution of Precision (делить на 100 для реального значения)
	HDOP       *uint16 // Horizontal Dilution of Precision (делить на 100 для реального значения)
	PDOP       *uint16 // Position Dilution of Precision (делить на 100 для реального значения)
	Satellites *uint8  // Количество спутников
	NorthSpeed *uint16 // Скорость на север (0.1 м/с)
	EastSpeed  *uint16 // Скорость на восток (0.1 м/с)
}

// StateData содержит данные состояния терминала из EGTS SR_STATE_DATA
type StateData struct {
	State              uint8  // Флаги состояния
	MainPowerVoltage   uint8  // Напряжение основного питания (* 0.1V)
	BackupBatVoltage   uint8  // Напряжение резервной батареи (* 0.1V)
	InternalBatVoltage uint8  // Напряжение встроенной батареи (* 0.1V)
	StateFlags         uint8  // Дополнительные флаги состояния
}

// TermIdentity содержит данные идентификации терминала из EGTS SR_TERM_IDENTITY
type TermIdentity struct {
	TerminalID     uint32 // Идентификатор терминала
	HomeDispatcher *uint16 // Идентификатор домашнего диспетчера (опционально)
	IMEI           string // IMEI терминала (15 байт)
	IMSI           string // IMSI SIM-карты (16 байт)
	LanguageCode   string // Код языка (3 байта, опционально)
	NetworkID      []byte // Network Identifier (3 байта, опционально)
	BufferSize     *uint16 // Размер буфера (опционально)
	MSISDN         string // Номер телефона (15 байт, опционально)
}

// ADSensorsData содержит данные аналоговых и дискретных датчиков из EGTS SR_AD_SENSORS_DATA
type ADSensorsData struct {
	DigitalInputsOutputs map[string]uint8    // ADIO датчики (ключ: "adio_X_Y")
	DigitalOutputs       map[string]uint8    // Дискретные выходы (ключ: "dout_X")
	AnalogSensors        map[string]int32    // Аналоговые датчики (ключ: "ans_X")
}

// LiquidLevelData содержит данные уровня жидкости из EGTS SR_LIQUID_LEVEL_SENSOR
type LiquidLevelData struct {
	SensorFlags       uint8  // Флаги датчика
	ModuleAddress     uint16 // Адрес модуля
	LevelMM           *uint32 // Уровень в миллиметрах (опционально)
	LevelL            *uint32 // Уровень в литрах (* 10, опционально)
	NavDataNumber     uint8  // Номер навигационных данных
	SensorErrorStatus uint8  // Статус ошибки датчика
}

// CounterData содержит данные счетчика из EGTS SR_ABS_CNTR_DATA
type CounterData struct {
	CounterNumber uint8     // Номер счетчика
	CounterValue  int32     // Значение счетчика
	CounterTime   *time.Time // Время счетчика (для счетчика 105)
}

// AbsAnalogSensorData содержит данные абсолютного аналогового датчика из EGTS SR_ABS_AN_SENS_DATA
type AbsAnalogSensorData struct {
	SensorNumber uint8 // Номер датчика
	SensorValue  int32 // Значение датчика
}

// GetExtPosData извлекает расширенные данные о позиции из подзаписи SR_EXT_POS_DATA
func GetExtPosData(subRecord *SubRecord) (*ExtPosData, error) {
	if subRecord.Type != SrExtPosData {
		return nil, fmt.Errorf("неверный тип подзаписи: %d (ожидался %d)", subRecord.Type, SrExtPosData)
	}

	if len(subRecord.Data) < 1 {
		return nil, fmt.Errorf("недостаточно данных для SR_EXT_POS_DATA: %d байт", len(subRecord.Data))
	}

	extPos := &ExtPosData{}
	reader := bytes.NewReader(subRecord.Data)

	// Читаем флаги наличия полей (1 байт)
	var flags uint8
	binary.Read(reader, binary.LittleEndian, &flags)

	// Биты флагов (биты 7-3 не используются):
	// Бит 4 (NSFE): North Speed Field Existence
	// Бит 3 (SFE): Satellites Field Existence
	// Бит 2 (PFE): PDOP Field Existence
	// Бит 1 (HFE): HDOP Field Existence
	// Бит 0 (VFE): VDOP Field Existence
	nsfe := (flags >> 4) & 0x01
	sfe := (flags >> 3) & 0x01
	pfe := (flags >> 2) & 0x01
	hfe := (flags >> 1) & 0x01
	vfe := flags & 0x01

	// VDOP (опционально, 2 байта)
	if vfe == 1 {
		var vdop uint16
		if err := binary.Read(reader, binary.LittleEndian, &vdop); err == nil {
			extPos.VDOP = &vdop
		}
	}

	// HDOP (опционально, 2 байта)
	if hfe == 1 {
		var hdop uint16
		if err := binary.Read(reader, binary.LittleEndian, &hdop); err == nil {
			extPos.HDOP = &hdop
		}
	}

	// PDOP (опционально, 2 байта)
	if pfe == 1 {
		var pdop uint16
		if err := binary.Read(reader, binary.LittleEndian, &pdop); err == nil {
			extPos.PDOP = &pdop
		}
	}

	// Satellites (опционально, 1 байт)
	if sfe == 1 {
		var sat uint8
		if err := binary.Read(reader, binary.LittleEndian, &sat); err == nil {
			extPos.Satellites = &sat
		}
	}

	// North Speed (опционально, 2 байта)
	if nsfe == 1 {
		var ns uint16
		if err := binary.Read(reader, binary.LittleEndian, &ns); err == nil {
			extPos.NorthSpeed = &ns
		}
	}

	return extPos, nil
}

// GetStateData извлекает данные состояния терминала из подзаписи SR_STATE_DATA
func GetStateData(subRecord *SubRecord) (*StateData, error) {
	if subRecord.Type != SrStateData {
		return nil, fmt.Errorf("неверный тип подзаписи: %d (ожидался %d)", subRecord.Type, SrStateData)
	}

	if len(subRecord.Data) < 5 {
		return nil, fmt.Errorf("недостаточно данных для SR_STATE_DATA: %d байт (минимум 5)", len(subRecord.Data))
	}

	state := &StateData{}
	reader := bytes.NewReader(subRecord.Data)

	// ST (1 байт) - флаги состояния
	binary.Read(reader, binary.LittleEndian, &state.State)

	// MPSV (1 байт) - напряжение основного питания (* 0.1V)
	binary.Read(reader, binary.LittleEndian, &state.MainPowerVoltage)

	// BBV (1 байт) - напряжение резервной батареи (* 0.1V)
	binary.Read(reader, binary.LittleEndian, &state.BackupBatVoltage)

	// IBV (1 байт) - напряжение встроенной батареи (* 0.1V)
	binary.Read(reader, binary.LittleEndian, &state.InternalBatVoltage)

	// ST_FL (1 байт) - дополнительные флаги состояния
	binary.Read(reader, binary.LittleEndian, &state.StateFlags)

	return state, nil
}

// GetTermIdentity извлекает данные идентификации терминала из подзаписи SR_TERM_IDENTITY
func GetTermIdentity(subRecord *SubRecord) (*TermIdentity, error) {
	if subRecord.Type != SrTermIdentity {
		return nil, fmt.Errorf("неверный тип подзаписи: %d (ожидался %d)", subRecord.Type, SrTermIdentity)
	}

	if len(subRecord.Data) < 5 {
		return nil, fmt.Errorf("недостаточно данных для SR_TERM_IDENTITY: %d байт (минимум 5)", len(subRecord.Data))
	}

	identity := &TermIdentity{}
	reader := bytes.NewReader(subRecord.Data)

	// TID (4 байта) - Terminal ID
	binary.Read(reader, binary.LittleEndian, &identity.TerminalID)

	// FLG (1 байт) - флаги наличия полей
	var flags uint8
	binary.Read(reader, binary.LittleEndian, &flags)

	// Биты флагов:
	// Бит 7 (HDIDE): Home Dispatcher ID Exists
	// Бит 6 (IMEIE): IMEI Exists
	// Бит 5 (IMSIE): IMSI Exists
	// Бит 4 (LNGCE): Language Code Exists
	// Бит 3 (NIDE): Network ID Exists
	// Бит 2 (BSE): Buffer Size Exists
	// Бит 1 (MSISDNE): MSISDN Exists
	hdide := (flags >> 7) & 0x01
	imeie := (flags >> 6) & 0x01
	imsie := (flags >> 5) & 0x01
	lngce := (flags >> 4) & 0x01
	nide := (flags >> 3) & 0x01
	bse := (flags >> 2) & 0x01
	msisdne := (flags >> 1) & 0x01

	// HDID (2 байта, опционально) - Home Dispatcher ID
	if hdide == 1 {
		var hdid uint16
		if err := binary.Read(reader, binary.LittleEndian, &hdid); err == nil {
			identity.HomeDispatcher = &hdid
		}
	}

	// IMEI (15 байт, опционально)
	if imeie == 1 {
		imeiBytes := make([]byte, 15)
		if _, err := reader.Read(imeiBytes); err == nil {
			// Удаляем нулевые байты в конце
			identity.IMEI = string(bytes.TrimRight(imeiBytes, "\x00"))
		}
	}

	// IMSI (16 байт, опционально)
	if imsie == 1 {
		imsiBytes := make([]byte, 16)
		if _, err := reader.Read(imsiBytes); err == nil {
			// Удаляем нулевые байты в конце
			identity.IMSI = string(bytes.TrimRight(imsiBytes, "\x00"))
		}
	}

	// LNGC (3 байта, опционально) - Language Code
	if lngce == 1 {
		lngcBytes := make([]byte, 3)
		if _, err := reader.Read(lngcBytes); err == nil {
			identity.LanguageCode = string(bytes.TrimRight(lngcBytes, "\x00"))
		}
	}

	// NID (3 байта, опционально) - Network ID
	if nide == 1 {
		nidBytes := make([]byte, 3)
		if _, err := reader.Read(nidBytes); err == nil {
			identity.NetworkID = nidBytes
		}
	}

	// BS (2 байта, опционально) - Buffer Size
	if bse == 1 {
		var bs uint16
		if err := binary.Read(reader, binary.LittleEndian, &bs); err == nil {
			identity.BufferSize = &bs
		}
	}

	// MSISDN (15 байт, опционально) - Phone number
	if msisdne == 1 {
		msisdnBytes := make([]byte, 15)
		if _, err := reader.Read(msisdnBytes); err == nil {
			identity.MSISDN = string(bytes.TrimRight(msisdnBytes, "\x00"))
		}
	}

	return identity, nil
}

// GetADSensorsData извлекает данные аналоговых и дискретных датчиков из подзаписи SR_AD_SENSORS_DATA
func GetADSensorsData(subRecord *SubRecord) (*ADSensorsData, error) {
	if subRecord.Type != SrAdSensorsData {
		return nil, fmt.Errorf("неверный тип подзаписи: %d (ожидался %d)", subRecord.Type, SrAdSensorsData)
	}

	if len(subRecord.Data) < 3 {
		return nil, fmt.Errorf("недостаточно данных для SR_AD_SENSORS_DATA: %d байт (минимум 3)", len(subRecord.Data))
	}

	sensors := &ADSensorsData{
		DigitalInputsOutputs: make(map[string]uint8),
		DigitalOutputs:       make(map[string]uint8),
		AnalogSensors:        make(map[string]int32),
	}

	reader := bytes.NewReader(subRecord.Data)

	// DIOE (1 байт) - Digital Inputs/Outputs Enable
	var dioe uint8
	binary.Read(reader, binary.LittleEndian, &dioe)

	// DOUT (1 байт) - Digital Outputs
	var dout uint8
	binary.Read(reader, binary.LittleEndian, &dout)

	// Парсим дискретные выходы (8 бит)
	for i := 0; i < 8; i++ {
		bit := (dout >> i) & 0x01
		sensors.DigitalOutputs[fmt.Sprintf("dout_%d", i)] = bit
	}

	// ASFE (1 байт) - Analog Sensors Field Existence
	var asfe uint8
	binary.Read(reader, binary.LittleEndian, &asfe)

	// Парсим ADIO (если DIOE != 0)
	if dioe != 0 {
		for i := 0; i < 8; i++ {
			if ((dioe >> i) & 0x01) == 1 {
				var adio uint8
				if err := binary.Read(reader, binary.LittleEndian, &adio); err != nil {
					break
				}
				// Парсим биты ADIO
				for j := 0; j < 8; j++ {
					bit := (adio >> j) & 0x01
					sensors.DigitalInputsOutputs[fmt.Sprintf("adio_%d_%d", i, j)] = bit
				}
			}
		}
	}

	// Парсим аналоговые датчики (если ASFE != 0)
	if asfe != 0 {
		for i := 0; i < 8; i++ {
			if ((asfe >> i) & 0x01) == 1 {
				// Читаем 3 байта значения датчика
				var ansBytes [3]byte
				if _, err := reader.Read(ansBytes[:]); err != nil {
					break
				}
				ansValue := convert3BytesToInt(ansBytes[:])
				sensors.AnalogSensors[fmt.Sprintf("ans_%d", i)] = ansValue
			}
		}
	}

	return sensors, nil
}

// GetLiquidLevelData извлекает данные уровня жидкости из подзаписи SR_LIQUID_LEVEL_SENSOR
func GetLiquidLevelData(subRecord *SubRecord) (*LiquidLevelData, error) {
	if subRecord.Type != SrLiquidLevel {
		return nil, fmt.Errorf("неверный тип подзаписи: %d (ожидался %d)", subRecord.Type, SrLiquidLevel)
	}

	if len(subRecord.Data) < 3 {
		return nil, fmt.Errorf("недостаточно данных для SR_LIQUID_LEVEL_SENSOR: %d байт (минимум 3)", len(subRecord.Data))
	}

	liquid := &LiquidLevelData{}
	reader := bytes.NewReader(subRecord.Data)

	// Флаги (1 байт)
	binary.Read(reader, binary.LittleEndian, &liquid.SensorFlags)

	// MADDR (2 байта) - Module Address
	binary.Read(reader, binary.LittleEndian, &liquid.ModuleAddress)

	// Парсим флаги
	// Бит 7-5: не используются
	// Биты 4-2: ERR + RDF (формат данных)
	// Биты 1-0: номер навигационных данных
	liquid.NavDataNumber = liquid.SensorFlags & 0x07       // биты 2-0
	liquid.SensorErrorStatus = (liquid.SensorFlags >> 1) & 0x01 // бит 1
	rdf := (liquid.SensorFlags >> 2) & 0x03                // биты 3-2

	// LLSD - Liquid Level Sensor Data
	// Размер зависит от флага RDF[4] (бит 4):
	// Если бит 4 == 0: 4 байта (uint32)
	// Если бит 4 == 1: переменная длина
	if ((liquid.SensorFlags >> 4) & 0x01) == 0 {
		// 4 байта
		var llsd uint32
		if err := binary.Read(reader, binary.LittleEndian, &llsd); err == nil {
			// Определяем единицы измерения по битам RDF[3:2]
			if rdf == 0 || rdf == 1 {
				// Миллиметры
				liquid.LevelMM = &llsd
			} else if rdf == 2 {
				// Литры (* 10)
				levelL := llsd * 10
				liquid.LevelL = &levelL
			}
		}
	} else {
		// Переменная длина - читаем оставшиеся байты
		remainingLen := int(subRecord.Length) - 3
		if remainingLen > 0 && remainingLen <= 8 {
			llsdBytes := make([]byte, remainingLen)
			if _, err := reader.Read(llsdBytes); err == nil {
				// Конвертируем в int32 (с учетом знака)
				var llsdValue int32
				if remainingLen == 3 {
					llsdValue = convert3BytesToInt(llsdBytes)
				} else {
					// Для других размеров просто читаем как uint32
					for i := 0; i < remainingLen && i < 4; i++ {
						llsdValue |= int32(llsdBytes[i]) << (8 * i)
					}
				}

				llsdUint := uint32(llsdValue)
				if rdf == 0 || rdf == 1 {
					liquid.LevelMM = &llsdUint
				} else if rdf == 2 {
					levelL := llsdUint * 10
					liquid.LevelL = &levelL
				}
			}
		}
	}

	return liquid, nil
}

// GetCounterData извлекает данные счетчика из подзаписи SR_ABS_CNTR_DATA
func GetCounterData(subRecord *SubRecord) (*CounterData, error) {
	if subRecord.Type != SrAbsCntrData {
		return nil, fmt.Errorf("неверный тип подзаписи: %d (ожидался %d)", subRecord.Type, SrAbsCntrData)
	}

	if len(subRecord.Data) < 4 {
		return nil, fmt.Errorf("недостаточно данных для SR_ABS_CNTR_DATA: %d байт (минимум 4)", len(subRecord.Data))
	}

	counter := &CounterData{}
	reader := bytes.NewReader(subRecord.Data)

	// CN (1 байт) - Counter Number
	binary.Read(reader, binary.LittleEndian, &counter.CounterNumber)

	// CNV (3 байта) - Counter Value
	var cnvBytes [3]byte
	reader.Read(cnvBytes[:])
	counter.CounterValue = convert3BytesToInt(cnvBytes[:])

	// Для счетчика 105 (egts_old_mark_time) значение - это Unix timestamp с эпохи 1970
	if counter.CounterNumber == 105 {
		timestamp := time.Unix(int64(counter.CounterValue), 0)
		counter.CounterTime = &timestamp
	}

	return counter, nil
}

// GetAbsAnalogSensorData извлекает данные абсолютного аналогового датчика из подзаписи SR_ABS_AN_SENS_DATA
func GetAbsAnalogSensorData(subRecord *SubRecord) (*AbsAnalogSensorData, error) {
	if subRecord.Type != SrAbsAnSensData {
		return nil, fmt.Errorf("неверный тип подзаписи: %d (ожидался %d)", subRecord.Type, SrAbsAnSensData)
	}

	if len(subRecord.Data) < 4 {
		return nil, fmt.Errorf("недостаточно данных для SR_ABS_AN_SENS_DATA: %d байт (минимум 4)", len(subRecord.Data))
	}

	sensor := &AbsAnalogSensorData{}
	reader := bytes.NewReader(subRecord.Data)

	// ASN (1 байт) - Analog Sensor Number
	binary.Read(reader, binary.LittleEndian, &sensor.SensorNumber)

	// ASV (3 байта) - Analog Sensor Value
	var asvBytes [3]byte
	reader.Read(asvBytes[:])
	sensor.SensorValue = convert3BytesToInt(asvBytes[:])

	return sensor, nil
}
