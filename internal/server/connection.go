package server

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"trackers-receiver/internal/egts"
	"trackers-receiver/internal/storage"
	"trackers-receiver/pkg/models"
)

// ConnectionHandler обрабатывает одно TCP подключение от трекера
// Спроектирован для высокопроизводительной обработки с минимальными аллокациями
type ConnectionHandler struct {
	// Соединение
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer

	// Хранилище (интерфейс для гибкости)
	storage storage.QueueStorage

	// Конфигурация
	config *ConnectionConfig

	// Контекст для graceful shutdown
	ctx    context.Context
	cancel context.CancelFunc

	// Состояние подключения (данные трекера)
	imei     string
	imsi     string
	oid      uint32
	tid      uint32
	deviceID string // IMEI или TID как строка

	// Метрики подключения
	stats *ConnectionStats

	// IP адрес клиента
	remoteAddr string
}

// ConnectionConfig конфигурация для connection handler
type ConnectionConfig struct {
	ReadTimeout    time.Duration // Таймаут чтения (600 секунд как в Python)
	WriteTimeout   time.Duration // Таймаут записи (30 секунд)
	IdleTimeout    time.Duration // Idle timeout (300 секунд)
	MaxPacketSize  int           // Максимальный размер пакета (защита от DoS)
	StrictCRC      bool          // Строгая проверка CRC (false = как Python)
	BufferSize     int           // Размер буфера для чтения/записи
	QueueCharger   string        // Имя очереди charger
	QueueFasttrack string        // Имя очереди fasttrack
}

// DefaultConnectionConfig возвращает конфигурацию по умолчанию
func DefaultConnectionConfig() *ConnectionConfig {
	return &ConnectionConfig{
		ReadTimeout:    600 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    300 * time.Second,
		MaxPacketSize:  65536, // 64KB
		StrictCRC:      false, // Толерантный режим как Python
		BufferSize:     8192,  // 8KB буфер
		QueueCharger:   "charger",
		QueueFasttrack: "fasttrack",
	}
}

// ConnectionStats статистика подключения
type ConnectionStats struct {
	PacketsReceived  atomic.Uint64
	PacketsProcessed atomic.Uint64
	BytesReceived    atomic.Uint64
	BytesSent        atomic.Uint64
	ErrorsCount      atomic.Uint64
	CRCErrors        atomic.Uint64
	StartTime        time.Time
	LastActivity     time.Time
}

// NewConnectionHandler создает новый обработчик подключения
func NewConnectionHandler(conn net.Conn, stor storage.QueueStorage, config *ConnectionConfig) *ConnectionHandler {
	ctx, cancel := context.WithCancel(context.Background())

	handler := &ConnectionHandler{
		conn:     conn,
		reader:   bufio.NewReaderSize(conn, config.BufferSize),
		writer:   bufio.NewWriterSize(conn, config.BufferSize),
		storage:  stor,
		config:   config,
		ctx:      ctx,
		cancel:   cancel,
		stats: &ConnectionStats{
			StartTime:    time.Now(),
			LastActivity: time.Now(),
		},
		remoteAddr: conn.RemoteAddr().String(),
	}

	return handler
}

// Handle главный метод обработки подключения
// Блокирующий вызов, обрабатывает подключение до отключения клиента
func (h *ConnectionHandler) Handle() error {
	defer h.cleanup()

	// Устанавливаем read timeout
	if err := h.conn.SetReadDeadline(time.Now().Add(h.config.ReadTimeout)); err != nil {
		return fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Читаем первые байты для определения протокола
	signature := make([]byte, 2)
	if _, err := io.ReadFull(h.reader, signature); err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}

	h.stats.BytesReceived.Add(2)

	// Проверяем сигнатуру EGTS (0x01 0x00)
	if signature[0] != 0x01 || signature[1] != 0x00 {
		return &ProtocolError{
			Code:    "INVALID_SIGNATURE",
			Message: fmt.Sprintf("unknown protocol signature: 0x%02X 0x%02X", signature[0], signature[1]),
			IP:      h.remoteAddr,
		}
	}

	// Обрабатываем EGTS пакеты в цикле
	for {
		select {
		case <-h.ctx.Done():
			return h.ctx.Err()
		default:
			// Обрабатываем один пакет
			if err := h.handleEGTSPacket(signature); err != nil {
				h.stats.ErrorsCount.Add(1)

				// Определяем, критическая ли ошибка
				if isFatalError(err) {
					return err
				}

				// Для некритичных ошибок логируем и продолжаем
				// TODO: добавить логирование
				continue
			}

			// Обновляем время активности
			h.stats.LastActivity = time.Now()

			// Проверяем idle timeout
			if time.Since(h.stats.LastActivity) > h.config.IdleTimeout {
				return &ConnectionError{
					Code:    "IDLE_TIMEOUT",
					Message: fmt.Sprintf("idle timeout: no activity for %v", h.config.IdleTimeout),
				}
			}

			// Читаем следующую сигнатуру для следующего пакета
			signature = make([]byte, 2)
			if _, err := io.ReadFull(h.reader, signature); err != nil {
				if err == io.EOF {
					return nil // Клиент отключился
				}
				return fmt.Errorf("failed to read next signature: %w", err)
			}
			h.stats.BytesReceived.Add(2)
		}
	}
}

// handleEGTSPacket обрабатывает один EGTS пакет
func (h *ConnectionHandler) handleEGTSPacket(signature []byte) error {
	h.stats.PacketsReceived.Add(1)

	// Читаем оставшуюся часть заголовка (10 байт = 11 - 2 байта сигнатуры)
	headerRest := make([]byte, 9)
	if _, err := io.ReadFull(h.reader, headerRest); err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}
	h.stats.BytesReceived.Add(9)

	// Собираем полный заголовок
	headerData := append(signature, headerRest...)

	// Читаем FrameDataLength для определения размера тела
	fdl := binary.LittleEndian.Uint16(headerData[5:7])

	// Защита от слишком больших пакетов
	if int(fdl) > h.config.MaxPacketSize {
		return &ProtocolError{
			Code:    "PACKET_TOO_LARGE",
			Message: fmt.Sprintf("packet size %d exceeds max %d", fdl, h.config.MaxPacketSize),
			IP:      h.remoteAddr,
		}
	}

	// Читаем тело пакета (FrameData + CRC16)
	bodySize := int(fdl) + 2 // +2 для CRC16
	bodyData := make([]byte, bodySize)
	if _, err := io.ReadFull(h.reader, bodyData); err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}
	h.stats.BytesReceived.Add(uint64(bodySize))

	// Собираем полный пакет
	fullPacket := append(headerData, bodyData...)

	// Парсим пакет
	packet, err := egts.ParsePacket(fullPacket)
	if err != nil {
		// CRC ошибка?
		if isCRCError(err) {
			h.stats.CRCErrors.Add(1)

			// В толерантном режиме продолжаем обработку
			if !h.config.StrictCRC {
				// TODO: логировать warning
				// Пытаемся все равно обработать
			} else {
				return err
			}
		} else {
			return fmt.Errorf("failed to parse packet: %w", err)
		}
	}

	// Обрабатываем пакет по типу
	switch packet.Header.PacketType {
	case egts.PtAppdata:
		return h.processAppdataPacket(packet)
	case egts.PtResponse:
		// Обрабатываем ответ от трекера (редко)
		return h.processResponsePacket(packet)
	default:
		// Неизвестный тип пакета - не критично
		// TODO: логировать warning
		return h.sendErrorResponse(packet.Header.PacketID, egts.ProcessingResultUnsupportedType)
	}
}

// processAppdataPacket обрабатывает EGTS_PT_APPDATA пакет
func (h *ConnectionHandler) processAppdataPacket(packet *egts.Packet) error {
	if len(packet.Records) == 0 {
		// Пустой пакет - отправляем подтверждение но не обрабатываем
		return h.sendResponse(packet.Header.PacketID, nil, egts.ProcessingResultOK)
	}

	// Собираем документы из всех записей
	documents := make([]*models.Document, 0, len(packet.Records))
	recordNumbers := make([]uint16, 0, len(packet.Records))

	for _, record := range packet.Records {
		// Обрабатываем запись
		doc, err := h.processRecord(record, packet.Header.PacketID)
		if err != nil {
			// TODO: логировать ошибку
			continue
		}

		if doc != nil {
			documents = append(documents, doc)
			recordNumbers = append(recordNumbers, record.RecordNumber)
		}
	}

	// Сохраняем документы в Redis
	if len(documents) > 0 {
		if err := h.saveDocuments(documents); err != nil {
			// Ошибка сохранения - но все равно отправляем OK трекеру
			// TODO: логировать error, сохранить в fallback queue
		}
	}

	// Отправляем подтверждение
	return h.sendResponse(packet.Header.PacketID, recordNumbers, egts.ProcessingResultOK)
}

// processRecord обрабатывает одну запись и создает документ
func (h *ConnectionHandler) processRecord(record *egts.Record, packetID uint16) (*models.Document, error) {
	// Извлекаем OID/TID если есть
	if record.ObjectID != 0 {
		h.oid = record.ObjectID
	}

	var doc *models.Document

	// Обрабатываем подзаписи
	for _, subRecord := range record.SubRecords {
		switch subRecord.Type {
		case egts.SrTermIdentity:
			// Идентификация терминала
			identity, err := egts.GetTermIdentity(subRecord)
			if err == nil {
				h.imei = identity.IMEI
				h.imsi = identity.IMSI
				h.tid = identity.TerminalID
				h.deviceID = h.imei
				if h.deviceID == "" {
					h.deviceID = fmt.Sprintf("%d", h.tid)
				}
			}

		case egts.SrPosData:
			// Создаем новый документ для каждого SR_POS_DATA
			if doc != nil {
				// Уже был документ - это новая навигационная точка
				// Сохраняем предыдущий
				break
			}

			posData, err := egts.GetPositionData(subRecord)
			if err != nil {
				return nil, fmt.Errorf("failed to parse position data: %w", err)
			}

			// Создаем документ
			doc = h.createDocument(packetID)

			// Заполняем навигационные данные
			navData := &models.NavigationData{
				Timestamp:   posData.NavigationTime,
				Longitude:   posData.Longitude,
				Latitude:    posData.Latitude,
				Speed:       posData.Speed,
				Course:      posData.Course,
				Track:       posData.Odometer,
				Altitude:    posData.Altitude,
				Source:      posData.Source,
				ExtraDOP:    posData.ExtraDOP,
			}

			doc.SetNavigationData(navData)
			doc.SetPosDataExtras(posData.DigitalInputs, posData.Odometer)

		case egts.SrExtPosData:
			// Расширенные данные позиции
			if doc == nil {
				continue
			}
			extPos, err := egts.GetExtPosData(subRecord)
			if err == nil {
				if extPos.PDOP != nil {
					pdop := uint8(*extPos.PDOP / 10) // Конвертируем из uint16 в uint8
					doc.NavData.PDOP = &pdop
				}
				if extPos.HDOP != nil {
					hdop := uint8(*extPos.HDOP / 10)
					doc.NavData.HDOP = &hdop
				}
				if extPos.VDOP != nil {
					vdop := uint8(*extPos.VDOP / 10)
					doc.NavData.VDOP = &vdop
				}
				doc.NavData.Satellites = extPos.Satellites
			}

		case egts.SrStateData:
			// Данные состояния
			if doc == nil {
				continue
			}
			state, err := egts.GetStateData(subRecord)
			if err == nil {
				doc.NavData.BatVoltage = &state.InternalBatVoltage
				doc.NavData.MainPowerVol = &state.MainPowerVoltage
				doc.NavData.BuiltinAcc = &state.BackupBatVoltage
			}

		case egts.SrLiquidLevel:
			// Уровень топлива
			if doc == nil {
				continue
			}
			liquid, err := egts.GetLiquidLevelData(subRecord)
			if err == nil {
				sensor := map[string]interface{}{
					"nav_data_number": liquid.NavDataNumber,
					"det_status":      liquid.SensorErrorStatus,
				}
				if liquid.LevelMM != nil {
					sensor["level_mm"] = *liquid.LevelMM
				}
				if liquid.LevelL != nil {
					sensor["level_l"] = *liquid.LevelL
				}
				doc.AddLiquidLevelSensor(sensor)
			}

		case egts.SrAbsCntrData:
			// Счетчики
			if doc == nil {
				continue
			}
			counter, err := egts.GetCounterData(subRecord)
			if err == nil {
				if counter.CounterTime != nil {
					doc.AddCounter(counter.CounterNumber, *counter.CounterTime)
				} else {
					doc.AddCounter(counter.CounterNumber, counter.CounterValue)
				}
			}
		}
	}

	return doc, nil
}

// createDocument создает базовый документ с метаданными
func (h *ConnectionHandler) createDocument(packetID uint16) *models.Document {
	// Парсим IP и Port
	host, port, _ := net.SplitHostPort(h.remoteAddr)
	address := [2]interface{}{host, port}

	// Client ID = OID или TID
	clientID := h.oid
	if clientID == 0 {
		clientID = h.tid
	}

	doc := models.NewDocument("egts", h.deviceID, address)
	doc.Client = clientID
	doc.IMEI = h.imei
	doc.IMSI = h.imsi

	return doc
}

// saveDocuments сохраняет документы в обе очереди
func (h *ConnectionHandler) saveDocuments(documents []*models.Document) error {
	ctx := context.Background()

	// Используем batch операции для производительности
	// Сохраняем в обе очереди (как в Python версии)

	// Queue: charger
	if err := h.storage.PushBatch(ctx, h.config.QueueCharger, documents); err != nil {
		return fmt.Errorf("failed to push to charger queue: %w", err)
	}

	// Queue: fasttrack
	if err := h.storage.PushBatch(ctx, h.config.QueueFasttrack, documents); err != nil {
		return fmt.Errorf("failed to push to fasttrack queue: %w", err)
	}

	h.stats.PacketsProcessed.Add(uint64(len(documents)))
	return nil
}

// sendResponse отправляет EGTS_PT_RESPONSE пакет трекеру
func (h *ConnectionHandler) sendResponse(packetID uint16, recordNumbers []uint16, processingResult uint8) error {
	builder := egts.NewResponseBuilder(packetID)
	responseData, err := builder.BuildResponse(processingResult, recordNumbers, egts.RecordStatusOK)
	if err != nil {
		return fmt.Errorf("failed to build response: %w", err)
	}

	return h.sendData(responseData)
}

// sendErrorResponse отправляет ответ с ошибкой
func (h *ConnectionHandler) sendErrorResponse(packetID uint16, processingResult uint8) error {
	builder := egts.NewResponseBuilder(packetID)
	responseData, err := builder.BuildErrorResponse(processingResult)
	if err != nil {
		return fmt.Errorf("failed to build error response: %w", err)
	}

	return h.sendData(responseData)
}

// sendData отправляет данные трекеру
func (h *ConnectionHandler) sendData(data []byte) error {
	// Устанавливаем write timeout
	if err := h.conn.SetWriteDeadline(time.Now().Add(h.config.WriteTimeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	// Записываем в буфер
	if _, err := h.writer.Write(data); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	// Flush буфера
	if err := h.writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush writer: %w", err)
	}

	h.stats.BytesSent.Add(uint64(len(data)))
	return nil
}

// processResponsePacket обрабатывает EGTS_PT_RESPONSE от трекера (редко)
func (h *ConnectionHandler) processResponsePacket(packet *egts.Packet) error {
	// Обычно сервер не получает RESPONSE от трекера
	// Но если получили - просто игнорируем
	return nil
}

// cleanup освобождает ресурсы при завершении обработки
func (h *ConnectionHandler) cleanup() {
	h.cancel()
	h.writer.Flush()
	h.conn.Close()
}

// GetStats возвращает статистику подключения
func (h *ConnectionHandler) GetStats() *ConnectionStats {
	return h.stats
}

// Close закрывает подключение
func (h *ConnectionHandler) Close() error {
	h.cancel()
	return h.conn.Close()
}

// Ошибки

// ProtocolError ошибка протокола
type ProtocolError struct {
	Code    string
	Message string
	IP      string
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("[%s] %s (ip=%s)", e.Code, e.Message, e.IP)
}

// ConnectionError ошибка подключения
type ConnectionError struct {
	Code    string
	Message string
}

func (e *ConnectionError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// isFatalError определяет, является ли ошибка критической
func isFatalError(err error) bool {
	switch err.(type) {
	case *ProtocolError:
		return true
	case *ConnectionError:
		return true
	default:
		return false
	}
}

// isCRCError проверяет, является ли ошибка ошибкой CRC
func isCRCError(err error) bool {
	if err == nil {
		return false
	}
	// Проверяем текст ошибки
	errStr := err.Error()
	return len(errStr) > 0 && (errStr[:6] == "невер" || errStr[:9] == "invalid C")
}
