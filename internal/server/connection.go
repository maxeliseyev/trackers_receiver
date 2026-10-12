package server

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	"trackers-receiver/internal/egts"
	"trackers-receiver/internal/storage"
	"trackers-receiver/pkg/models"
)

// ConnectionHandler serves one tracker connection until it disconnects or
// sends something unrecoverable.
type ConnectionHandler struct {
	conn       net.Conn
	reader     *bufio.Reader
	storage    storage.QueueStorage
	config     *ConnectionConfig
	remoteAddr string

	// Identity reported by the tracker; persists across packets.
	imei string
	imsi string
	oid  uint32
	tid  uint32
}

type ConnectionConfig struct {
	// ReadTimeout is how long to wait for the next packet before dropping the connection.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	// MaxPacketSize limits FDL to bound per-connection memory.
	MaxPacketSize int
	// StrictCRC drops the connection on a CRC mismatch instead of skipping the packet.
	StrictCRC bool
	// BufferSize is the per-connection read buffer; it is multiplied by the
	// number of connections, so keep it small.
	BufferSize     int
	QueueCharger   string
	QueueFasttrack string
}

func DefaultConnectionConfig() *ConnectionConfig {
	return &ConnectionConfig{
		ReadTimeout:    600 * time.Second,
		WriteTimeout:   30 * time.Second,
		MaxPacketSize:  65536,
		StrictCRC:      false,
		BufferSize:     2048,
		QueueCharger:   "charger",
		QueueFasttrack: "fasttrack",
	}
}

func NewConnectionHandler(conn net.Conn, stor storage.QueueStorage, config *ConnectionConfig) *ConnectionHandler {
	return &ConnectionHandler{
		conn:       conn,
		reader:     bufio.NewReaderSize(conn, config.BufferSize),
		storage:    stor,
		config:     config,
		remoteAddr: conn.RemoteAddr().String(),
	}
}

// Handle blocks until the connection is done. A clean disconnect between
// packets returns nil.
func (h *ConnectionHandler) Handle() error {
	defer h.Close()

	for {
		raw, err := h.readPacket()
		if errors.Is(err, errDisconnected) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := h.handlePacket(raw); err != nil {
			if isFatalError(err) {
				return err
			}
			log.Printf("[WARN] %s: %v", h.remoteAddr, err)
		}
	}
}

// readPacket reads one transport packet: header, frame data and CRC16.
// It returns errDisconnected if the peer closed the connection between packets.
func (h *ConnectionHandler) readPacket() ([]byte, error) {
	if err := h.conn.SetReadDeadline(time.Now().Add(h.config.ReadTimeout)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}

	header := make([]byte, egts.MinHeaderLength)
	if _, err := io.ReadFull(h.reader, header); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errDisconnected
		}
		return nil, fmt.Errorf("read header: %w", err)
	}

	if header[0] != egts.ProtocolVersion {
		return nil, h.protocolError("INVALID_SIGNATURE", fmt.Sprintf("unexpected PRV 0x%02X", header[0]))
	}

	hl := int(header[3])
	if hl < egts.MinHeaderLength {
		return nil, h.protocolError("INVALID_HEADER", fmt.Sprintf("header length %d", hl))
	}

	fdl := int(binary.LittleEndian.Uint16(header[5:7]))
	if fdl > h.config.MaxPacketSize {
		return nil, h.protocolError("PACKET_TOO_LARGE", fmt.Sprintf("frame data length %d exceeds %d", fdl, h.config.MaxPacketSize))
	}

	packet := make([]byte, hl+fdl+2)
	copy(packet, header)
	if _, err := io.ReadFull(h.reader, packet[egts.MinHeaderLength:]); err != nil {
		return nil, fmt.Errorf("read packet body: %w", err)
	}
	return packet, nil
}

func (h *ConnectionHandler) handlePacket(raw []byte) error {
	packet, err := egts.ParsePacket(raw)
	if err != nil {
		if errors.Is(err, egts.ErrHeaderCRC) || errors.Is(err, egts.ErrBodyCRC) {
			if h.config.StrictCRC {
				return h.protocolError("CRC_MISMATCH", err.Error())
			}
			return fmt.Errorf("packet skipped: %w", err)
		}
		return fmt.Errorf("parse packet: %w", err)
	}

	switch packet.Header.PacketType {
	case egts.PtAppdata:
		return h.processAppdataPacket(packet)
	case egts.PtResponse:
		// Acknowledgements from the tracker need no reply.
		return nil
	default:
		return h.sendErrorResponse(packet.Header.PacketID, egts.ProcessingResultUnsupportedType)
	}
}

// processAppdataPacket stores the navigation records and acknowledges the packet.
// Records that fail to parse are not confirmed.
func (h *ConnectionHandler) processAppdataPacket(packet *egts.Packet) error {
	documents := make([]*models.Document, 0, len(packet.Records))
	recordNumbers := make([]uint16, 0, len(packet.Records))

	for _, record := range packet.Records {
		doc, err := h.processRecord(record)
		if err != nil {
			log.Printf("[WARN] %s: record %d: %v", h.remoteAddr, record.RecordNumber, err)
			continue
		}
		if doc != nil {
			documents = append(documents, doc)
			recordNumbers = append(recordNumbers, record.RecordNumber)
		}
	}

	if len(documents) > 0 {
		// The packet is acknowledged even if saving fails: the tracker would
		// otherwise resend it forever while storage is down.
		if err := h.saveDocuments(documents); err != nil {
			log.Printf("[ERROR] %s: save %d documents: %v", h.remoteAddr, len(documents), err)
		}
	}

	return h.sendResponse(packet.Header.PacketID, recordNumbers)
}

// processRecord turns a record into a document. It returns nil if the record
// carries no SR_POS_DATA. Only the first SR_POS_DATA in a record is used, and
// subrecords that precede it (other than identity) are ignored.
func (h *ConnectionHandler) processRecord(record *egts.Record) (*models.Document, error) {
	if record.ObjectID != 0 {
		h.oid = record.ObjectID
	}

	var doc *models.Document

	for _, sr := range record.SubRecords {
		if doc == nil && sr.Type != egts.SrTermIdentity && sr.Type != egts.SrPosData {
			continue
		}

		switch sr.Type {
		case egts.SrTermIdentity:
			if identity, err := egts.GetTermIdentity(sr); err == nil {
				h.imei = identity.IMEI
				h.imsi = identity.IMSI
				h.tid = identity.TerminalID
			}

		case egts.SrPosData:
			if doc != nil {
				continue
			}
			pos, err := egts.GetPositionData(sr)
			if err != nil {
				return nil, err
			}
			doc = h.createDocument()
			doc.SetNavigationData(&models.NavigationData{
				Timestamp: pos.NavigationTime,
				Longitude: pos.Longitude,
				Latitude:  pos.Latitude,
				Speed:     pos.Speed,
				Course:    pos.Course,
				Track:     pos.Odometer,
				Altitude:  pos.Altitude,
				Source:    pos.Source,
				ExtraDOP:  pos.ExtraDOP,
			})
			doc.SetPosDataExtras(pos.DigitalInputs, pos.Odometer)

		case egts.SrExtPosData:
			ext, err := egts.GetExtPosData(sr)
			if err != nil {
				continue
			}
			// DOPs arrive scaled by 100; the document stores them scaled by 10.
			doc.NavData.PDOP = scaleDOP(ext.PDOP)
			doc.NavData.HDOP = scaleDOP(ext.HDOP)
			doc.NavData.VDOP = scaleDOP(ext.VDOP)
			doc.NavData.Satellites = ext.Satellites

		case egts.SrStateData:
			state, err := egts.GetStateData(sr)
			if err != nil {
				continue
			}
			doc.NavData.BatVoltage = &state.InternalBatVoltage
			doc.NavData.MainPowerVol = &state.MainPowerVoltage
			doc.NavData.BuiltinAcc = &state.BackupBatVoltage

		case egts.SrLiquidLevel:
			liquid, err := egts.GetLiquidLevelData(sr)
			if err != nil {
				continue
			}
			sensor := map[string]any{
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

		case egts.SrAbsCntrData:
			counter, err := egts.GetCounterData(sr)
			if err != nil {
				continue
			}
			if counter.CounterTime != nil {
				doc.AddCounter(counter.CounterNumber, *counter.CounterTime)
			} else {
				doc.AddCounter(counter.CounterNumber, counter.CounterValue)
			}
		}
	}

	return doc, nil
}

func scaleDOP(v *uint16) *uint8 {
	if v == nil {
		return nil
	}
	s := uint8(*v / 10)
	return &s
}

func (h *ConnectionHandler) createDocument() *models.Document {
	host, port, _ := net.SplitHostPort(h.remoteAddr)

	clientID := h.oid
	if clientID == 0 {
		clientID = h.tid
	}

	imei := h.imei
	if imei == "" {
		imei = strconv.FormatUint(uint64(clientID), 10)
	}

	doc := models.NewDocument("egts", imei, [2]any{host, port})
	doc.Client = clientID
	doc.IMSI = h.imsi
	return doc
}

// saveDocuments writes the documents to both queues, as the Python receiver did.
func (h *ConnectionHandler) saveDocuments(documents []*models.Document) error {
	ctx, cancel := context.WithTimeout(context.Background(), h.config.WriteTimeout)
	defer cancel()

	for _, queue := range []string{h.config.QueueCharger, h.config.QueueFasttrack} {
		if err := h.storage.PushBatch(ctx, queue, documents); err != nil {
			return err
		}
	}
	return nil
}

func (h *ConnectionHandler) sendResponse(packetID uint16, recordNumbers []uint16) error {
	data, err := egts.NewResponseBuilder(packetID).BuildResponse(egts.ProcessingResultOK, recordNumbers, egts.RecordStatusOK)
	if err != nil {
		return fmt.Errorf("build response: %w", err)
	}
	return h.write(data)
}

func (h *ConnectionHandler) sendErrorResponse(packetID uint16, processingResult uint8) error {
	data, err := egts.NewResponseBuilder(packetID).BuildErrorResponse(processingResult)
	if err != nil {
		return fmt.Errorf("build error response: %w", err)
	}
	return h.write(data)
}

// write failures are fatal: the stream is unusable afterwards.
func (h *ConnectionHandler) write(data []byte) error {
	if err := h.conn.SetWriteDeadline(time.Now().Add(h.config.WriteTimeout)); err != nil {
		return &ConnectionError{Code: "WRITE_FAILED", Message: err.Error()}
	}
	if _, err := h.conn.Write(data); err != nil {
		return &ConnectionError{Code: "WRITE_FAILED", Message: err.Error()}
	}
	return nil
}

func (h *ConnectionHandler) Close() error {
	return h.conn.Close()
}

func (h *ConnectionHandler) protocolError(code, msg string) *ProtocolError {
	return &ProtocolError{Code: code, Message: msg, IP: h.remoteAddr}
}

// errDisconnected marks a clean disconnect between packets.
var errDisconnected = errors.New("client disconnected")

// ProtocolError means the peer is not speaking EGTS correctly. It closes the
// connection and counts against the peer in the rate limiter.
type ProtocolError struct {
	Code    string
	Message string
	IP      string
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("[%s] %s (ip=%s)", e.Code, e.Message, e.IP)
}

// ConnectionError means the connection itself failed and must be closed.
type ConnectionError struct {
	Code    string
	Message string
}

func (e *ConnectionError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func isFatalError(err error) bool {
	var pe *ProtocolError
	var ce *ConnectionError
	return errors.As(err, &pe) || errors.As(err, &ce)
}
