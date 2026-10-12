package server

import (
	"fmt"
	"log"
	"net"
	"time"

	"trackers-receiver/internal/egts"
	"trackers-receiver/pkg/models"
)

// processAuthRecord remembers the terminal's identity and reports whether the
// record carried EGTS_SR_TERM_IDENTITY.
func (h *ConnectionHandler) processAuthRecord(record *egts.Record) bool {
	identified := false
	for _, sr := range record.SubRecords {
		if sr.Type != egts.SrTermIdentity {
			continue
		}
		identified = true
		identity, err := egts.GetTermIdentity(sr)
		if err != nil {
			log.Printf("[WARN] %s: record %d: %v", h.remoteAddr, record.RecordNumber, err)
			continue
		}
		h.tid = identity.TerminalID
		if identity.IMEI != nil {
			h.imei = identity.IMEI
		}
		if identity.IMSI != nil {
			h.imsi = identity.IMSI
		}
	}
	return identified
}

// processTeledataRecord makes a document for every EGTS_SR_POS_DATA in the
// record. Other subrecords add to the document of the position they follow;
// those before the first position add to the first document.
func (h *ConnectionHandler) processTeledataRecord(record *egts.Record) []*models.Document {
	var documents []*models.Document
	doc := &models.Document{}
	positioned := false

	for _, sr := range record.SubRecords {
		switch sr.Type {
		case egts.SrPosData:
			pos, err := egts.GetPositionData(sr)
			if err != nil {
				log.Printf("[WARN] %s: record %d: %v", h.remoteAddr, record.RecordNumber, err)
				continue
			}
			if positioned {
				documents = append(documents, doc)
				doc = &models.Document{}
			}
			positioned = true
			h.setPosition(doc, pos)

		case egts.SrExtPosData:
			if ext, err := egts.GetExtPosData(sr); err == nil {
				doc.Nav.Ext = extPosition(ext)
			}

		case egts.SrStateData:
			if state, err := egts.GetStateData(sr); err == nil {
				doc.Nav.State = &models.State{
					MainPower:     state.MainPowerVoltage,
					BackupBattery: state.BackupBatVoltage,
					Battery:       state.InternalBatVoltage,
				}
			}

		case egts.SrAdSensorsData:
			if sensors, err := egts.GetADSensorsData(sr); err == nil {
				doc.ADSensors = adSensors(sensors)
			}

		case egts.SrLiquidLevel:
			if liquid, err := egts.GetLiquidLevelData(sr); err == nil {
				doc.LiquidLevels = append(doc.LiquidLevels, models.LiquidLevel{
					Sensor: liquid.NavDataNumber,
					Error:  liquid.SensorErrorStatus,
					MM:     liquid.LevelMM,
					Litres: liquid.LevelL,
				})
			}

		case egts.SrAbsAnSensData:
			if analog, err := egts.GetAbsAnalogSensorData(sr); err == nil {
				if doc.AbsAnalog == nil {
					doc.AbsAnalog = make(map[string]uint32)
				}
				doc.AbsAnalog[fmt.Sprintf("asn_%d", analog.SensorNumber)] = analog.SensorValue
			}

		case egts.SrAbsCntrData:
			if counter, err := egts.GetCounterData(sr); err == nil {
				h.addCounter(doc, counter)
			}
		}
	}

	if positioned {
		documents = append(documents, doc)
	}
	return documents
}

func (h *ConnectionHandler) setPosition(doc *models.Document, pos *egts.PositionData) {
	doc.Client = h.oid
	if doc.Client == 0 {
		doc.Client = h.tid
	}
	doc.DateCreate = time.Now()
	doc.NPHRequestID = h.nphRequestID
	doc.IMEI = h.imei
	doc.IMSI = h.imsi
	doc.Address = h.address

	doc.DigitalInputs = pos.DigitalInputs
	doc.Odometer = pos.Odometer
	doc.Nav.Timestamp = pos.NavigationTime
	doc.Nav.Latitude = pos.Latitude
	doc.Nav.Longitude = pos.Longitude
	doc.Nav.Speed = pos.Speed
	doc.Nav.Course = pos.Course
	doc.Nav.Altitude = pos.Altitude
	doc.Nav.ExtraDOP = pos.ExtraDOP
	doc.Nav.Source = pos.Source
}

// extPosition keeps the satellite count and a single DOP: the smaller of PDOP
// and HDOP, in whole units rounded up.
func extPosition(ext *egts.ExtPosData) *models.ExtPosition {
	pdop, hdop := wholeDOP(ext.PDOP), wholeDOP(ext.HDOP)
	if pdop == nil || hdop != nil && *hdop < *pdop {
		pdop = hdop
	}
	return &models.ExtPosition{Satellites: ext.Satellites, PDOP: pdop}
}

// wholeDOP converts a DOP transmitted multiplied by 100 to whole units, rounding up.
func wholeDOP(v *uint16) *uint16 {
	if v == nil {
		return nil
	}
	w := (*v + 99) / 100
	return &w
}

func adSensors(s *egts.ADSensorsData) map[string]any {
	m := make(map[string]any, len(s.DigitalOutputs)+len(s.DigitalInputsOutputs)+len(s.AnalogSensors))
	for k, v := range s.DigitalOutputs {
		m[k] = v
	}
	for k, v := range s.DigitalInputsOutputs {
		m[k] = v
	}
	// The Python receiver stored "1" instead of the sensor value, and the
	// documents keep that format until the consumers are ready for values.
	for k := range s.AnalogSensors {
		m[k] = "1"
	}
	return m
}

var counterNames = map[uint8]string{
	100: "cnt_ack",
	101: "cnt_noack",
	102: "cnt_connect",
	103: "egts_new_mark",
	104: "egts_old_mark",
	105: "egts_old_mark_time",
}

// addCounter stores well-known counters under their names and any other as
// the "cn"/"cnv" pair. Counter 110 carries the NPH request ID, which applies
// to this document and the rest of the packet.
func (h *ConnectionHandler) addCounter(doc *models.Document, c *egts.CounterData) {
	if doc.Counters == nil {
		doc.Counters = make(map[string]any)
	}
	name, ok := counterNames[c.CounterNumber]
	switch {
	case ok && c.CounterTime != nil:
		doc.Counters[name] = *c.CounterTime
	case ok:
		doc.Counters[name] = c.CounterValue
	default:
		doc.Counters["cn"] = c.CounterNumber
		doc.Counters["cnv"] = c.CounterValue
	}
	if c.CounterNumber == 110 {
		h.nphRequestID = c.CounterValue
		doc.NPHRequestID = c.CounterValue
	}
}

func clientAddress(addr net.Addr) models.Address {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return models.Address{IP: tcp.IP.String(), Port: tcp.Port}
	}
	return models.Address{IP: addr.String()}
}
