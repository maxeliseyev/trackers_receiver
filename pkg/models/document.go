package models

import (
	"fmt"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// Document is one navigation point as pushed to the queues. Its msgpack
// encoding reproduces the documents of the Python receiver key for key,
// because the consumers decode them with that receiver's utils/pack.py.
type Document struct {
	Client       uint32 // OID, or TID when OID is absent
	DateCreate   time.Time
	NPHRequestID uint32 // PID of the packet, or the value of counter 110
	Nav          NavigationData

	DigitalInputs uint8  // DIN
	Odometer      uint32 // metres

	LiquidLevels []LiquidLevel     // data_type_8, one entry per sensor
	Counters     map[string]any    // data_type_23
	ADSensors    map[string]any    // egts_sr_ad_sensors_data
	AbsAnalog    map[string]uint32 // egts_sr_abs_an_sens_data, "asn_<n>"

	// IMEI and IMSI are sent as transmitted in EGTS_SR_TERM_IDENTITY, NUL
	// padding included, and as an empty string when the terminal did not
	// identify itself on this connection.
	IMEI    []byte
	IMSI    []byte
	Address Address
}

type NavigationData struct {
	Timestamp time.Time
	Latitude  float64
	Longitude float64
	Speed     int    // km/h
	Course    int    // degrees
	Altitude  *int32 // metres, nil when not transmitted
	ExtraDOP  uint8  // VLD<<7 | LOHS<<6 | LAHS<<5
	Source    uint8  // SRC

	// Ext is set by EGTS_SR_EXT_POS_DATA, State by EGTS_SR_STATE_DATA. The
	// keys they fill are absent from the document without them.
	Ext   *ExtPosition
	State *State
}

type ExtPosition struct {
	Satellites *uint8
	PDOP       *uint16 // whole units; the smaller of PDOP and HDOP
}

// State holds voltages in units of 0.1 V.
type State struct {
	MainPower     uint8
	BackupBattery uint8
	Battery       uint8
}

type LiquidLevel struct {
	Sensor uint8
	Error  uint8
	MM     *uint32
	Litres *uint32 // the raw value multiplied by 10, as the Python receiver stored it
}

type Address struct {
	IP   string
	Port int
}

const (
	source  = "egts"
	version = "1.0.1"
)

// pair is a map entry; maps are written as pair lists to keep the key order
// of the Python receiver, which makes the two outputs easy to compare.
type pair struct {
	key   string
	value any
}

type orderedMap []pair

func (m orderedMap) EncodeMsgpack(enc *msgpack.Encoder) error {
	if err := enc.EncodeMapLen(len(m)); err != nil {
		return err
	}
	for _, p := range m {
		if err := enc.EncodeString(p.key); err != nil {
			return err
		}
		if err := enc.Encode(p.value); err != nil {
			return err
		}
	}
	return nil
}

// naiveTime is a datetime without a time zone in the receiver's pack.py
// encoding: {"__dt__": datetime.isoformat()}. isoformat omits the fraction
// when there are no microseconds.
type naiveTime time.Time

func (t naiveTime) EncodeMsgpack(enc *msgpack.Encoder) error {
	tt := time.Time(t).UTC()
	s := tt.Format("2006-01-02T15:04:05")
	if us := tt.Nanosecond() / 1000; us != 0 {
		s += fmt.Sprintf(".%06d", us)
	}
	return enc.Encode(orderedMap{{"__dt__", s}})
}

// EncodeMsgpack writes the document as the Python receiver did.
func (d *Document) EncodeMsgpack(enc *msgpack.Encoder) error {
	doc := orderedMap{
		{"data_type_2", orderedMap{{"di_in", d.DigitalInputs}, {"odometer", d.Odometer}}},
		{"client", d.Client},
		{"source", source},
		{"date_create", naiveTime(d.DateCreate)},
		{"nph_request_id", d.NPHRequestID},
		{"nav_data", d.navFields()},
		{"loc", orderedMap{{"type", "Point"}, {"coordinates", []float64{d.Nav.Latitude, d.Nav.Longitude}}}},
	}
	if d.ADSensors != nil {
		doc = append(doc, pair{"egts_sr_ad_sensors_data", d.ADSensors})
	}
	if len(d.LiquidLevels) > 0 {
		levels := make([]orderedMap, len(d.LiquidLevels))
		for i, l := range d.LiquidLevels {
			// "det_dtatus" is misspelt in the Python receiver, and consumers use that key.
			levels[i] = orderedMap{{"nav_data_number", l.Sensor}, {"det_dtatus", l.Error}}
			if l.MM != nil {
				levels[i] = append(levels[i], pair{"level_mm", *l.MM})
			}
			if l.Litres != nil {
				levels[i] = append(levels[i], pair{"level_l", *l.Litres})
			}
		}
		doc = append(doc, pair{"data_type_8", levels})
	}
	if d.AbsAnalog != nil {
		doc = append(doc, pair{"egts_sr_abs_an_sens_data", d.AbsAnalog})
	}
	if d.Counters != nil {
		counters := make(map[string]any, len(d.Counters))
		for k, v := range d.Counters {
			if t, ok := v.(time.Time); ok {
				v = naiveTime(t)
			}
			counters[k] = v
		}
		doc = append(doc, pair{"data_type_23", counters})
	}
	doc = append(doc,
		pair{"imei", identityField(d.IMEI)},
		pair{"imsi", identityField(d.IMSI)},
		pair{"address", []any{d.Address.IP, d.Address.Port}},
		pair{"version", version},
	)
	return enc.Encode(doc)
}

func (d *Document) navFields() orderedMap {
	n := &d.Nav
	m := orderedMap{
		{"time_stamp", naiveTime(n.Timestamp)},
		{"longitude", n.Longitude},
		{"latitude", n.Latitude},
		{"bat_voltage", nil},
		{"speed_avg", n.Speed},
		{"speed_max", nil},
		{"course", n.Course},
		{"track", d.Odometer},
		{"altitude", n.Altitude},
		{"extra_dop", n.ExtraDOP},
		{"extra_dop_bin", fmt.Sprintf("%08b", n.ExtraDOP)},
		{"src", n.Source},
	}
	if n.Ext != nil {
		m = append(m, pair{"nsat", n.Ext.Satellites}, pair{"pdop", n.Ext.PDOP})
	}
	if n.State != nil {
		m[3].value = n.State.Battery
		m = append(m, pair{"builtin_acc", n.State.BackupBattery}, pair{"mpsv", n.State.MainPower})
	}
	return m
}

func identityField(b []byte) any {
	if b == nil {
		return ""
	}
	return b
}
