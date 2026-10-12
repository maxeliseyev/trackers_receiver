package models

import (
	"strconv"
	"time"
)

// Document is the protocol-independent record pushed to the queues.
// Field names and msgpack tags must stay compatible with the Python receiver.
type Document struct {
	Client     uint32    `msgpack:"client"` // OID, or TID when OID is absent
	Source     string    `msgpack:"source"` // protocol name, e.g. "egts"
	DateCreate time.Time `msgpack:"date_create"`
	IMEI       string    `msgpack:"imei"`
	IMSI       string    `msgpack:"imsi"`
	Address    [2]any    `msgpack:"address"` // [host, port] of the tracker
	Version    string    `msgpack:"version"`

	NavData  *NavigationData `msgpack:"nav_data"`
	Location *GeoLocation    `msgpack:"loc"`

	DataType2  map[string]any   `msgpack:"data_type_2,omitempty"`  // SR_POS_DATA extras
	DataType8  []map[string]any `msgpack:"data_type_8,omitempty"`  // SR_LIQUID_LEVEL_SENSOR, one entry per sensor
	DataType23 map[string]any   `msgpack:"data_type_23,omitempty"` // SR_ABS_CNTR_DATA

	SensorData map[string]any   `msgpack:"egts_sr_ad_sensors_data,omitempty"`
	AnalogData map[string]int32 `msgpack:"egts_sr_abs_an_sens_data,omitempty"`
}

type NavigationData struct {
	Timestamp time.Time `msgpack:"time_stamp"`

	Longitude float64 `msgpack:"longitude"`
	Latitude  float64 `msgpack:"latitude"`

	Speed    int  `msgpack:"speed_avg"` // km/h
	SpeedMax *int `msgpack:"speed_max"`
	Course   int  `msgpack:"course"` // degrees, 0-359

	Altitude *int32 `msgpack:"altitude"` // metres
	Track    uint32 `msgpack:"track"`    // odometer, metres

	Satellites *uint8  `msgpack:"nsat"`
	PDOP       *uint16 `msgpack:"pdop"`
	HDOP       *uint16 `msgpack:"hdop"`
	VDOP       *uint16 `msgpack:"vdop"`

	// Voltages in units of 0.1 V.
	BatVoltage   *uint8 `msgpack:"bat_voltage"`
	BuiltinAcc   *uint8 `msgpack:"builtin_acc"`
	MainPowerVol *uint8 `msgpack:"mpsv"`

	ExtraDOP    uint8  `msgpack:"extra_dop"` // VLD<<7 | LOHS<<6 | LAHS<<5
	ExtraDOPBin string `msgpack:"extra_dop_bin"`
	Source      uint8  `msgpack:"src"`
}

// GeoLocation is a GeoJSON point. Coordinates are stored as [lat, lon], not the
// GeoJSON-standard [lon, lat], because downstream consumers expect that order.
type GeoLocation struct {
	Type        string     `msgpack:"type"`
	Coordinates [2]float64 `msgpack:"coordinates"`
}

func NewDocument(source string, imei string, address [2]any) *Document {
	return &Document{
		Source:     source,
		IMEI:       imei,
		Address:    address,
		DateCreate: time.Now().UTC(),
		Version:    "1.0.1",
		NavData:    &NavigationData{},
		Location:   &GeoLocation{Type: "Point"},
	}
}

// SetNavigationData also updates Location from the new coordinates.
func (d *Document) SetNavigationData(nav *NavigationData) {
	d.NavData = nav
	if nav != nil {
		d.Location = &GeoLocation{
			Type:        "Point",
			Coordinates: [2]float64{nav.Latitude, nav.Longitude},
		}
	}
}

func (d *Document) AddLiquidLevelSensor(sensor map[string]any) {
	d.DataType8 = append(d.DataType8, sensor)
}

func (d *Document) SetPosDataExtras(digitalInputs uint8, odometer uint32) {
	if d.DataType2 == nil {
		d.DataType2 = make(map[string]any)
	}
	d.DataType2["di_in"] = digitalInputs
	d.DataType2["odometer"] = odometer
}

var counterNames = map[uint8]string{
	100: "cnt_ack",
	101: "cnt_noack",
	102: "cnt_connect",
	103: "egts_new_mark",
	104: "egts_old_mark",
	105: "egts_old_mark_time",
}

// AddCounter stores the value under the counter's well-known name (or its number),
// and also as the last seen pair under "cn"/"cnv".
func (d *Document) AddCounter(counterNumber uint8, value any) {
	if d.DataType23 == nil {
		d.DataType23 = make(map[string]any)
	}

	name, ok := counterNames[counterNumber]
	if !ok {
		name = strconv.Itoa(int(counterNumber))
	}
	d.DataType23[name] = value
	d.DataType23["cn"] = counterNumber
	d.DataType23["cnv"] = value
}

func (d *Document) Validate() error {
	if d.Source == "" {
		return ErrInvalidSource
	}
	if d.IMEI == "" {
		return ErrMissingIMEI
	}
	if d.NavData == nil {
		return ErrMissingNavData
	}
	return nil
}

var (
	ErrInvalidSource  = &DocumentError{Code: "INVALID_SOURCE", Message: "source cannot be empty"}
	ErrMissingIMEI    = &DocumentError{Code: "MISSING_IMEI", Message: "IMEI is required"}
	ErrMissingNavData = &DocumentError{Code: "MISSING_NAV_DATA", Message: "navigation data is required"}
)

type DocumentError struct {
	Code    string
	Message string
}

func (e *DocumentError) Error() string {
	return e.Message
}
