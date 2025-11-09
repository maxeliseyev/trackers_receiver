package models

import (
	"time"
)

// Document представляет унифицированную структуру данных для всех протоколов
// Сериализуется в MessagePack и сохраняется в Redis
// Формат совместим с Python версией для обратной совместимости
type Document struct {
	// Метаданные трекера
	Client     uint32         `msgpack:"client"`      // OID или TID трекера
	Source     string         `msgpack:"source"`      // Протокол: "egts", "galileosky", etc.
	DateCreate time.Time      `msgpack:"date_create"` // Время создания записи на сервере (UTC)
	IMEI       string         `msgpack:"imei"`        // IMEI терминала (15 цифр)
	IMSI       string         `msgpack:"imsi"`        // IMSI SIM-карты (опционально)
	Address    [2]interface{} `msgpack:"address"`     // [IP, Port] клиента
	Version    string         `msgpack:"version"`     // Версия формата документа (например "1.0.1")

	// Основные навигационные данные
	NavData *NavigationData `msgpack:"nav_data"`

	// GeoJSON локация (для MongoDB/PostgreSQL с geo-индексами)
	Location *GeoLocation `msgpack:"loc"`

	// Дополнительные данные (опционально, зависят от типа подзаписей)
	DataType2  map[string]interface{}   `msgpack:"data_type_2,omitempty"`  // SR_POS_DATA дополнительные поля
	DataType8  []map[string]interface{} `msgpack:"data_type_8,omitempty"`  // SR_LIQUID_LEVEL_SENSOR (массив датчиков)
	DataType23 map[string]interface{}   `msgpack:"data_type_23,omitempty"` // SR_ABS_CNTR_DATA (счетчики)

	// Датчики
	SensorData map[string]interface{} `msgpack:"egts_sr_ad_sensors_data,omitempty"`  // SR_AD_SENSORS_DATA
	AnalogData map[string]int32       `msgpack:"egts_sr_abs_an_sens_data,omitempty"` // SR_ABS_AN_SENS_DATA
}

// NavigationData содержит основные навигационные данные
type NavigationData struct {
	// Время навигационного события (от трекера)
	Timestamp time.Time `msgpack:"time_stamp"`

	// Координаты
	Longitude float64 `msgpack:"longitude"` // Долгота (-180.0 до 180.0)
	Latitude  float64 `msgpack:"latitude"`  // Широта (-90.0 до 90.0)

	// Параметры движения
	Speed    int  `msgpack:"speed_avg"` // Средняя скорость (км/ч)
	SpeedMax *int `msgpack:"speed_max"` // Максимальная скорость (опционально)
	Course   int  `msgpack:"course"`    // Курс (0-511 градусов, 9 бит)

	// Высота и точность
	Altitude *int32 `msgpack:"altitude"` // Высота в дециметрах (опционально)
	Track    uint32 `msgpack:"track"`    // Одометр в метрах

	// Спутниковая информация
	Satellites *uint8 `msgpack:"nsat"` // Количество спутников (опционально)
	PDOP       *uint8 `msgpack:"pdop"` // Position Dilution of Precision * 10 (опционально)
	HDOP       *uint8 `msgpack:"hdop"` // Horizontal DOP (опционально)
	VDOP       *uint8 `msgpack:"vdop"` // Vertical DOP (опционально)

	// Питание
	BatVoltage   *uint8 `msgpack:"bat_voltage"`   // Напряжение внутренней батареи * 10 (В)
	BuiltinAcc   *uint8 `msgpack:"builtin_acc"`   // Встроенный аккумулятор (опционально)
	MainPowerVol *uint8 `msgpack:"mpsv"`          // Основное питание * 10 (В)

	// Дополнительные флаги
	ExtraDOP    uint8  `msgpack:"extra_dop"`     // Битовые флаги валидности (VLD|LOHS|LAHS)
	ExtraDOPBin string `msgpack:"extra_dop_bin"` // Бинарное представление флагов (для отладки)
	Source      uint8  `msgpack:"src"`           // Источник данных (0=внешний GNSS, 1=встроенный)
}

// GeoLocation представляет координаты в формате GeoJSON
// Используется для spatial индексов в MongoDB/PostgreSQL
type GeoLocation struct {
	Type        string     `msgpack:"type"`        // Всегда "Point"
	Coordinates [2]float64 `msgpack:"coordinates"` // [latitude, longitude] - ВАЖНО: lat, lon (не lon, lat!)
}

// NewDocument создает новый документ с базовыми полями
func NewDocument(source string, imei string, address [2]interface{}) *Document {
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

// SetNavigationData устанавливает навигационные данные и автоматически обновляет Location
func (d *Document) SetNavigationData(nav *NavigationData) {
	d.NavData = nav

	// Автоматически обновляем GeoJSON координаты
	if nav != nil {
		d.Location = &GeoLocation{
			Type:        "Point",
			Coordinates: [2]float64{nav.Latitude, nav.Longitude},
		}
	}
}

// AddLiquidLevelSensor добавляет данные датчика уровня топлива
func (d *Document) AddLiquidLevelSensor(sensor map[string]interface{}) {
	if d.DataType8 == nil {
		d.DataType8 = make([]map[string]interface{}, 0)
	}
	d.DataType8 = append(d.DataType8, sensor)
}

// SetPosDataExtras устанавливает дополнительные данные из SR_POS_DATA
func (d *Document) SetPosDataExtras(digitalInputs uint8, odometer uint32) {
	if d.DataType2 == nil {
		d.DataType2 = make(map[string]interface{})
	}
	d.DataType2["di_in"] = digitalInputs
	d.DataType2["odometer"] = odometer
}

// AddCounter добавляет значение счетчика
func (d *Document) AddCounter(counterNumber uint8, value interface{}) {
	if d.DataType23 == nil {
		d.DataType23 = make(map[string]interface{})
	}

	// Известные счетчики
	switch counterNumber {
	case 100:
		d.DataType23["cnt_ack"] = value
	case 101:
		d.DataType23["cnt_noack"] = value
	case 102:
		d.DataType23["cnt_connect"] = value
	case 103:
		d.DataType23["egts_new_mark"] = value
	case 104:
		d.DataType23["egts_old_mark"] = value
	case 105:
		d.DataType23["egts_old_mark_time"] = value
	default:
		// Общий счетчик
		d.DataType23[string(rune(counterNumber))] = value
	}

	// Сохраняем также общие поля
	d.DataType23["cn"] = counterNumber
	d.DataType23["cnv"] = value
}

// SetAnalogSensorData устанавливает данные аналоговых датчиков
func (d *Document) SetAnalogSensorData(sensors map[string]interface{}) {
	d.SensorData = sensors
}

// SetAbsoluteAnalogSensorData устанавливает абсолютные аналоговые датчики
func (d *Document) SetAbsoluteAnalogSensorData(sensors map[string]int32) {
	d.AnalogData = sensors
}

// Validate проверяет корректность документа перед сохранением
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

// Ошибки валидации
var (
	ErrInvalidSource  = &DocumentError{Code: "INVALID_SOURCE", Message: "source cannot be empty"}
	ErrMissingIMEI    = &DocumentError{Code: "MISSING_IMEI", Message: "IMEI is required"}
	ErrMissingNavData = &DocumentError{Code: "MISSING_NAV_DATA", Message: "navigation data is required"}
)

// DocumentError представляет ошибку валидации документа
type DocumentError struct {
	Code    string
	Message string
}

func (e *DocumentError) Error() string {
	return e.Message
}
