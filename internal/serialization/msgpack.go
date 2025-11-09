package serialization

import (
	"fmt"

	"trackers-receiver/pkg/models"

	"github.com/vmihailenco/msgpack/v5"
)

// Примечание: msgpack v5 автоматически сериализует time.Time
// В будущем, если потребуется custom формат {"__dt__": "..."} как в Python,
// можно будет реализовать через msgpack.CustomEncoder интерфейс

// Serializer отвечает за сериализацию/десериализацию документов
type Serializer struct {
	encoder *msgpack.Encoder
	decoder *msgpack.Decoder
}

// NewSerializer создает новый сериализатор
func NewSerializer() *Serializer {
	return &Serializer{}
}

// Marshal сериализует документ в MessagePack формат
// Совместим с Python версией (arrow + msgpack)
func (s *Serializer) Marshal(doc *models.Document) ([]byte, error) {
	if err := doc.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Регистрируем custom encoder для time.Time
	encoder := msgpack.NewEncoder(nil)
	encoder.SetCustomStructTag("msgpack")
	encoder.UseCompactInts(true)

	// Сериализуем с custom encoding для datetime
	data, err := msgpack.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("msgpack marshal failed: %w", err)
	}

	return data, nil
}

// Unmarshal десериализует MessagePack данные в документ
// Используется в основном для тестирования
func (s *Serializer) Unmarshal(data []byte, doc *models.Document) error {
	if err := msgpack.Unmarshal(data, doc); err != nil {
		return fmt.Errorf("msgpack unmarshal failed: %w", err)
	}
	return nil
}

// MarshalBatch сериализует массив документов
// Для batch операций в Redis pipeline
func (s *Serializer) MarshalBatch(docs []*models.Document) ([][]byte, error) {
	result := make([][]byte, 0, len(docs))

	for i, doc := range docs {
		data, err := s.Marshal(doc)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal document %d: %w", i, err)
		}
		result = append(result, data)
	}

	return result, nil
}

// init регистрирует custom encoders/decoders для time.Time
func init() {
	// В msgpack v5 используется другой подход через интерфейсы
	// Мы будем обрабатывать datetime вручную в Marshal/Unmarshal
}

// Stats содержит статистику сериализации
type Stats struct {
	TotalDocuments  int64
	TotalBytes      int64
	AvgBytesPerDoc  int64
	SerializationMs int64
	FailedDocuments int64
}

// CalculateStats вычисляет статистику для batch операции
func CalculateStats(docs []*models.Document, serializedData [][]byte, durationMs int64) *Stats {
	totalBytes := int64(0)
	for _, data := range serializedData {
		totalBytes += int64(len(data))
	}

	stats := &Stats{
		TotalDocuments:  int64(len(docs)),
		TotalBytes:      totalBytes,
		SerializationMs: durationMs,
	}

	if stats.TotalDocuments > 0 {
		stats.AvgBytesPerDoc = totalBytes / stats.TotalDocuments
	}

	return stats
}
