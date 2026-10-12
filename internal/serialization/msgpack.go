package serialization

import (
	"fmt"

	"trackers-receiver/pkg/models"

	"github.com/vmihailenco/msgpack/v5"
)

// Serializer encodes documents in the MessagePack layout produced by the
// original Python receiver. time.Time uses msgpack's native timestamp extension.
type Serializer struct{}

func NewSerializer() *Serializer {
	return &Serializer{}
}

func (s *Serializer) Marshal(doc *models.Document) ([]byte, error) {
	if err := doc.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	data, err := msgpack.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("msgpack marshal failed: %w", err)
	}
	return data, nil
}

func (s *Serializer) Unmarshal(data []byte, doc *models.Document) error {
	if err := msgpack.Unmarshal(data, doc); err != nil {
		return fmt.Errorf("msgpack unmarshal failed: %w", err)
	}
	return nil
}
