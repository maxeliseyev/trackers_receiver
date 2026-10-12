package serialization

import (
	"bytes"
	"fmt"

	"trackers-receiver/pkg/models"

	"github.com/vmihailenco/msgpack/v5"
)

// Serializer encodes documents as the Python receiver did; see
// models.Document.EncodeMsgpack for the layout.
type Serializer struct{}

func NewSerializer() *Serializer {
	return &Serializer{}
}

func (s *Serializer) Marshal(doc *models.Document) ([]byte, error) {
	var buf bytes.Buffer
	enc := msgpack.NewEncoder(&buf)
	// Like Python's msgpack: the smallest integer encoding, and maps in a
	// stable order so that equal documents encode to equal bytes.
	enc.UseCompactInts(true)
	enc.SetSortMapKeys(true)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("msgpack marshal failed: %w", err)
	}
	return buf.Bytes(), nil
}
