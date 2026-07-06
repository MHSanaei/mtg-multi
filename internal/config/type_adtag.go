package config

import (
	"encoding/hex"
	"fmt"

	"github.com/mhsanaei/mtg-multi/mtglib"
)

// TypeAdTag is a Telegram advertising tag (ad_tag / proxy tag). It is a
// 16-byte value, configured as a 32-character hex string, and used to route a
// client through Telegram middle proxies so a sponsored channel is shown.
type TypeAdTag struct {
	Value []byte
}

func (t *TypeAdTag) Set(value string) error {
	if value == "" {
		t.Value = nil

		return nil
	}

	decoded, err := hex.DecodeString(value)
	if err != nil {
		return fmt.Errorf("incorrect ad-tag, must be a hex string: %w", err)
	}

	if len(decoded) != mtglib.AdTagLength {
		return fmt.Errorf("ad-tag must be %d bytes (%d hex chars), got %d",
			mtglib.AdTagLength, mtglib.AdTagLength*2, len(decoded))
	}

	t.Value = decoded

	return nil
}

// Get returns the tag as a pointer to a fixed-size array, or nil when unset.
func (t *TypeAdTag) Get() *[mtglib.AdTagLength]byte {
	if len(t.Value) != mtglib.AdTagLength {
		return nil
	}

	var out [mtglib.AdTagLength]byte

	copy(out[:], t.Value)

	return &out
}

func (t *TypeAdTag) UnmarshalText(data []byte) error {
	return t.Set(string(data))
}

func (t TypeAdTag) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeAdTag) String() string {
	if len(t.Value) == 0 {
		return ""
	}

	return hex.EncodeToString(t.Value)
}
