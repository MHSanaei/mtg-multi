package config

import (
	"time"

	"github.com/mhsanaei/mtg-multi/mtglib"
)

// TypeExpiry is a secret validity deadline parsed from an RFC3339 timestamp or a
// plain YYYY-MM-DD date. The zero value means the secret never expires.
type TypeExpiry struct {
	Value time.Time
}

func (t *TypeExpiry) Set(value string) error {
	parsed, err := mtglib.ParseExpiry(value)
	if err != nil {
		return err
	}

	t.Value = parsed

	return nil
}

func (t TypeExpiry) Get(defaultValue time.Time) time.Time {
	if t.Value.IsZero() {
		return defaultValue
	}

	return t.Value
}

func (t *TypeExpiry) UnmarshalText(data []byte) error {
	return t.Set(string(data))
}

func (t TypeExpiry) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeExpiry) String() string {
	if t.Value.IsZero() {
		return ""
	}

	return t.Value.Format(time.RFC3339)
}
