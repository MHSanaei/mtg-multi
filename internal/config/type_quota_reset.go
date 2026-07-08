package config

import (
	"github.com/mhsanaei/mtg-multi/mtglib"
)

// TypeQuotaReset is a per-secret data-quota reset policy: "none" (default) or
// "monthly".
type TypeQuotaReset struct {
	Value string
}

func (t *TypeQuotaReset) Set(value string) error {
	reset, err := mtglib.ParseQuotaReset(value)
	if err != nil {
		return err
	}

	t.Value = reset.String()

	return nil
}

func (t TypeQuotaReset) Get(defaultValue string) string {
	if t.Value == "" {
		return defaultValue
	}

	return t.Value
}

func (t *TypeQuotaReset) UnmarshalText(data []byte) error {
	return t.Set(string(data))
}

func (t TypeQuotaReset) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t TypeQuotaReset) String() string {
	return t.Value
}
