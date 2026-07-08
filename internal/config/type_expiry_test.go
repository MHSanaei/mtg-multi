package config_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mhsanaei/mtg-multi/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTypeExpiry(t *testing.T) {
	t.Parallel()

	var e config.TypeExpiry

	require.NoError(t, e.Set("2026-12-31"))
	assert.Equal(t, 2026, e.Value.Year())
	assert.Equal(t, time.December, e.Value.Month())

	require.NoError(t, e.Set("2026-01-02T15:04:05Z"))
	assert.Equal(t, 15, e.Value.Hour())

	assert.Error(t, e.Set("not-a-date"))
}

func TestTypeExpiryGetDefault(t *testing.T) {
	t.Parallel()

	var zero config.TypeExpiry

	def := time.Unix(42, 0)
	assert.Equal(t, def, zero.Get(def))

	require.NoError(t, zero.Set("2026-06-15"))
	assert.Equal(t, 2026, zero.Get(def).Year())
}

func TestTypeExpiryJSON(t *testing.T) {
	t.Parallel()

	var holder struct {
		V config.TypeExpiry `json:"v"`
	}

	require.NoError(t, json.Unmarshal([]byte(`{"v":"2027-06-15"}`), &holder))
	assert.Equal(t, 2027, holder.V.Value.Year())

	assert.Error(t, json.Unmarshal([]byte(`{"v":"bogus"}`), &holder))
}
