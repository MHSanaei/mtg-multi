package config_test

import (
	"encoding/json"
	"testing"

	"github.com/mhsanaei/mtg-multi/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTypeQuotaReset(t *testing.T) {
	t.Parallel()

	var q config.TypeQuotaReset

	require.NoError(t, q.Set("monthly"))
	assert.Equal(t, "monthly", q.Value)

	require.NoError(t, q.Set("none"))
	assert.Equal(t, "none", q.Value)

	require.NoError(t, q.Set("MONTHLY"))
	assert.Equal(t, "monthly", q.Value)

	assert.Error(t, q.Set("weekly"))
}

func TestTypeQuotaResetGetDefault(t *testing.T) {
	t.Parallel()

	var zero config.TypeQuotaReset
	assert.Equal(t, "none", zero.Get("none"))
}

func TestTypeQuotaResetJSON(t *testing.T) {
	t.Parallel()

	var holder struct {
		V config.TypeQuotaReset `json:"v"`
	}

	require.NoError(t, json.Unmarshal([]byte(`{"v":"monthly"}`), &holder))
	assert.Equal(t, "monthly", holder.V.Value)

	assert.Error(t, json.Unmarshal([]byte(`{"v":"weekly"}`), &holder))
}
