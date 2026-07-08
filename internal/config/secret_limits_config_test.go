package config_test

import (
	"fmt"
	"testing"

	"github.com/mhsanaei/mtg-multi/internal/config"
	"github.com/mhsanaei/mtg-multi/mtglib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretLimitsParse(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("alice.example.com").Hex()
	bob := mtglib.GenerateSecret("bob.example.com").Hex()

	raw := fmt.Sprintf(`
bind-to = "10.0.0.1:443"
usage-state-file = "/var/lib/mtg/usage.json"

[secret-limits.alice]
quota = "10GB"
quota-reset = "monthly"
expires = "2030-01-01"
disabled = true

[secret-limits.bob]
quota = "500MB"

[secrets]
alice = "%s"
bob = "%s"
`, alice, bob)

	conf, err := config.Parse([]byte(raw))
	require.NoError(t, err)
	require.NoError(t, conf.Validate())

	assert.Equal(t, "/var/lib/mtg/usage.json", conf.UsageStateFile)

	limits := conf.GetSecretLimits()
	require.Len(t, limits, 2)

	a := limits["alice"]
	assert.Equal(t, int64(10*1024*1024*1024), a.QuotaBytes)
	assert.Equal(t, mtglib.QuotaResetMonthly, a.QuotaReset)
	assert.True(t, a.Disabled)
	assert.Equal(t, 2030, a.ExpiresAt.Year())

	b := limits["bob"]
	assert.Equal(t, int64(500*1024*1024), b.QuotaBytes)
	assert.Equal(t, mtglib.QuotaResetNone, b.QuotaReset)
	assert.False(t, b.Disabled)
	assert.True(t, b.ExpiresAt.IsZero())
}

func TestSecretLimitsUnknownSecretRejected(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("alice.example.com").Hex()

	raw := fmt.Sprintf(`
bind-to = "10.0.0.1:443"

[secret-limits.ghost]
quota = "1GB"

[secrets]
alice = "%s"
`, alice)

	conf, err := config.Parse([]byte(raw))
	require.NoError(t, err)
	assert.ErrorContains(t, conf.Validate(), "unknown secret")
}

func TestSecretLimitsAbsentIsNil(t *testing.T) {
	t.Parallel()

	alice := mtglib.GenerateSecret("alice.example.com").Hex()

	raw := fmt.Sprintf(`
bind-to = "10.0.0.1:443"

[secrets]
alice = "%s"
`, alice)

	conf, err := config.Parse([]byte(raw))
	require.NoError(t, err)
	require.NoError(t, conf.Validate())

	assert.Nil(t, conf.GetSecretLimits())
	assert.Empty(t, conf.UsageStateFile)
}
