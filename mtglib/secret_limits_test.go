package mtglib

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseQuotaBytes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"  ", 0, false},
		{"1024", 1024, false},
		{"1KiB", 1024, false},
		{"1KB", 1024, false},
		{"10GB", 10 * 1024 * 1024 * 1024, false},
		{"500 MiB", 500 * 1024 * 1024, false},
		{"nonsense", 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseQuotaBytes(tc.in)
			if tc.wantErr {
				assert.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseQuotaReset(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"", "none", "NONE", "monthly", "Monthly"} {
		got, err := ParseQuotaReset(in)
		require.NoError(t, err)

		if in == "monthly" || in == "Monthly" {
			assert.Equal(t, QuotaResetMonthly, got)
		} else {
			assert.Equal(t, QuotaResetNone, got)
		}
	}

	_, err := ParseQuotaReset("weekly")
	assert.Error(t, err)
}

func TestParseExpiry(t *testing.T) {
	t.Parallel()

	empty, err := ParseExpiry("")
	require.NoError(t, err)
	assert.True(t, empty.IsZero())

	date, err := ParseExpiry("2026-12-31")
	require.NoError(t, err)
	assert.Equal(t, 2026, date.Year())
	assert.Equal(t, time.December, date.Month())

	ts, err := ParseExpiry("2026-01-02T15:04:05Z")
	require.NoError(t, err)
	assert.Equal(t, 15, ts.Hour())

	_, err = ParseExpiry("31/12/2026")
	assert.Error(t, err)
}

func TestSecretLimitsIsZero(t *testing.T) {
	t.Parallel()

	assert.True(t, SecretLimits{}.IsZero())
	assert.False(t, SecretLimits{QuotaBytes: 1}.IsZero())
	assert.False(t, SecretLimits{Disabled: true}.IsZero())
	assert.False(t, SecretLimits{QuotaReset: QuotaResetMonthly}.IsZero())
	assert.False(t, SecretLimits{ExpiresAt: time.Now()}.IsZero())
}

func TestQuotaResetString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "none", QuotaResetNone.String())
	assert.Equal(t, "monthly", QuotaResetMonthly.String())
}

func TestDenyReasonString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "allowed", DenyNone.String())
	assert.Equal(t, "disabled", DenyDisabled.String())
	assert.Equal(t, "expired", DenyExpired.String())
	assert.Equal(t, "quota_exceeded", DenyQuota.String())
}
