package mtglib

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newLimitTestProxy(secrets map[string]Secret, limits map[string]SecretLimits) *Proxy {
	p := &Proxy{
		stats:     NewProxyStats(),
		liveConns: make(map[string]map[*streamContext]struct{}),
		logger:    testLogger(),
	}

	set := buildSecretSet(secrets, nil, nil, limits)
	for _, name := range set.names {
		p.stats.PreRegister(name)
	}

	p.secrets.Store(set)

	return p
}

func TestCheckLimits(t *testing.T) {
	t.Parallel()

	p := newLimitTestProxy(map[string]Secret{"alice": GenerateSecret("alice.example.com")}, nil)
	p.stats.users["alice"].quotaUsed.Store(1000)

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	cases := []struct {
		name       string
		lim        SecretLimits
		wantOK     bool
		wantReason DenyReason
	}{
		{"no limits", SecretLimits{}, true, DenyNone},
		{"disabled", SecretLimits{Disabled: true}, false, DenyDisabled},
		{"expired", SecretLimits{ExpiresAt: past}, false, DenyExpired},
		{"not yet expired", SecretLimits{ExpiresAt: future}, true, DenyNone},
		{"under quota", SecretLimits{QuotaBytes: 2000}, true, DenyNone},
		{"at quota", SecretLimits{QuotaBytes: 1000}, false, DenyQuota},
		{"over quota", SecretLimits{QuotaBytes: 500}, false, DenyQuota},
		{"disabled beats quota", SecretLimits{Disabled: true, QuotaBytes: 5000}, false, DenyDisabled},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := p.checkLimits("alice", tc.lim)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.wantReason, reason)
		})
	}
}

func TestCloseDeniedConns(t *testing.T) {
	t.Parallel()

	secrets := map[string]Secret{
		"disabled": GenerateSecret("d.example.com"),
		"expired":  GenerateSecret("e.example.com"),
		"quota":    GenerateSecret("q.example.com"),
		"ok":       GenerateSecret("o.example.com"),
	}
	limits := map[string]SecretLimits{
		"disabled": {Disabled: true},
		"expired":  {ExpiresAt: time.Now().Add(-time.Hour)},
		"quota":    {QuotaBytes: 100},
		"ok":       {QuotaBytes: 1_000_000},
	}

	p := newLimitTestProxy(secrets, limits)
	p.stats.users["quota"].quotaUsed.Store(500) // over quota

	streams := map[string]*streamContext{}
	for name := range secrets {
		streams[name] = registerFakeStream(p, name)
	}

	p.closeDeniedConns()

	assert.ErrorIs(t, streams["disabled"].Err(), context.Canceled, "disabled secret's stream must be closed")
	assert.ErrorIs(t, streams["expired"].Err(), context.Canceled, "expired secret's stream must be closed")
	assert.NoError(t, streams["quota"].Err(), "over-quota stream must NOT be killed mid-flight")
	assert.NoError(t, streams["ok"].Err(), "healthy stream must stay connected")
}

func TestQuotaMonthlyRollover(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	stats.PreRegister("alice")
	stats.users["alice"].quotaUsed.Store(500)

	lastMonth := time.Now().AddDate(0, -1, 0)
	stats.users["alice"].periodStart.Store(lastMonth.UnixNano())

	// A monthly reset zeroes usage when the calendar month has changed.
	used := stats.QuotaUsed("alice", QuotaResetMonthly)
	assert.Equal(t, int64(0), used)

	// A "none" policy never rolls over.
	stats.users["alice"].quotaUsed.Store(500)
	stats.users["alice"].periodStart.Store(lastMonth.UnixNano())
	assert.Equal(t, int64(500), stats.QuotaUsed("alice", QuotaResetNone))
}

func TestQuotaSameMonthNoRollover(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	stats.PreRegister("alice")
	stats.users["alice"].quotaUsed.Store(500)
	stats.users["alice"].periodStart.Store(time.Now().UnixNano())

	assert.Equal(t, int64(500), stats.QuotaUsed("alice", QuotaResetMonthly))
}

func TestResetQuota(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	stats.PreRegister("alice")
	stats.users["alice"].quotaUsed.Store(1234)

	before := time.Now()
	stats.ResetQuota("alice")

	assert.Equal(t, int64(0), stats.users["alice"].quotaUsed.Load())
	assert.GreaterOrEqual(t, stats.users["alice"].periodStart.Load(), before.UnixNano())
}

func TestLoadFlushUsageRoundTrip(t *testing.T) {
	t.Parallel()

	path := t.TempDir() + "/usage.json"
	period := time.Now().Add(-48 * time.Hour).UnixNano()

	src := NewProxyStats()
	src.PreRegister("alice")
	src.users["alice"].quotaUsed.Store(7777)
	src.users["alice"].periodStart.Store(period)

	require.NoError(t, src.FlushUsage(path))

	dst := NewProxyStats()
	require.NoError(t, dst.LoadUsage(path))

	assert.Equal(t, int64(7777), dst.users["alice"].quotaUsed.Load())
	assert.Equal(t, period, dst.users["alice"].periodStart.Load())
}

func TestLoadUsageMissingFileIsOK(t *testing.T) {
	t.Parallel()

	stats := NewProxyStats()
	assert.NoError(t, stats.LoadUsage(t.TempDir()+"/does-not-exist.json"))
}

func TestSwapPreservesUsage(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	p := newLimitTestProxy(map[string]Secret{"alice": alice}, map[string]SecretLimits{
		"alice": {QuotaBytes: 1000},
	})
	p.stats.users["alice"].quotaUsed.Store(400)

	// Reloading with a larger quota must not wipe the usage counter.
	require.NoError(t, p.ReplaceSecrets(SecretConfig{
		Secrets: map[string]Secret{"alice": alice},
		Limits:  map[string]SecretLimits{"alice": {QuotaBytes: 5000}},
	}))

	assert.Equal(t, int64(400), p.stats.users["alice"].quotaUsed.Load())
	assert.Equal(t, int64(5000), p.secrets.Load().limits[0].QuotaBytes)
}
