package mtglib

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/units"
)

// QuotaReset defines how a per-secret data quota is replenished.
type QuotaReset int32

const (
	// QuotaResetNone means the quota is a single lifetime allowance that is
	// never automatically replenished (it can still be cleared explicitly via
	// the management API).
	QuotaResetNone QuotaReset = iota

	// QuotaResetMonthly means the used-bytes counter is reset to zero at the
	// start of every calendar month.
	QuotaResetMonthly
)

// String returns the config/API spelling of the reset policy.
func (q QuotaReset) String() string {
	switch q {
	case QuotaResetMonthly:
		return "monthly"
	default:
		return "none"
	}
}

// SecretLimits carries the optional per-user governance limits attached to a
// named secret: a data quota (with an optional monthly reset), a validity
// deadline, and an on/off switch. The zero value means "no limits" — unlimited
// traffic, never expires, enabled — so a secret without an entry is unrestricted.
type SecretLimits struct {
	// QuotaBytes is the maximum number of relayed bytes (client read + write)
	// allowed in the current quota period. 0 means unlimited.
	QuotaBytes int64

	// QuotaReset selects how QuotaBytes is replenished.
	QuotaReset QuotaReset

	// ExpiresAt is the instant after which the secret stops working. The zero
	// time means the secret never expires.
	ExpiresAt time.Time

	// Disabled, when true, rejects every new connection for the secret without
	// removing it from the set.
	Disabled bool
}

// IsZero reports whether the limits impose no restriction at all, i.e. the
// secret is unlimited, never-expiring and enabled. Callers use it to avoid
// materialising empty entries in maps and API responses.
func (l SecretLimits) IsZero() bool {
	return l.QuotaBytes == 0 && l.QuotaReset == QuotaResetNone &&
		l.ExpiresAt.IsZero() && !l.Disabled
}

// DenyReason explains why a connection was refused by the per-user limits.
type DenyReason int

const (
	// DenyNone means the connection is allowed.
	DenyNone DenyReason = iota

	// DenyDisabled means the secret is administratively disabled.
	DenyDisabled

	// DenyExpired means the secret's expiry deadline has passed.
	DenyExpired

	// DenyQuota means the secret has used up its data quota.
	DenyQuota
)

// String returns a short machine-friendly reason label for logs.
func (d DenyReason) String() string {
	switch d {
	case DenyDisabled:
		return "disabled"
	case DenyExpired:
		return "expired"
	case DenyQuota:
		return "quota_exceeded"
	default:
		return "allowed"
	}
}

// quotaBytesCleaner mirrors the config parser so the management API accepts the
// same human-friendly sizes as the config file ("10GB", "500 MiB", ...).
var quotaBytesCleaner = strings.NewReplacer(" ", "", "\t", "", "IB", "iB")

// ParseQuotaBytes parses a byte size as a bare integer count ("1048576") or a
// human-friendly unit form ("10GB", "500MiB", ...). An empty string yields 0
// (unlimited).
func ParseQuotaBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}

	// A bare integer is interpreted as a plain byte count.
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n < 0 {
			return 0, fmt.Errorf("quota must be positive (%q)", s)
		}

		return n, nil
	}

	parsed, err := units.ParseBase2Bytes(quotaBytesCleaner.Replace(strings.ToUpper(s)))
	if err != nil {
		return 0, fmt.Errorf("incorrect quota value (%q): %w", s, err)
	}

	if parsed < 0 {
		return 0, fmt.Errorf("quota must be positive (%q)", s)
	}

	return int64(parsed), nil
}

// ParseQuotaReset parses the reset policy spelling. Empty and "none" both map to
// QuotaResetNone.
func ParseQuotaReset(s string) (QuotaReset, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none":
		return QuotaResetNone, nil
	case "monthly":
		return QuotaResetMonthly, nil
	default:
		return QuotaResetNone, fmt.Errorf("unknown quota reset %q (want \"none\" or \"monthly\")", s)
	}
}

// ParseExpiry parses an expiry deadline in RFC3339 ("2026-12-31T00:00:00Z") or
// plain date ("2026-12-31") form. An empty string yields the zero time (never).
func ParseExpiry(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}

	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}

	if t, err := time.Parse(time.DateOnly, s); err == nil {
		return t, nil
	}

	return time.Time{}, fmt.Errorf("invalid expiry %q (want RFC3339 or YYYY-MM-DD)", s)
}
