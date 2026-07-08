package mtglib

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// usageFlushInterval is how often persisted quota usage is written to disk and
// monthly quota periods are rolled over for display freshness.
const usageFlushInterval = 30 * time.Second

type secretStats struct {
	connections atomic.Int64
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64
	lastSeen    atomic.Value // stores time.Time

	// quotaUsed counts bytes against the current quota period (client read +
	// write). It is incremented by countingConn, reset by a monthly rollover or
	// an explicit ResetQuota, and persisted across restarts. Unlike
	// bytesIn/bytesOut it is not a lifetime display counter.
	quotaUsed atomic.Int64

	// periodStart is the unix-nano start of the current quota period, used to
	// detect monthly rollovers. 0 means "not started yet".
	periodStart atomic.Int64
}

// rolloverIfNeeded zeroes quotaUsed when the monthly quota period has elapsed.
// It is a no-op for any reset policy other than monthly. The first call for a
// monthly secret simply anchors the period start. Concurrent callers race
// harmlessly: a compare-and-swap ensures only one performs the reset.
func (st *secretStats) rolloverIfNeeded(reset QuotaReset, now time.Time) {
	if reset != QuotaResetMonthly {
		return
	}

	startNano := st.periodStart.Load()
	if startNano == 0 {
		st.periodStart.CompareAndSwap(0, now.UnixNano())

		return
	}

	start := time.Unix(0, startNano)
	if now.Year() != start.Year() || now.Month() != start.Month() {
		if st.periodStart.CompareAndSwap(startNano, now.UnixNano()) {
			st.quotaUsed.Store(0)
		}
	}
}

// ProxyStats tracks per-secret connection stats with atomic counters.
// Thread-safe for concurrent access from proxy goroutines.
type ProxyStats struct {
	mu        sync.RWMutex
	users     map[string]*secretStats
	startedAt time.Time

	// Throttle: per-user connection caps recomputed every throttleInterval.
	throttleMu       sync.RWMutex
	throttleCaps     map[string]int64
	throttleLimit    int64
	throttleInterval time.Duration
	throttleActive   atomic.Bool
}

// NewProxyStats creates a new ProxyStats instance.
func NewProxyStats() *ProxyStats {
	return &ProxyStats{
		users:     make(map[string]*secretStats),
		startedAt: time.Now(),
	}
}

func (s *ProxyStats) getOrCreate(name string) *secretStats {
	s.mu.RLock()
	st, ok := s.users[name]
	s.mu.RUnlock()

	if ok {
		return st
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if st, ok = s.users[name]; ok {
		return st
	}

	st = &secretStats{}
	st.lastSeen.Store(time.Time{})
	s.users[name] = st

	return st
}

// PreRegister adds a secret name to the stats map so it appears in output
// even if no connections have been made yet.
func (s *ProxyStats) PreRegister(name string) {
	s.getOrCreate(name)
}

// OnConnect increments the active connection count for the given secret.
func (s *ProxyStats) OnConnect(name string) {
	s.getOrCreate(name).connections.Add(1)
}

// OnDisconnect decrements the active connection count for the given secret.
func (s *ProxyStats) OnDisconnect(name string) {
	s.getOrCreate(name).connections.Add(-1)
}

// AddBytesIn adds to the bytes-in counter for the given secret.
func (s *ProxyStats) AddBytesIn(name string, n int64) {
	s.getOrCreate(name).bytesIn.Add(n)
}

// AddBytesOut adds to the bytes-out counter for the given secret.
func (s *ProxyStats) AddBytesOut(name string, n int64) {
	s.getOrCreate(name).bytesOut.Add(n)
}

// UpdateLastSeen sets the last-seen timestamp for the given secret to now.
func (s *ProxyStats) UpdateLastSeen(name string) {
	s.getOrCreate(name).lastSeen.Store(time.Now())
}

// QuotaUsed returns the bytes counted against the secret's current quota period,
// rolling the monthly period over first when it is due.
func (s *ProxyStats) QuotaUsed(name string, reset QuotaReset) int64 {
	st := s.getOrCreate(name)
	st.rolloverIfNeeded(reset, time.Now())

	return st.quotaUsed.Load()
}

// quotaUsedValue returns the raw used-bytes counter without a rollover. It is
// used for display, where the periodic loop and connection gate keep the value
// fresh.
func (s *ProxyStats) quotaUsedValue(name string) int64 {
	s.mu.RLock()
	st, ok := s.users[name]
	s.mu.RUnlock()

	if !ok {
		return 0
	}

	return st.quotaUsed.Load()
}

// rollover applies a monthly quota rollover for a single secret if it is due.
func (s *ProxyStats) rollover(name string, reset QuotaReset, now time.Time) {
	s.getOrCreate(name).rolloverIfNeeded(reset, now)
}

// ResetQuota zeroes the used-bytes counter for the secret and restarts its quota
// period from now.
func (s *ProxyStats) ResetQuota(name string) {
	st := s.getOrCreate(name)
	st.quotaUsed.Store(0)
	st.periodStart.Store(time.Now().UnixNano())
}

// usageRecord is the persisted per-secret quota state.
type usageRecord struct {
	QuotaUsed   int64 `json:"quota_used"`
	PeriodStart int64 `json:"period_start"`
}

// LoadUsage restores persisted quota usage from path. A missing file is not an
// error (there is simply nothing to restore yet).
func (s *ProxyStats) LoadUsage(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return fmt.Errorf("cannot read usage state %s: %w", path, err)
	}

	var records map[string]usageRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return fmt.Errorf("cannot parse usage state %s: %w", path, err)
	}

	for name, rec := range records {
		st := s.getOrCreate(name)
		st.quotaUsed.Store(rec.QuotaUsed)
		st.periodStart.Store(rec.PeriodStart)
	}

	return nil
}

// FlushUsage writes the current quota usage of every known secret to path
// atomically (write-temp-then-rename), so a crash never leaves a truncated file.
func (s *ProxyStats) FlushUsage(path string) error {
	s.mu.RLock()
	records := make(map[string]usageRecord, len(s.users))

	for name, st := range s.users {
		records[name] = usageRecord{
			QuotaUsed:   st.quotaUsed.Load(),
			PeriodStart: st.periodStart.Load(),
		}
	}
	s.mu.RUnlock()

	data, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("cannot marshal usage state: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil { //nolint: mnd
		return fmt.Errorf("cannot write usage state %s: %w", tmp, err)
	}

	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("cannot replace usage state %s: %w", path, err)
	}

	return nil
}

// SetThrottle configures connection throttling. Must be called before
// startThrottleLoop and before any connections arrive.
func (s *ProxyStats) SetThrottle(limit int64, interval time.Duration) {
	s.throttleLimit = limit
	s.throttleInterval = interval
	s.throttleCaps = make(map[string]int64)
}

// CanConnect returns true if the user is allowed to open a new connection
// under the current throttle caps. If throttling is not configured or the
// user has no cap, it always returns true.
func (s *ProxyStats) CanConnect(name string) bool {
	if s.throttleLimit == 0 {
		return true
	}

	s.throttleMu.RLock()
	cap, hasCap := s.throttleCaps[name]
	s.throttleMu.RUnlock()

	if !hasCap {
		return true
	}

	return s.getOrCreate(name).connections.Load() < cap
}

// startThrottleLoop runs a background goroutine that recomputes per-user
// caps every throttleInterval.
func (s *ProxyStats) startThrottleLoop(ctx context.Context, logger Logger) {
	go func() {
		ticker := time.NewTicker(s.throttleInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.recomputeCaps(logger)
			}
		}
	}()

	logger.BindStr("limit", fmt.Sprintf("%d", s.throttleLimit)).
		BindStr("interval", s.throttleInterval.String()).
		Info("throttle loop started")
}

func (s *ProxyStats) recomputeCaps(logger Logger) {
	s.mu.RLock()
	userConns := make(map[string]int64, len(s.users))
	for name, st := range s.users {
		userConns[name] = st.connections.Load()
	}
	s.mu.RUnlock()

	caps := computeFairCaps(userConns, s.throttleLimit)
	wasActive := s.throttleActive.Load()
	nowActive := len(caps) > 0

	s.throttleMu.Lock()
	s.throttleCaps = caps
	s.throttleActive.Store(nowActive)
	s.throttleMu.Unlock()

	if nowActive && !wasActive {
		logger.Warning("throttle activated")
	} else if !nowActive && wasActive {
		logger.Info("throttle deactivated")
	}
}

// computeFairCaps implements the fair-share algorithm. Users below the equal
// share keep their connections; remaining budget is split equally among the
// rest. Returns nil when no throttling is needed.
func computeFairCaps(userConns map[string]int64, limit int64) map[string]int64 {
	var total int64
	for _, c := range userConns {
		total += c
	}

	if total <= limit {
		return nil
	}

	remaining := make(map[string]int64, len(userConns))
	maps.Copy(remaining, userConns)

	budget := limit
	caps := make(map[string]int64)

	for len(remaining) > 0 {
		fairShare := budget / int64(len(remaining))
		changed := false

		for name, conns := range remaining {
			if conns <= fairShare {
				budget -= conns
				delete(remaining, name)
				changed = true
			}
		}

		if !changed {
			for name := range remaining {
				caps[name] = fairShare
			}

			break
		}
	}

	return caps
}

// StatsResponse is the JSON response for the stats endpoint.
type StatsResponse struct {
	StartedAt        time.Time                `json:"started_at"`
	UptimeSeconds    int64                    `json:"uptime_seconds"`
	TotalConnections int64                    `json:"total_connections"`
	Throttle         *ThrottleJSON            `json:"throttle,omitempty"`
	Users            map[string]UserStatsJSON `json:"users"`
}

// ThrottleJSON is the throttle portion of the stats JSON response.
type ThrottleJSON struct {
	Active bool             `json:"active"`
	Limit  int64            `json:"limit"`
	Caps   map[string]int64 `json:"caps,omitempty"`
}

// UserStatsJSON is the per-user portion of the stats JSON response. The quota
// and expiry fields describe the secret's configured limits and are filled in by
// the proxy (which holds the secret snapshot); ProxyStats itself only fills the
// runtime counters, including QuotaUsed.
type UserStatsJSON struct {
	Connections int64      `json:"connections"`
	BytesIn     int64      `json:"bytes_in"`
	BytesOut    int64      `json:"bytes_out"`
	LastSeen    *time.Time `json:"last_seen"`

	QuotaUsed      int64      `json:"quota_used"`
	Quota          int64      `json:"quota,omitempty"`
	QuotaRemaining *int64     `json:"quota_remaining,omitempty"`
	QuotaReset     string     `json:"quota_reset,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	Disabled       bool       `json:"disabled,omitempty"`
}

// buildResponse assembles the base stats response (runtime counters and throttle
// state). Per-secret limit fields are left zero for the proxy to overlay.
func (s *ProxyStats) buildResponse() StatsResponse {
	s.mu.RLock()

	var totalConns int64

	users := make(map[string]UserStatsJSON, len(s.users))

	for name, st := range s.users {
		conns := st.connections.Load()
		totalConns += conns

		lastSeen := st.lastSeen.Load().(time.Time) //nolint: forcetypeassert
		var lastSeenPtr *time.Time
		if !lastSeen.IsZero() {
			lastSeenPtr = &lastSeen
		}

		users[name] = UserStatsJSON{
			Connections: conns,
			BytesIn:     st.bytesIn.Load(),
			BytesOut:    st.bytesOut.Load(),
			LastSeen:    lastSeenPtr,
			QuotaUsed:   st.quotaUsed.Load(),
		}
	}
	s.mu.RUnlock()

	var throttle *ThrottleJSON
	if s.throttleLimit > 0 {
		s.throttleMu.RLock()
		active := s.throttleActive.Load()

		var capsCopy map[string]int64
		if len(s.throttleCaps) > 0 {
			capsCopy = make(map[string]int64, len(s.throttleCaps))
			maps.Copy(capsCopy, s.throttleCaps)
		}

		s.throttleMu.RUnlock()

		throttle = &ThrottleJSON{
			Active: active,
			Limit:  s.throttleLimit,
			Caps:   capsCopy,
		}
	}

	return StatsResponse{
		StartedAt:        s.startedAt,
		UptimeSeconds:    int64(time.Since(s.startedAt).Seconds()),
		TotalConnections: totalConns,
		Throttle:         throttle,
		Users:            users,
	}
}

func (s *ProxyStats) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(s.buildResponse()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// The management HTTP API (GET /stats, POST /reload, /secrets and /adtag
// routes) is served by (*Proxy).startAPIServer in proxy_api.go, which builds a
// mux with access to the whole proxy. reloadHandler below is shared by that
// server for the /reload route.

// reloadHandler answers POST /reload by running reload and reporting the
// outcome: 200 on success, 405 for a non-POST, 503 when the proxy has no
// reloader wired, and 500 when the reload itself fails (the previous secret
// set stays active). A nil reload is treated as unavailable.
func reloadHandler(reload func() error, logger Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "only POST is allowed", http.StatusMethodNotAllowed)

			return
		}

		if reload == nil {
			http.Error(w, "reload is not supported", http.StatusServiceUnavailable)

			return
		}

		if err := reload(); err != nil {
			logger.WarningError("secret reload failed", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}` + "\n")) //nolint: errcheck
	}
}
