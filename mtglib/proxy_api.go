package mtglib

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// SecretInfo is the JSON representation of a single named secret returned by
// GET /secrets. AdTag is the per-secret override (empty when none) and
// EffectiveAdTag is the tag actually applied after global fallback.
type SecretInfo struct {
	Name           string `json:"name"`
	Secret         string `json:"secret"`
	Host           string `json:"host"`
	AdTag          string `json:"ad_tag,omitempty"`
	EffectiveAdTag string `json:"effective_ad_tag,omitempty"`
}

// SnapshotSecrets returns the active secret set as a name-sorted list, exposing
// the secret material and both per-secret and effective advertising tags. It
// reads the atomic snapshot lock-free.
func (p *Proxy) SnapshotSecrets() []SecretInfo {
	set := p.secrets.Load()
	out := make([]SecretInfo, len(set.names))

	for i, name := range set.names {
		info := SecretInfo{
			Name:   name,
			Secret: set.secrets[i].Base64(),
			Host:   set.secrets[i].Host,
		}

		if set.adTags[i] != nil {
			info.AdTag = hex.EncodeToString(set.adTags[i][:])
		}

		if eff := set.effectiveAdTag(i); eff != nil {
			info.EffectiveAdTag = hex.EncodeToString(eff[:])
		}

		out[i] = info
	}

	return out
}

// ReplaceSecrets swaps the entire secret configuration (secrets + advertising
// tags) for cfg, going through the same validation, atomic swap and stale
// connection close as a file reload.
func (p *Proxy) ReplaceSecrets(cfg SecretConfig) error {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	return p.swapSecretConfigLocked(cfg)
}

// PutSecret adds or updates a single secret, optionally setting its per-secret
// advertising tag (nil clears the override). Only a key change closes that
// secret's live connections; an adtag-only change leaves them running because
// closeStaleConns keys on the secret key, not the tag.
func (p *Proxy) PutSecret(name string, s Secret, adTag *[AdTagLength]byte) error {
	if name == "" {
		return fmt.Errorf("%w: empty name", ErrSecretInvalid)
	}

	if !s.Valid() {
		return ErrSecretInvalid
	}

	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	cfg := p.secrets.Load().toConfig()
	cfg.Secrets[name] = s

	if adTag != nil {
		if cfg.SecretAdTags == nil {
			cfg.SecretAdTags = make(map[string][AdTagLength]byte)
		}

		cfg.SecretAdTags[name] = *adTag
	} else {
		delete(cfg.SecretAdTags, name)
	}

	return p.swapSecretConfigLocked(cfg)
}

// DeleteSecret removes a single secret and its advertising override. It returns
// ErrSecretNotFound for an unknown name and ErrLastSecret if the removal would
// empty the set. The removed secret's live connections are closed.
func (p *Proxy) DeleteSecret(name string) error {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	cfg := p.secrets.Load().toConfig()

	if _, ok := cfg.Secrets[name]; !ok {
		return ErrSecretNotFound
	}

	if len(cfg.Secrets) == 1 {
		return ErrLastSecret
	}

	delete(cfg.Secrets, name)
	delete(cfg.SecretAdTags, name)

	return p.swapSecretConfigLocked(cfg)
}

// GlobalAdTag returns the currently active global advertising tag, or nil when
// none is set.
func (p *Proxy) GlobalAdTag() *[AdTagLength]byte {
	return p.secrets.Load().globalAdTag
}

// SetGlobalAdTag sets (or, with nil, clears) the global advertising tag. It does
// not close any live connection: the tag only affects how new connections are
// routed.
func (p *Proxy) SetGlobalAdTag(tag *[AdTagLength]byte) error {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	cfg := p.secrets.Load().toConfig()
	cfg.GlobalAdTag = tag

	return p.swapSecretConfigLocked(cfg)
}

// startAPIServer starts the management HTTP API in background goroutines and
// shuts it down when ctx is cancelled. It supersedes ProxyStats.StartServer:
// the mux is built with access to the whole proxy so it can serve the secrets
// and adtag routes in addition to /stats and /reload.
func (p *Proxy) startAPIServer(ctx context.Context, bindTo, token string) {
	srv := &http.Server{
		Addr:    bindTo,
		Handler: p.buildAPIHandler(token),
	}

	ln, err := net.Listen("tcp", bindTo)
	if err != nil {
		p.logger.WarningError("cannot start management API listener", err)

		return
	}

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			p.logger.WarningError("management API server error", err)
		}
	}()

	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second) //nolint: mnd
		defer cancel()

		srv.Shutdown(shutdownCtx) //nolint: errcheck
	}()

	authState := "unauthenticated"
	if token != "" {
		authState = "bearer-token"
	}

	p.logger.BindStr("bind", bindTo).BindStr("auth", authState).Info("Management API server started")
}

// buildAPIHandler wires every management route and wraps the mux in the bearer
// token middleware. When p has no file reloader, /reload keeps reporting the
// capability as unavailable (503).
func (p *Proxy) buildAPIHandler(token string) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/stats", p.stats)

	var reload func() error
	if p.reloader != nil {
		reload = p.ReloadSecrets
	}

	mux.HandleFunc("/reload", reloadHandler(reload, p.logger))

	mux.HandleFunc("GET /secrets", p.handleGetSecrets)
	mux.HandleFunc("PUT /secrets", p.handlePutSecrets)
	mux.HandleFunc("POST /secrets", p.handlePostSecret)
	mux.HandleFunc("DELETE /secrets/{name}", p.handleDeleteSecret)

	mux.HandleFunc("GET /adtag", p.handleGetAdTag)
	mux.HandleFunc("PUT /adtag", p.handlePutAdTag)
	mux.HandleFunc("DELETE /adtag", p.handleDeleteAdTag)

	return withAuth(token, mux)
}

// withAuth guards next with an optional bearer token. An empty token is a
// pass-through, preserving the previous no-auth, localhost-bind behavior. The
// comparison is constant-time to avoid leaking the token through timing.
func withAuth(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}

	expected := []byte("Bearer " + token)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))

		if subtle.ConstantTimeCompare(got, expected) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)

			return
		}

		next.ServeHTTP(w, r)
	})
}

func (p *Proxy) handleGetSecrets(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"secrets": p.SnapshotSecrets()})
}

type secretEntry struct {
	Secret string `json:"secret"`
	AdTag  string `json:"ad_tag,omitempty"`
}

type putSecretsRequest struct {
	Secrets map[string]secretEntry `json:"secrets"`
	AdTag   string                 `json:"ad_tag,omitempty"`
}

func (p *Proxy) handlePutSecrets(w http.ResponseWriter, r *http.Request) {
	var req putSecretsRequest

	if !decodeJSON(w, r, &req) {
		return
	}

	cfg := SecretConfig{
		Secrets:      make(map[string]Secret, len(req.Secrets)),
		SecretAdTags: make(map[string][AdTagLength]byte),
	}

	for name, entry := range req.Secrets {
		secret, err := ParseSecret(entry.Secret)
		if err != nil {
			httpError(w, http.StatusBadRequest, fmt.Errorf("invalid secret %q: %w", name, err))

			return
		}

		cfg.Secrets[name] = secret

		tag, err := parseAdTagHex(entry.AdTag)
		if err != nil {
			httpError(w, http.StatusBadRequest, fmt.Errorf("invalid ad_tag for %q: %w", name, err))

			return
		}

		if tag != nil {
			cfg.SecretAdTags[name] = *tag
		}
	}

	global, err := parseAdTagHex(req.AdTag)
	if err != nil {
		httpError(w, http.StatusBadRequest, fmt.Errorf("invalid ad_tag: %w", err))

		return
	}

	cfg.GlobalAdTag = global

	if err := p.ReplaceSecrets(cfg); err != nil {
		httpError(w, secretMutationStatus(err), err)

		return
	}

	writeJSON(w, http.StatusOK, statusOK)
}

type postSecretRequest struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
	AdTag  string `json:"ad_tag,omitempty"`
}

func (p *Proxy) handlePostSecret(w http.ResponseWriter, r *http.Request) {
	var req postSecretRequest

	if !decodeJSON(w, r, &req) {
		return
	}

	secret, err := ParseSecret(req.Secret)
	if err != nil {
		httpError(w, http.StatusBadRequest, fmt.Errorf("invalid secret: %w", err))

		return
	}

	tag, err := parseAdTagHex(req.AdTag)
	if err != nil {
		httpError(w, http.StatusBadRequest, fmt.Errorf("invalid ad_tag: %w", err))

		return
	}

	if err := p.PutSecret(req.Name, secret, tag); err != nil {
		httpError(w, secretMutationStatus(err), err)

		return
	}

	writeJSON(w, http.StatusOK, statusOK)
}

func (p *Proxy) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	if err := p.DeleteSecret(name); err != nil {
		httpError(w, secretMutationStatus(err), err)

		return
	}

	writeJSON(w, http.StatusOK, statusOK)
}

func (p *Proxy) handleGetAdTag(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]any{"ad_tag": nil}

	if tag := p.GlobalAdTag(); tag != nil {
		resp["ad_tag"] = hex.EncodeToString(tag[:])
	}

	writeJSON(w, http.StatusOK, resp)
}

type putAdTagRequest struct {
	AdTag string `json:"ad_tag"`
}

func (p *Proxy) handlePutAdTag(w http.ResponseWriter, r *http.Request) {
	var req putAdTagRequest

	if !decodeJSON(w, r, &req) {
		return
	}

	tag, err := parseAdTagHex(req.AdTag)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)

		return
	}

	if tag == nil {
		httpError(w, http.StatusBadRequest, errors.New("ad_tag is required; use DELETE /adtag to clear it"))

		return
	}

	if err := p.SetGlobalAdTag(tag); err != nil {
		httpError(w, secretMutationStatus(err), err)

		return
	}

	writeJSON(w, http.StatusOK, statusOK)
}

func (p *Proxy) handleDeleteAdTag(w http.ResponseWriter, _ *http.Request) {
	if err := p.SetGlobalAdTag(nil); err != nil {
		httpError(w, secretMutationStatus(err), err)

		return
	}

	writeJSON(w, http.StatusOK, statusOK)
}

var statusOK = map[string]string{"status": "ok"}

// secretMutationStatus maps a mutation error to an HTTP status: 404 for an
// unknown secret, 409 when a delete would empty the set, and 400 for every
// validation failure (invalid secret, invalid/oversized adtag, empty set).
func secretMutationStatus(err error) int {
	switch {
	case errors.Is(err, ErrSecretNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrLastSecret):
		return http.StatusConflict
	default:
		return http.StatusBadRequest
	}
}

// parseAdTagHex decodes a hex advertising tag. An empty string yields (nil,
// nil) — meaning "no tag" — and any non-empty value must decode to exactly
// AdTagLength bytes.
func parseAdTagHex(s string) (*[AdTagLength]byte, error) {
	if s == "" {
		return nil, nil
	}

	decoded, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("ad_tag must be a hex string: %w", err)
	}

	if len(decoded) != AdTagLength {
		return nil, fmt.Errorf("ad_tag must be %d bytes (%d hex chars), got %d",
			AdTagLength, AdTagLength*2, len(decoded))
	}

	var out [AdTagLength]byte

	copy(out[:], decoded)

	return &out, nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		httpError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))

		return false
	}

	return true
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(body) //nolint: errcheck
}

func httpError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}
