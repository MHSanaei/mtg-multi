package mtglib

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type noopReloadLogger struct{}

func (n noopReloadLogger) Named(string) Logger            { return n }
func (n noopReloadLogger) BindInt(string, int) Logger     { return n }
func (n noopReloadLogger) BindStr(string, string) Logger  { return n }
func (n noopReloadLogger) BindJSON(string, string) Logger { return n }
func (n noopReloadLogger) Printf(string, ...any)          {}
func (n noopReloadLogger) Info(string)                    {}
func (n noopReloadLogger) InfoError(string, error)        {}
func (n noopReloadLogger) Warning(string)                 {}
func (n noopReloadLogger) WarningError(string, error)     {}
func (n noopReloadLogger) Debug(string)                   {}
func (n noopReloadLogger) DebugError(string, error)       {}

func testLogger() Logger { return noopReloadLogger{} }

func TestBuildSecretSet(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("shared.example.com")
	bob := GenerateSecret("shared.example.com")
	carol := GenerateSecret("carol.example.com")

	set := buildSecretSet(map[string]Secret{"bob": bob, "alice": alice, "carol": carol}, nil, nil)

	assert.Equal(t, []string{"alice", "bob", "carol"}, set.names)
	require.Len(t, set.secrets, 3)
	assert.Equal(t, alice.Key, set.secrets[0].Key)
	assert.Equal(t, bob.Key, set.secrets[1].Key)
	assert.Equal(t, carol.Key, set.secrets[2].Key)
	assert.Equal(t, []string{"carol.example.com", "shared.example.com"}, set.hostnames)
}

func newReloadTestProxy(secrets map[string]Secret) *Proxy {
	p := &Proxy{
		stats:     NewProxyStats(),
		liveConns: make(map[string]map[*streamContext]struct{}),
	}
	set := buildSecretSet(secrets, nil, nil)

	for _, name := range set.names {
		p.stats.PreRegister(name)
	}

	p.secrets.Store(set)

	return p
}

func registerFakeStream(p *Proxy, secretName string) *streamContext {
	ctx, cancel := context.WithCancel(context.Background())
	sc := &streamContext{ctx: ctx, ctxCancel: cancel, secretName: secretName}
	p.registerConn(sc)

	return sc
}

func TestProxyReloadSecrets(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	bob := GenerateSecret("bob.example.com")

	t.Run("removed secret closes its streams and keeps the rest", func(t *testing.T) {
		t.Parallel()

		p := newReloadTestProxy(map[string]Secret{"alice": alice, "bob": bob})
		p.reloader = func() (SecretConfig, error) {
			return SecretConfig{Secrets: map[string]Secret{"alice": alice}}, nil
		}

		aliceStream := registerFakeStream(p, "alice")
		bobStream := registerFakeStream(p, "bob")

		require.NoError(t, p.ReloadSecrets())

		assert.Equal(t, []string{"alice"}, p.secrets.Load().names)
		assert.NoError(t, aliceStream.Err())
		assert.ErrorIs(t, bobStream.Err(), context.Canceled)
	})

	t.Run("re-keyed secret closes its old streams", func(t *testing.T) {
		t.Parallel()

		p := newReloadTestProxy(map[string]Secret{"alice": alice})
		rekeyed := GenerateSecret("alice.example.com")
		p.reloader = func() (SecretConfig, error) {
			return SecretConfig{Secrets: map[string]Secret{"alice": rekeyed}}, nil
		}

		stream := registerFakeStream(p, "alice")

		require.NoError(t, p.ReloadSecrets())

		assert.Equal(t, rekeyed.Key, p.secrets.Load().secrets[0].Key)
		assert.ErrorIs(t, stream.Err(), context.Canceled)
	})

	t.Run("added secret is pre-registered and disturbs nothing", func(t *testing.T) {
		t.Parallel()

		p := newReloadTestProxy(map[string]Secret{"alice": alice})
		p.reloader = func() (SecretConfig, error) {
			return SecretConfig{Secrets: map[string]Secret{"alice": alice, "bob": bob}}, nil
		}

		stream := registerFakeStream(p, "alice")

		require.NoError(t, p.ReloadSecrets())

		assert.Equal(t, []string{"alice", "bob"}, p.secrets.Load().names)
		assert.NoError(t, stream.Err())

		p.stats.mu.RLock()
		_, hasBob := p.stats.users["bob"]
		p.stats.mu.RUnlock()
		assert.True(t, hasBob, "the new secret must appear in stats immediately")
	})

	t.Run("no reloader is a typed error", func(t *testing.T) {
		t.Parallel()

		p := newReloadTestProxy(map[string]Secret{"alice": alice})

		assert.ErrorIs(t, p.ReloadSecrets(), ErrReloaderNotConfigured)
	})

	t.Run("reloader failure keeps the current set", func(t *testing.T) {
		t.Parallel()

		p := newReloadTestProxy(map[string]Secret{"alice": alice})
		p.reloader = func() (SecretConfig, error) {
			return SecretConfig{}, errors.New("cannot read config")
		}

		assert.Error(t, p.ReloadSecrets())
		assert.Equal(t, []string{"alice"}, p.secrets.Load().names)
	})

	t.Run("empty secret set is rejected and the current set survives", func(t *testing.T) {
		t.Parallel()

		p := newReloadTestProxy(map[string]Secret{"alice": alice})
		p.reloader = func() (SecretConfig, error) {
			return SecretConfig{Secrets: map[string]Secret{}}, nil
		}

		assert.ErrorIs(t, p.ReloadSecrets(), ErrSecretInvalid)
		assert.Equal(t, []string{"alice"}, p.secrets.Load().names)
	})
}

func TestReloadHandler(t *testing.T) {
	t.Parallel()

	t.Run("POST runs the reload and returns ok", func(t *testing.T) {
		t.Parallel()

		called := false
		h := reloadHandler(func() error {
			called = true

			return nil
		}, testLogger())

		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodPost, "/reload", nil))

		assert.True(t, called)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
	})

	t.Run("GET is rejected", func(t *testing.T) {
		t.Parallel()

		h := reloadHandler(func() error { return nil }, testLogger())

		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/reload", nil))

		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		assert.Equal(t, http.MethodPost, rec.Header().Get("Allow"))
	})

	t.Run("missing reloader reports unavailable", func(t *testing.T) {
		t.Parallel()

		h := reloadHandler(nil, testLogger())

		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodPost, "/reload", nil))

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})

	t.Run("reload error surfaces as 500", func(t *testing.T) {
		t.Parallel()

		h := reloadHandler(func() error { return errors.New("bad config") }, testLogger())

		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodPost, "/reload", nil))

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
