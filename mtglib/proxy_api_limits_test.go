package mtglib

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func findSecret(infos []SecretInfo, name string) *SecretInfo {
	for i := range infos {
		if infos[i].Name == name {
			return &infos[i]
		}
	}

	return nil
}

func TestAPISecretLimits(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	bob := GenerateSecret("bob.example.com")

	t.Run("POST sets quota/expiry/disabled and GET reflects them", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		body := `{"name":"bob","secret":"` + bob.Hex() +
			`","quota":"1MB","quota_reset":"monthly","expires":"2030-01-01","disabled":true}`
		require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPost, "/secrets", body).Code)

		rec := doAPI(t, p, "", http.MethodGet, "/secrets", "")
		require.Equal(t, http.StatusOK, rec.Code)

		var resp struct {
			Secrets []SecretInfo `json:"secrets"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

		got := findSecret(resp.Secrets, "bob")
		require.NotNil(t, got)
		assert.Equal(t, int64(1024*1024), got.Quota)
		assert.Equal(t, "monthly", got.QuotaReset)
		assert.True(t, got.Disabled)
		require.NotNil(t, got.ExpiresAt)
		assert.Equal(t, 2030, got.ExpiresAt.Year())
	})

	t.Run("POST with an invalid quota is 400", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		body := `{"name":"bob","secret":"` + bob.Hex() + `","quota":"banana"}`
		assert.Equal(t, http.StatusBadRequest, doAPI(t, p, "", http.MethodPost, "/secrets", body).Code)
	})

	t.Run("POST with an invalid expiry is 400", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		body := `{"name":"bob","secret":"` + bob.Hex() + `","expires":"soon"}`
		assert.Equal(t, http.StatusBadRequest, doAPI(t, p, "", http.MethodPost, "/secrets", body).Code)
	})

	t.Run("disabling a secret closes its live streams immediately", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		stream := registerFakeStream(p, "alice")

		body := `{"name":"alice","secret":"` + alice.Hex() + `","disabled":true}`
		require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPost, "/secrets", body).Code)

		assert.Error(t, stream.Err(), "disabling a secret must drop its live streams")
	})

	t.Run("reset-quota zeroes usage", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		p.stats.users["alice"].quotaUsed.Store(999)

		require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPost, "/secrets/alice/reset-quota", "").Code)
		assert.Equal(t, int64(0), p.stats.users["alice"].quotaUsed.Load())
	})

	t.Run("reset-quota of an unknown secret is 404", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		assert.Equal(t, http.StatusNotFound, doAPI(t, p, "", http.MethodPost, "/secrets/ghost/reset-quota", "").Code)
	})

	t.Run("GET /stats reports quota usage and remaining", func(t *testing.T) {
		t.Parallel()

		p := newAPITestProxy(map[string]Secret{"alice": alice})
		body := `{"secrets":{"alice":{"secret":"` + alice.Hex() + `","quota":"1000"}}}`
		require.Equal(t, http.StatusOK, doAPI(t, p, "", http.MethodPut, "/secrets", body).Code)
		p.stats.users["alice"].quotaUsed.Store(250)

		rec := doAPI(t, p, "", http.MethodGet, "/stats", "")
		require.Equal(t, http.StatusOK, rec.Code)

		var resp StatsResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

		u := resp.Users["alice"]
		assert.Equal(t, int64(1000), u.Quota)
		assert.Equal(t, int64(250), u.QuotaUsed)
		require.NotNil(t, u.QuotaRemaining)
		assert.Equal(t, int64(750), *u.QuotaRemaining)
	})
}
