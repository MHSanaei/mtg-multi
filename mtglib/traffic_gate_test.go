package mtglib

import (
	"testing"

	"github.com/mhsanaei/mtg-multi/internal/testlib"
	"github.com/stretchr/testify/assert"
)

// TestWrapTrafficGating verifies that connTraffic (and thus per-read/write
// EventTraffic allocation) is only added when metrics are configured.
func TestWrapTrafficGating(t *testing.T) {
	t.Parallel()

	conn := &testlib.EssentialsConnMock{}
	ctx := &streamContext{streamID: "s"}

	t.Run("emitTraffic=false returns the bare conn", func(t *testing.T) {
		t.Parallel()

		p := &Proxy{emitTraffic: false}
		got := p.wrapTraffic(conn, ctx)

		_, wrapped := got.(connTraffic)
		assert.False(t, wrapped, "must not wrap when no metrics observer is configured")
		assert.True(t, got == conn, "must return the same conn unchanged")
	})

	t.Run("emitTraffic=true wraps in connTraffic", func(t *testing.T) {
		t.Parallel()

		p := &Proxy{emitTraffic: true}
		got := p.wrapTraffic(conn, ctx)

		_, wrapped := got.(connTraffic)
		assert.True(t, wrapped, "must wrap so traffic events reach the observers")
	})
}
