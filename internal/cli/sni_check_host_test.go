package cli

import (
	"context"
	"net"
	"testing"

	"github.com/mhsanaei/mtg-multi/internal/config"
	"github.com/stretchr/testify/require"
)

// TestRunSNICheckUsesExplicitHost covers the multi-secret contract that
// differs from upstream: runSNICheck must resolve the host it is given, not
// conf.Secret.Host, which is empty when the config uses [secrets].
func TestRunSNICheckUsesExplicitHost(t *testing.T) {
	const ourV4 = "192.0.2.4" // RFC 5737 TEST-NET-1

	resolver := startSNITestDNS(t, net.ParseIP(ourV4), net.ParseIP("2001:db8::1"))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() }) //nolint: errcheck

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			conn.Close() //nolint: errcheck
		}
	}()

	ntw := &ipv4OnlyEgressNetwork{
		listenerAddr: listener.Addr().String(),
		detectedV4:   ourV4,
	}

	conf := &config.Config{} // Secret.Host deliberately empty

	res, err := runSNICheck(context.Background(), conf, resolver, ntw, "first-secret.test")
	require.NoError(t, err)
	require.Equal(t, ourV4, res.OurIP4)
	require.Contains(t, res.ResolvedIP4, ourV4)

	_, err = runSNICheck(context.Background(), conf, resolver, ntw, "")
	require.Error(t, err, "empty host must not silently pass")
}
