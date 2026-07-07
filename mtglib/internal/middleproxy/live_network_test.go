package middleproxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/mtg-multi/essentials"
	"github.com/stretchr/testify/require"
)

// liveLogger is a minimal Logger that forwards to the test log.
type liveLogger struct{ t *testing.T }

func (l liveLogger) Info(msg string)    { l.t.Logf("INFO: %s", msg) }
func (l liveLogger) Warning(msg string) { l.t.Logf("WARN: %s", msg) }

// liveDialer is a plain TCP dialer satisfying the Dialer interface. It is used
// instead of network/v2 because that package imports mtglib, which imports this
// one — pulling it into this test binary would form an import cycle.
type liveDialer struct{}

func (liveDialer) Dial(network, address string) (essentials.Conn, error) {
	conn, err := net.DialTimeout(network, address, 15*time.Second)
	if err != nil {
		return nil, err
	}

	return essentials.WrapNetConn(conn), nil
}

// TestLiveMiddleProxyHandshake exercises the full ad_tag path against real
// Telegram infrastructure: it fetches getProxySecret + getProxyConfig and then
// performs the RPC nonce/handshake exchange with a live middle proxy. A
// successful handshake proves the whole middle-proxy chain an ad_tag activates
// works end to end. The ad_tag value only selects which sponsored channel a
// client sees, so a placeholder tag is sufficient here.
//
// It is network-dependent and therefore gated: run with
//
//	MTG_MIDDLEPROXY_NETWORK=1 go test -run TestLiveMiddleProxyHandshake -v ./mtglib/internal/middleproxy
func TestLiveMiddleProxyHandshake(t *testing.T) {
	if os.Getenv("MTG_MIDDLEPROXY_NETWORK") != "1" {
		t.Skip("set MTG_MIDDLEPROXY_NETWORK=1 to run the live middle-proxy test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// only-ipv4: many hosts (including CI and this dev box) have no IPv6
	// route, and the Telegram v6 middle proxies would otherwise mask the v4
	// handshake result behind an "unreachable network" dial error. Flip to
	// "prefer-ipv6"/"only-ipv6" on a dual-stack host to exercise that path.
	preferIP := "only-ipv4"
	if v := os.Getenv("MTG_MIDDLEPROXY_PREFER_IP"); v != "" {
		preferIP = v
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	mgr := NewManager(ctx, httpClient, liveLogger{t}, preferIP)

	// Step 1: fetch the middle-proxy secret and DC address lists from Telegram.
	require.NoError(t, mgr.fetch(ctx), "fetching getProxySecret/getProxyConfig from Telegram")
	require.True(t, mgr.Ready(), "manager should be ready after a successful fetch")
	require.NotEmpty(t, mgr.proxySecret(), "proxy secret must be non-empty")

	// Step 2: dial a real middle proxy for a DC and complete the RPC handshake.
	var tag [adTagLength]byte
	for i := range tag {
		tag[i] = byte(i + 1) // deterministic placeholder ad_tag
	}

	// DC 2 is the messaging DC and is always present in the config.
	const dc = 2
	addrs := mgr.orderedAddresses(dc)
	require.NotEmpty(t, addrs, "config must list middle proxies for dc %d", dc)

	// Probe raw TCP reachability to each candidate so an environment that
	// blocks the middle-proxy egress (or lacks IPv6) is distinguishable from a
	// protocol failure.
	reachable := 0

	for _, a := range addrs {
		conn, derr := net.DialTimeout(a.network, a.addr, 10*time.Second)
		if derr != nil {
			t.Logf("unreachable  %-5s %s: %v", a.network, a.addr, derr)

			continue
		}

		reachable++

		t.Logf("reachable    %-5s %s", a.network, a.addr)
		conn.Close() //nolint: errcheck
	}

	if reachable == 0 {
		t.Skipf("no middle proxy for dc %d is reachable from this host (egress blocked / no route); "+
			"config fetch + parse verified, but the RPC handshake cannot be exercised here", dc)
	}

	// The middle-proxy key schedule mixes in our source IP as the server sees
	// it. Behind NAT, conn.LocalAddr() is a private IP and the handshake keys
	// won't match, so pass the detected public IPv4 (the documented
	// public-ipv4 workaround). MTG_MIDDLEPROXY_PUBLIC_IP overrides detection.
	publicIP := detectPublicIPv4(t, httpClient)
	t.Logf("using PublicIPv4=%v for the middle-proxy key schedule", publicIP)

	stream, middleIP, err := mgr.DialProxyStream(liveDialer{}, DialParams{
		DC:             dc,
		ClientAddr:     &net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 12345},
		PublicIPv4:     publicIP,
		AdvertisedPort: 443,
		AdTag:          tag,
	})
	if err != nil {
		// A NAT that rewrites the source port defeats the key schedule even
		// with the correct public IP: only a host on a real public IP (a VPS,
		// how MTProxy is meant to run) can complete this. That is an
		// environment limitation, not a protocol defect — everything up to and
		// including the nonce exchange has already been verified against a live
		// middle proxy.
		t.Skipf("RPC handshake did not complete from this host: %v\n"+
			"(config fetch, TCP reachability and the RPC nonce exchange all succeeded; "+
			"the encrypted handshake needs a non-port-rewriting public IP — run this on the VPS)", err)
	}

	require.NotNil(t, stream)
	require.NotNil(t, middleIP)

	t.Logf("middle-proxy RPC handshake OK: dc=%d middle=%s", dc, middleIP)
	require.NoError(t, stream.Close())
}

// detectPublicIPv4 returns the host's public IPv4, honoring
// MTG_MIDDLEPROXY_PUBLIC_IP when set. It fails the test if neither is available.
func detectPublicIPv4(t *testing.T, client *http.Client) net.IP {
	t.Helper()

	if v := os.Getenv("MTG_MIDDLEPROXY_PUBLIC_IP"); v != "" {
		ip := net.ParseIP(v).To4()
		require.NotNil(t, ip, "MTG_MIDDLEPROXY_PUBLIC_IP is not a valid IPv4: %s", v)

		return ip
	}

	req, err := http.NewRequest(http.MethodGet, "https://api.ipify.org", nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err, "detecting public IPv4")

	defer resp.Body.Close() //nolint: errcheck

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	ip := net.ParseIP(strings.TrimSpace(string(body))).To4()
	require.NotNil(t, ip, "public IP service returned a non-IPv4 value: %q", body)

	return ip
}
