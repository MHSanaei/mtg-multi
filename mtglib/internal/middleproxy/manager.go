package middleproxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/mtg-multi/essentials"
)

const (
	secretURL     = "https://core.telegram.org/getProxySecret"
	configURLv4   = "https://core.telegram.org/getProxyConfig"
	configURLv6   = "https://core.telegram.org/getProxyConfigV6"
	refreshPeriod = time.Hour
	fetchTimeout  = 30 * time.Second
)

// Dialer is the subset of mtglib.Network the manager needs to reach a middle
// proxy. It is declared here to keep this internal package free of an import
// cycle back to mtglib.
type Dialer interface {
	Dial(network, address string) (essentials.Conn, error)
}

// Logger is the minimal logging surface used by the background refresh loop.
// mtglib.Logger satisfies it.
type Logger interface {
	Info(string)
	Warning(string)
}

// Manager fetches and caches Telegram's proxy secret and middle-proxy address
// lists, and dials RPC proxy streams that carry an ad_tag. It fetches lazily on
// first use (so a proxy without advertising never touches the network) and then
// refreshes hourly. It is safe for concurrent use.
type Manager struct {
	ctx        context.Context
	httpClient *http.Client
	logger     Logger
	preferIP   string

	mu       sync.RWMutex
	ready    bool
	secret   []byte
	middleV4 map[int][]string
	middleV6 map[int][]string

	fetchMu     sync.Mutex
	refreshOnce sync.Once
}

// NewManager builds a Manager. httpClient should be built with the proxy's
// network settings (e.g. mtglib.Network.MakeHTTPClient) so DNS and upstream
// proxying apply. preferIP is the proxy's IP connectivity preference. The
// hourly refresh loop and any in-flight fetches stop when ctx is cancelled.
func NewManager(ctx context.Context, httpClient *http.Client, logger Logger, preferIP string) *Manager {
	return &Manager{
		ctx:        ctx,
		httpClient: httpClient,
		logger:     logger,
		preferIP:   preferIP,
	}
}

// Warm triggers an initial fetch in the background. Call it at startup when
// advertising is configured so the first client does not pay the fetch latency.
func (m *Manager) Warm() {
	go func() {
		if err := m.ensureReady(); err != nil {
			m.logger.Warning("cannot fetch middle-proxy config: " + err.Error())
		}
	}()
}

// ensureReady fetches the config if it has not been loaded yet and starts the
// hourly refresh loop on first success.
func (m *Manager) ensureReady() error {
	if m.Ready() {
		return nil
	}

	if err := m.fetch(m.ctx); err != nil {
		return err
	}

	m.startRefresh()

	return nil
}

func (m *Manager) startRefresh() {
	m.refreshOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(refreshPeriod)
			defer ticker.Stop()

			for {
				select {
				case <-m.ctx.Done():
					return
				case <-ticker.C:
					if err := m.fetch(m.ctx); err != nil {
						m.logger.Warning("cannot refresh middle-proxy config: " + err.Error())
					}
				}
			}
		}()
	})
}

// Ready reports whether the proxy secret and at least one middle-proxy address
// have been fetched.
func (m *Manager) Ready() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.ready
}

func (m *Manager) proxySecret() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.secret
}

func (m *Manager) fetch(ctx context.Context) error {
	m.fetchMu.Lock()
	defer m.fetchMu.Unlock()

	secret, err := m.fetchBytes(ctx, secretURL)
	if err != nil {
		return fmt.Errorf("cannot fetch proxy secret: %w", err)
	}

	v4, err := m.fetchConfig(ctx, configURLv4)
	if err != nil {
		return fmt.Errorf("cannot fetch proxy config v4: %w", err)
	}

	v6, err := m.fetchConfig(ctx, configURLv6)
	if err != nil {
		// IPv6 config is optional; keep going with v4 only.
		m.logger.Warning("cannot fetch proxy config v6: " + err.Error())

		v6 = map[int][]string{}
	}

	m.mu.Lock()
	m.secret = secret
	m.middleV4 = v4
	m.middleV6 = v6
	m.ready = len(secret) > 0 && (len(v4) > 0 || len(v6) > 0)
	m.mu.Unlock()

	m.logger.Info(fmt.Sprintf("middle-proxy config loaded: %d v4 DCs, %d v6 DCs", len(v4), len(v6)))

	return nil
}

func (m *Manager) fetchBytes(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err //nolint: wrapcheck
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot GET %s: %w", url, err)
	}

	defer resp.Body.Close() //nolint: errcheck

	if resp.StatusCode >= http.StatusBadRequest {
		io.Copy(io.Discard, resp.Body) //nolint: errcheck

		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	return io.ReadAll(resp.Body) //nolint: wrapcheck
}

func (m *Manager) fetchConfig(ctx context.Context, url string) (map[int][]string, error) {
	data, err := m.fetchBytes(ctx, url)
	if err != nil {
		return nil, err
	}

	return parseMiddleConfig(data)
}

// parseMiddleConfig parses a getProxyConfig body, collecting every
// "proxy_for <dc> <ip:port>;" line keyed by the signed DC id. Comment and
// "default" lines are ignored.
func parseMiddleConfig(data []byte) (map[int][]string, error) {
	out := map[int][]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())

		if !strings.HasPrefix(text, "proxy_for") {
			continue
		}

		fields := strings.Fields(text)
		if len(fields) < 3 {
			continue
		}

		dc, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}

		addr := strings.TrimRight(fields[2], ";")
		if _, _, err := net.SplitHostPort(addr); err != nil {
			continue
		}

		out[dc] = append(out[dc], addr)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("cannot parse proxy config: %w", err)
	}

	return out, nil
}

type middleAddress struct {
	network string
	addr    string
}

// orderedAddresses returns the middle-proxy addresses to try for dc, honoring
// the IP-family preference and including both DC signs (Telegram lists +N and
// -N separately). The requested dc is passed as its absolute value; both +dc
// and -dc entries are returned.
func (m *Manager) orderedAddresses(dc int) []middleAddress {
	m.mu.RLock()
	defer m.mu.RUnlock()

	v6First := strings.Contains(m.preferIP, "ipv6")
	onlyV4 := m.preferIP == "only-ipv4"
	onlyV6 := m.preferIP == "only-ipv6"

	var out []middleAddress

	appendFamily := func(table map[int][]string, network string) {
		for _, key := range []int{dc, -dc} {
			for _, addr := range table[key] {
				out = append(out, middleAddress{network: network, addr: addr})
			}
		}
	}

	if v6First {
		if !onlyV4 {
			appendFamily(m.middleV6, "tcp6")
		}

		if !onlyV6 {
			appendFamily(m.middleV4, "tcp4")
		}
	} else {
		if !onlyV6 {
			appendFamily(m.middleV4, "tcp4")
		}

		if !onlyV4 {
			appendFamily(m.middleV6, "tcp6")
		}
	}

	return out
}

// DialParams carries the addressing the proxy contributes to a middle-proxy
// dial. ClientAddr is the real client's address (put in RPC_PROXY_REQ). PublicIPv4
// and PublicIPv6 optionally override the address the middle proxy sees as our
// source (needed on multi-homed hosts); the family matching the dialed socket
// is used. AdvertisedPort is the port reported as ours in RPC_PROXY_REQ.
type DialParams struct {
	DC            int
	ClientAddr    *net.TCPAddr
	PublicIPv4    net.IP
	PublicIPv6    net.IP
	AdvertisedPort int
	AdTag         [adTagLength]byte
}

// DialProxyStream connects to a middle proxy for params.DC, performs the RPC
// handshake, and returns an essentials.Conn that transparently carries the
// client's traffic wrapped in RPC_PROXY_REQ with the ad_tag. It also returns
// the middle-proxy IP for the connected-to-DC event.
func (m *Manager) DialProxyStream(dialer Dialer, params DialParams) (essentials.Conn, net.IP, error) {
	if err := m.ensureReady(); err != nil {
		return nil, nil, err
	}

	secret := m.proxySecret()
	if len(secret) == 0 {
		return nil, nil, fmt.Errorf("middle-proxy secret is not available")
	}

	addresses := m.orderedAddresses(params.DC)
	if len(addresses) == 0 {
		return nil, nil, fmt.Errorf("no middle proxy address for dc %d", params.DC)
	}

	var lastErr error

	for _, a := range addresses {
		conn, err := dialer.Dial(a.network, a.addr)
		if err != nil {
			lastErr = err

			continue
		}

		local := toTCPAddr(conn.LocalAddr())
		remote := toTCPAddr(conn.RemoteAddr())

		// Pick the advertised public IP whose family matches the socket, so the
		// key schedule and RPC_PROXY_REQ agree with what the middle proxy sees.
		publicIP := params.PublicIPv4
		if local.IP.To4() == nil {
			publicIP = params.PublicIPv6
		}

		// The key schedule uses our source IP as the middle proxy sees it. On a
		// public host that is conn.LocalAddr(); the operator can override the IP
		// (keeping the ephemeral source port) for multi-homed hosts.
		keyLocal := local
		if publicIP != nil {
			keyLocal = &net.TCPAddr{IP: publicIP, Port: local.Port}
		}

		frame, err := doHandshake(conn, secret, keyLocal, remote)
		if err != nil {
			conn.Close() //nolint: errcheck
			lastErr = err

			continue
		}

		rpcIP := local.IP
		if publicIP != nil {
			rpcIP = publicIP
		}

		rpcOurAddr := &net.TCPAddr{IP: rpcIP, Port: params.AdvertisedPort}

		var connID [8]byte
		if _, err := rand.Read(connID[:]); err != nil {
			conn.Close() //nolint: errcheck

			return nil, nil, err //nolint: wrapcheck
		}

		return newMiddleConn(conn, frame, connID, params.AdTag, params.ClientAddr, rpcOurAddr), remote.IP, nil
	}

	return nil, nil, fmt.Errorf("cannot connect to any middle proxy for dc %d: %w", params.DC, lastErr)
}

func toTCPAddr(addr net.Addr) *net.TCPAddr {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp
	}

	return &net.TCPAddr{}
}
