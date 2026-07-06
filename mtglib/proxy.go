package mtglib

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mhsanaei/mtg-multi/essentials"
	"github.com/mhsanaei/mtg-multi/mtglib/internal/dc"
	"github.com/mhsanaei/mtg-multi/mtglib/internal/doppel"
	"github.com/mhsanaei/mtg-multi/mtglib/internal/relay"
	"github.com/mhsanaei/mtg-multi/mtglib/internal/tls"
	"github.com/mhsanaei/mtg-multi/mtglib/internal/tls/fake"
	"github.com/mhsanaei/mtg-multi/mtglib/obfuscation"
	"github.com/panjf2000/ants/v2"
)

// secretSet is an immutable snapshot of the secrets a proxy serves. The proxy
// keeps it behind an atomic pointer so a running handshake always reads a
// single consistent view, and ReloadSecrets can swap the whole set in without
// locking the hot path. secrets, names and hostnames stay index-aligned:
// secrets[i] belongs to names[i]; hostnames is the deduplicated, sorted set of
// secret hosts used for SNI matching.
type secretSet struct {
	secrets   []Secret
	names     []string
	hostnames []string
}

// buildSecretSet turns a name->secret map into an immutable, name-sorted
// snapshot. Sorting keeps names[i] and secrets[i] aligned and makes the
// matched index stable across processes for a given secret map.
func buildSecretSet(secretsMap map[string]Secret) *secretSet {
	names := make([]string, 0, len(secretsMap))
	for name := range secretsMap {
		names = append(names, name)
	}

	sort.Strings(names)

	secretsList := make([]Secret, 0, len(secretsMap))
	for _, name := range names {
		secretsList = append(secretsList, secretsMap[name])
	}

	hostnameSet := make(map[string]struct{}, len(secretsList))
	for _, s := range secretsList {
		hostnameSet[s.Host] = struct{}{}
	}

	hostnames := make([]string, 0, len(hostnameSet))
	for h := range hostnameSet {
		hostnames = append(hostnames, h)
	}

	sort.Strings(hostnames)

	return &secretSet{secrets: secretsList, names: names, hostnames: hostnames}
}

// Proxy is an MTPROTO proxy structure.
type Proxy struct {
	ctx             context.Context
	ctxCancel       context.CancelFunc
	streamWaitGroup sync.WaitGroup

	allowFallbackOnUnknownDC    bool
	tolerateTimeSkewness        time.Duration
	idleTimeout                 time.Duration
	handshakeTimeout            time.Duration
	domainFrontingPort          int
	domainFrontingHost          string
	domainFrontingProxyProtocol bool
	workerPool                  *ants.PoolWithFunc
	telegram                    *dc.Telegram
	configUpdater               *dc.PublicConfigUpdater
	doppelGanger                *doppel.Ganger

	stats           *ProxyStats
	secrets         atomic.Pointer[secretSet]
	reloader        func() (map[string]Secret, error)
	reloadMu        sync.Mutex
	liveMu          sync.Mutex
	liveConns       map[string]map[*streamContext]struct{}
	network         Network
	antiReplayCache AntiReplayCache
	blocklist       IPBlocklist
	allowlist       IPBlocklist
	eventStream     EventStream
	logger          Logger
}

// DomainFrontingAddress returns a host:port pair for a fronting domain.
// If a fronting host (literal IP or hostname) is configured, it is used
// instead of the secret's hostname. When secrets use different hostnames,
// pass the matched secret's host to front the correct domain.
func (p *Proxy) DomainFrontingAddress() string {
	return p.domainFrontingAddressForHost(p.secrets.Load().secrets[0].Host)
}

func (p *Proxy) domainFrontingAddressForHost(host string) string {
	if p.domainFrontingHost != "" {
		host = p.domainFrontingHost
	}

	return net.JoinHostPort(host, strconv.Itoa(p.domainFrontingPort))
}

// ServeConn serves a connection. We do not check IP blocklist and concurrency
// limit here.
func (p *Proxy) ServeConn(conn essentials.Conn) {
	p.streamWaitGroup.Add(1)
	defer p.streamWaitGroup.Done()

	ctx := newStreamContext(p.ctx, p.logger, conn)
	defer ctx.Close()

	if err := ctx.clientConn.SetDeadline(time.Now().Add(p.handshakeTimeout)); err != nil {
		ctx.logger.WarningError("cannot set handshake timeout", err)
		return
	}

	stop := context.AfterFunc(ctx, func() {
		ctx.Close()
	})
	defer stop()

	p.eventStream.Send(ctx, NewEventStart(ctx.streamID, ctx.ClientIP()))
	ctx.logger.Info("Stream has been started")

	defer func() {
		p.eventStream.Send(ctx, NewEventFinish(ctx.streamID))
		ctx.logger.Info("Stream has been finished")
	}()

	if !p.doFakeTLSHandshake(ctx) {
		return
	}

	if !p.stats.CanConnect(ctx.secretName) {
		ctx.logger.Info("connection throttled")
		p.eventStream.Send(ctx, NewEventThrottled(ctx.streamID, ctx.secretName))

		return
	}

	p.stats.OnConnect(ctx.secretName)
	p.stats.UpdateLastSeen(ctx.secretName)

	defer p.stats.OnDisconnect(ctx.secretName)

	p.registerConn(ctx)
	defer p.unregisterConn(ctx)

	clientConn, err := p.doppelGanger.NewConn(ctx.clientConn)
	if err != nil {
		ctx.logger.InfoError("cannot wrap into doppelganger connection", err)
		return
	}
	defer clientConn.Stop()

	ctx.clientConn = clientConn

	if err := p.doObfuscatedHandshake(ctx); err != nil {
		ctx.logger.InfoError("obfuscated handshake is failed", err)
		return
	}

	if err := ctx.clientConn.SetDeadline(time.Time{}); err != nil {
		ctx.logger.WarningError("cannot set deadline", err)
		return
	}

	if err := p.doTelegramCall(ctx); err != nil {
		ctx.logger.WarningError("cannot dial to telegram", err)
		return
	}

	tracker := newIdleTracker(p.idleTimeout)

	relay.Relay(
		ctx,
		ctx.logger.Named("relay"),
		connIdleTimeout{Conn: ctx.telegramConn, tracker: tracker},
		newCountingConn(connIdleTimeout{Conn: ctx.clientConn, tracker: tracker}, p.stats, ctx.secretName),
	)
}

// Serve starts a proxy on a given listener.
func (p *Proxy) Serve(listener net.Listener) error {
	p.streamWaitGroup.Add(1)
	defer p.streamWaitGroup.Done()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-p.ctx.Done():
				return nil
			default:
				return fmt.Errorf("cannot accept a new connection: %w", err)
			}
		}

		ipAddr := conn.RemoteAddr().(*net.TCPAddr).IP //nolint: forcetypeassert
		logger := p.logger.BindStr("ip", ipAddr.String())

		if !p.allowlist.Contains(ipAddr) {
			conn.Close() //nolint: errcheck
			logger.Info("ip was rejected by allowlist")
			p.eventStream.Send(p.ctx, NewEventIPAllowlisted(ipAddr))

			continue
		}

		if p.blocklist.Contains(ipAddr) {
			conn.Close() //nolint: errcheck
			logger.Info("ip was blacklisted")
			p.eventStream.Send(p.ctx, NewEventIPBlocklisted(ipAddr))

			continue
		}

		err = p.workerPool.Invoke(conn)

		switch {
		case err == nil:
		case errors.Is(err, ants.ErrPoolClosed):
			return nil
		case errors.Is(err, ants.ErrPoolOverload):
			conn.Close() //nolint: errcheck
			logger.Info("connection was concurrency limited")
			p.eventStream.Send(p.ctx, NewEventConcurrencyLimited())
		}
	}
}

// Shutdown 'gracefully' shutdowns all connections. Please remember that it
// does not close an underlying listener.
func (p *Proxy) Shutdown() {
	p.ctxCancel()
	p.streamWaitGroup.Wait()
	p.workerPool.Release()
	p.configUpdater.Wait()
	p.doppelGanger.Shutdown()

	p.allowlist.Shutdown()
	p.blocklist.Shutdown()
}

// ReloadSecrets re-reads the secret set through the configured reloader and
// swaps it in atomically, so a client add, removal, disable or re-key takes
// effect without restarting the process. Connections whose secret disappeared
// or was re-keyed are closed; every other live stream keeps running, and the
// /stats counters carry across the swap. It returns ErrReloaderNotConfigured
// when the proxy was built without a SecretsReloader, and an error (leaving the
// current set active) when the reloader fails or yields no valid secret.
func (p *Proxy) ReloadSecrets() error {
	if p.reloader == nil {
		return ErrReloaderNotConfigured
	}

	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	secretsMap, err := p.reloader()
	if err != nil {
		return fmt.Errorf("cannot reload secrets: %w", err)
	}

	if len(secretsMap) == 0 {
		return ErrSecretInvalid
	}

	for _, s := range secretsMap {
		if !s.Valid() {
			return ErrSecretInvalid
		}
	}

	newSet := buildSecretSet(secretsMap)
	oldSet := p.secrets.Swap(newSet)

	for _, name := range newSet.names {
		p.stats.PreRegister(name)
	}

	p.closeStaleConns(oldSet, newSet)

	return nil
}

func (p *Proxy) registerConn(ctx *streamContext) {
	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	conns := p.liveConns[ctx.secretName]
	if conns == nil {
		conns = make(map[*streamContext]struct{})
		p.liveConns[ctx.secretName] = conns
	}

	conns[ctx] = struct{}{}
}

func (p *Proxy) unregisterConn(ctx *streamContext) {
	p.liveMu.Lock()
	defer p.liveMu.Unlock()

	conns := p.liveConns[ctx.secretName]
	if conns == nil {
		return
	}

	delete(conns, ctx)

	if len(conns) == 0 {
		delete(p.liveConns, ctx.secretName)
	}
}

// closeStaleConns closes every live stream whose secret was dropped from the
// new set or whose key changed since the old set (a re-key), and leaves the
// rest connected. Streams are snapshotted under the lock and closed outside it,
// so each stream's own unregister (which also takes the lock) cannot deadlock.
func (p *Proxy) closeStaleConns(oldSet, newSet *secretSet) {
	newKeys := make(map[string][SecretKeyLength]byte, len(newSet.names))
	for i, name := range newSet.names {
		newKeys[name] = newSet.secrets[i].Key
	}

	oldKeys := make(map[string][SecretKeyLength]byte)
	if oldSet != nil {
		for i, name := range oldSet.names {
			oldKeys[name] = oldSet.secrets[i].Key
		}
	}

	var stale []*streamContext

	p.liveMu.Lock()
	for name, conns := range p.liveConns {
		if newKey, kept := newKeys[name]; kept {
			if oldKey, had := oldKeys[name]; had && oldKey == newKey {
				continue
			}
		}

		for sc := range conns {
			stale = append(stale, sc)
		}
	}
	p.liveMu.Unlock()

	for _, sc := range stale {
		sc.Close()
	}
}

func (p *Proxy) doFakeTLSHandshake(ctx *streamContext) bool {
	rewind := newConnRewind(ctx.clientConn)

	// Read the active secret snapshot once so a concurrent ReloadSecrets swap
	// cannot desync the key list, hostnames and matched index mid-handshake.
	set := p.secrets.Load()

	secretKeys := make([][]byte, len(set.secrets))
	for i := range set.secrets {
		secretKeys[i] = set.secrets[i].Key[:]
	}

	result, err := fake.ReadClientHelloMulti(
		rewind,
		secretKeys,
		set.hostnames,
		p.tolerateTimeSkewness,
	)
	if err != nil {
		p.logger.InfoError("cannot read client hello", err)

		frontHost := set.secrets[0].Host
		if result != nil && result.MatchedHost != "" {
			frontHost = result.MatchedHost
		}

		p.doDomainFrontingForHost(ctx, rewind, frontHost)

		return false
	}

	if p.antiReplayCache.SeenBefore(result.Hello.SessionID) {
		p.logger.Warning("replay attack has been detected!")
		p.eventStream.Send(p.ctx, NewEventReplayAttack(ctx.streamID))
		p.doDomainFrontingForHost(ctx, rewind, result.MatchedHost)

		return false
	}

	matchedSecret := set.secrets[result.MatchedIndex]
	ctx.matchedSecretKey = matchedSecret.Key[:]
	ctx.secretName = set.names[result.MatchedIndex]
	ctx.logger = ctx.logger.BindStr("secret_name", ctx.secretName)

	gangerNoise := p.doppelGanger.NoiseParams()
	noiseParams := fake.NoiseParams{Mean: gangerNoise.Mean, Jitter: gangerNoise.Jitter}

	if err := fake.SendServerHello(ctx.clientConn, matchedSecret.Key[:], result.Hello, noiseParams); err != nil {
		p.logger.InfoError("cannot send welcome packet", err)
		return false
	}

	ctx.clientConn = tls.New(ctx.clientConn, true, false)

	return true
}

func (p *Proxy) doObfuscatedHandshake(ctx *streamContext) error {
	// Use the secret key that was matched during the FakeTLS handshake.
	obfs := obfuscation.Obfuscator{
		Secret: ctx.matchedSecretKey,
	}

	dc, conn, err := obfs.ReadHandshake(ctx.clientConn)
	if err != nil {
		return fmt.Errorf("cannot process client handshake: %w", err)
	}

	ctx.dc = dc
	ctx.clientConn = conn
	ctx.logger = ctx.logger.BindInt("dc", dc)

	return nil
}

func (p *Proxy) doTelegramCall(ctx *streamContext) error {
	dcid := ctx.dc

	addresses := p.telegram.GetAddresses(dcid)
	if len(addresses) == 0 && p.allowFallbackOnUnknownDC {
		ctx.logger = ctx.logger.BindInt("original_dc", dcid)
		ctx.logger.Warning("unknown DC, fallbacks")
		ctx.dc = dc.DefaultDC
		addresses = p.telegram.GetAddresses(dc.DefaultDC)
	}

	var (
		conn      essentials.Conn
		err       error
		foundAddr dc.Addr
	)

	for _, addr := range addresses {
		conn, err = p.network.Dial(addr.Network, addr.Address)
		if err == nil {
			foundAddr = addr
			break
		}
	}
	if err != nil {
		return fmt.Errorf("no addresses to call: %w", err)
	}
	if conn == nil {
		return fmt.Errorf("no available addresses for DC %d", ctx.dc)
	}

	tgConn, err := foundAddr.Obfuscator.SendHandshake(conn, ctx.dc)
	if err != nil {
		conn.Close() // nolint: errcheck
		return fmt.Errorf("cannot perform server handshake: %w", err)
	}

	ctx.telegramConn = connTraffic{
		Conn:     tgConn,
		streamID: ctx.streamID,
		stream:   p.eventStream,
		ctx:      ctx,
	}

	telegramHost, _, err := net.SplitHostPort(foundAddr.Address)
	if err != nil {
		conn.Close() //nolint: errcheck

		return fmt.Errorf("cannot parse telegram address %s: %w", foundAddr.Address, err)
	}

	p.eventStream.Send(
		ctx,
		NewEventConnectedToDC(ctx.streamID,
			net.ParseIP(telegramHost),
			ctx.dc),
	)

	return nil
}

func (p *Proxy) doDomainFrontingForHost(ctx *streamContext, conn *connRewind, host string) {
	p.eventStream.Send(p.ctx, NewEventDomainFronting(ctx.streamID))
	conn.Rewind()

	nativeDialer := p.network.NativeDialer()
	fConn, err := nativeDialer.DialContext(ctx, "tcp", p.domainFrontingAddressForHost(host))
	if err != nil {
		p.logger.WarningError("cannot dial to the fronting domain", err)

		return
	}

	frontConn := essentials.WrapNetConn(fConn)

	if p.domainFrontingProxyProtocol {
		frontConn = newConnProxyProtocol(ctx.clientConn, frontConn)
	}

	frontConn = connTraffic{
		Conn:     frontConn,
		ctx:      ctx,
		streamID: ctx.streamID,
		stream:   p.eventStream,
	}

	tracker := newIdleTracker(p.idleTimeout)

	relay.Relay(
		ctx,
		ctx.logger.Named("domain-fronting"),
		connIdleTimeout{Conn: frontConn, tracker: tracker},
		connIdleTimeout{Conn: conn, tracker: tracker},
	)
}

// NewProxy makes a new proxy instance.
func NewProxy(opts ProxyOpts) (*Proxy, error) {
	if err := opts.valid(); err != nil {
		return nil, fmt.Errorf("invalid settings: %w", err)
	}

	tg, err := dc.New(opts.getPreferIP())
	if err != nil {
		return nil, fmt.Errorf("cannot build telegram dc fetcher: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	logger := opts.getLogger("proxy")
	updatersLogger := logger.Named("telegram-updaters")

	initialSet := buildSecretSet(opts.getSecrets())

	stats := NewProxyStats()
	for _, name := range initialSet.names {
		stats.PreRegister(name)
	}

	if opts.ThrottleMaxConnections > 0 {
		stats.SetThrottle(int64(opts.ThrottleMaxConnections), opts.getThrottleCheckInterval())
		stats.startThrottleLoop(ctx, logger)
	}

	if opts.DomainFrontingIP != "" {
		logger.Warning("mtglib.ProxyOpts.DomainFrontingIP is deprecated and ignored; use DomainFrontingHost instead")
	}

	proxy := &Proxy{
		ctx:                      ctx,
		ctxCancel:                cancel,
		stats:                    stats,
		reloader:                 opts.SecretsReloader,
		liveConns:                make(map[string]map[*streamContext]struct{}),
		network:                  opts.Network,
		antiReplayCache:          opts.AntiReplayCache,
		blocklist:                opts.IPBlocklist,
		allowlist:                opts.IPAllowlist,
		eventStream:              opts.EventStream,
		logger:                   logger,
		domainFrontingPort:       opts.getDomainFrontingPort(),
		domainFrontingHost:       opts.DomainFrontingHost,
		tolerateTimeSkewness:     opts.getTolerateTimeSkewness(),
		idleTimeout:              opts.getIdleTimeout(),
		handshakeTimeout:         opts.getHandshakeTimeout(),
		allowFallbackOnUnknownDC: opts.AllowFallbackOnUnknownDC,
		telegram:                 tg,
		doppelGanger: doppel.NewGanger(
			ctx,
			opts.Network,
			logger.Named("doppelganger"),
			opts.DoppelGangerEach,
			int(opts.DoppelGangerPerRaid),
			opts.DoppelGangerURLs,
			opts.DoppelGangerDRS,
		),
		configUpdater: dc.NewPublicConfigUpdater(
			tg,
			updatersLogger.Named("public-config"),
			opts.Network.MakeHTTPClient(nil),
		),
		domainFrontingProxyProtocol: opts.DomainFrontingProxyProtocol,
	}

	proxy.secrets.Store(initialSet)

	// Start the stats/reload API only now that the proxy exists, so the
	// /reload route can drive ReloadSecrets. The two share the api-bind-to
	// listener; reload is a no-op-with-error when no reloader was supplied.
	if opts.APIBindTo != "" {
		stats.StartServer(ctx, opts.APIBindTo, logger, proxy.ReloadSecrets)
	}

	proxy.doppelGanger.Run()

	if opts.AutoUpdate {
		proxy.configUpdater.Run(ctx, dc.PublicConfigUpdateURLv4, "tcp4")
		proxy.configUpdater.Run(ctx, dc.PublicConfigUpdateURLv6, "tcp6")
	}

	pool, err := ants.NewPoolWithFunc(opts.getConcurrency(),
		func(arg any) {
			proxy.ServeConn(arg.(essentials.Conn)) //nolint: forcetypeassert
		},
		ants.WithLogger(opts.getLogger("ants")),
		ants.WithNonblocking(true))
	if err != nil {
		panic(err)
	}

	proxy.workerPool = pool

	return proxy, nil
}
