# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

mtg-multi is a Telegram MTProto proxy (FakeTLS, domain fronting, anti-replay, doppelganger traffic mimicry) forked from [9seconds/mtg](https://github.com/9seconds/mtg), extended for many users: named per-user secrets, per-user stats, a management HTTP API, hot secret reload, connection throttling, per-user quota/expiry/disable, and the middle-proxy ad-tag. Module path: `github.com/mhsanaei/mtg-multi`.

## Repositories and remotes

- `origin` = `MHSanaei/mtg-multi` (this fork, default branch `main`).
- `upstream` = `dolonet/mtg-multi` (default branch `master`), itself a fork of `9seconds/mtg`. Upstream changes are brought in with manual "sync: merge upstream/master through <sha>" merges or by re-applying upstream commits; histories have diverged (module rename, fork-only features), so expect conflicts.
- `gh` resolves to the **upstream** repo by default here. Pass `-R MHSanaei/mtg-multi` for PRs/issues on the fork.

## Commands

Tooling is driven by [mise](https://mise.jdx.dev) (`.mise.toml`); CI runs the same tasks. Go version is pinned by `go.mod` (`go 1.27.x`).

```sh
go build                      # or: mise run build  -> ./mtg-multi binary
go build -tags prof           # pprof server on localhost:${MTG_PROF_PORT:-6000}
mise run test                 # go test -v -race ./...
mise run covtest              # what CI runs (coverage, -count=2, -race)
mise run lint                 # golangci-lint run (config: .golangci.yml, v2)
mise run fmt                  # gofumpt -w --extra .   (code must be gofumpt --extra clean)
mise run vuln                 # govulncheck ./...
mise run 'test:fuzz:*'        # the three fuzz targets, 120s each (CI "Fuzzing" job)
```

Single test / suite method (many tests use testify suites, e.g. `ProxyTestSuite` run as `TestProxy`):

```sh
go test ./mtglib -run 'TestProxy/TestHTTPSRequest' -count=1
go test ./mtglib/obfuscation -run 'TestHandshakeFrame' -count=1
go test ./mtglib/obfuscation -run=XXX -fuzz=FuzzGenerateHandshakeFrame -fuzztime=20s
```

`-race` needs cgo (a C compiler); on Windows without gcc drop `-race`. Live-network tests are skipped unless opted in: `MTG_PROBE_NETWORK=1` (`mtglib/dcprobe`), `MTG_MIDDLEPROXY_NETWORK=1` (`mtglib/internal/middleproxy`). The default test run must stay offline (fronting targets are local stand-ins, not httpbin.org).

## Architecture

**Entry and CLI.** `main.go` → kong-parsed `internal/cli.CLI` with subcommands `run`, `simple-run`, `generate-secret`, `access`, `doctor`, `version`. `internal/cli/run_proxy.go:runProxy` is the composition root: it turns a `config.Config` into `mtglib.ProxyOpts` by building the pluggable pieces (logger, `network`, anti-replay cache, IP block/allowlists, event stream with statsd/Prometheus observers), calls `mtglib.NewProxy`, serves each `bind-to` listener, and handles shutdown via `waitAndShutdown`. `makeSecretsReloader` re-parses the same config file for hot reload.

**Config** (`internal/config`). `parse.go` unmarshals TOML into a loose `tomlConfig`, re-encodes it to JSON, and decodes into the typed `Config`, whose fields are `Type*` wrappers (`type_*.go`, each with its own validation and tests). `env.go` overlays Docker-style environment variables (`MTG_*` wins over unprefixed `SECRET`/`TAG`/…). `Config.Validate` does cross-field checks. In TOML, `[secrets]` must be the last section in the global scope, otherwise later top-level keys get parsed as secrets. Adding an option usually touches: `tomlConfig` + `Config` (+ a `Type*` if needed), `Validate`, `ProxyOpts`, `runProxy`, `example.config.toml` (documents every option with defaults), and README.

**Core library** (`mtglib`). `Proxy` is the central object; external concerns (`Network`, `AntiReplayCache`, `IPBlocklist`, `EventStream`, `Logger`) are interfaces defined in `mtglib` with default implementations in top-level packages (`network`, `antireplay`, `ipblocklist`, `events`, `stats`, `logger`). Per-connection flow in `Proxy.ServeConn` (`proxy.go`):

1. per-IP pending-handshake slot (`pending_handshakes.go`, opt-in), released once the secret is proven or the connection is fronted;
2. `doFakeTLSHandshake`: matches the ClientHello against **every** configured secret (`mtglib/internal/tls/fake`), checks anti-replay, time skew, and per-secret limits; anything that fails is relayed to the fronting domain with its original bytes (`doDomainFrontingForHost`, `connRewind`), so probers can't tell a wrong secret from a real site;
3. throttling (`ProxyStats.CanConnect`), stats registration, doppelganger wrapper (`internal/doppel`);
4. `doObfuscatedHandshake` (`mtglib/obfuscation`, obfuscated2; the DC id keeps its sign, negative = media DC);
5. `doTelegramCall`: direct dial to the DC (`internal/dc`, with public-config auto-update), or via the middle proxy (`internal/middleproxy`) when an ad-tag applies;
6. `internal/relay.Relay` pumps bytes, wrapped with idle tracking and a `countingConn` for per-user byte counts/quota.

**Multi-user state.** Secrets live in an immutable `secretSet` (secrets, names, per-secret/global ad-tags, limits) behind an atomic pointer; `ReloadSecrets`, the management API (`proxy_api.go`: `/stats`, `/reload`, `/secrets`, ad-tag and quota endpoints, optional bearer token), and `ReplaceSecrets`/`PutSecret`/`DeleteSecret` build a new set and swap it, then close connections whose secret was removed, re-keyed, or is now denied (`closeStaleConns`, `closeDeniedConns`). A running handshake must read a single snapshot. `ProxyStats` (`proxy_stats.go`) holds per-user counters, quota usage (persisted to `usage-state-file`, with monthly rollover), and the fair-share throttle loop.

**Listeners.** `internal/utils` (listener with socket options), `internal/proxyprotocol` (PROXY protocol), `internal/acceptretry` (temporary accept errors are retried with backoff; `Serve` returning on its own makes `runProxy` exit so a supervisor restarts the process).

**Events/metrics.** `mtglib/events.go` defines event types; `events` fans them out to observers; `stats` implements Prometheus and statsd observers. A new event needs: the type in `mtglib/events.go`, a method on the `events.Observer` interface (`events/init.go`), a dispatch case in `events/event_stream.go`, implementations in `events/multi_observer.go` and `events/noop.go`, and in both `stats/prometheus.go` and `stats/statsd.go`.

**Other.** `mtglib/dcprobe` + `internal/cli/doctor.go` (diagnostics), `contrib/sni-router` (HAProxy/Caddy deployment example), `benchmarks/` (relay benchmarks; errcheck disabled there and in tests).

## Conventions

- Commit messages follow Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `build:`, `refactor:`, optional scope like `feat(mtglib):`).
- New proxy behaviour is opt-in and off by default, documented in `example.config.toml` and README.
