# mtg-multi

A fast, censorship-resistant [Telegram MTProto proxy](https://core.telegram.org/mtproto),
forked from [9seconds/mtg](https://github.com/9seconds/mtg) and extended for
running one instance for many users.

Upstream mtg is a single-secret proxy. mtg-multi keeps everything that makes mtg
good — FakeTLS, domain fronting, anti-replay, traffic-shape mimicry — and adds
the pieces you need to run a shared proxy: named per-user secrets, live per-user
traffic stats, a management API, hot reload, connection throttling, and the
sponsored-channel ad-tag that mtg v2 removed.

## What's different from upstream

- **Multiple secrets** — one named secret per user, each with its own fronting host.
- **Per-user stats** — a JSON endpoint with live connection and byte counters.
- **Management API** — add, remove, and re-key secrets and the ad-tag at runtime.
- **Hot reload** — swap the secret set from the config file without dropping users.
- **Sponsored channel (ad-tag)** — the promoted-channel feature, back again.
- **Connection throttling** — automatic fair-share per-user connection caps.
- **Per-user quotas, expiry & disable** — data caps (with optional monthly reset),
  a validity deadline, and an on/off switch, persisted across restarts.
- **Public IP override** and **Docker-style environment variables**.

Everything else — FakeTLS, domain fronting, the doppelganger traffic mimic,
SOCKS5 proxy chaining, IP blocklists/allowlists, Prometheus and statsd metrics —
works exactly as in upstream. See the [upstream README](https://github.com/9seconds/mtg)
for the shared internals.

## Table of contents

- [Quick start](#quick-start)
- [Running with Docker](#running-with-docker)
- [Features](#features)
  - [Multiple secrets](#multiple-secrets)
  - [Per-user stats API](#per-user-stats-api)
  - [Hot secret reload](#hot-secret-reload)
  - [Secrets & ad-tag management API](#secrets--ad-tag-management-api)
  - [API authentication](#api-authentication)
  - [Sponsored channel (ad-tag)](#sponsored-channel-ad-tag)
  - [Connection throttling](#connection-throttling)
  - [Per-user quotas, expiry & disable](#per-user-quotas-expiry--disable)
  - [Public IP override](#public-ip-override)
  - [Environment variables](#environment-variables)
- [Command reference](#command-reference)
- [Configuration](#configuration)
- [Credits](#credits)

## Quick start

Download a binary from [Releases](https://github.com/mhsanaei/mtg-multi/releases),
or build from source (requires Go 1.26+):

```console
git clone https://github.com/mhsanaei/mtg-multi.git
cd mtg-multi
go build          # produces ./mtg-multi
```

If you use [mise](https://mise.jdx.dev/), `mise install && mise run build` sets
up the toolchain and builds the same binary.

Generate a secret for each user. The hostname is the site you front behind: it
does not have to point at your server, but it should be a real, reachable HTTPS
site — the classic choice is a large CDN such as `storage.googleapis.com`:

```console
mtg-multi generate-secret --hex storage.googleapis.com
```

Write a minimal config:

```toml
bind-to = "0.0.0.0:443"
api-bind-to = "127.0.0.1:9090"

[throttle]
max-connections = 5000

# [secrets] must be the LAST section in the global scope. In TOML, every key
# after a [section] header belongs to that table, so any top-level option
# placed below [secrets] would be parsed as a secret.
[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
bob   = "ee0123456789abcdef0123456789abcd9573746f726167652e676f6f676c65617069732e636f6d"
```

Run it:

```console
mtg-multi run /etc/mtg/config.toml
```

Then print the connection links and QR codes for your users:

```console
mtg-multi access /etc/mtg/config.toml
```

## Running with Docker

The image is published to the GitHub Container Registry and ships a working
default config, so it can be configured entirely from environment variables in
the style of the official `telegrammessenger/proxy` image:

```console
docker run -d --name mtg -p 443:443 \
    -e SECRET=00112233445566778899aabbccddeeff \
    -e SECRET_HOST=storage.googleapis.com \
    -e TAG=3f40462915a3e6026a4d790127b95ded \
    -e MTG_BIND_TO=0.0.0.0:443 \
    ghcr.io/mhsanaei/mtg-multi:latest
```

To run with a full config file instead, mount it over the bundled default at
`/config/config.toml`:

```console
docker run -d --name mtg -p 443:443 \
    -v /etc/mtg/config.toml:/config/config.toml:ro \
    ghcr.io/mhsanaei/mtg-multi:latest
```

See [Environment variables](#environment-variables) for the full list.

## Features

### Multiple secrets

Define named secrets in the config, one per user. Each name is used as the label
in per-user stats, and each secret may front behind a different hostname.

```toml
[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
bob   = "ee0123456789abcdef0123456789abcd9573746f726167652e676f6f676c65617069732e636f6d"
```

The single-secret `secret = "..."` form from upstream still works and is treated
as one secret named `default`.

### Per-user stats API

Set `api-bind-to` to start a small HTTP server (bind it to loopback unless you
also set an [API token](#api-authentication)):

```toml
api-bind-to = "127.0.0.1:9090"
```

```console
curl http://127.0.0.1:9090/stats
```

```json
{
  "started_at": "2026-03-29T10:30:00Z",
  "uptime_seconds": 3600,
  "total_connections": 15,
  "users": {
    "alice": {
      "connections": 8,
      "bytes_in": 1048576,
      "bytes_out": 2097152,
      "last_seen": "2026-03-29T11:25:30Z"
    }
  }
}
```

`last_seen` is `null` for a user who has never connected. The `throttle` object
is included only when [throttling](#connection-throttling) is configured.

### Hot secret reload

The `api-bind-to` listener also serves a reload endpoint, so the `[secrets]` set
can change without restarting the proxy:

```console
curl -X POST http://127.0.0.1:9090/reload
```

On success it re-reads the same config file passed to `mtg-multi run` and swaps
the secret set in atomically:

- added secrets start working immediately;
- connections whose secret was removed or re-keyed are closed;
- every other user stays connected and their stats counters carry over.

Only `[secrets]`, `ad-tag`, `[secret-ad-tags]`, and `[secret-limits]` are
hot-applied. Changing the
bind address, domain fronting, network, or throttle settings still needs a
restart.

Responses: `200 {"status":"ok"}` on success; `500` if the config cannot be read
(the current set stays active); `503` when the proxy was started without a config
file (`simple-run`); `405` for a non-POST request.

### Secrets & ad-tag management API

The same listener exposes CRUD endpoints so you can manage secrets and the ad-tag
at runtime, without editing the file or restarting:

| Method & path | Action |
|---|---|
| `GET /secrets` | List secrets (`name`, `secret`, `host`, `ad_tag`, `effective_ad_tag`, plus `quota`/`quota_used`/`quota_remaining`/`expires_at`/`disabled` when set). |
| `POST /secrets` | Add or update one: `{"name","secret","ad_tag"?,"quota"?,"quota_reset"?,"expires"?,"disabled"?}`. |
| `PUT /secrets` | Replace the whole set: `{"secrets":{name:{secret,ad_tag?,quota?,quota_reset?,expires?,disabled?}},"ad_tag"?}`. |
| `DELETE /secrets/{name}` | Remove one (`404` if unknown, `409` if it is the last one). |
| `POST /secrets/{name}/reset-quota` | Zero the secret's used-bytes counter (`404` if unknown). |
| `GET /adtag` | Read the global ad-tag: `{"ad_tag":"<hex>"\|null}`. |
| `PUT /adtag` | Set the global ad-tag: `{"ad_tag":"<32 hex chars>"}`. |
| `DELETE /adtag` | Clear the global ad-tag. |

These go through the same atomic-swap machinery as `/reload`: a changed secret
key closes that user's connections, while an ad-tag-only change does not.

Direct API mutations are **in-memory only** — a later `POST /reload` (or a
restart) re-reads the config file and overrides them. Treat the file as the
source of truth and the API as a live override.

### API authentication

By default the API is unauthenticated and protected only by binding to loopback.
Because it can mutate secrets, you can require a bearer token on **every**
endpoint:

```toml
api-token = "change-me"
```

```console
curl -H "Authorization: Bearer change-me" http://127.0.0.1:9090/secrets
```

Missing or wrong tokens get `401`. When `api-token` is unset, behavior is
unchanged (no auth). Always set a token if the API is reachable from anything but
localhost.

### Sponsored channel (ad-tag)

Upstream mtg v2 dropped the promoted-channel feature; mtg-multi brings it back.
When an ad-tag is set, matching clients are routed through Telegram **middle
proxies** (the RPC protocol) instead of directly to the data centers, and your
sponsored channel appears at the top of their chat list.

```toml
ad-tag = "0123456789abcdef0123456789abcdef"
public-ipv4 = "1.2.3.4"   # this proxy's reachable public address
```

One global tag applies to every secret; you can override it per secret:

```toml
[secret-ad-tags]
bob = "fedcba9876543210fedcba9876543210"
```

**Getting a tag.** Register your proxy with [@MTProxybot](https://t.me/MTProxybot)
to obtain a 32-character hex `ad_tag`. When the bot asks for your secret, give it
the **bare 16-byte key only** — 32 hex characters, without the `ee` prefix and
without the appended hostname. For example, from the secret
`ee`**`3610182353be658466cea76f358bf9bb`**`7777772e...` you paste only
`3610182353be658466cea76f358bf9bb`. Pasting the full FakeTLS secret makes the bot
reply *"Incorrect secret value. It must contain 32 hex characters"* — that is the
bot's format requirement, not an error in your proxy.

**Requirements and behavior.**

- The middle-proxy path adds one network hop and needs a reachable **public IP**.
  On a host behind NAT or with multiple addresses, set `public-ipv4` /
  `public-ipv6` — the proxy's source address (and port) are mixed into the RPC
  key schedule, so the middle proxy must see the address you advertise. A machine
  behind a port-rewriting NAT cannot complete this handshake; run on a host with
  a real public IP (a VPS).
- If a middle proxy cannot be reached, that connection **falls back to a direct
  DC connection** (logged as a warning) so the client stays online — the sponsored
  channel just won't show for that session.
- The middle-proxy secret and address list are fetched from Telegram lazily on
  first use and refreshed hourly, so a proxy without an ad-tag never contacts
  those endpoints.

### Connection throttling

Automatic per-user connection limits protect the server from overload. A
background goroutine recomputes caps every few seconds using a fair-share
algorithm: light users keep all their connections, and the remaining budget is
split equally among heavy consumers. New connections from over-cap users are
rejected; existing connections are never killed.

```toml
[throttle]
max-connections = 5000
check-interval = "5s"
```

Example — limit 100, with users A=1, B=1, C=90, D=110: A and B stay at 1, and the
remaining budget of 98 is split so C and D are each capped at 49.

Throttle state is exposed in the stats response:

```json
{
  "throttle": {
    "active": true,
    "limit": 5000,
    "caps": { "heavy-user": 2450 }
  }
}
```

### Per-user quotas, expiry & disable

Each named secret can carry governance limits — a data quota, a validity
deadline, and an on/off switch — so you can run mtg-multi as a reseller or
multi-tenant proxy. Add a `[secret-limits.<name>]` table for any secret in
`[secrets]`; a secret without one is unlimited, never expires and is enabled.

```toml
# Persist quota usage across restarts (optional but recommended for quotas).
usage-state-file = "/var/lib/mtg/usage.json"

[secret-limits.alice]
quota = "10GB"            # human size or a bare byte count; omit for unlimited
quota-reset = "monthly"   # "none" (default, lifetime cap) or "monthly"
expires = "2026-12-31"    # RFC3339 or YYYY-MM-DD; omit for never
disabled = false          # true rejects the secret without removing it

[secret-limits.bob]
quota = "500MB"
```

When a user is over quota, past its expiry, or disabled, new connections are
transparently routed to the **fronting domain** — exactly like a wrong secret —
so a prober cannot tell a limited user from an invalid one. Enforcement happens
at connection time: an in-progress session is not cut off mid-stream, but
disabling or expiring a secret (via reload or the API) closes its live
connections immediately. A quota overrun never kills an active session.

Usage is exposed per user in `/stats` and `/secrets`:

```json
{
  "users": {
    "alice": {
      "connections": 2,
      "bytes_in": 1048576,
      "bytes_out": 2097152,
      "quota_used": 3145728,
      "quota": 10737418240,
      "quota_remaining": 10734272512,
      "quota_reset": "monthly",
      "expires_at": "2026-12-31T00:00:00Z"
    }
  }
}
```

Set `usage-state-file` so `quota_used` survives restarts; it is flushed
atomically every ~30 seconds and on shutdown. With `quota-reset = "monthly"` the
counter resets at the start of each calendar month. Clear a user's usage
manually with `POST /secrets/{name}/reset-quota`. Limits set through the
management API are in-memory only and are overridden by the next reload — the
config file remains the source of truth.

### Public IP override

Useful when automatic detection via ifconfig.co is unavailable, or when the
address the outside world sees differs from any local interface.

```toml
public-ipv4 = "1.2.3.4"
public-ipv6 = "2001:db8::1"
```

These addresses are used by `mtg-multi access` to build links, by
`mtg-multi doctor` to validate the SNI-to-DNS match, and — when an ad-tag is set
— as this proxy's own address in the middle-proxy handshake.

### Environment variables

For parity with the official
[telegrammessenger/proxy](https://hub.docker.com/r/telegrammessenger/proxy/)
image, `mtg-multi run` overlays a few environment variables on top of the config
file. The environment always wins over the file, and it is re-applied on every
config read, so an env-pinned secret or tag survives a `POST /reload`.

| Variable | Meaning |
|---|---|
| `SECRET` | Proxy secret. Either a full mtg secret (`ee…` hex or base64) or a bare 16-byte hex key in the official-image format — the latter also needs `SECRET_HOST`. Replaces the whole `[secrets]` set and `[secret-ad-tags]`. |
| `SECRET_HOST` | Domain-fronting hostname combined with a bare 16-byte `SECRET` into a FakeTLS secret. Ignored when `SECRET` is already a full secret. |
| `TAG` | Advertising tag from [@MTProxybot](https://t.me/MTProxybot); same as `ad-tag` in the config. An empty value clears the tag. Like the official image, it is not persisted — provide it on every run. |
| `MTG_BIND_TO` | Comma-separated `host:port` list overriding `bind-to`. |

The `MTG_`-prefixed variants (`MTG_SECRET`, `MTG_SECRET_HOST`, `MTG_TAG`) take
precedence over the bare names, so a generic name like `SECRET` in a shell can't
be captured by accident outside a container.

`WORKERS` and `SECRET_COUNT` from the official image are not applicable — one Go
process already uses every CPU core, and multiple secrets are configured through
`[secrets]` or the API. Setting either is ignored with a startup warning.

## Command reference

| Command | Description |
|---|---|
| `mtg-multi generate-secret [--hex] <hostname>` | Generate a new secret for the given fronting hostname. `--hex`/`-x` prints hex instead of base64. |
| `mtg-multi run <config>` | Run the proxy from a config file (supports the full feature set and hot reload). |
| `mtg-multi simple-run <bind-to> <secret>` | Run without a config file, from flags only (no `[secrets]`, no reload). |
| `mtg-multi access [--ipv4 IP] [--ipv6 IP] [--port N] [--hex] <config>` | Print `tg://` / `t.me` links and QR-code URLs for the configured secrets. |
| `mtg-multi doctor [--skip-native-check] <config>` | Check connectivity, clock skew, fronting reachability, and SNI-to-DNS match. Run this first when something is off. |
| `mtg-multi version` | Print the version. |

## Configuration

[example.config.toml](example.config.toml) documents every option with its
default value and inline notes. A real config only needs the options you actually
change — every key has a sensible default.

## Credits

mtg-multi is a fork of [9seconds/mtg](https://github.com/9seconds/mtg) by Sergey
Arkhipov and contributors. All of the core proxy engineering is theirs; this fork
adds the multi-user layer on top. The middle-proxy (ad-tag) implementation is
ported from the last mtg v1 release that shipped it.
