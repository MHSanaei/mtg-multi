# mtg-multi

Fork of [9seconds/mtg](https://github.com/9seconds/mtg) with multi-secret support and per-user stats.

[English](#whats-different) | [Русский](#чем-отличается)

---

## What's different

**Multiple secrets.** Upstream mtg allows only one secret per instance. mtg-multi lets you define named secrets in the config — one per user. Secrets may use different hostnames for per-user domain fronting.

```toml
[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
bob   = "ee0123456789abcdef0123456789abcd9573746f726167652e676f6f676c65617069732e636f6d"
```

**Stats API.** A lightweight HTTP endpoint that shows live per-user traffic.

```toml
api-bind-to = "127.0.0.1:9090"
```

```
GET /stats
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

**Hot secret reload.** The same `api-bind-to` listener also serves a reload
endpoint, so the `[secrets]` set can change without restarting the proxy:

```
POST /reload
```

On success it re-reads the same config file passed to `mtg run` and swaps the
`[secrets]` set in atomically. Added secrets work immediately; connections whose
secret was removed or re-keyed are closed; every other user stays connected and
their stats counters carry over. Only `[secrets]` is hot-applied — changing the
bind address, domain fronting, network, or throttle still needs a restart.
Responses: `200 {"status":"ok"}`, `500` if the config cannot be read (the
current set stays active), `503` when the proxy was started without a config
file (`simple-run`), and `405` for a non-POST request.

**Sponsored channel (ad-tag).** Upstream mtg v2 dropped the promoted-channel
feature; mtg-multi brings it back. Register your proxy with
[@MTProxybot](https://t.me/MTProxybot) to obtain a 32-character hex `ad_tag`.
When it is set, matching clients are routed through Telegram **middle proxies**
(the RPC protocol) instead of directly to the DCs, and a sponsored channel
appears at the top of their chat list.

```toml
ad-tag = "0123456789abcdef0123456789abcdef"
public-ipv4 = "1.2.3.4"   # this proxy's reachable address, required by the middle proxy
```

One global tag applies to every secret; you can override it per secret:

```toml
[secret-ad-tags]
bob = "fedcba9876543210fedcba9876543210"
```

Notes: the middle-proxy path adds one hop and needs a reachable public IP
(set `public-ipv4`/`public-ipv6` if you are behind NAT or multi-homed). If a
middle proxy cannot be reached, that connection falls back to a direct DC
connection (logged as a warning) so the client stays online — the sponsored
channel just will not show that time. The middle-proxy secret and address list
are fetched from Telegram lazily on first use and refreshed hourly, so a proxy
without an ad-tag never touches those endpoints.

**Secrets & ad-tag management API.** The `api-bind-to` listener also lets you
manage secrets and the ad-tag at runtime, without editing the file or
restarting:

```
GET    /secrets            list secrets (name, secret, host, ad_tag, effective_ad_tag)
POST   /secrets            add/update one: {"name","secret","ad_tag"?}
PUT    /secrets            replace the whole set: {"secrets":{name:{secret,ad_tag?}},"ad_tag"?}
DELETE /secrets/{name}     remove one (404 unknown, 409 if it is the last one)
GET    /adtag              read the global ad-tag: {"ad_tag":"<hex>"|null}
PUT    /adtag              set the global ad-tag: {"ad_tag":"<32 hex chars>"}
DELETE /adtag              clear the global ad-tag
```

These go through the same atomic-swap machinery as `/reload`: a changed secret
key closes that user's connections, an ad-tag-only change does not. Direct API
mutations are **in-memory only** — a later `POST /reload` (or a restart)
re-reads the config file and overrides them.

**API authentication.** By default the API is unauthenticated and protected only
by binding to loopback. Since the API can now mutate secrets, you can require a
bearer token on **every** endpoint:

```toml
api-token = "change-me"
```

```console
curl -H "Authorization: Bearer change-me" http://127.0.0.1:9090/secrets
```

Missing or wrong tokens get `401`. When `api-token` is unset, behavior is
unchanged (no auth).

**Connection throttling.** Automatic per-user connection limits to protect the server from overload. A background goroutine recomputes caps every few seconds using a fair-share algorithm: small users keep their connections, remaining budget is split equally among heavy consumers. New connections from over-cap users are rejected; existing connections are not killed.

```toml
[throttle]
max-connections = 5000
check-interval = "5s"
```

Example: limit = 100, users A=1, B=1, C=90, D=110.
A and B stay at 1. Remaining budget 98 is split: C and D are capped at 49 each.

Throttle state is exposed via the Stats API:

```json
{
  "throttle": {
    "active": true,
    "limit": 5000,
    "caps": { "heavy-user": 2450 }
  }
}
```

**Public IP override.** Useful when auto-detection via ifconfig.co is unavailable.

```toml
public-ipv4 = "1.2.3.4"
public-ipv6 = "2001:db8::1"
```

Everything else — domain fronting, doppelganger, proxy chaining, blocklists, metrics — works exactly as in upstream. See the [upstream README](https://github.com/9seconds/mtg) for details.

## Quick start

Download a binary from [Releases](https://github.com/mhsanaei/mtg-multi/releases) or build from source:

```console
git clone https://github.com/mhsanaei/mtg-multi.git
cd mtg-multi
mise install && mise tasks run build
```

Generate secrets:

```console
mtg-multi generate-secret --hex storage.googleapis.com
```

Minimal config:

```toml
bind-to = "0.0.0.0:443"
api-bind-to = "127.0.0.1:9090"

[throttle]
max-connections = 5000

# [secrets] must be the last section in the global scope —
# in TOML, all keys after a [section] become part of that table.
[secrets]
alice = "ee..."
bob   = "ee..."
```

Run:

```console
mtg-multi run /etc/mtg/config.toml
```

See [example.config.toml](example.config.toml) for all available options.

---

## Чем отличается

**Несколько секретов.** В оригинальном mtg — один секрет на инстанс. mtg-multi позволяет задать именованные секреты в конфиге, по одному на пользователя. Секреты могут использовать разные hostname для per-user domain fronting.

```toml
[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
bob   = "ee0123456789abcdef0123456789abcd9573746f726167652e676f6f676c65617069732e636f6d"
```

**Stats API.** HTTP-эндпоинт с live-статистикой трафика по пользователям.

```toml
api-bind-to = "127.0.0.1:9090"
```

```
GET /stats
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

**Рекламный канал (ad-tag).** mtg v2 убрал поддержку промо-каналов; mtg-multi
возвращает её. Зарегистрируйте прокси в [@MTProxybot](https://t.me/MTProxybot)
и получите `ad_tag` (32 hex-символа). Когда он задан, подходящие клиенты идут
через middle-прокси Telegram (протокол RPC), а не напрямую в DC, и у них вверху
списка чатов появляется спонсируемый канал.

```toml
ad-tag = "0123456789abcdef0123456789abcdef"
public-ipv4 = "1.2.3.4"   # доступный адрес этого прокси, нужен middle-прокси

[secret-ad-tags]
bob = "fedcba9876543210fedcba9876543210"   # переопределение тега для отдельного секрета
```

Если middle-прокси недоступен, соединение откатывается на прямое подключение к
DC (с предупреждением в логе), чтобы клиент оставался онлайн. Секрет и список
middle-прокси загружаются с Telegram лениво при первом использовании и
обновляются раз в час.

**API управления секретами и ad-tag.** Тот же слушатель `api-bind-to` позволяет
менять секреты и ad-tag на лету, без правки файла и рестарта:

```
POST   /reload             перечитать [secrets], ad-tag и [secret-ad-tags] из файла
GET    /secrets            список секретов
POST   /secrets            добавить/обновить один: {"name","secret","ad_tag"?}
PUT    /secrets            заменить весь набор
DELETE /secrets/{name}     удалить один
GET/PUT/DELETE /adtag      прочитать/задать/очистить глобальный ad-tag
```

Изменения через API применяются только в памяти — последующий `POST /reload`
(или рестарт) перечитывает файл и перезаписывает их.

**Аутентификация API.** По умолчанию API без аутентификации и защищён только
привязкой к loopback. Так как API теперь может менять секреты, можно включить
bearer-токен на всех эндпоинтах:

```toml
api-token = "change-me"
```

Запросы без токена или с неверным токеном получают `401`. Если `api-token` не
задан — поведение прежнее (без аутентификации).

**Троттлинг подключений.** Автоматические per-user лимиты для защиты сервера от перегрузки. Фоновая горутина каждые несколько секунд пересчитывает капы по алгоритму fair-share: маленькие пользователи сохраняют свои подключения, оставшийся бюджет делится поровну между крупными потребителями. Новые подключения сверх капа отклоняются; существующие не разрываются.

```toml
[throttle]
max-connections = 5000
check-interval = "5s"
```

Пример: лимит = 100, пользователи A=1, B=1, C=90, D=110.
A и B остаются на 1. Оставшийся бюджет 98 делится: C и D получают кап 49.

Состояние троттлинга доступно через Stats API:

```json
{
  "throttle": {
    "active": true,
    "limit": 5000,
    "caps": { "heavy-user": 2450 }
  }
}
```

**Ручное указание публичного IP.** Для случаев, когда ifconfig.co недоступен с сервера.

```toml
public-ipv4 = "1.2.3.4"
public-ipv6 = "2001:db8::1"
```

Всё остальное — domain fronting, doppelganger, цепочки прокси, блоклисты, метрики — работает как в оригинале. Подробности в [README upstream](https://github.com/9seconds/mtg).

## Быстрый старт

Скачайте бинарник из [Releases](https://github.com/mhsanaei/mtg-multi/releases) или соберите из исходников:

```console
git clone https://github.com/mhsanaei/mtg-multi.git
cd mtg-multi
mise install && mise tasks run build
```

Генерация секрета:

```console
mtg-multi generate-secret --hex storage.googleapis.com
```

Минимальный конфиг:

```toml
bind-to = "0.0.0.0:443"
api-bind-to = "127.0.0.1:9090"

[throttle]
max-connections = 5000

# [secrets] должен быть последней секцией в глобальном scope —
# в TOML все ключи после [section] становятся частью этой таблицы.
[secrets]
alice = "ee..."
bob   = "ee..."
```

Запуск:

```console
mtg-multi run /etc/mtg/config.toml
```

Все доступные опции — в [example.config.toml](example.config.toml).
