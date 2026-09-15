# Response actions

All twelve, with every option, and what each costs you as well as the attacker.

← [Documentation](../index.md) · [Responses](index.md)

---

| Action | What it does | Default policy uses it |
| --- | --- | --- |
| [`decoy-content`](#decoy-content) | serves the fake content a decoy carries | through a decoy's `respondWith` |
| [`not-found`](#not-found) | a flat 404 | yes, below the tarpit threshold |
| [`redirect`](#redirect) | bounces the client toward another decoy | through a decoy's `respondWith` |
| [`tarpit`](#tarpit) | holds the response open, longer as the score climbs | yes, past the tarpit threshold |
| [`block`](#block) | blocks the address for a period; later requests are refused before any detector runs | yes, past the block threshold |
| [`drip-feed`](#drip-feed) | trickles a never-finished response byte by byte | only if selected |
| [`large-payload`](#large-payload) | streams a large response to soak up bandwidth and storage | only if selected |
| [`fake-success`](#fake-success) | a plausible success with a fake session token | only if selected |
| [`fake-data`](#fake-data) | freshly synthesised fake secrets tailored to the path | only if selected |
| [`gzip-bomb`](#gzip-bomb) | a few KB that inflate to megabytes in a naive client | only if selected |
| [`chaos`](#chaos) | a random 5xx or random bytes | only if selected |
| [`rate-limit`](#rate-limit) | a standard 429 with `Retry-After` | only if selected |

Every TOML section also takes `enabled`. Keys are the snake_case of the options.

---

## Revealing nothing

### `not-found`

`notFoundAction()` — a `404` with an empty body, or the decoy payload's `status` if it has one. The
probe itself was the signal. No options.

### `rate-limit`

`rateLimitAction(options)` — looks like ordinary rate limiting, so it reveals nothing about the
honeypot while telling well-behaved clients to back off.

| Option | TOML | Default |
| --- | --- | --- |
| `retryAfterSeconds` | `retry_after_seconds` | `60` |
| `status` | `status` | `429` |
| `body` | `body` | `"Too Many Requests"` |

## Keeping them engaged

### `decoy-content`

`decoyContentAction()` — serves the detection's `metadata.payload`: a decoy's `status` (default 200),
`contentType` (default `text/plain`) and `body`. So a probe for `/.env` appears to succeed, and the
attacker keeps engaging with bait instead of moving on. No options; configure the payload on the
[decoy](../detection/decoys.md).

### `redirect`

`redirectAction()` — a `302` (or the payload's `status`) to the payload's `location`. The built-in
`wp-admin` decoy uses it to bounce to the fake `wp-login.php`. No options.

### `fake-success`

`fakeSuccessAction(options)` — as if the exploit or login worked. A sticky decoy: the attacker
believes they are in and keeps going, handing over more intent. Nothing real is granted; the token
is noise.

| Option | TOML | Default |
| --- | --- | --- |
| `status` | `status` | `200` |
| `body` | `body` | `{"status":"ok","authenticated":true,"token":"<random>","expiresIn":3600}`; in code also a `(ctx) => string` |
| `contentType` | `content_type` | `"application/json"` |
| `setSessionCookie` | `set_session_cookie` | `true`: a random `session` cookie, `HttpOnly`, `SameSite=Lax` |

A good place for a [honeytoken](../detection/traps-and-honeytokens.md#honeytokens): put one in the body,
and a later request presenting it is proof.

### `fake-data`

`fakeDataAction(options)` — **freshly synthesised** fake secrets tailored to the path, randomised on
every hit, so responses cannot be diffed and anything exfiltrated is noise the attacker cannot tell
from a real leak.

| Path contains | Serves |
| --- | --- |
| `.env` | a fake dotenv |
| `aws`, `credentials` | a fake `~/.aws/credentials` |
| `user`, `account`, `member`, `dump` | a JSON user table with bcrypt-shaped hashes |
| anything else | a generic secrets blob |

| Option | TOML | Default |
| --- | --- | --- |
| `names` | `names` | a small built-in set of first names; setting it replaces them |
| `domain` | `domain` | `"corp.internal"`: the fake internal domain in emails and hostnames |
| `rows` | `rows` | `8`: rows a listing returns |

**Never seed `names` with real employee names, or point `domain` at a name you own or use.** This
action serves that data to attackers by design; real names or a real internal domain turn a decoy into
genuine reconnaissance, useful for spear-phishing. Plausibility is the goal, not identity.

## Wasting their time

These hold a connection. They cost a slot on your side too, so each has a concurrency cap and
**degrades to an immediate response at capacity**, so a flood cannot turn retaliation into a
self-inflicted denial of service. A client that disconnects releases its slot at once, including one
that disconnects before the action starts.

### `tarpit`

`tarpitAction(options)` — waits, then answers. It pins a slot in the scanner's connection pool and
burns its time.

| Option | TOML | Default |
| --- | --- | --- |
| `delayMs` | `delay_ms` | `[2000, 8000]`: a random delay in the range; a number is fixed |
| `status` | `status` | `404` |
| `body` | `body` | `"Not Found"` |
| `escalate` | `escalate` | `true`: multiply the delay by `min(4, 1 + totalScore / 50)` |
| `maxConcurrent` | `max_concurrent` | `1000` |

It is also the proof guard's default fallback, so in middleware mode it is what an unproven block
becomes. A tarpitted real visitor waits seconds once; a blocked one is refused everywhere.

### `drip-feed`

`dripFeedAction(options)` — a `200` whose body arrives one chunk at a time and never finishes before
`maxDurationMs`, pinning the client's connection.

| Option | TOML | Default |
| --- | --- | --- |
| `chunkBytes` | `chunk_bytes` | `1` |
| `intervalMs` | `interval_ms` | `1000` |
| `maxDurationMs` | `max_duration_ms` | `120000` |
| `status` | `status` | `200` |
| `maxConcurrent` | `max_concurrent` | `256` |

## Wasting their resources

These push data. Use them judiciously: each streams real bandwidth from your side, and payload served
to a spoofed source is wasted. They shine against automated scrapers that save or decompress what they
download.

### `large-payload`

`largePayloadAction(options)` — streams a large body, generated from a reused buffer, so the size
costs nothing in memory.

| Option | TOML | Default |
| --- | --- | --- |
| `totalBytes` | `total_bytes` | `52428800` (50 MB) |
| `chunkBytes` | `chunk_bytes` | `65536`; at least 1 (the stream advances by this, so 0 would spin forever) |
| `throttleMs` | `throttle_ms` | `0` |
| `contentType` | `content_type` | `"application/octet-stream"` |
| `maxConcurrent` | `max_concurrent` | `64`: lower than the others, because each stream is real bandwidth |

It respects backpressure, so a client that stops reading holds a slot rather than filling memory.

### `gzip-bomb`

`gzipBombAction(options)` — a few KB on the wire with `Content-Encoding: gzip`, inflating to
`decompressedBytes` in a client that decompresses naively. Built once and cached, so serving it costs
nothing.

| Option | TOML | Default |
| --- | --- | --- |
| `decompressedBytes` | `decompressed_bytes` | `10485760` (10 MB); at most 256 MB |
| `contentType` | `content_type` | `"text/html; charset=utf-8"` |

The ceiling is for **you**: the buffer is allocated and compressed in this process the first time it is
served, so a stray zero is not a bigger bomb, it is a multi-gigabyte allocation and a blocked event loop
on the first probe. The config refuses it at startup.

## Breaking their tooling

### `chaos`

`chaosAction(options)` — answers unpredictably, a random 5xx or random bytes, to break the assumptions
automated tooling makes.

| Option | TOML | Default |
| --- | --- | --- |
| `statuses` | `statuses` | `[500, 502, 503, 504]`; must not be empty |
| `garbageChance` | `garbage_chance` | `0.5`, a probability between 0 and 1 |
| `maxGarbageBytes` | `max_garbage_bytes` | `4096`; at least 64 |

## Stopping

### `block`

`blockAction(options)` — writes the address to the blocklist until `now + durationMs` and answers. Every
later request from the address is refused `403` by the engine before any detector runs, so a blocked
attacker costs almost nothing to serve.

| Option | TOML | Default |
| --- | --- | --- |
| `durationMs` | `duration_ms` | `900000` (15 minutes) |
| `status` | `status` | `403` |
| `body` | `body` | `"Forbidden"` |
| `sendRetryAfter` | `send_retry_after` | `true` |

A block reaches whatever the blocklist is: in memory per instance, [Redis](../operations/firewall.md#the-blocklists)
across replicas, and the [firewall](../operations/firewall.md) if an enforcer wraps it.

**Blocking is best-effort.** If the blocklist throws (a Redis outage, a failing enforcer), the failure is
reported through `onError` with source `blocklist` and the response is still the `403`. Propagating it
used to turn every flagged request into a 500, which is a honeypot tell, while reporting nothing.

In middleware mode, `block` runs only with proof. See [the proof guard](../concepts/the-guard.md).

## Related

- [Writing a policy](policy.md) — choosing among them
- [Writing a response](writing-a-response.md) — adding a thirteenth
- [Configuration](../reference/configuration.md#responses) — the TOML sections in one place
