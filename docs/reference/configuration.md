# Configuration reference

Every TOML section and key, with its default and its consequence.

← [Documentation](../index.md)

---

The standalone service is configured by a TOML file, so a deployment changes without touching code or
rebuilding an image. [`hackerpot.toml`](../../hackerpot.toml) at the repository root is the shipped
default: **every value in it is a built-in default**, annotated, so deleting it changes nothing and it
doubles as the living reference. A test asserts that the shipped file resolves to exactly the built-in
defaults, so the file cannot drift from the code.

---

## Loading and precedence

```bash
hackerpot serve --config ./hackerpot.toml
HACKERPOT_CONFIG=./hackerpot.toml hackerpot serve
```

- **Discovery.** With no `--config` or `HACKERPOT_CONFIG`, the first of these that exists is used:
  `./hackerpot.toml`, `./hackerpot.config.toml`, `./config/hackerpot.toml`,
  `/etc/hackerpot/hackerpot.toml`. With none, the built-in defaults apply: the file is optional.
- **Discovery is relative to the working directory.** The `hackerpot.toml` inside the npm package is a
  reference to copy, never loaded from `node_modules`. An installed dependency silently imposing its own
  configuration would be the wrong behaviour.
- **An explicitly named file that is missing is an error**, not a silent fall back to discovery.
- **Precedence: built-in defaults < config file < [environment variables](environment.md).**

## Validation

The config is strict, because a honeypot that silently ignores `[detectors.rate-spke]` is a honeypot with a
detector quietly switched off.

- **Unknown keys are a hard error**, with the key named, exit code 2, printed as
  `hackerpot: <path>: <message>` on stderr (1 is reserved for a runtime failure).
- So are wrong types, unparsable regexes, unmatchable allowlist entries, a port claimed by two listeners, and
  contradictions: `tarpit_threshold` above `block_threshold`, a store enabled with no location, the
  management API enabled with no keys, `max_bytes = 0` with archives, half-configured basic auth, a
  throttle with one of its two keys, a webhook-and-command enforcer, a trap path without a leading `/`, an
  `expected_hosts` entry with a port, an unknown id in `shadow_detectors` or `disabled`, and a dashboard on
  a public address without authentication.
- **Section names accept hyphens or underscores** interchangeably: `[detectors.rate-spike]` is
  `[detectors.rate_spike]`.
- **Regex-valued keys** take a bare pattern, compiled case-insensitively, or a `/pattern/flags` literal.
- `hackerpot config` resolves and validates without binding a port, and prints the result with secrets
  redacted. `hackerpot check` also serves every response action once. See [the CLI](../testing/cli.md).

## Sections at a glance

| Section | Controls | Reloads on SIGHUP |
| --- | --- | --- |
| [`[server]`](#server) | the attacker-facing HTTP listener | no |
| [`[logging]`](#logging) | log format and detail | yes |
| [`[engine]`](#engine) | windows, detector deadline, shadow detectors | `shadow_detectors` only |
| [`[audit]`](#audit) | the traffic audit | no |
| [`[service_tokens]`](#service_tokens) | secrets that exempt your monitors | yes |
| [`[policy]`](#policy) | the escalation thresholds | yes |
| [`[store.*]`](#stores) | memory, file, Redis, Elasticsearch | no |
| [`[intel]`](#intel) | peer IOC feeds | feeds and limits; not `enabled`, `enforce` |
| [`[allowlist]`](#allowlist) | addresses exempt from everything | yes |
| [`[blocklist]`](#blocklist) | where blocks live, and firewall enforcement | no |
| [`[detectors.*]`](#detectors) | one table per detector | yes |
| [`[responses.*]`](#responses) | one table per response action | yes |
| [`[port-scan]`](#port-scan) | the port-scan sentinel | no |
| [`[smtp]`, `[ssh]`, `[ftp]`, `[telnet]`](#protocol-honeypots) | the protocol honeypots | no |
| [`[syslog]`](#syslog) | forwarding to a SIEM | no |
| [`[management]`](#management) | the operator API and webhooks | no |
| [`[dashboard]`](#dashboard) | the operator dashboard | no |

---

## `[server]`

| Key | Default | |
| --- | --- | --- |
| `host` | `"0.0.0.0"` | |
| `port` | `4004` | |
| `trust_proxy` | `false` | take the client address from `X-Forwarded-For`. **Only** behind a proxy you control that overwrites the header; otherwise a client picks its own address, escapes its score, impersonates an allowlisted source and gets victims blocked. See [the client IP](../integration/client-ip.md) |

## `[logging]`

| Key | Default | |
| --- | --- | --- |
| `format` | `"json"` | `"json"`: one object per event. `"text"`: key=value lines, control characters escaped |
| `startup` | `true` | the one-line startup summary |
| `include_headers` | `false` | request headers in each `hit` line; attacker-controlled and noisy |
| `include_body` | `false` | the request body in each `hit` line |

## `[engine]`

| Key | Default | |
| --- | --- | --- |
| `activity_window_ms` | `60000` | the sliding window the stateful detectors read; must be at least their largest window |
| `detector_timeout_ms` | `2000` | an async detector past this is skipped for that request and reported; `0` disables |
| `shadow_detectors` | `[]` | detector ids that run and report but never act; see [shadow mode](../detection/shadow-mode.md) |
| `fingerprint_window_ms` | `3600000` | how long the actor registry remembers a fingerprint's addresses; bounds `repeat-actor` and its memory |

## `[audit]`

See [the traffic audit](../operations/audit.md).

| Key | Default | |
| --- | --- | --- |
| `enabled` | `true` | |
| `window_seconds` | `300` | the stretch being judged; at least 1 |
| `baseline_seconds` | `3600` | what it is compared with; at least `window_seconds` |
| `interval_seconds` | `60` | how often; at least 1 |
| `min_samples` | `50` | requests in the window before any check speaks |
| `cooldown_seconds` | `900` | silence per check after it fires |
| `campaign_min_ips` | `10` | addresses newly probing one path to count as a campaign; `0` turns it off |

## `[service_tokens]`

See [service tokens](../integration/service-tokens.md).

| Key | Default | |
| --- | --- | --- |
| `header` | `"x-hackerpot-token"` | letters, digits and hyphens |
| `[service_tokens.tokens]` | none | name = secret; an empty secret is an error; under 16 characters logs a warning |

## `[policy]`

See [scoring](../concepts/scoring.md#the-escalation-ladder).

| Key | Default | |
| --- | --- | --- |
| `block_threshold` | `40` | cumulative score at which an address is blocked (in middleware, with proof) |
| `tarpit_threshold` | `15` | cumulative score past which unrouted detections are tarpitted; must not exceed `block_threshold` |

## Stores

With no durable store enabled, `[store.memory]` is used. Enable several and they are composed. See
[stores](../operations/stores.md).

### `[store.memory]`

| Key | Default | |
| --- | --- | --- |
| `max_hits` | `10000` | retained incidents (a ring buffer); also how far back the API, dashboard and IOC feed see; `> 0` |
| `max_score_entries` | `100000` | per-address scores kept, least recently updated shed first; `> 0` |

### `[store.file]`

| Key | Default | |
| --- | --- | --- |
| `enabled` | `true` when `path` is set | |
| `path` | `""` | the JSONL log; setting it enables the store |
| `load_on_start` | `true` | replay the file (streamed) so scores survive a restart |
| `max_bytes` | `134217728` (128 MB) | roll into an archive at this size; `0` disables rotation |
| `max_archives` | `10` | archives kept; `0` keeps all. `max_bytes = 0` with `max_archives > 0` is an error |
| `max_archive_age_seconds` | `0` | also prune archives older than this; `0` is off |
| `compress_archives` | `true` | gzip rolled segments |
| `max_score_entries` | `100000` | |

### `[store.redis]`

| Key | Default | |
| --- | --- | --- |
| `enabled` | `true` when `url` is set | |
| `url` | `""` | setting it enables the store |
| `key_prefix` | `"hackerpot:"` | |
| `score_ttl_seconds` | `0` | seconds before a quiet address's score expires; `0` never |
| `max_hits` | `10000` | the hit log's length, and so Redis's memory ceiling (`× 64 KB` worst case) |
| `max_retries_per_request` | `3` | reconnect attempts before a command fails; `0` waits forever and hangs requests in an outage |
| `command_timeout_ms` | `5000` | a live but silent server; `0` disables |

### `[store.elastic]`

| Key | Default | |
| --- | --- | --- |
| `enabled` | `true` when `node` is set | |
| `node` | `""` | an http(s) URL; setting it enables the store |
| `index` | `"hackerpot-hits"` | |
| `api_key` | `""` | or both `username` and `password`; one without the other is an error |
| `username`, `password` | `""` | |
| `max_hits` | `1000` | documents a read returns |
| `refresh` | `false` | make each write immediately searchable; slower |
| `timeout_ms` | `10000` | per request; `scoreFor` is on the request path |

## `[intel]`

See [threat intel](../operations/threat-intel.md).

| Key | Default | |
| --- | --- | --- |
| `enabled` | `true` when `feeds` is set | |
| `feeds` | `[]` | peer `/ioc.txt` URLs; https, except a loopback host |
| `refresh_seconds` | `300` | at least 30 |
| `min_score` | `0` | sent as `?min_score=` |
| `api_key` | `""` | bearer token for the peer |
| `ttl_seconds` | `3600` | how long an ingested block lasts; `> 0` |
| `max_entries` | `10000` | per refresh; `> 0` |
| `enforce` | `false` | let ingested entries reach the firewall enforcer. Logs a warning; a feed you enforce is as trusted as root |

## `[allowlist]`

| Key | Default | |
| --- | --- | --- |
| `ips` | `[]` | addresses and CIDR ranges, IPv4 or IPv6, exempt from everything: never detected, scored, blocked or recorded. Validated at startup, and compared by value. The most effective false-positive control there is |

## `[blocklist]`

| Key | Default | |
| --- | --- | --- |
| `backend` | `"memory"` | `"memory"` per instance, or `"redis"`, sharing `[store.redis]`'s connection (required) |
| `key_prefix` | `"hackerpot:block:"` | for Redis |
| `max_entries` | `100000` | memory only; expired entries swept first, then the soonest-to-expire shed |

### `[blocklist.enforcer]`

See [firewall enforcement](../operations/firewall.md).

| Key | Default | |
| --- | --- | --- |
| `enabled` | `true` when `command` or `webhook` is set | |
| `command` | `""` | a program run through `execFile`, no shell |
| `args` | `[]` | must contain `{ip}`; requires `command` |
| `webhook` | `""` | an http(s) URL; one of `command` or `webhook`, not both |
| `secret` | `""` | signs the webhook body |
| `headers` | `{}` | `[blocklist.enforcer.headers]` |
| `timeout_ms` | `5000` | the block response awaits it |
| `max_per_window` | 50 for a command, 100 for a webhook | past it enforcement is dropped, not queued; `> 0` |
| `window_ms` | `1000` | `> 0` |

## Detectors

Each detector is a `[detectors.<id>]` table taking `enabled`, `score` and `respond_with`, plus its own
options in snake_case. Every option is on [the detectors page](../detection/detectors.md); the list here
is for scanning.

| Section | Default | Own keys |
| --- | --- | --- |
| `[detectors.decoy-path]` | on | `replace_defaults` (false), `disabled` ([]), `[[detectors.decoy-path.decoys]]`; no `score` or `respond_with` |
| `[detectors.payload-injection]` | on, 10 | `inspect_body` (true), `inspect_headers` |
| `[detectors.ssrf-probe]` | on, 9 | `inspect_body`, `inspect_headers` |
| `[detectors.nosql-injection]` | on, 9 | `inspect_body` |
| `[detectors.prototype-pollution]` | on, 8 | `inspect_body` |
| `[detectors.insecure-deserialization]` | on, 9 | `inspect_body`, `inspect_headers` |
| `[detectors.graphql-abuse]` | on, 7 | `max_depth` (12), `inspect_body` |
| `[detectors.jwt-weakness]` | on, 9 | `inspect_headers` |
| `[detectors.crlf-injection]` | on, 8 | `inspect_headers` |
| `[detectors.web-shell]` | on, 9 | `patterns` (regex list) |
| `[detectors.header-anomaly]` | on, 7 | `flag_missing_host` (true) |
| `[detectors.header-integrity]` | on, 9 | `duplicate_score` (3) |
| `[detectors.target-integrity]` | on, 7 | `weak_score` (3) |
| `[detectors.crawler-verification]` | **off**, 10 | `treat_missing_ptr_as_forgery` (true), `published_ranges` (false), `ranges_refresh_hours` (12, at least 1) |
| `[detectors.trap]` | **off**, 15 | `paths`, `form_fields` ([]), `header_name` |
| `[detectors.host-header-injection]` | on, 6 | `expected_hosts` (hostnames, no port) |
| `[detectors.sensitive-file]` | on, 6 | `patterns` (regex list) |
| `[detectors.open-redirect]` | on, 5 | `params`, `trusted_hosts` |
| `[detectors.suspicious-method]` | on, 6 | `methods` |
| `[detectors.credential-bruteforce]` | on, 9 | `auth_paths` (regex), `window_ms` (60000), `attempt_threshold` (8) |
| `[detectors.path-bruteforce]` | on, 8 | `window_ms` (30000), `unique_path_threshold` (15) |
| `[detectors.scanner-signature]` | on, 6 | `extra_patterns` (regex list), `flag_missing_user_agent` (true) |
| `[detectors.client-anomaly]` | on, 4 | `required_browser_headers` |
| `[detectors.rate-spike]` | on, 4 | `window_ms` (10000), `request_threshold` (60) |
| `[detectors.repeat-actor]` | on, 7 | `distinct_ip_threshold` (3), `window_ms` (600000) |
| `[detectors.honeytoken]` | on when tokens are listed, 15 | `tokens`: strings, or `[[detectors.honeytoken.tokens]]` with `value` and `label` |

**List-valued defaults are documented, not set.** In the shipped file, keys like `inspect_headers`,
`params` and `methods` appear only as commented examples. The library owns the lists; a restated default in
the file would go stale silently the moment the library changed, and the file, which wins, would then run
the old behaviour. **Setting a list replaces it**.

A custom decoy:

```toml
[[detectors.decoy-path.decoys]]
id = "internal-backup"               # required; one sharing a built-in id replaces it
description = "Fake internal backup" # defaults to the id
path = "/internal/backup.sql"        # or pattern = "^/internal/.*\\.sql$"; one, not both
score = 9                            # default 5
method = "GET"                       # optional
respond_with = "large-payload"
[detectors.decoy-path.decoys.payload]
status = 200
content_type = "application/sql"
body = "-- nothing here"
# location = "/elsewhere"            # for respond_with = "redirect"
```

See [decoys](../detection/decoys.md).

## Responses

Each response action is a `[responses.<id>]` table with `enabled` (default `true`) plus its options.
**Disabling an action removes it from the registry**; make sure nothing still names it. Every option is on
[the actions page](../responses/actions.md).

| Section | Keys (defaults) |
| --- | --- |
| `[responses.decoy-content]`, `[responses.not-found]`, `[responses.redirect]` | `enabled` only |
| `[responses.block]` | `duration_ms` (900000), `status` (403), `body` ("Forbidden"), `send_retry_after` (true) |
| `[responses.tarpit]` | `delay_ms` ([2000, 8000], a number or a range), `status` (404), `body` ("Not Found"), `escalate` (true), `max_concurrent` (1000) |
| `[responses.drip-feed]` | `chunk_bytes` (1), `interval_ms` (1000), `max_duration_ms` (120000), `status` (200), `max_concurrent` (256) |
| `[responses.large-payload]` | `total_bytes` (52428800), `chunk_bytes` (65536, at least 1), `throttle_ms` (0), `content_type` ("application/octet-stream"), `max_concurrent` (64) |
| `[responses.fake-success]` | `status` (200), `content_type` ("application/json"), `set_session_cookie` (true), `body` |
| `[responses.fake-data]` | `names`, `domain` ("corp.internal"), `rows` (8) |
| `[responses.gzip-bomb]` | `decompressed_bytes` (10485760, at most 256 MB), `content_type` ("text/html; charset=utf-8") |
| `[responses.chaos]` | `statuses` ([500, 502, 503, 504], not empty), `garbage_chance` (0.5, 0–1), `max_garbage_bytes` (4096, at least 64) |
| `[responses.rate-limit]` | `retry_after_seconds` (60), `status` (429), `body` ("Too Many Requests") |

## `[port-scan]`

See [the port-scan sentinel](../protocols/port-scan.md).

| Key | Default | |
| --- | --- | --- |
| `enabled` | `true` when `ports` is set | |
| `ports` | `[]` | listing any enables it |
| `host` | `"0.0.0.0"` | |
| `scan_threshold` | `2` | distinct ports for a sweep |
| `banner` | `"SSH-2.0-OpenSSH_8.4"` | `""` stays silent |
| `max_tracked_ips` | `10000` | `> 0` |
| `retention_ms` | `3600000` | `> 0` |

## Protocol honeypots

All **off by default**. Full descriptions: [SSH](../protocols/ssh.md), [SMTP](../protocols/smtp.md),
[FTP](../protocols/ftp.md), [Telnet](../protocols/telnet.md).

| Key | `[ssh]` | `[smtp]` | `[ftp]` | `[telnet]` |
| --- | --- | --- | --- | --- |
| `enabled` | `false` | `false` | `false` | `false` |
| `port` | `2222` | `2525` | `2121` | `2323` |
| `host` | `"0.0.0.0"` | `"0.0.0.0"` | `"0.0.0.0"` | `"0.0.0.0"` |
| `banner` / `ident` | `ident = "OpenSSH_8.4"` | `"Postfix"` | `"(vsFTPd 3.0.3)"` | `"Ubuntu 22.04.3 LTS"` |
| `hostname` | — | `"mail"` | — | `"srv01"` |
| `max_auth_attempts` | `6` | — | `6` | `3` |
| `drop_above_score` | `0` (never) | `0` | `0` | `0` |
| `max_connections` | `256` | `256` | `256` | `256` |
| `max_session_ms` | `120000` (> 0) | `120000` (> 0) | `120000` (> 0) | `120000` (> 0) |
| `interactive` | `false` | — | `false` | `false` |
| `accept_on_attempt` | `1` (≤ `max_auth_attempts`) | — | `1` | `1` |
| `max_commands` | `100` | — | `100` | `100` |
| `max_command_length` | `4096` | — | `512` | `4096` |
| other | `shell_hostname` ("srv01"), `host_key_files` ([]), `host_keys` ([]) | `local_domains` ([]), `capture_body` (true), `max_body_chars` (2000) | | |

## `[syslog]`

See [alert sinks](../operations/alert-sinks.md#syslog-and-siem).

| Key | Default | |
| --- | --- | --- |
| `enabled` | `true` when `host` is set | |
| `host` | `""` | the collector |
| `port` | `514` | |
| `protocol` | `"udp"` | or `"tcp"` |
| `format` | `"cef"` | `"cef"`, `"json"` or `"text"` |
| `facility` | `13` | 0–23 |
| `severity` | `4` | 0–7 |
| `hostname` | `"hackerpot"` | in the syslog header |
| `min_score` | `0` | |
| `max_bytes` | `1024` | at least 480 |
| `include_body` | `false` | |

## `[management]`

See [the management API](../operations/management-api.md).

| Key | Default | |
| --- | --- | --- |
| `enabled` | `true` when `api_keys` is set | enabled with no keys is an error |
| `host` | `"127.0.0.1"` | keep it private |
| `port` | `9500` | |
| `api_keys` | `[]` | `Authorization: Bearer` or `X-API-Key` |
| `websocket` | `true` | the `/stream` live feed |
| `webhook_global_max_per_minute` | `0` | cap across all webhooks; `0` unlimited |

### `[[management.webhooks]]`

See [webhooks](../operations/webhooks.md).

| Key | Default | |
| --- | --- | --- |
| `url` | — | required, http(s) |
| `format` | `"hackerpot"` | `"slack"`, `"discord"` |
| `secret` | — | HMAC-SHA256 signatures |
| `headers` | — | `[management.webhooks.headers]` |
| `min_score` | `0` | |
| `max_retries` | `3` | |
| `timeout_ms` | `10000` | `> 0` |
| `max_in_flight` | `32` | `> 0` |
| `dedupe_window_seconds` | off | |
| `throttle_window_seconds`, `max_per_window` | off | both or neither; each `> 0` |
| `omit_body` | `false`; `true` for slack and discord | |
| `redact` | `true` | |
| `anomalies` | `true` | |

## `[dashboard]`

The operator dashboard: served by `hackerpot serve` when enabled, reading the engine directly, or by
`hackerpot dashboard` on its own, reading a management API. See [the dashboard](../operations/dashboard.md).

| Key | Default | |
| --- | --- | --- |
| `enabled` | `false` | serve it from `hackerpot serve` |
| `host` | `"127.0.0.1"` | anything but loopback requires authentication, or `auth = "none"` |
| `port` | `9501` | |
| `base_path` | `"/"` | |
| `title` | `"hackerpot"` | |
| `instance` | `""` | the deployment's name; empty uses the hostname |
| `username`, `password` | `""` | basic auth; both required. Prefer `DASHBOARD_USERNAME` / `DASHBOARD_PASSWORD` |
| `token` | `""` | at least 16 random characters; `Authorization: Bearer` or `?token=`. Prefer `DASHBOARD_TOKEN` |
| `auth` | inferred | `"basic"`, `"token"`, or `"none"`; write `"none"` only when something in front authenticates |
| `refusal` | `"unauthorized"` | `"not-found"` or `"close"` to conceal the page; must be `"unauthorized"` with basic auth |
| `allowed_hosts` | `[]` | extra `Host` names to answer (the DNS-rebinding check); the public name behind a proxy |
| `allowed_clients` | `[]` | addresses or CIDRs allowed at all, checked before authentication |
| `redact_credentials` | `true` | hide `Authorization`, `Cookie`, API-key headers and password fields from the page |
| `mask_ip` | `false` | show addresses as their `/24` or `/48` |
| `hide` | `[]` | sections withheld on the server: `overview`, `incidents`, `statistics`, `sessions`, `actors`, `intel` |
| `management_url` | `""` | for `hackerpot dashboard`: the management API to read |
| `management_api_key` | `""` | its key; prefer `DASHBOARD_MANAGEMENT_API_KEY` |

---

## A worked example

```toml
[server]
port = 4004
trust_proxy = true                # only because a proxy we control fronts this listener

[policy]
block_threshold = 30              # a stricter ladder than 40 / 15
tarpit_threshold = 10

[store.file]
path = "/data/hits.jsonl"
max_bytes = 134217728
max_archives = 10

[detectors.path-bruteforce]
unique_path_threshold = 25
window_ms = 20000

[detectors.rate-spike]
enabled = false                   # too noisy behind our CDN

[detectors.honeytoken]
tokens = ["AKIA_HACKERPOT_HONEYTOKEN_DEMO"]

[[detectors.decoy-path.decoys]]
id = "internal-backup"
description = "Fake internal backup endpoint"
path = "/internal/backup.sql"
score = 9
respond_with = "large-payload"

[responses.tarpit]
delay_ms = [3000, 12000]

[port-scan]
ports = [2222, 8022, 9200]

[management]
api_keys = ["a-long-random-string"]

[[management.webhooks]]
url = "https://hooks.slack.com/services/T000/B000/xxxx"
format = "slack"
min_score = 40
dedupe_window_seconds = 300
```

## Sharing a config with a library deployment

The loader is exported, so a middleware deployment can share one file with a standalone one:

```ts
import { HoneypotEngine, buildHoneypotConfig, createMiddleware, loadConfig } from "@osqd/hackerpot";

const config = loadConfig({ path: "./hackerpot.toml" });   // file, then environment overrides
const built = buildHoneypotConfig(config, (hit) => console.warn("[honeypot]", hit.ip), (error, source) => console.error(source, error.message));
const engine = new HoneypotEngine(built.config);

app.use(createMiddleware(engine));
```

| Function | |
| --- | --- |
| `loadConfig({ path?, cwd?, env?, applyEnv? })` | discover, parse, validate, apply the environment |
| `loadConfigFile(path)`, `parseConfigText(text, source)`, `parseConfig(raw, source)` | the steps separately |
| `defaultConfig()` | the built-in defaults, identical to the shipped file |
| `describeConfig(config)` | the redacted JSON `hackerpot config` prints |
| `buildHoneypotConfig(config, onHit?, onError?, shared?)` | a complete `HoneypotConfig`: detectors, responses, policy, store, blocklist, allowlist, windows, shadow set, service tokens, audit. Returns `{ config, store, describe, blocklistDescribe, ingestTarget?, close }` |
| `buildDetectors`, `buildResponseActions`, `buildPolicy`, `buildAudit`, `createStore`, `createBlocklist` | the pieces |
| `createManagementServer`, `createSyslogSink`, `createPortScanSentinel`, `createSmtpHoneypot`, `createSshHoneypot`, `createFtpHoneypot`, `createTelnetHoneypot` | the listeners a config enables, or `undefined` |
| `buildDashboardOptions(config)`, `buildDashboardSource(config, overrides)` | the dashboard |
| `planReload(running, next)` | what a reload would apply and refuse |
| `ConfigError` | what every validation failure throws |

`buildHoneypotConfig` opens connections (Redis, the file store), so call `built.close()` on shutdown.

## Related

- [Environment variables](environment.md) — the overrides
- [The command line](../testing/cli.md) — `config` and `check`
- [Runtime changes](../operations/runtime-changes.md) — what reloads
