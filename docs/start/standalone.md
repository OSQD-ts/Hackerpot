# Running it standalone

The service from a TOML file, `hackerpot serve`, and Docker.

← [Documentation](../index.md)

---

Standalone, hackerpot runs on its own address or ports, where everything that reaches it is
unsolicited. There is no application behind it to protect, so the trade-offs are different
from middleware: it reads every request body up front, and it blocks on score.

```bash
npx hackerpot serve                         # built-in defaults, or ./hackerpot.toml if present
npx hackerpot serve --config ./hackerpot.toml
docker run --rm -p 4004:4004 ghcr.io/osqd-ts/hackerpot
```

With no config file anywhere, the service starts with the built-in defaults: the HTTP
honeypot on `0.0.0.0:4004`, an in-memory store, the default detectors and responses, the
traffic audit on, and every other listener off. The shipped
[`hackerpot.toml`](../../hackerpot.toml) is exactly those defaults, annotated, so copying
it changes nothing until you edit it.

## A config worth starting from

```toml
[server]
port = 4004
trust_proxy = false             # true only behind a proxy that overwrites X-Forwarded-For

[store.file]
path = "/data/hits.jsonl"       # setting a path enables the durable store
max_bytes = 134217728           # roll into a gzipped archive at 128 MB
max_archives = 10

[detectors.honeytoken]
tokens = ["AKIA_HACKERPOT_HONEYTOKEN_DEMO"]   # the fake key you planted in a decoy

[ssh]
enabled = true
port = 2222

[management]
api_keys = ["a-long-random-string"]           # setting a key enables the operator API
```

Validate it before it binds anything:

```bash
npx hackerpot config --config ./hackerpot.toml   # resolve, validate, print as JSON (secrets redacted)
npx hackerpot check  --config ./hackerpot.toml   # also serve every response action once over loopback
```

An unknown key, a wrong type, a port claimed twice or a contradictory pair of settings is
a startup error that names the key, with exit code 2. See
[configuration](../reference/configuration.md).

## What the service runs

One process, every listener its config enables:

| Listener | Default | Turned on by |
| --- | --- | --- |
| HTTP honeypot | `0.0.0.0:4004` | always |
| Port-scan sentinel | off | listing any `[port-scan] ports` |
| SMTP, SSH, FTP, Telnet | off | `enabled = true` in the section |
| Management API | off, `127.0.0.1:9500` | setting `[management] api_keys` |
| Dashboard | off, `127.0.0.1:9501` | `[dashboard] enabled = true` |
| Syslog forwarding | off | setting `[syslog] host` |
| Threat-intel poller | off | listing `[intel] feeds` |

Every protocol listener shares the HTTP honeypot's store, so an address brute-forcing SSH
and probing HTTP accrues one score. Each event is logged to stdout as one JSON object
(`[logging] format = "text"` for key=value lines): `startup`, `hit`, `shadow`, `anomaly`,
`reload`, and a `*-error` kind for every failure the service absorbs rather than crashes on.

## Signals

| Signal | Effect |
| --- | --- |
| `SIGTERM`, `SIGINT` | graceful shutdown: every listener closes, the store flushes |
| `SIGHUP` | re-read the config and apply detectors, responses, policy, allowlist, logging, service tokens and intel feeds live; name everything else as needing a restart |

See [runtime changes](../operations/runtime-changes.md).

## With Docker

```bash
docker run --rm -p 4004:4004 \
  -v "$PWD/hackerpot.toml:/app/hackerpot.toml:ro" \
  -v "$PWD/data:/data" \
  ghcr.io/osqd-ts/hackerpot
```

Or the whole stack, with Redis for shared scores and a durable hit log:

```bash
docker compose up -d
HACKERPOT_MANAGEMENT_API_KEY=… DASHBOARD_PASSWORD=… docker compose --profile dashboard up -d
```

The second line adds the dashboard as its own container, reading the honeypot's management
API. See [Docker](../integration/docker.md).

## From code instead of a file

The same service, programmatically:

```ts
import { HoneypotServer, PortScanSentinel } from "@osqd/hackerpot";

const server = new HoneypotServer({ onHit: (hit) => console.warn("[honeypot]", hit.ip, hit.respondedWith) });
await server.listen(4004);

const sentinel = new PortScanSentinel({ ports: [8022, 9200], onEvent: (e) => console.warn("[port-scan]", e.ip, e.port, e.isScan) });
await sentinel.listen();
```

`HoneypotServer` takes the same options as `HoneypotEngine` and exposes it as
`server.engine`. To build a server from a TOML file in code, use `loadConfig` and
`buildHoneypotConfig`; see [configuration](../reference/configuration.md#sharing-a-config-with-a-library-deployment).

## Related

- [The command line](../testing/cli.md) — every command and flag
- [Configuration](../reference/configuration.md) — every key
- [Environment variables](../reference/environment.md) — the last-mile overrides
- [Protocol honeypots](../protocols/index.md) — SSH, SMTP, FTP, Telnet
