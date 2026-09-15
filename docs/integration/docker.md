# Docker

The image, the compose stack, and the dashboard profile.

← [Documentation](../index.md) · [Integration](index.md)

---

## The image

```bash
docker run --rm -p 4004:4004 ghcr.io/osqd-ts/hackerpot           # the latest release, memory store
docker run --rm -p 4004:4004 ghcr.io/osqd-ts/hackerpot:edge      # built from main

docker run --rm -p 4004:4004 \
  -v "$PWD/hackerpot.toml:/app/hackerpot.toml:ro" \
  -v "$PWD/data:/data" \
  -e HIT_LOG=/data/hits.jsonl \
  ghcr.io/osqd-ts/hackerpot                                       # your config, a durable hit log
```

| | |
| --- | --- |
| Platforms | `linux/amd64`, `linux/arm64` |
| Tags | `<version>`, `<major>.<minor>`, `latest`; `edge` follows `main` |
| Command | `node dist/standalone.js`: the `hackerpot` command, `serve` by default |
| Config | `/app/hackerpot.toml`, the shipped defaults; mount yours over it or set `HACKERPOT_CONFIG` |
| Data | `/data`, a volume owned by the runtime user; the natural place for `[store.file] path` |
| User | the unprivileged `node` user (uid 1000) |
| Ports | `4004` (HTTP honeypot), `9501` (dashboard); the management API is `9500` |

Any other command runs in its place:

```bash
docker run --rm ghcr.io/osqd-ts/hackerpot node dist/standalone.js detectors
docker run --rm -v "$PWD/access.log:/tmp/access.log:ro" ghcr.io/osqd-ts/hackerpot node dist/standalone.js replay /tmp/access.log
```

Environment variables override the file; see [environment](../reference/environment.md).

### How it is built

Multi-stage: a build stage compiles `dist/`, and the runtime stage installs production dependencies only,
with `--ignore-scripts`. Nothing in the runtime tree needs a lifecycle script (`ssh2`'s is an optional
native accelerator with a pure-JS fallback), so running install code there would buy nothing and hand
every transitive dependency a shell in the build.

`/data` is created and owned in the image. A named volume mounted at a path that does not exist in the
image is created root-owned, and the container, running as uid 1000, could not write to it: every hit-log
write failed while the startup banner still reported the file store as working.

It shuts down gracefully on `SIGTERM`. Its `HEALTHCHECK` is a plain TCP connect, deliberately **not** an
HTTP request, so the probe never registers as a honeypot hit or trips `scanner-signature`.

```bash
npm run docker:build      # docker build -t hackerpot .
npm run docker:run        # docker run --rm -p 4004:4004 hackerpot
```

## The compose stack

```bash
docker compose up -d --build
```

[`docker-compose.yml`](../../docker-compose.yml) runs:

| Service | What it is |
| --- | --- |
| `honeypot` | the service on `4004`, the port-scan sentinel on `8022`, `9200` and `7001`, a hit log in the `hitlog` volume, Redis for scores |
| `redis` | Redis 7 on the compose network only, persistence off |
| `dashboard` | **only with `--profile dashboard`**; see below |

The honeypot's environment:

| Variable | Value | Why |
| --- | --- | --- |
| `TRUST_PROXY` | `false` | 4004 is published straight to the host, with no proxy overwriting `X-Forwarded-For`. Turning it on here would let any client forge its address |
| `SCAN_PORTS` | `8022,9200,7001` | must match the published ports |
| `REDIS_URL`, `REDIS_SCORE_TTL` | `redis://redis:6379`, `3600` | shared scores that decay |
| `REDIS_MAX_HITS` | `1500` | a **memory** bound, see below |
| `HIT_LOG` | `/data/hits.jsonl` | a durable log beside Redis |
| `HONEYTOKENS` | a demo value | replace with the values you planted |
| `MANAGEMENT_API_KEYS` | `${HACKERPOT_MANAGEMENT_API_KEY:-}` | unset leaves the API, and so the dashboard, off |
| `MANAGEMENT_HOST`, `MANAGEMENT_PORT` | `0.0.0.0`, `9500` | bound inside the container, **not published**: only the compose network reaches it |

**After changing any source, run `docker compose up -d --build`.** The file sets both `build:` and
`image: hackerpot`, so compose reuses an existing image with that tag instead of building, and
`npm run docker:build` tags exactly that name. Without `--build` you silently keep running the old build.

To use your own config, uncomment the `./hackerpot.toml:/app/hackerpot.toml:ro` mount. The environment
above still overrides it.

### Why `REDIS_MAX_HITS` is 1500

The Redis hit log is one list holding whole incidents, request bodies included, so its worst case is
`max_hits × 64 KB`: the 10,000 default is about 630 MB, against the 256 MB the compose file gives Redis.
An attacker reaches that by doing what a honeypot invites (sending flagged requests with large bodies),
Redis is OOM-killed and restarted empty, and every accrued score and active block is gone. A
`maxmemory-policy` does not help: the list is a single key, so eviction would discard the small score and
block keys first. 1500 × 64 KB is about 95 MB. Raise both together, never one.

### Containment

The honeypot is the one container on the host whose job is to be attacked, so it gets an outer boundary
that matches the bounds the code keeps internally:

```yaml
cap_drop: [ALL]
security_opt: [no-new-privileges:true]
read_only: true
tmpfs: ["/tmp:rw,noexec,nosuid,size=16m"]
mem_limit: 512m
pids_limit: 256
```

It binds only ports above 1024 and runs as uid 1000, so it needs no capabilities, and it writes nothing
outside `/data`. Memory is the resource an attacker can most directly inflate: the engine caps every map
it owns, but a cap the kernel enforces is the one that holds if a future detector forgets to. Raise
`mem_limit` if you raise store retention. Redis gets the same treatment, starting as the `redis` user so
it never needs `SETUID` back.

Privileged service ports (22, 23, 25) need capabilities the container does not have. Publish the host's
real port to the unprivileged one instead: `"22:2222"`, with `[ssh] enabled = true`.

## The dashboard profile

```bash
HACKERPOT_MANAGEMENT_API_KEY=… DASHBOARD_PASSWORD=… docker compose --profile dashboard up -d
```

The `dashboard` service runs the same image with `command: ["node", "dist/standalone.js", "dashboard"]`,
which is [`hackerpot dashboard`](../testing/cli.md#dashboard): the operator dashboard as its own service,
reading the honeypot through its management API at `http://honeypot:9500`.

| Variable | Value |
| --- | --- |
| `DASHBOARD_HOST`, `DASHBOARD_PORT` | `0.0.0.0`, `9501` inside the container |
| `DASHBOARD_MANAGEMENT_URL` | `http://honeypot:9500` |
| `DASHBOARD_MANAGEMENT_API_KEY` | `${HACKERPOT_MANAGEMENT_API_KEY}`, **required** |
| `DASHBOARD_USERNAME` | `${DASHBOARD_USERNAME:-ops}` |
| `DASHBOARD_PASSWORD` | `${DASHBOARD_PASSWORD}`, **required** |

Why it is shaped this way:

- **It holds the API key itself**, so no browser ever sees it.
- **It is published on the host's loopback only** (`127.0.0.1:9501`). Reach it through an SSH tunnel, or a
  reverse proxy with TLS; behind a proxy, set `DASHBOARD_ALLOWED_HOSTS` to the public name, or the DNS
  rebinding check refuses it.
- **It is a profile, not a default service**, so `docker compose up` never starts a page showing captured
  attacker data without somebody deciding to. Compose refuses to start it without the key and the
  password.
- It gets the same containment, with a TCP health check of its own.

To run the dashboard inside the honeypot process instead, reading the engine directly with no management
API, set `[dashboard] enabled = true` (or `DASHBOARD_ENABLED=true`) and publish `9501`. See
[the dashboard](../operations/dashboard.md).

## Related

- [Running it standalone](../start/standalone.md) — the service the image runs
- [Environment variables](../reference/environment.md) — everything the compose file sets
- [Stores](../operations/stores.md#redisstore) — Redis retention in detail
