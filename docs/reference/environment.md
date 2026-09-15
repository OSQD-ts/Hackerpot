# Environment variables

Every variable that overrides the config file.

← [Documentation](../index.md)

---

**Precedence: built-in defaults < config file < environment.** A deployment's real configuration lives in
the file; the environment handles the last mile per container, so it wins. Every variable here also keeps
working with no file at all.

Values are trimmed, and an empty value counts as unset. Booleans accept `1`, `true`, `yes`, `on` and `0`,
`false`, `no`, `off`. A value of the wrong type is a startup error naming the variable, with exit code 2,
exactly as a bad key in the file would be.

## The service

| Variable | Overrides | Notes |
| --- | --- | --- |
| `HACKERPOT_CONFIG` | — | path to the TOML file; an explicitly named missing file is an error |
| `PORT` | `[server] port` | 0–65535 |
| `HOST` | `[server] host` | |
| `TRUST_PROXY` | `[server] trust_proxy` | read [the client IP](../integration/client-ip.md) first |
| `LOG_FORMAT` | `[logging] format` | `json` or `text` |

## Stores and detection

| Variable | Overrides | Notes |
| --- | --- | --- |
| `HIT_LOG` | `[store.file] path` | enables the file store |
| `REDIS_URL` | `[store.redis] url` | enables the Redis store; with `HIT_LOG`, both are composed |
| `REDIS_SCORE_TTL` | `[store.redis] score_ttl_seconds` | seconds; scores decay |
| `REDIS_MAX_HITS` | `[store.redis] max_hits` | Redis's memory ceiling in practice; see [stores](../operations/stores.md#redisstore) |
| `HONEYTOKENS` | `[detectors.honeytoken] tokens` | comma-separated; **replaces** the list, labelled `env-honeytoken`; enables the detector when non-empty |
| `SCAN_PORTS` | `[port-scan] ports` | comma-separated; enables the sentinel when non-empty |
| `SCAN_BANNER` | `[port-scan] banner` | |

## Management API

| Variable | Overrides | Notes |
| --- | --- | --- |
| `MANAGEMENT_API_KEYS` | `[management] api_keys` | comma-separated; setting any enables the API |
| `MANAGEMENT_HOST` | `[management] host` | keep it private |
| `MANAGEMENT_PORT` | `[management] port` | |

The management API enabled with no keys, from either source, is a startup error.

## Dashboard

Dashboard credentials belong in the environment rather than in a file baked into an image, and
`hackerpot dashboard` run as its own container is configured mostly from here.

| Variable | Overrides | Notes |
| --- | --- | --- |
| `DASHBOARD_ENABLED` | `[dashboard] enabled` | serve the dashboard from `hackerpot serve` |
| `DASHBOARD_HOST` | `[dashboard] host` | also `hackerpot dashboard --host` |
| `DASHBOARD_PORT` | `[dashboard] port` | also `--port` |
| `DASHBOARD_TOKEN` | `[dashboard]` auth | at least 16 characters; wins over username and password |
| `DASHBOARD_USERNAME` | `[dashboard] username` | basic auth; needs a password |
| `DASHBOARD_PASSWORD` | `[dashboard] password` | basic auth; the username may come from the file |
| `DASHBOARD_ALLOWED_HOSTS` | `[dashboard] allowed_hosts` | comma-separated; the public name behind a reverse proxy |
| `DASHBOARD_ALLOWED_CLIENTS` | `[dashboard] allowed_clients` | comma-separated addresses or CIDRs |
| `DASHBOARD_MANAGEMENT_URL` | `[dashboard] management_url` | for `hackerpot dashboard`; also `--management-url` |
| `DASHBOARD_MANAGEMENT_API_KEY` | `[dashboard] management_api_key` | for `hackerpot dashboard`; also `--api-key` |

## Compose-level variables

[`docker-compose.yml`](../../docker-compose.yml) interpolates two variables of its own into the ones above.
They are read by compose, not by hackerpot:

| Variable | Feeds |
| --- | --- |
| `HACKERPOT_MANAGEMENT_API_KEY` | the honeypot's `MANAGEMENT_API_KEYS` and the dashboard's `DASHBOARD_MANAGEMENT_API_KEY` |
| `DASHBOARD_USERNAME`, `DASHBOARD_PASSWORD` | the dashboard service's credentials (username defaults to `ops`) |

## The demo

`npm run demo` (`demo/server.ts`) is a local convenience, not the service, and reads its own:
`PORT` (4004), `MGMT_PORT` (9500), `GUI_PORT` (9501), `SMTP_PORT` (2525), `SSH_PORT` (2222), `FTP_PORT`
(2121), `TELNET_PORT` (2323), `SCAN_PORTS` (`8022,9200,7001`) and `MGMT_API_KEY` (`dev-key`). See
[try it locally](../testing/try-it.md).

## In code

`applyEnvOverrides(config, env = process.env)` applies exactly this table to a parsed config.
`loadConfig({ path, env, applyEnv })` calls it unless `applyEnv` is false.

## Related

- [Configuration](configuration.md) — the file these override
- [Docker](../integration/docker.md) — the variables the compose file sets
