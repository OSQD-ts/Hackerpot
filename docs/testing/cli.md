# The command line

Every `hackerpot` command and flag.

← [Documentation](../index.md) · [Testing](index.md)

---

```
hackerpot serve [options]            Run the service every enabled section describes (the default)
hackerpot dashboard [options]        Run only the dashboard, reading a running HackerPot
hackerpot check [options]            Validate the config and serve every response action once
hackerpot config [options]           Print the resolved configuration as JSON
hackerpot replay <log> [--json]      What the configured detectors would make of an access log
hackerpot explain [request] [--json] Which detectors fire on one request, and why
hackerpot detectors [options]        List the detectors the config installs
hackerpot robots [options]           A robots.txt disallowing the decoys and trap paths
hackerpot --help | --version
```

Installed with the package (`npx hackerpot`), in the container (`node dist/standalone.js <command>`),
and from a clone (`npx tsx src/standalone.ts <command>`, or the `serve`, `dashboard`, `replay`,
`explain`, `config:check` and `config:verify` npm scripts).

**Every command takes `-c, --config <path>`** (or `HACKERPOT_CONFIG`). Without it, the first of
`./hackerpot.toml`, `./hackerpot.config.toml`, `./config/hackerpot.toml` and
`/etc/hackerpot/hackerpot.toml` is used; with none, the built-in defaults. An explicitly named file that
is missing is an error.

## Exit codes

| Code | Means |
| --- | --- |
| `0` | success |
| `1` | `check` found a failing action; an unknown command; a runtime failure |
| `2` | an invalid config or bad arguments, printed as `hackerpot: <path>: <message>` on stderr |

A bad config is an operator mistake, not a crash, so it gets its own code.

---

## `serve`

```bash
hackerpot serve --config /etc/hackerpot/hackerpot.toml
hackerpot                                   # the same: serve is the default
```

Runs every listener the config enables and stays up until `SIGTERM` or `SIGINT`. `SIGHUP` reloads what
can be reloaded and names the rest. See [running it standalone](../start/standalone.md) and
[runtime changes](../operations/runtime-changes.md).

The older flag forms still work, so a container or script written against them keeps running:
`hackerpot --check`, `--print-config`, `--replay <file>`, `--explain [text]`.

## `dashboard`

```bash
hackerpot dashboard --management-url http://10.0.0.5:9500 --api-key "$KEY"
DASHBOARD_PASSWORD=… hackerpot dashboard --config ./hackerpot.toml
```

Runs only [the dashboard](../operations/dashboard.md), as its own service beside a running stack. It
reads the honeypot through its management API and holds the API key server-side, so no browser ever sees
it.

| Flag | Environment | Default |
| --- | --- | --- |
| `--management-url <url>` | `DASHBOARD_MANAGEMENT_URL` | `[dashboard] management_url`, else this config's own `[management]` listener |
| `--api-key <key>` | `DASHBOARD_MANAGEMENT_API_KEY` | `[dashboard] management_api_key`, else this config's first `[management] api_keys` |
| `--host <address>` | `DASHBOARD_HOST` | `127.0.0.1` |
| `--port <port>` | `DASHBOARD_PORT` | `9501` |

Authentication and everything else come from `[dashboard]`: `username` and `password`, or a `token`
(`DASHBOARD_USERNAME`, `DASHBOARD_PASSWORD`, `DASHBOARD_TOKEN`). Bound anywhere but loopback it refuses
to start without authentication, with exit code 2. With no management API to read, or no key for it, it
says so and exits 2.

The compose file's `dashboard` profile runs exactly this. See [Docker](../integration/docker.md#the-dashboard-profile).

## `check`

```bash
hackerpot check --config ./hackerpot.toml
npm run config:verify -- --config ./hackerpot.toml
```

Validates the config, then serves every enabled response action once over a loopback socket, with a
throwaway blocklist so nothing is really blocked:

```
ok     decoy-content (200)
ok     not-found (404)
ok     redirect (302)
ok     block (403)
held   tarpit
held   drip-feed (200)
ok     large-payload (200)
ok     fake-success (200)
ok     fake-data (200)
ok     gzip-bomb (200)
ok     chaos (502)
ok     rate-limit (429)

all 12 response actions answered
```

`ok` completed; `held` was still delaying or streaming when the check stopped waiting, which is the job of
`tarpit`, `drip-feed` and `large-payload`; `failed` threw, rejected or reported an error. A deliberate 5xx,
as `chaos` sends, is not a failure. **Exits 1 if any action failed.**

A config can validate and still produce a response that breaks once a request is routed to it. Library
callers: `checkResponseActions(actions)`.

## `config`

```bash
hackerpot config --config ./hackerpot.toml
npm run config:check -- --config ./hackerpot.toml
```

Resolves the file (with environment overrides applied), validates it without binding a port, and prints
the result as JSON, with regex values rendered as `/pattern/flags` literals:

```json
{
  "source": "/srv/hackerpot/hackerpot.toml",
  "server": { "host": "0.0.0.0", "port": 4004, "trustProxy": false },
  "logging": { "format": "json", "startup": true, "includeHeaders": false, "includeBody": false },
  …
}
```

**Every credential is redacted**: management API keys, webhook secrets and headers, the Redis URL's
password, the Elasticsearch password, the peer-feed key, dashboard secrets. Redaction is by key name, so a
credential added to any section later is covered. Empty values are left as they are, so the output still
distinguishes "configured" from "not configured". This is a command people run casually, in CI and over
screen shares; validating a config should never be what copies its secrets somewhere they are kept.

The fastest way to debug a config, and a good CI step.

## `replay`

```bash
hackerpot replay /var/log/nginx/access.log --config ./hackerpot.toml
hackerpot replay access.log --json
```

Runs an access log through the configured detectors, binding nothing and writing to a store of its own.
See [replaying your logs](replay.md).

| Flag | |
| --- | --- |
| `<log>` | combined or common log format, or one JSON object per line |
| `--json` | the summary as JSON |

## `explain`

```bash
hackerpot explain "sqlmap/1.7.2#stable" --url /.env
pbpaste | hackerpot explain --json
hackerpot explain --ip 203.0.113.9 --method POST --url /login "Mozilla/5.0 …"
```

The question that arrives by ticket rather than by traffic: *why was this flagged?* It takes a
User-Agent, a `curl` command copied from a browser's developer tools, or a block of raw request headers
(optionally with a request line), as an argument or on stdin. It prints every detector that fires with its
score and reason, which of them are proof, and the response the policy would choose:

```
Request   GET /.env
From      203.0.113.10, User-Agent "sqlmap/1.7.2#stable"

2 detector(s) fired, score 16:
  +10  decoy-path               Exposed .env file probe
  +6   scanner-signature        User-Agent matches known tooling signature: sqlmap/1.7.2#stable  [proof]

Response  decoy-content
```

```
Request   GET /search (1 query parameter(s))
From      203.0.113.10, User-Agent "Mozilla/5.0"

No detector fired. The honeypot would leave this request alone.
```

| Flag | |
| --- | --- |
| `[request]` | the text; omitted, it is read from stdin |
| `--url <path>` | the path and query, when the text does not carry one |
| `--method <verb>` | the method |
| `--ip <address>` | the client address (default `203.0.113.10`) |
| `--json` | the request and the evaluation result as JSON |

It is a dry run on an engine of its own, with a fresh store and no history, so it answers *what would this
look like as a first request*, which is what a ticket is usually asking. The volume detectors therefore
never fire here. It **binds nothing and looks nothing up**: `crawler-verification` gets a resolver that
answers nothing, so a claim reads as unverifiable rather than refuted.

Library callers: `parseRequestText(text, { url, method, ip })`, `explainRequest(engine, facts)` and
`formatExplanation(facts, result)`.

## `detectors`

```bash
hackerpot detectors --config ./hackerpot.toml
```

Lists what a configuration actually installs: id, whether it reads the body, whether it is shadowed, and
its description.

```
decoy-path                 headers         Request targeted a decoy path that no legitimate client would know about
payload-injection          body            Request contains a recognizable exploitation payload
…
repeat-actor               headers         One actor fingerprint seen attacking from several distinct IPs (IP rotation)

23 detectors installed from /srv/hackerpot/hackerpot.toml.
```

The reliable answer to "is `trap` on?" for your setup. See [detection](../detection/index.md).

## `robots`

```bash
hackerpot robots --sitemap https://example.com/sitemap.xml > public/robots.txt
```

A `robots.txt` listing the configured decoys (custom ones included, disabled ones left out) and, when
`[detectors.trap]` is enabled, the trap paths, as `Disallow`. A legitimate crawler skips them; anything
that fetches one anyway has identified itself. See [decoys](../detection/decoys.md#robotstxt-as-a-lure).

| Flag | |
| --- | --- |
| `--sitemap <url>` | adds a `Sitemap:` line |

## In code

`@osqd/hackerpot/cli` exports `main(argv)`, which resolves to an exit code, and `readStdin()`.

## Related

- [Replaying your logs](replay.md) · [The corpus](corpus.md)
- [Configuration](../reference/configuration.md) — what `config` prints
- [Environment variables](../reference/environment.md)
