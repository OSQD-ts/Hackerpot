# The dashboard

The operator view: what it shows, what it refuses to do, and every option it takes.

← [Documentation](../index.md) · [Operations](index.md)

---

The [management API](management-api.md) answers programs. The dashboard is for a person: every incident
as it lands, why each detector fired, what the honeypot answered, and what one address or one actor did
across its whole visit.

```ts
import { HoneypotServer, startDashboard } from "@osqd/hackerpot";

const server = new HoneypotServer({ /* … */ });
await server.listen(4004);

const dashboard = await startDashboard(server.engine);
console.log(dashboard.url); // http://127.0.0.1:9501/
```

That is the whole integration. It listens on a port of its own, on loopback, reads the engine's store,
subscribes to the engine for new incidents, and returns a handle with `url`, `port`, `host`, `clients`
and `close()`. `startDashboard` accepts an engine, anything with an `engine` property (so a
`HoneypotServer` works as it is), or a [source](#where-it-reads-from).

Everything on the page is text an attacker wrote: paths, User-Agents, request bodies, shell commands
typed into the Telnet honeypot. The page never assembles HTML from data, runs under a nonce CSP with
`default-src 'none'`, and sends no CORS headers. The rest of this page is what that design means in
practice.

---

## What it shows

Six screens, in a tab strip. A section switched off on the server ([`sections`](#sections-withheld-on-the-server))
has no tab at all.

### Overview

The incident count and the facts under it: unique addresses, actors, active blocks and tracked
addresses (read from the metrics, so they need the `intel` section), how many detectors fired, and how
long the store has been observing. Then five cards (top offender, last seen, peak rate, median score,
blocked share), the incident volume over the observation window, detections by type, top offenders by
cumulative score, the mix of response actions served, and the five latest incidents.

Every chart has a **table view** beside it, so the numbers are readable without the picture.

### Incidents

The incident table: time, source address, method, path, detectors, score and response. Filter by
detector or source address, and choose how many rows to show (50 to 1000). New incidents enter at the
top as they happen when they match the filter.

Open a row (click it, or focus it and press Enter) and it explains itself:

- **Why this fired**: one card per detection, with the reason the detector gave, the score it added,
  what the attacker was after and how the detector recognised it. [Shadow
  detectors](../detection/shadow-mode.md) are listed separately, scored at zero.
- **Response**: what the action did and why the policy chose it, and what this address did overall,
  with a button to show only its incidents.
- **Decoded payloads**: values from the query, headers, body and detector samples that were hidden
  behind URL, base64 or hex encoding, often layered, peeled back to what they say. The encoding chain
  is shown (`url → base64`), up to twelve values per incident.
- **Request headers**, marked "credentials redacted by the server" when [redaction](#redaction) is on,
  the **request body**, and the **raw incident JSON**.

### Statistics

The analytics, grouped by what they answer. A window selector (all, 5m, 15m, 1h, 6h, 24h) and a
protocol filter narrow every panel at once; a switch shows every chart as a data table.

| Group | Panels |
| --- | --- |
| Volume and tempo | incidents over time with distinct addresses per bucket, cumulative unique addresses and actors, request cadence (gaps between requests from one address), and an activity clock of hour by weekday |
| Detections | detector frequency, score contribution per detector, and a co-occurrence matrix of detectors firing on the same request |
| Severity | per-incident score distribution, score percentiles, response mix, and the escalation funnel by source address |
| Attack surface | most-probed paths, HTTP methods, the split between HTTP and the SSH, SMTP, FTP and Telnet honeypots, User-Agents, and request shape |
| Sources | address class, country and ASN (only with a data-backed enricher), and a sortable per-address breakdown |
| Obfuscation | the encoding layers observed and the share of incidents carrying an encoded payload |

### Sessions

Each source address's incidents in order: the attack as a narrative rather than a list of rows. Open a
session to read its timeline.

### Actors

Incidents grouped by [actor fingerprint](../concepts/actors.md) (header order and User-Agent family)
instead of by address, so one attacker rotating through addresses collapses into one actor. Sorted by
how many addresses each used.

### Threat intel

The [indicator list](management-api.md#rest): every source address with its cumulative score,
incident count and detectors, filtered by a minimum score, with **Copy IP list** and **Copy JSON**.
Under it, the Prometheus exposition the source serves, verbatim, which is the same text a scrape of
[`/metrics`](metrics.md) returns.

### The live feed

The page holds one [server-sent events](https://html.spec.whatwg.org/multipage/server-sent-events.html)
stream on `/api/events`. The **Live feed** switch in the toolbar turns it off and on, and the status in
the header says `live`, `connecting`, `reconnecting in 4s`, or why it is down.

```text
retry: 3000

event: hello
data: {"version":"0.1.0","source":"this process"}
```

That is the start of a real stream from the demo. Each incident follows as an `incident` event with an
`id`.

The server does not replay missed frames. When a stream is interrupted and comes back, the page reloads
its data as soon as the server says hello again, so it never quietly shows a picture with a hole in it.
A stream the browser cannot reopen by itself (a `401`, a `503` because the dashboard is full, a `404`
because the section is off) is retried with backoff, and the page makes one request to find out why and
says so.

Two notices appear above the screens when the feed was thinned, with **Reload** and **Dismiss** (Escape
dismisses too):

- **"N incidents dropped because this browser fell behind"**: a `lagged` event. The browser stopped
  reading, the server stopped queueing for it, and counted what it did not send.
- **"N skipped by the server's per-viewer rate limit"**: a `skipped` event, during a burst past
  [`maxEventsPerSecond`](#operating-limits).

Neither means the incidents are gone. They are in the store; Reload fetches them.

### What the analytics cover

**The page analyses the most recent 1000 incidents, not the whole store.** It fetches
`/api/incidents?limit=1000` and derives every chart in the browser from that list, so the numbers always
agree with the rows you can click through to. Live incidents are merged into the same list, which stays
capped at 1000.

When the store holds more, the page says so: the Overview's count reads "analytics below cover the most
recent 1,000", and the Statistics scope line ends "the most recent 1,000 loaded". The totals from
`/api/stats` and the metrics are the whole store; the charts are the window.

---

## Three ways to run it

The same page, the same API, the same security checks, behind three front ends.

### On its own listener

```ts
const dashboard = await startDashboard(server.engine, {
  port: 9501,
  auth: { username: "ops", password: process.env.DASHBOARD_PASSWORD! },
});
```

`startDashboard(source, options)` binds `127.0.0.1:9501` by default. `port: 0` binds an ephemeral port;
read it back from `dashboard.port`. A taken port is a `DashboardConfigError` ("the port is in use. Pass
another port, or 0.") rather than a crash later.

A separate listener from the honeypot on purpose. The honeypot's port is the one attackers are invited
to, and the dashboard describes them. `close()` ends every stream, unsubscribes and stops listening, and
is safe to call twice.

### Mounted on a server you already have

```ts
import { createDashboardHandler } from "@osqd/hackerpot";

const dashboard = createDashboardHandler(server.engine, {
  basePath: "/_hackerpot",
  auth: { authorize: (req) => sessionFrom(req)?.role === "admin" },
  allowedClients: ["10.0.0.0/8"],
});

https.createServer(tls, (req, res) => {
  if (req.url === "/_hackerpot" || req.url?.startsWith("/_hackerpot/")) return dashboard(req, res);
  return admin(req, res);
}).listen(443);
```

`createDashboardHandler(source, options)` is the dashboard without the socket: a `(request, response)`
function you mount wherever you already terminate TLS, under one hostname. Two things differ, and both
follow from not owning the socket:

- **`auth` is required**, including the explicit `auth: false`. There is no bind address to inspect, so
  nothing is assumed about who can reach it.
- **`close()` does not close your server.** It ends every event stream and unsubscribes from the
  source. `dashboard.clients` is the number of live viewers.

`basePath` is the path *the browser* uses, because the page builds every API URL from it. Routing
accepts a request with or without the prefix, so it works whether or not your framework strips the
mount point. Mount it outside the honeypot middleware, so reading the dashboard never shows up in it.

### Inside a page of your own

```html
<hackerpot-dashboard src="/_hackerpot"></hackerpot-dashboard>
```

The mounted handler above, rendered by a custom element inside your own admin page, with the screens and
theme you choose. See [Embedding the dashboard](embedding.md).

---

## Where it reads from

A dashboard reads from a **source**: something that can list incidents, compute the statistics,
sessions, actors and indicators, render the metrics, and announce new incidents. Every source answers
in the management API's own shapes, so the page is the same whichever kind is behind it. The header
names the source ("this process", "management API at 10.0.0.5:9500").

### In this process

| Source | Reads | Hears new incidents from | Metrics |
| --- | --- | --- | --- |
| an engine, or `engineSource(engine)` | `engine.store` | the engine: every hit it records, plus anything given to `engine.publish` | the store's counts plus `active_blocks` and `tracked_ips` |
| `managementServerSource(server, store)` | `store` | the management server's broker | the server's own `/metrics` counters, which only rise |
| `brokerSource(broker, store)` | `store` | an `IncidentBroker` | derived from the store |
| `storeSource({ store, subscribe, metrics?, description? })` | `store` | any `subscribe` function | yours, or derived from the store |

Protocol honeypots record into the store themselves. For their hits to reach the live feed too, publish
them on the engine, which is what the standalone service and the demo do:

```ts
const ssh = new SshHoneypot({ port: 2222, store, onHit: (hit) => server.engine.publish(hit) });
```

Metrics "derived from the store" are counted from what the store still retains, so they fall when
retention trims old hits. The management server's own `/metrics` counters do not; see
[Metrics](metrics.md#counted-in-memory-not-read-from-the-store).

### Another HackerPot's management API

```ts
import { managementApiSource, startDashboard } from "@osqd/hackerpot";

const source = managementApiSource({
  url: "http://10.0.0.5:9500",
  apiKey: process.env.HACKERPOT_MANAGEMENT_API_KEY!,
});
await startDashboard(source, { auth: { token: process.env.DASHBOARD_TOKEN! } });
```

A remote source reads a running HackerPot over HTTP: each read is one REST request with the key in
`Authorization`, and the live feed is one WebSocket to `/stream`. The WebSocket opens when the first
viewer subscribes, closes when the last one leaves, and reopens with backoff (up to 30 seconds) when it
drops, so one dashboard holds one connection however many browsers watch it.

| Option | Default | |
| --- | --- | --- |
| `url` | required | `http` or `https`; anything else throws |
| `apiKey` | required | one of the management API's `api_keys`; empty throws |
| `timeoutMs` | `10000` | per request, and for the WebSocket handshake |
| `onError` | none | the live connection dropped or a reconnect failed |

**The key stays on the server.** The browser authenticates to the dashboard with the dashboard's own
credential and never sees the management API key. That buys three things:

- A viewer's credential opens the dashboard's read-only routes and nothing else. Revoking a viewer never
  means rotating the key your other tooling uses.
- The management API need not be reachable from any browser. In the compose stack it is not published
  at all; only the dashboard container reaches it.
- [Redaction](#redaction) and [sections](#sections-withheld-on-the-server) are applied by the dashboard,
  so what the key can read and what a viewer is shown are separate decisions.

When the management API cannot answer, the dashboard's route returns `502` with the reason ("the
dashboard's source could not answer: management API answered 401 for /stats"), and the page shows that
message rather than an empty store.

---

## Running it from the service

### Inside `hackerpot serve`

```toml
[dashboard]
enabled = true
host = "127.0.0.1"
port = 9501
```

The standalone service then serves the dashboard itself, reading its own engine, which also carries the
SSH, SMTP, FTP and Telnet hits. It needs no management API. Bound anywhere but loopback, the config is
refused unless it sets `username` and `password`, a `token`, or `auth = "none"`. Every key is in the
[configuration reference](../reference/configuration.md#dashboard); credentials belong in
`DASHBOARD_USERNAME`, `DASHBOARD_PASSWORD` or `DASHBOARD_TOKEN` (the token wins when both are set).

### As its own service beside the stack

```bash
hackerpot dashboard --management-url http://10.0.0.5:9500 --api-key "$KEY"
```

`hackerpot dashboard` runs only the dashboard, reading a running HackerPot through a
[remote source](#another-hackerpots-management-api). It binds no honeypot port.

| Flag | Environment | Default |
| --- | --- | --- |
| `--management-url <url>` | `DASHBOARD_MANAGEMENT_URL` | `[dashboard] management_url`, else this config's own `[management]` listener (`0.0.0.0` read as `127.0.0.1`) |
| `--api-key <key>` | `DASHBOARD_MANAGEMENT_API_KEY` | `[dashboard] management_api_key`, else this config's first `[management] api_keys` entry |
| `--host <address>` | `DASHBOARD_HOST` | `127.0.0.1` |
| `--port <port>` | `DASHBOARD_PORT` | `9501` |
| `-c, --config <path>` | `HACKERPOT_CONFIG` | `./hackerpot.toml`, else the defaults |

The fallback to `[management]` means the same `hackerpot.toml` the honeypot runs from is enough for a
dashboard on the same machine. Everything else (authentication, refusal, allowed hosts and clients,
redaction, hidden sections, title) comes from `[dashboard]` and its environment variables;
`[dashboard] enabled` is not read by this command.

It logs JSON lines. Run against the demo's management API on port 9502:

```text
$ hackerpot dashboard --port 9502 --management-url http://127.0.0.1:9500 --api-key dev-key
{"ts":"2026-09-15T17:02:36.493Z","kind":"startup","service":"dashboard","url":"http://127.0.0.1:9502/","source":"management API at 127.0.0.1:9500"}
{"ts":"2026-09-15T17:02:36.856Z","kind":"shutdown","signal":"SIGTERM"}
```

The two refusals, both exit code 2:

```text
$ hackerpot dashboard --host 0.0.0.0 --management-url http://127.0.0.1:9500 --api-key dev-key
hackerpot: The dashboard is set to bind 0.0.0.0, which publishes it beyond this machine, and no `auth` was configured. Configure `auth`, keep the default host "127.0.0.1", or write `auth: false` to state that something in front of it already authenticates.

$ hackerpot dashboard
hackerpot: the dashboard has no management API to read: pass --management-url, set [dashboard] management_url, or enable [management] in this config
```

Source failures after startup are logged as `dashboard-source-error`, viewer socket errors as
`dashboard-error`. See also [the command line](../testing/cli.md#dashboard).

### The compose profile

```bash
HACKERPOT_MANAGEMENT_API_KEY=… DASHBOARD_PASSWORD=… docker compose --profile dashboard up -d
```

The `dashboard` service in `docker-compose.yml` runs `hackerpot dashboard` in its own container:

- It reads `http://honeypot:9500` on the compose network. The honeypot turns its management API on only
  when `HACKERPOT_MANAGEMENT_API_KEY` is set, and does not publish it.
- It binds `0.0.0.0` inside the container and is published on the host's **loopback only**
  (`127.0.0.1:9501`). Reach it through an SSH tunnel or a TLS reverse proxy.
- Basic auth: `DASHBOARD_USERNAME` (default `ops`) and `DASHBOARD_PASSWORD`, which is required. Compose
  refuses to start the service without it or without the management key.
- A profile rather than a default service, so `docker compose up` never starts a page of captured
  attacker data without somebody deciding to.

See [Docker](../integration/docker.md#the-dashboard-profile).

---

## Security

The page lists attacker addresses, captured request bodies, credentials an attacker tried, and which
detector fired on what. For somebody probing your deployment that is a map of what to avoid next. So the
defaults are cautious and the unsafe combinations do not start.

### It refuses to start in an unsafe configuration

| Configuration | Result |
| --- | --- |
| `startDashboard` with no `host` and no `auth` | allowed: loopback, and the operating system is the access control |
| `host` anything but `127.0.0.1`, `::1` or `localhost`, and no `auth` | `DashboardConfigError` |
| `createDashboardHandler` with no `auth` | `DashboardConfigError` |
| basic auth with an empty username or password | `DashboardConfigError` |
| a token shorter than 16 characters | `DashboardConfigError` |
| `refusal: "not-found"` or `"close"` with basic auth | `DashboardConfigError` (nobody could ever be prompted for the password) |
| `allowedClients` with an entry that is not an address or CIDR | `DashboardConfigError` (nothing could reach it) |

### Authentication

| `auth` | Accepts |
| --- | --- |
| `{ username, password }` | HTTP Basic. Both halves are hashed and compared in constant time, so a wrong username is no faster than a wrong password. |
| `{ token }` | `Authorization: Bearer <token>`, or `?token=<token>` so a link can be opened directly. The page carries a `?token=` it was opened with onto its own requests. The query form lands in browser history and proxy logs: fine on a laptop, a poor idea for a shared deployment. |
| `{ authorize(request) }` | Your own check on the raw `IncomingMessage`: a session cookie, a header your gateway sets, an mTLS subject. `true` or a non-empty string admits; `false`, `""` or a throw refuses. May be async. |
| `false` | Nothing. An explicit, greppable statement that something in front already authenticates. |

Authentication runs **before routing**: an unauthenticated caller gets the same refusal for every path,
so it cannot map the endpoints. A custom `authorize` sends no `WWW-Authenticate`, so the browser shows no
prompt; send people to your own sign-in page. The dashboard is read-only and keeps no audit trail, so a
viewer name returned by `authorize` admits them and is not recorded anywhere.

### Saying less to a stranger

| `refusal` | What a refused caller gets |
| --- | --- |
| `"unauthorized"` (default) | `401` (with `WWW-Authenticate` for Basic), `421` for a wrong host, `403` for a forbidden client or a cross-site write, `429` while locked out |
| `"not-found"` | `404`, byte-identical to the answer for a path that does not exist |
| `"close"` | nothing: the connection is destroyed |
| `{ redirect, status? }` | `302` (or `303`, `307`, `308`) to your sign-in page |

Anything but the default collapses every pre-routing refusal into one answer, so a probe cannot tell
"wrong host" from "wrong password" from "locked out". Under the default they keep distinct statuses on
purpose: the likelier reader is an operator debugging their own deployment.

This is **concealment, not access control**. It raises the cost of finding the page and does nothing
against somebody holding the credential. The TOML key takes the three string forms; a redirect is
library-only.

### Before credentials are looked at

Four checks run first, in this order, because they ask whether the request was addressed to this server
by something allowed to address it, which a password cannot settle:

1. **`allowedClients`**: addresses or CIDRs allowed to reach the dashboard at all. Everyone else is
   refused.
2. **`authThrottle`**: after 5 failed credentials from one address, further attempts are refused for 1
   second, doubling with each failure up to 5 minutes. A success clears it. At most 10,000 addresses are
   remembered, oldest forgotten first.
3. **`allowedHosts`**: the DNS-rebinding defence. On a loopback bind the `Host` header must be
   `localhost`, `127.0.0.1`, `[::1]`, or a name you added; a site pointing its own name at 127.0.0.1 is
   same-origin with the page but cannot make the browser send a `Host` you did not list. On a public
   bind or mounted, the names you pass are enforced and nothing is checked when you pass none, so a
   dashboard behind a reverse proxy answers only to its public name. `"*"` disables it.
4. **The same-origin check**: a `POST`, `PUT`, `PATCH` or `DELETE` must carry `Sec-Fetch-Site:
   same-origin` or `none`, or, without fetch metadata, an `Origin` naming this host.

From the demo:

```text
$ curl -i -H 'Host: rebind.attacker.example' http://127.0.0.1:9501/api/bootstrap
HTTP/1.1 421 Misdirected Request
This dashboard answers only the host names it was configured for. Add yours with `allowedHosts`.

$ curl -i -X POST -H 'Origin: https://evil.example' http://127.0.0.1:9501/api/stats
HTTP/1.1 403 Forbidden
403 cross-site request

$ curl -i -X POST http://127.0.0.1:9501/api/stats
HTTP/1.1 405 Method Not Allowed
{"error":"the dashboard is read-only"}
```

### Read-only, and hard to misuse from a browser

- **Read-only.** Only `GET` and `HEAD` are served; anything else is `405`. There is no control on the
  page that changes the honeypot.
- **A nonce CSP on the page**, fresh per response:

  ```text
  content-security-policy: default-src 'none'; script-src 'nonce-…'; style-src 'nonce-…'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
  ```

- **On every response**: `cache-control: no-store` (a cached dashboard is a cached evidence trail),
  `x-frame-options: DENY`, `x-content-type-options: nosniff`, `referrer-policy: no-referrer` (a token
  can be in the query).
- **No CORS headers.** Another site cannot read the dashboard through a logged-in browser.
- **No HTML from data.** Every attacker-written value reaches the document through `textContent`, and
  the bootstrap is escaped so a title containing `</script>` cannot close its element.

### Redaction

Applied on the server, to every incident before it is sent, including the live feed.

| `redact` | Default | Effect |
| --- | --- | --- |
| `credentials` | `true` | `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, `X-Auth-Token` and any header whose name reads as a secret, token, API key, password or credential become `[redacted]` (the name stays). Secret-named form and JSON body fields likewise. Every removed value is also scrubbed from detection reasons, because detectors quote what they saw. |
| `maskIp` | `false` | Addresses shown as their `/24` (IPv4) or `/48` (IPv6): in incidents, top offenders, sessions, actors and indicators. |

Credential redaction is on by default even for an operator's page: a captured password is a real
person's password as often as it is a guess, and a dashboard is screen-shared and left open far more
often than a log is read. Turn it off when you need to see what an attacker tried. `maskIp` is for a
dashboard shared more widely than your logs.

### Sections withheld on the server

```ts
await startDashboard(server.engine, {
  auth: { token: process.env.DASHBOARD_TOKEN! },
  sections: { intel: false, sessions: false },
});
```

A section switched off is withheld on the server: its tab is removed from the page and its routes
answer `404` ("the intel section is switched off on this dashboard"), so the data never leaves the
process. Hiding a screen in `<hackerpot-dashboard>` is cosmetic by comparison. In TOML,
`hide = ["intel", "sessions"]`.

| Section | Routes it gates |
| --- | --- |
| `overview` | `/api/stats`, `/api/incidents` and `/api/events`, each also served while another section below needs it |
| `incidents` | `/api/incidents/:id`; `/api/incidents` and `/api/events` too, unless `overview` or `statistics` is still on. While those still serve incidents, the captured request stays in the process: no body, and no header but the User-Agent the identity charts need |
| `statistics` | `/api/stats` and `/api/incidents`, unless `overview` is still on |
| `sessions` | `/api/sessions`, `/api/sessions/:ip` |
| `actors` | `/api/actors`, `/api/actors/:fingerprint` |
| `intel` | `/api/ioc`, `/api/metrics` |

**Read the `incidents` row carefully.** The Overview and Statistics screens are computed from the
incident list, so with either of them on, the list and the live feed are still served, and each
incident there carries its headers and body. Switching off `incidents` alone removes the table and the
detail route, not the captured requests. To keep captured requests off the wire, switch off
`overview`, `incidents` and `statistics` together, and keep [redaction](#redaction) on.

---

## Options

For `startDashboard(source, options)` and `createDashboardHandler(source, options)`. The TOML column is
the `[dashboard]` key that sets the same thing.

| Option | Default | TOML | Consequence |
| --- | --- | --- | --- |
| `port` | `9501` | `port` | `0` binds an ephemeral port; read it from `dashboard.port`. Listener only. |
| `host` | `"127.0.0.1"` | `host` | Anything but loopback publishes the page and requires `auth`. Listener only. |
| `auth` | none on loopback | `username`/`password`, `token`, `auth` | Required mounted and on a public bind. See [Authentication](#authentication). |
| `refusal` | `"unauthorized"` | `refusal` | What a refused caller is told. See [Saying less to a stranger](#saying-less-to-a-stranger). |
| `basePath` | `"/"` | `base_path` | The path the browser reaches the page under. A listener answers `404` outside it. |
| `title` | `"hackerpot"` | `title` | The header and the tab title. |
| `instance` | the hostname | `instance` | Which deployment this is, in the header. |
| `links` | `[]` | none | `{ label, href }` links in the header: your runbook, your SIEM. |
| `sections` | all on | `hide` | Sections withheld on the server. See [above](#sections-withheld-on-the-server). |
| `redact.credentials` | `true` | `redact_credentials` | Credentials stripped before an incident is sent. |
| `redact.maskIp` | `false` | `mask_ip` | Addresses shown as `/24` or `/48`. |
| `allowedHosts` | loopback names, on loopback | `allowed_hosts` | Extra `Host` names answered. On a public bind or mounted, enforced when given; `"*"` disables. |
| `allowedClients` | everyone | `allowed_clients` | Addresses or CIDRs allowed at all, checked before auth. An invalid entry refuses to start. |
| `authThrottle` | `{ maxAttempts: 5, lockoutMs: 1000, maxLockoutMs: 300000 }` | none | Backoff per address after failed credentials; `false` switches it off. |
| `maxClients` | `16` | none | Concurrent live-feed viewers; past it the stream answers `503`. |
| `maxEventsPerSecond` | `100` | none | Incidents per second per viewer; the surplus is skipped and counted. `0` removes the cap. |
| `onError` | ignored | logged by the service | Failures the dashboard absorbs: a source that is down, a viewer's socket error. |

Every option except `port` and `host` applies to `createDashboardHandler`, where `auth` is required.

---

## API routes

All relative to `basePath`, all behind the same checks and authentication as the page, all `GET`.

| Route | Returns |
| --- | --- |
| `/` | the page |
| `/api/bootstrap` | `{ base, title, instance, version, sections, links, source, redaction }`; what the page and the element start from |
| `/api/events` | the live feed: `text/event-stream` with `hello`, `incident`, `lagged` and `skipped` events |
| `/api/incidents` | `{ incidents }`, redacted. The management API's filters: `ip`, `detector`, `since`, `limit` (default 100; at most 5000 here, and a remote management API caps at 1000) |
| `/api/incidents/:id` | `{ incident }`, or `404` |
| `/api/stats` | the management API's `/stats` |
| `/api/sessions`, `/api/sessions/:ip` | `{ sessions }`, `{ session }` |
| `/api/actors`, `/api/actors/:fingerprint` | `{ actors }`, `{ actor }` |
| `/api/ioc` | `{ indicators }`; `?min_score=` |
| `/api/metrics` | Prometheus text |

The shapes are the management API's; see [data shapes](../reference/data-shapes.md). A source that fails
answers `502` with the reason.

```text
$ curl -s http://127.0.0.1:9501/api/bootstrap
{"base":"","title":"hackerpot demo","instance":"demo","version":"0.1.0","sections":{"overview":true,"incidents":true,"statistics":true,"sessions":true,"actors":true,"intel":true},"links":[],"source":"this process","redaction":{"credentials":true,"maskIp":false}}
```

---

## Operating limits

A busy honeypot is a firehose, and every open browser is a consumer of it. Three bounds keep a viewer
from costing the process more than it should:

- **`maxClients`** (16). Past it `/api/events` answers `503` with "this dashboard already has 16 live
  viewers"; the page keeps retrying and says why.
- **`maxEventsPerSecond`** (100, per viewer). Past it incidents are skipped for that viewer and, once the
  second is over and another incident arrives, it gets a `skipped` event with the count.
- **Lag.** When a viewer's socket stops draining, the server stops writing incidents to it and counts
  them; when it drains, the viewer gets a `lagged` event with the count. A viewer still stuck after 20
  seconds, or more than 5000 incidents behind, is disconnected (checked as incidents arrive), and its
  browser reconnects and reloads.

Heartbeat comments keep idle streams open through proxies. The dashboard subscribes to its source only
while somebody watches, so an idle dashboard holds no remote connection.

Behind nginx, the stream sends `X-Accel-Buffering: no`; a proxy that buffers responses some other way
must be told not to, or the feed arrives in lumps.

---

## It reports on one deployment's store

A dashboard reads one store. Two honeypots with separate memory stores are two dashboards, each showing
half. Honeypots sharing a Redis store show the whole deployment's incidents on either, but the live feed
and the engine-only gauges (`active_blocks`, `tracked_ips`) still come from the one process the
dashboard subscribes to, and a remote source reads through one management API.

The header names the instance (`instance`, defaulting to the hostname) and the source, so a partial
picture does not look like a whole one. Aggregating a fleet is a job for Prometheus and your log
pipeline, not a page.

And it shows what the store retains. A memory store holds a bounded number of hits and forgets them on
restart; "what happened last week" needs a [store](stores.md) that keeps last week.

---

## Related

- [Embedding the dashboard](embedding.md): the same dashboard inside an admin page you already have
- [Management API](management-api.md): the REST and WebSocket API a remote source reads
- [Metrics](metrics.md): the exposition on the Threat intel screen
- [Threat model](../concepts/threat-model.md#exposure-of-the-management-api-and-the-dashboard): why the
  operator surfaces are bounded the way they are
- [Try it locally](../testing/try-it.md): the demo, with the dashboard on port 9501
- [The course](../course/index.md): the dashboard in a running example
