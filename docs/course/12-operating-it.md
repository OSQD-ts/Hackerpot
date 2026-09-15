# Lesson 12 — Operating it

**Goal:** get what the honeypot sees to the people and programs that act on it — without
that path becoming something an attacker can use — and know which numbers to alert on.

← [Course](index.md) · Prev: [The standalone service and protocol honeypots](11-standalone-and-protocols.md) · Next: [Scaling and changing it live](13-scaling.md)

---

## Where incidents go

```
                                 ┌──► store ──► management API (REST) ──► your tools, the dashboard
                                 │         └──► /metrics ──────────────► Prometheus
  engine / protocol honeypots ───┤
                                 ├──► onHit / service log ─────────────► your log pipeline
                                 ├──► live feed (WebSocket, SSE) ──────► dashboard, your consumers
                                 ├──► webhooks ────────────────────────► your endpoint, Slack, Discord
                                 └──► syslog ──────────────────────────► your SIEM
```

Every one of the listeners in that picture shows captured attacker data: addresses, bodies,
credentials an attacker tried, which detector fired on what. For somebody probing Pantry,
that is a map of what to avoid next. **None of them belongs on the attacker-facing
interface.**

## The management API, webhooks and metrics

`pantry/lesson-12.mjs`:

```js
import http from "node:http";
import { createHmac } from "node:crypto";
import { HoneypotEngine, ManagementServer, MemoryStore } from "@osqd/hackerpot";

const KEY = "pantry-management-key-0123456789";
const SECRET = "pantry-webhook-secret";

// A receiver standing in for your alerting endpoint.
const receiver = http.createServer((req, res) => {
  let raw = "";
  req.on("data", (c) => (raw += c));
  req.on("end", () => {
    const ts = req.headers["x-hackerpot-timestamp"];
    const expected = `sha256=${createHmac("sha256", SECRET).update(`${ts}.${raw}`).digest("hex")}`;
    const { type, incident } = JSON.parse(raw);
    console.log(`  [webhook] ${type} ${incident.ip} ${incident.path} total=${incident.totalScore} signature ok=${req.headers["x-hackerpot-signature-v2"] === expected}`);
    res.end();
  });
});
await new Promise((r) => receiver.listen(0, "127.0.0.1", r));

const store = new MemoryStore();
let management;
const engine = new HoneypotEngine({ store, onHit: (hit) => management.publish(hit) });

management = new ManagementServer({
  store,
  host: "127.0.0.1",
  port: 0,
  apiKeys: [KEY],
  webhooks: [{ url: `http://127.0.0.1:${receiver.address().port}/hackerpot`, secret: SECRET, minScore: 40 }],
  detectorFailures: () => engine.detectorFailures,
});
await management.listen();
const api = `http://127.0.0.1:${management.address().port}`;

// A scripted client walking decoys, judged as the middleware would.
for (const path of ["/.env", "/.git/config", "/.aws/credentials", "/.ssh/id_rsa"]) {
  await engine.evaluate({ method: "GET", path, query: {}, headers: { host: "pantry.example", "user-agent": "curl/8.4.0" }, ip: "203.0.113.5" }, { blockRequiresProof: true });
}
await new Promise((r) => setTimeout(r, 300));

const get = (path) => fetch(api + path, { headers: { authorization: `Bearer ${KEY}` } });
console.log("GET /health (no key)", (await fetch(api + "/health")).status);
console.log("GET /stats  (no key)", (await fetch(api + "/stats")).status);
const stats = await (await get("/stats")).json();
console.log("totalIncidents", stats.totalIncidents, "byResponse", JSON.stringify(stats.byResponse));
console.log("ioc.txt:", (await (await get("/ioc.txt?min_score=40")).text()).trim());
const metrics = await (await get("/metrics")).text();
console.log(metrics.split("\n").filter((l) => /^hackerpot_(incidents_total|downgrades_total|top_offender_score)/.test(l)).join("\n"));

await management.close();
receiver.close();
```

Port 0 again: the operating system picks free ports for both listeners, and the script
closes them.

### Checkpoint

```
  [webhook] incident 203.0.113.5 /.aws/credentials total=48 signature ok=true
  [webhook] incident 203.0.113.5 /.ssh/id_rsa total=64 signature ok=true
GET /health (no key) 200
GET /stats  (no key) 401
totalIncidents 4 byResponse {"decoy-content":2,"tarpit":2}
ioc.txt: 203.0.113.5
hackerpot_incidents_total 4
hackerpot_top_offender_score 64
hackerpot_downgrades_total 2
```

**The API.** Everything but `/health` needs a key, sent as `Authorization: Bearer` or
`X-API-Key`. It binds loopback by default, and enabling it with no keys is a startup error:
a keyless API over captured attacker data is a misconfiguration, not a permissive setting.
`/ioc.txt` is one address per line, ready for an `ipset`.

**The webhook** fired twice, not four times. `minScore` reads the address's **cumulative**
score, so a webhook with a high `minScore` *is* an alert channel: it speaks only once an
address has crossed into persistent-attacker territory. Each delivery is signed. Verify the
`-V2` signature, which covers `<timestamp>.<body>`, over the **raw** body, and reject old
timestamps, and a captured delivery cannot be replayed against you.

**The metrics** are counted in memory as incidents are published, so a scrape never reads
the store.

## The two numbers to alert on

**`hackerpot_downgrades_total`** — blocks the proof guard refused. It is 2 above: the
`curl` client crossed the block line twice with nothing but suspicion. A rising count means
scores are reaching the block threshold on evidence that proves nothing. In front of Pantry
that is the shape of detectors adding up on real visitors, which is precisely how people get
blocked when the guard is off. It is the guard's own report card.

**`hackerpot_detector_failures_total`** — detection is degraded, usually because of a
resolver or a custom detector rather than the traffic.

And the thing worth waking somebody for that is not a number: **a replayed honeytoken or a
sprung trap.** Somebody read bait and used it.

## The traffic audit

Counters cannot tell you a number is *unusual*. An attack is an event, not a level. The
audit keeps a short **window** and the **baseline** before it, and raises an anomaly when a
check clears its bar.

`pantry/lesson-12b.mjs`:

```js
import { HoneypotEngine, TrafficAudit } from "@osqd/hackerpot";

const audit = new TrafficAudit({ windowMs: 300_000, baselineMs: 3_600_000, minSamples: 50 });
const engine = new HoneypotEngine({ audit });
const now = Date.UTC(2026, 8, 15, 12, 0, 0);
const browser = { host: "pantry.example", "user-agent": "Mozilla/5.0 Chrome/126.0.0.0", accept: "text/html", "accept-language": "en", "accept-encoding": "gzip" };

// An ordinary hour: 600 page views, 6 probes.
for (let i = 0; i < 600; i++) {
  await engine.evaluate({ method: "GET", path: `/recipes/${i % 40}`, query: {}, headers: browser, ip: `198.51.100.${i % 200}` }, { now: new Date(now - 3_600_000 - 240_000 + i * 6000) });
}
for (let i = 0; i < 6; i++) {
  await engine.evaluate({ method: "GET", path: "/.env", query: {}, headers: browser, ip: `203.0.113.${i}` }, { now: new Date(now - 3_000_000 + i * 60_000) });
}
// The last five minutes: 60 page views, and 14 new addresses probing a path nobody probed before.
for (let i = 0; i < 60; i++) {
  await engine.evaluate({ method: "GET", path: `/recipes/${i}`, query: {}, headers: browser, ip: `198.51.100.${i}` }, { now: new Date(now - 200_000 + i * 3000) });
}
for (let i = 0; i < 14; i++) {
  await engine.evaluate({ method: "GET", path: "/actuator/gateway/routes", query: {}, headers: browser, ip: `192.0.2.${i + 1}` }, { now: new Date(now - 150_000 + i * 5000) });
}

const { window, baseline } = audit.summary(now);
console.log(`window   ${window.requests} requests, ${window.flagged} flagged`);
console.log(`baseline ${baseline.requests} requests, ${baseline.flagged} flagged`);
for (const a of audit.evaluate(now)) console.log(`[${a.severity}] ${a.id}: ${a.summary}`);
```

### Checkpoint

```
window   79 requests, 14 flagged
baseline 601 requests, 6 flagged
[warning] probe-campaign: 14 different addresses started probing "/actuator/gateway/routes" in the last 3 minute(s), a path nothing probed before. This is what a newly published exploit looks like.
```

(The window counts are approximate by a request or two at the edges, because the audit
counts in buckets.) Fourteen unrelated addresses starting on the same new path at once is
what a freshly published vulnerability looks like from inside a honeypot: everybody is
running the same new list. One address running one probe looks like nothing; the union is
the signal.

The baseline **ends where the window begins**, so a large enough spike cannot raise its own
bar. Every check stays silent until the window holds `minSamples` requests — a quiet site at
3am produces "800% more probes" from four requests — and is then silent for a cooldown, so
an hour-long spike is one anomaly, not sixty. The standalone service runs the audit by
default and sends anomalies to every webhook.

## The dashboard

Counters and anomalies say *how much*. The dashboard says **which requests, and why**: the
live incident feed, statistics, per-address sessions, actors across addresses, and the
indicators.

`pantry/lesson-12c.mjs`:

```js
import { HoneypotEngine, startDashboard } from "@osqd/hackerpot";

const engine = new HoneypotEngine();
await engine.evaluate({ method: "GET", path: "/.env", query: {}, headers: { host: "pantry.example", "user-agent": "sqlmap/1.7.2#stable" }, ip: "203.0.113.5" });

const dashboard = await startDashboard(engine, { port: 0, title: "pantry", instance: "pantry-web-1" });
console.log("listening on", dashboard.url.replace(/:\d+\//, ":<port>/"));
const boot = await (await fetch(`${dashboard.url}api/bootstrap`)).json();
console.log("title", boot.title, "| instance", boot.instance, "| source", boot.source, "| redaction", JSON.stringify(boot.redaction));
const stats = await (await fetch(`${dashboard.url}api/stats`)).json();
console.log("incidents", stats.totalIncidents, "| by detector", JSON.stringify(stats.byDetector));
await dashboard.close();

try {
  await startDashboard(engine, { host: "0.0.0.0", port: 0 });
} catch (error) {
  console.log(`${error.name}: ${error.message}`);
}
```

### Checkpoint

```
listening on http://127.0.0.1:<port>/
title pantry | instance pantry-web-1 | source this process | redaction {"credentials":true,"maskIp":false}
incidents 1 | by detector {"decoy-path":1,"scanner-signature":1}
DashboardConfigError: The dashboard is set to bind 0.0.0.0, which publishes it beyond this machine, and no `auth` was configured. Configure `auth`, keep the default host "127.0.0.1", or write `auth: false` to state that something in front of it already authenticates.
```

Open `dashboard.url` in a browser (without the `close()`) and you have the page. Its
default port is **9501**, beside the management API's 9500.

Four decisions to notice:

- **It is a separate listener from the honeypot**, loopback by default, because the
  honeypot's port is the one attackers are invited to and the dashboard describes them.
- **It refuses to bind beyond loopback without authentication** — at startup, not as a log
  warning. `auth` is `{ username, password }`, `{ token }`, your own `{ authorize }`, or the
  explicit, greppable `false`.
- **Credentials are redacted by default.** A captured password is a real person's password
  as often as it is a guess, and a dashboard is screen-shared far more often than a log is
  read. `redact: { maskIp: true }` shows addresses as their `/24` too.
- **`sections` withholds screens on the server**, so a switched-off section's data never
  leaves the process.

## Beside a running stack

Standalone, the dashboard should not live in the process attackers talk to. `hackerpot
dashboard` runs it as its own service, reading the honeypot through its management API and
holding the API key itself, so no browser ever sees it. With lesson 11's `hackerpot serve`
running:

```bash
npx hackerpot dashboard --port 19501
```

```
{"ts":"2026-09-15T17:06:15.044Z","kind":"startup","service":"dashboard","url":"http://127.0.0.1:19501/","source":"management API at 127.0.0.1:19500"}
```

It found the management API and its key in the same `hackerpot.toml`. Then:

```bash
curl -s http://127.0.0.1:19501/api/stats
```

```
{"totalIncidents":1,"uniqueIps":1,"byDetector":{"decoy-path":1,"scanner-signature":1},"byResponse":{"decoy-content":1},"topOffenders":[{"ip":"127.0.0.1","score":16,"incidents":1}],"firstSeen":"2026-09-15T17:06:14.507Z","lastSeen":"2026-09-15T17:06:14.507Z"}
```

The same incident lesson 11 recorded, now read across a process boundary. `--port 19501`
keeps this clear of the default 9501; in production you leave it off.

## Inside a page Pantry already has

The dashboard is also an element. Mount the handler on Pantry's own server — **outside**
the honeypot middleware, so reading the dashboard never shows up in it — and drop the
element into the admin panel:

```js
import { createDashboardHandler } from "@osqd/hackerpot";
const dashboard = createDashboardHandler(engine, { basePath: "/_hackerpot", auth: { username: "ops", password: process.env.DASHBOARD_PASSWORD } });
```

```html
<hackerpot-dashboard src="/_hackerpot"></hackerpot-dashboard>
<script type="module">
  import { defineHackerpotDashboard } from "@osqd/hackerpot/element";
  defineHackerpotDashboard();
</script>
```

A shadow root is a styling boundary and **not a security boundary**: any script on the host
page can read everything on screen and call the dashboard's API as the viewer. Mount it only
on a page already behind your admin authentication. The capstone mounts the handler and
checks both sides of its authentication.

## Exercise

Pantry's security engineer wants to watch the dashboard from a laptop over the office VPN,
with the service bound to `0.0.0.0`. List everything that has to be true, in order of what
fails first.

<details>
<summary>Answer</summary>

1. **Authentication**, or it refuses to start, as the checkpoint showed. In TOML:
   `[dashboard] username` and `password` (or `DASHBOARD_PASSWORD`), or a `token` of at
   least 16 characters.
2. **The `Host` it is reached by must be allowed.** Off loopback, the dashboard checks the
   `Host` header against DNS rebinding; behind a proxy or a VPN name, set `allowed_hosts`.
3. **Reachability only from where it should be.** `allowed_clients` restricts it to the
   VPN's range before authentication is even tried, and wrong passwords are throttled.
4. **Never the attacker-facing interface.** A standalone honeypot's public address is the
   one place this must not answer; bind the VPN interface, not every interface, if you can.

Better still is the shape the compose stack uses in [lesson 13](13-scaling.md): published on
the host's loopback only, reached through an SSH tunnel or a TLS reverse proxy.
</details>

## What you learned

- Every operator surface shows attacker data; none belongs on the attacker-facing interface
- The management API needs a key; a webhook's `minScore` reads the cumulative score
- Alert on `downgrades_total` and `detector_failures_total`, and on sprung proof
- The audit compares a window with the baseline before it, with floors and cooldowns
- The dashboard is loopback by default, refuses a public bind without auth, redacts by default

## Where to read more

- [The dashboard](../operations/dashboard.md) · [Embedding it](../operations/embedding.md)
- [Management API](../operations/management-api.md) · [Webhooks](../operations/webhooks.md) · [Alert sinks](../operations/alert-sinks.md)
- [Metrics](../operations/metrics.md) · [The traffic audit](../operations/audit.md)

Next: [Scaling and changing it live](13-scaling.md).
