# Management API

REST and a live WebSocket feed over captured incidents, on a listener of its own.

← [Documentation](../index.md) · [Operations](index.md)

---

The operator API is how programs read what the honeypot recorded. It runs on **its own
listener, separate from the attacker-facing honeypot**, and every endpoint but `/health`
requires an API key.

```toml
[management]
host = "127.0.0.1"                    # keep it private: loopback, or an internal address
port = 9500
api_keys = ["a-long-random-string"]   # setting any key enables the API
websocket = true
```

Or `MANAGEMENT_API_KEYS=key1,key2`, `MANAGEMENT_HOST`, `MANAGEMENT_PORT` in the environment.
Enabling it with no keys is a startup error: the API serves captured attacker data, so an
enabled keyless API is a misconfiguration, not a permissive one.

**Bind it to a private network.** Point it at an internal or VPC address so your own services
can reach it, never at a public interface. The attackers the honeypot records must never be
able to read it.

## Authentication

Send a key as `Authorization: Bearer <key>` or `X-API-Key: <key>`. Keys are compared in
constant time. Repeated failed authentications from one peer are refused with `429` for a
while, on both HTTP and the WebSocket upgrade.

## REST

| Method and path | Returns |
| --- | --- |
| `GET /health` | `{ "status": "ok" }`; unauthenticated liveness probe |
| `GET /incidents` | `{ incidents: [...] }`, most recent first. Filters: `?ip=`, `?detector=`, `?since=<ISO 8601>`, `?limit=` (default 100, max 1000) |
| `GET /incidents/:id` | `{ incident }`, or `404` |
| `GET /stats` | totals, unique IPs, counts by detector and by response, top offenders by score, first and last seen |
| `GET /metrics` | the Prometheus exposition; see [metrics](metrics.md) |
| `GET /ioc` | `{ indicators: [...] }`: every source address with its cumulative score, incident count, detectors and first and last seen, highest score first. `?min_score=` |
| `GET /ioc.txt` | the same addresses, one per line, for an `ipset` or a firewall. `?min_score=` |
| `GET /sessions` | `{ sessions: [...] }`: each address's incidents as an ordered timeline, newest activity first |
| `GET /sessions/:ip` | `{ session }`, or `404` |
| `GET /actors` | `{ actors: [...] }`: incidents grouped by [actor fingerprint](../concepts/actors.md), each with every address one actor used, most addresses first |
| `GET /actors/:fingerprint` | `{ actor }`, or `404` |

```bash
curl -H "Authorization: Bearer $KEY" "http://127.0.0.1:9500/incidents?detector=honeytoken&limit=20"
curl -H "X-API-Key: $KEY"           "http://127.0.0.1:9500/stats"

# Confirmed offenders straight into a firewall set:
curl -s -H "X-API-Key: $KEY" "http://127.0.0.1:9500/ioc.txt?min_score=40" \
  | while read ip; do ipset add hackerpot-block "$ip" 2>/dev/null; done
```

The response shapes are in [data shapes](../reference/data-shapes.md).

### Reads are bounded

`/incidents` is pushed into the store where the backend can do it: Elasticsearch turns `ip` and
`since` into a real query, Redis slices the list for a plain `limit`, and the file store streams
into a bounded window instead of parsing the whole log. On a 72 MB hit log a single
`/incidents?ip=…&limit=100` went from 96 MB retained to 25 MB. The aggregate endpoints
(`/stats`, `/ioc`, `/sessions`, `/actors`) read the store's retained window by design: they
summarise it, so there is nothing to push down. See [stores](stores.md#reading-a-store).

### The IOC feed publishes first-hand observations only

`/ioc` and `/ioc.txt` list only addresses this instance saw attack it. An address ingested from
a peer's feed is blocked at the door without a recorded hit, so it is never republished, and a
poisoned feed cannot spread from one honeypot to the next. See [threat intel](threat-intel.md).

## WebSocket: the live feed

Connect to `GET /stream` for incidents pushed the moment they are recorded. The key goes in the
`Authorization` or `X-API-Key` header, or as `?api_key=` for browser clients that cannot set
headers.

| Frame | When |
| --- | --- |
| `{ "type": "connected", "ts": "…" }` | once, on connect |
| `{ "type": "incident", "incident": { … } }` | every incident |
| `{ "type": "lagged", "dropped": 12 }` | this viewer stopped reading and incidents were skipped |

```js
const ws = new WebSocket("ws://127.0.0.1:9500/stream?api_key=" + KEY);
ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  if (message.type === "incident") console.log(message.incident.ip, message.incident.detections.map((d) => d.detectorId));
};
```

A viewer that stops reading cannot make the server buffer without limit: its incidents are
dropped, it is told how many, and `hackerpot_stream_dropped_total` counts them. `websocket =
false` switches the feed off.

## In code

```ts
import { HoneypotEngine, ManagementServer, MemoryStore, createMiddleware } from "@osqd/hackerpot";

const store = new MemoryStore();
let management: ManagementServer;
const engine = new HoneypotEngine({ store, onHit: (hit) => management.publish(hit) });

management = new ManagementServer({
  store,
  host: "127.0.0.1",
  port: 9500,
  apiKeys: [process.env.MANAGEMENT_KEY!],
  webhooks: [{ url: "https://hooks.example.com/hackerpot", secret: process.env.HOOK_SECRET! }],
  metrics: async () => ({ active_blocks: (await engine.blocklist.size?.()) ?? 0 }),
  detectorFailures: () => engine.detectorFailures,
});
await management.listen();

app.use(createMiddleware(engine));
```

| Option | Default | |
| --- | --- | --- |
| `store` | — | required: what the REST endpoints read |
| `host`, `port` | `"127.0.0.1"`, `9500` | |
| `apiKeys` | — | required |
| `websocket` | `true` | |
| `webhooks` | `[]` | see [webhooks](webhooks.md) |
| `webhookGlobalMaxPerMinute` | unlimited | across all hooks |
| `broker` | a new `IncidentBroker` | share one to fan out to other subscribers |
| `metrics` | — | extra gauges, each emitted as `hackerpot_<name>` |
| `detectorFailures` | — | `() => engine.detectorFailures`, for `hackerpot_detector_failures_total` |
| `onError` | — | failures the server absorbs |

`publish(hit)` sends an incident to the live feed, the webhooks and the metrics counters;
`announce(anomaly)` sends a traffic anomaly to the webhooks. The server hardens itself with
`hardenHttpServer`. The functions behind each endpoint are exported (`listIncidents`,
`computeStats`, `computeIoc`, `computeSessions`, `computeActors`) for a front end of your own.

## Related

- [The dashboard](dashboard.md) — the same data, drawn; `hackerpot dashboard` reads this API
- [Webhooks](webhooks.md) — push rather than pull
- [Data shapes](../reference/data-shapes.md) — every response body
