# Lesson 1 — Your first detection

**Goal:** turn one HTTP request into a result, and understand every field that comes back.

← [Course](index.md) · Next: [Proof and suspicion](02-proof-and-suspicion.md)

---

## One call

Everything in this library is downstream of one method: `engine.evaluate(facts)`.

The facts are what a request is — a method, a path, a query, headers, and the address it
came from. `evaluate` normalises the path once, runs every detector over the request, adds
up what they found, reads the address's earlier score from the store, asks the policy for
one response action, and records an incident if anything fired.

It does **not** write a response. Choosing what to send and sending it are separate steps,
and the second belongs to whatever front end you mount ([lesson 10](10-in-front-of-an-app.md)).
That is why you can run `evaluate` over a log file, and why the next nine lessons happen in
a plain script with no server.

## Do this

`pantry/lesson-01.mjs`:

```js
import { HoneypotEngine } from "@osqd/hackerpot";

const engine = new HoneypotEngine();

const probe = {
  method: "GET",
  path: "/.env",
  query: {},
  headers: { host: "pantry.example", "user-agent": "curl/8.4.0", accept: "*/*" },
  ip: "203.0.113.10",
};

const result = await engine.evaluate(probe);

console.log("score     ", result.score);
console.log("totalScore", result.totalScore);
console.log("response  ", result.actionId);
console.log("path      ", result.path);
for (const d of result.detections) {
  console.log(`  +${d.score} ${d.detectorId}: ${d.reason}`);
}
```

```bash
node lesson-01.mjs
```

### Checkpoint

```
score      16
totalScore 16
response   decoy-content
path       /.env
  +10 decoy-path: Exposed .env file probe
  +6 scanner-signature: User-Agent matches known tooling signature: curl/8.4.0
```

If you got that, the library is installed and working.

## What each field means

| Field | |
| ----- | - |
| `detections` | everything that fired, highest score first. Each has a `detectorId`, a `reason`, a `score`, and sometimes `certain`, `family`, `respondWith` and `metadata` |
| `score` | what **this request** added |
| `totalScore` | the **address's** cumulative score after it — [lesson 3](03-scores-and-responses.md) |
| `actionId` | the response the policy chose. An empty string means nothing fired: pass the request on |
| `action` | the response action object itself, ready to run |
| `path` | the normalised path the detectors matched |
| `fingerprint` | a short hash of header order and User-Agent family — [lesson 9](09-actors-and-volume.md) |
| `tracker` | this address's sliding activity window |
| `downgradedFrom` | `"block"` when a block was refused for lack of proof — [lesson 4](04-the-guard.md) |
| `shadowDetections` | findings from shadowed detectors, which decided nothing — [lesson 13](13-scaling.md) |

Two detectors fired, for two different reasons. `decoy-path` fired because nothing on
Pantry links to `/.env`, so the only way to ask for it is to guess. `scanner-signature`
fired because the client *said* it was curl.

The response is `decoy-content`: the `.env` decoy carries a convincing fake file, so the
probe appears to have worked and whoever sent it keeps going. Nothing real is served.

## Now try a real browser

Put a browser's headers where later lessons can reuse them. `pantry/browser.mjs`:

```js
export const CHROME = {
  host: "pantry.example",
  "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
  accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "accept-language": "en-GB,en;q=0.9",
  "accept-encoding": "gzip, deflate, br",
};
```

`pantry/lesson-01b.mjs`:

```js
import { HoneypotEngine } from "@osqd/hackerpot";
import { CHROME } from "./browser.mjs";

const engine = new HoneypotEngine();
const visit = { method: "GET", path: "/recipes/42", query: {}, headers: CHROME, ip: "198.51.100.7" };
const result = await engine.evaluate(visit);
console.log("detections", result.detections.length);
console.log("score     ", result.score);
console.log("response  ", JSON.stringify(result.actionId));
const hits = await engine.store.list();
console.log("recorded  ", hits.length);
```

### Checkpoint

```
detections 0
score      0
response   ""
recorded   0
```

**Nothing fired and nothing was recorded.** That is the resting state of Pantry's readers,
and it is the point: a honeypot in front of a real site should leave no trace of people
who did nothing. The engine does not judge ordinary traffic leniently; it has nothing to
say about it at all.

## Exercise

Send the request a SQL injection tool sends: `GET /recipes` with
`q=' UNION SELECT username, password FROM users--` in the query and a `sqlmap` User-Agent.
Print the detections, then read back what the store kept with `engine.store.list()`.

<details>
<summary>Checkpoint</summary>

```js
import { HoneypotEngine } from "@osqd/hackerpot";
const engine = new HoneypotEngine();
const result = await engine.evaluate({
  method: "GET",
  path: "/recipes",
  query: { q: "' UNION SELECT username, password FROM users--" },
  headers: { host: "pantry.example", "user-agent": "sqlmap/1.7.2#stable (https://sqlmap.org)" },
  ip: "203.0.113.20",
});
console.log("score     ", result.score);
console.log("response  ", result.actionId);
for (const d of result.detections) console.log(`  +${d.score} ${d.detectorId}: ${d.reason}`);
const [hit] = await engine.store.list();
console.log("stored    ", hit.ip, hit.path, hit.respondedWith, hit.detections.length, "detections");
```

```
score      16
response   tarpit
  +10 payload-injection: sql-injection payload detected in query.q
  +6 scanner-signature: User-Agent matches known tooling signature: sqlmap/1.7.2#stable (https://sqlmap.org)
stored     203.0.113.20 /recipes tarpit 2 detections
```

The same score as the curl probe, and a different response. `payload-injection` carries no
fake content to serve, so the policy fell through to its score ladder, and 16 is past the
tarpit line of 15. [Lesson 3](03-scores-and-responses.md) walks that ladder.

The stored record is an **incident**: exactly what the management API returns and a
webhook posts, from [lesson 12](12-operating-it.md) on.
</details>

## Common mistake

**Passing a forwarded address as `ip`.** The facts want the address the connection came
from. Reading `X-Forwarded-For` yourself lets any client choose its own address, and every
score, block and allowlist entry keys on it. [Lesson 10](10-in-front-of-an-app.md) covers
the one setting that decides it.

## What you learned

- `evaluate` is the whole read path, and it never writes a response
- A request adds a `score`; the address carries a `totalScore`
- The policy picks one response by id, and an empty id means "pass it on"
- Ordinary traffic leaves nothing behind

## Where to read more

- [How it works](../concepts/how-it-works.md) — the lifecycle behind `evaluate`
- [Data shapes](../reference/data-shapes.md#the-incident) — the incident, field by field
- [API reference](../reference/api.md#the-engine) — every engine option and member

Next: [Proof and suspicion](02-proof-and-suspicion.md) — the idea the rest of the course
depends on.
