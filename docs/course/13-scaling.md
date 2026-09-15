# Lesson 13 — Scaling and changing it live

**Goal:** run Pantry's honeypot on more than one process without letting an attacker reset
their score by landing on another replica, and change detection without a restart.

← [Course](index.md) · Prev: [Operating it](12-operating-it.md) · Next: [Extending it](14-extending.md)

---

## What breaks at two replicas

Two things, and both are correctness rather than tuning.

**Scores.** An attacker's requests are spread across replicas by the load balancer. With a
memory store each replica sees a slice, and none of them sees enough to reach the block
threshold.

**Blocks.** A block written to one replica's memory refuses that replica's requests. The
next request lands elsewhere and is served.

Both fix the same way: one Redis.

## Do this

With a Redis running (`docker run --rm -p 6379:6379 redis:7-alpine`), and `ioredis` — which
the package already depends on — importable.

`pantry/lesson-13.mjs`:

```js
import Redis from "ioredis";
import { HoneypotServer, RedisBlocklist, RedisStore } from "@osqd/hackerpot";

const redis = new Redis(process.env.REDIS_URL ?? "redis://127.0.0.1:6379");
await redis.flushdb();   // a fresh example; never in production

// Two replicas behind one load balancer, sharing Redis.
const replica = () =>
  new HoneypotServer({
    store: new RedisStore({ client: redis, keyPrefix: "pantry:", scoreTtlSeconds: 3600, maxHits: 1500 }),
    blocklist: new RedisBlocklist({ client: redis, keyPrefix: "pantry:block:" }),
  });
const a = replica();
const b = replica();
await a.listen(0, "127.0.0.1");
await b.listen(0, "127.0.0.1");
const url = (server, path) => `http://127.0.0.1:${server.address().port}${path}`;

const probe = async (server, name, path) => {
  const res = await fetch(url(server, path), { headers: { "user-agent": "curl/8.4.0" } });
  await res.arrayBuffer();
  console.log(`replica ${name} ${path.padEnd(18)} ${res.status}  score in Redis: ${await redis.get("pantry:score:127.0.0.1") ?? "-"}`);
};

await probe(a, "A", "/.env");
await probe(b, "B", "/.git/config");
await probe(a, "A", "/.aws/credentials");
await probe(b, "B", "/recipes/42");
await probe(a, "A", "/recipes/42");

await a.close();
await b.close();
await redis.quit();
```

```bash
REDIS_URL=redis://127.0.0.1:6379 node lesson-13.mjs
```

### Checkpoint

```
replica A /.env              200  score in Redis: 16
replica B /.git/config       200  score in Redis: 32
replica A /.aws/credentials  403  score in Redis: 48
replica B /recipes/42        403  score in Redis: 48
replica A /recipes/42        403  score in Redis: 48
```

The score climbed across replicas: A saw 16, B added 16, A added 16 more and crossed 40. A
blocked the address, and **B refused it** on its very next request, before any detector ran
— the score did not move, because a blocked request costs nothing to serve. These are
standalone servers, so they block on score, with no proof needed.

Three settings in that code are not decoration:

- **`scoreTtlSeconds`** lets a quiet address's score decay. Without it suspicion only grows,
  and a shared address that tripped something once stays near the threshold forever.
- **`maxHits` is Redis's memory ceiling.** The hit log is one list holding whole incidents,
  bodies included, so its worst case is `maxHits × 64 KB`. An attacker who fills Redis gets
  it OOM-killed and restarted empty, which resets every score and every block. Size it to
  the memory Redis actually has.
- **A block key has a native TTL**, so an expired block is Redis's job, not yours.

## What stays per process, on purpose

The activity windows from [lesson 9](09-actors-and-volume.md) and the fingerprint registry
stay in memory per process, and are deliberately not shared. They feed suspicion that
scores low and can never block anybody in front of an app on its own; spending a Redis
round trip on every request to sharpen them is a bad bargain on the request path.

## Changing detection without a restart

A detector that fires on Pantry's readers is a problem you want to fix *now*. And a new or
retuned detector is a risk you want to take *gradually*. Both have the same tool: **shadow
mode.** A shadowed detector runs on every request and decides nothing.

`pantry/lesson-13b.mjs`:

```js
import { HoneypotEngine, clientAnomalyDetector, defaultDetectors } from "@osqd/hackerpot";

const engine = new HoneypotEngine({
  detectors: [...defaultDetectors().filter((d) => d.id !== "client-anomaly"), clientAnomalyDetector({ score: 12 })],
  onShadow: (event) => console.log(`  [shadow] ${event.ip} ${event.path} ${event.detections.map((d) => d.detectorId)} alsoHit=${event.alsoHit}`),
});

const copiedUserAgent = { host: "pantry.example", "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0 Safari/537.36" };
const ask = async (label, ip) => {
  const r = await engine.evaluate({ method: "GET", path: "/recipes/7", query: {}, headers: copiedUserAgent, ip });
  console.log(`${label.padEnd(9)} score ${r.score}, response ${JSON.stringify(r.actionId)}, recorded ${(await engine.store.list()).length}`);
};

await ask("live", "203.0.113.200");
engine.reconfigure({ shadowDetectors: ["client-anomaly"] });
await ask("shadowed", "203.0.113.201");
```

### Checkpoint

```
live      score 12, response "not-found", recorded 1
  [shadow] 203.0.113.201 /recipes/7 client-anomaly alsoHit=false
shadowed  score 0, response "", recorded 1
```

The same request, the same detector. Live, a retuned `client-anomaly` scored 12, chose a
response and recorded an incident. Shadowed, it was reported to `onShadow` and **nothing
else happened**: no score, no response, no incident. `alsoHit=false` is the line to read:
a request this detector would have added to your incidents that nothing else flagged.

A shadowed detection is not a weight of zero. It is kept out of the decision entirely, so a
shadowed detector emitting proof cannot make a block stick either.

`reconfigure` swaps detectors, response actions, the policy, the allowlist, the shadow set
and service tokens for the next request. It does **not** accept the store, the blocklist or
the activity windows: rebuilding those would hand every attacker a clean slate.

## The same thing from a file: SIGHUP

The standalone service re-reads its config on `SIGHUP`. Start lesson 11's service directly
under node, so the signal reaches the process itself rather than a wrapper that may not pass
it on:

```bash
node node_modules/@osqd/hackerpot/bin/hackerpot.mjs serve > hackerpot.log &
HACKERPOT_PID=$!
```

Now make three edits to `hackerpot.toml` — change `[server] port` to `14005`, and add:

```toml
[policy]
block_threshold = 30

[engine]
shadow_detectors = ["client-anomaly"]
```

— and send the signal. Then break the file (add `[logging]` with `format = "yaml"`) and send
it again:

```bash
kill -HUP $HACKERPOT_PID
kill -HUP $HACKERPOT_PID      # after breaking the file
```

### Checkpoint

```
{"ts":"2026-09-15T17:10:17.220Z","kind":"reload-requires-restart","key":"server","reason":"the HTTP listener is already bound","note":"not applied; restart to change this"}
{"ts":"2026-09-15T17:10:17.221Z","kind":"reload","config":"…/pantry/hackerpot.toml","applied":["engine.shadow_detectors","policy"],"requiresRestart":["server"],"detectors":25}
{"ts":"2026-09-15T17:10:19.223Z","kind":"reload-failed","error":"…/pantry/hackerpot.toml: [logging.format] must be one of \"json\", \"text\", got \"yaml\"","note":"keeping the running configuration"}
```

Three rules, one per line:

1. **What cannot be applied is named, with the reason.** The port changed in the file and
   the listener is already bound. An operator who edited a port, reloaded and saw no error
   would believe it took; silently ignoring a changed setting is the failure this is built
   around.
2. **What can be applied, is** — the policy and the shadow set, live, on the next request.
3. **A file that fails validation changes nothing.** A bad edit during an incident cannot
   take the honeypot down.

Put the file back afterwards. Detectors, responses, policy, allowlist, service tokens,
logging and intel feeds reload; listeners, stores, the blocklist and the audit need a
restart.

## The compose stack

A clone of the repository has the production shape as a compose file: the honeypot, Redis
for shared scores, a durable hit log, and the dashboard as an optional profile.

```bash
docker compose up -d --build
HACKERPOT_MANAGEMENT_API_KEY=… DASHBOARD_PASSWORD=… docker compose --profile dashboard up -d
```

What the profile adds:

```bash
HACKERPOT_MANAGEMENT_API_KEY=x DASHBOARD_PASSWORD=y docker compose --profile dashboard config --services
```

```
redis
honeypot
dashboard
```

Without both variables, compose refuses to start the dashboard at all: it names the missing
key and the missing password.

Things the file does that you would otherwise have to remember:

- **`TRUST_PROXY=false`**, because it publishes 4004 straight to the host — lesson 10's
  exercise, written down.
- **`REDIS_MAX_HITS=1500`**, sized to its 256 MB Redis, for the reason above.
- **The management API is bound inside the container and not published**; only the compose
  network reaches it.
- **The dashboard is a profile, not a default service**, published on the host's loopback
  only, holding the API key itself.
- **Containment**: every capability dropped, a read-only root filesystem, capped memory and
  processes — the one container on the host whose job is to be attacked.

After changing source, `--build`: the file sets both `build:` and `image:`, so without it
compose silently reuses the old image.

## Exercise

Pantry runs three replicas. Somebody changes `[store.redis] url` to a new Redis and sends
`SIGHUP` to all three. What happens, and why is that the right behaviour?

<details>
<summary>Answer</summary>

**Nothing is switched.** The store is on the list of things that need a restart, so each
replica logs a `reload-requires-restart` line naming the store, applies whatever else
changed, and keeps writing to the old Redis.

It is the right behaviour because swapping the store live would discard every accrued score
— an attacker two probes from a block would start again at zero, and so would every active
campaign. The honeypot refuses to do that implicitly. Changing the store is a restart, which
is a decision somebody makes on purpose, knowing what it costs.
</details>

## What you learned

- Scores and blocks must be shared across replicas; activity windows deliberately are not
- `scoreTtlSeconds` lets suspicion decay, and `maxHits` is a memory ceiling, not a preference
- Shadow mode runs a detector on real traffic and lets it decide nothing
- `reconfigure` and SIGHUP apply what is safe, name what is not, and survive a bad file
- The compose stack writes down the production decisions: trust, retention, exposure, containment

## Where to read more

- [Stores](../operations/stores.md#redisstore) · [Firewall enforcement](../operations/firewall.md#the-blocklists)
- [Shadow mode](../detection/shadow-mode.md) · [Runtime changes](../operations/runtime-changes.md)
- [Docker](../integration/docker.md) — the image, the stack, the dashboard profile

Next: [Extending it](14-extending.md).
