# Lesson 9 — Actors and volume

**Goal:** watch evidence build across requests, make time deterministic so you can test it,
and see one tool correlated across several addresses.

← [Course](index.md) · Prev: [Identity and crawler verification](08-identity.md) · Next: [In front of an app](10-in-front-of-an-app.md)

---

## One request tells you less than seventeen

Every lesson so far judged requests one at a time. Three detectors need more: `rate-spike`,
`path-bruteforce` and `credential-bruteforce` read each address's **activity window**, a
sliding record of what it asked for recently. A fourth, `repeat-actor`, reads across
addresses.

## Do this

A wordlist walk: seventeen paths that do not exist on Pantry, one a second.

`pantry/lesson-09.mjs`:

```js
import { HoneypotEngine } from "@osqd/hackerpot";

const engine = new HoneypotEngine();
const start = Date.UTC(2026, 8, 15, 9, 0, 0);
const headers = { host: "pantry.example", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/127.0", accept: "*/*", "accept-language": "en", "accept-encoding": "gzip" };
const words = ["old", "backup", "test", "dev", "staging", "tmp", "private", "v1", "v2", "beta", "cms", "portal", "files", "upload", "db", "logs", "conf"];

for (const [i, word] of words.entries()) {
  const r = await engine.evaluate(
    { method: "GET", path: `/${word}`, query: {}, headers, ip: "203.0.113.120" },
    { now: new Date(start + i * 1000) },
  );
  if (r.detections.length > 0) console.log(`t+${i}s /${word}: ${r.detections.map((d) => `${d.detectorId} +${d.score} (${d.reason})`).join(", ")}  total ${r.totalScore}`);
}
```

### Checkpoint

```
t+14s /db: path-bruteforce +8 (15 distinct paths requested in 30s)  total 8
t+15s /logs: path-bruteforce +8 (16 distinct paths requested in 30s)  total 16
t+16s /conf: path-bruteforce +8 (17 distinct paths requested in 30s)  total 24
```

**No single request was suspicious.** Each was a browser asking for a page that does not
exist. The case was built entirely out of the relationship between them: fifteen distinct
paths inside thirty seconds.

## `now`, and why it matters

`now` tells the engine when the request happened. Without it, the engine uses the clock, and
this lesson would have to sleep for seventeen seconds and still be flaky. With it you are
simulating time rather than waiting for it — which is exactly how a log replay works
([lesson 15](15-proving-it.md)), and how the traffic corpus exercises every stateful
detector deterministically.

## The windows

| Detector | Counts | Fires at | Window | Score |
| --- | --- | --- | --- | --- |
| `rate-spike` | requests | 60 | 10 s | 4 |
| `path-bruteforce` | distinct paths | 15 | 30 s | 8 |
| `credential-bruteforce` | POST/PUT/PATCH attempts on one login path | 8 | 60 s | 9 |

The activity window as a whole defaults to 60 seconds (`activityWindowMs`), and it must be
at least as long as the longest detector window, or that detector sees less history than it
asks for.

Every one of these is **suspicion**, and they score low on purpose. A corporate NAT, a
university and a mobile carrier's CGNAT pool all present hundreds of people as one address.

## Page loads are not wordlists

In front of Pantry the engine sees every request Pantry serves, assets included. One page
load of a modern single-page app is easily twenty distinct paths in a second.

`pantry/lesson-09b.mjs`:

```js
import { HoneypotEngine } from "@osqd/hackerpot";
import { CHROME } from "./browser.mjs";

const start = Date.UTC(2026, 8, 15, 9, 0, 0);
const assets = Array.from({ length: 24 }, (_, i) => `/assets/chunk-${i}.js`);

for (const activityStatus of ["seen", "passed"]) {
  const engine = new HoneypotEngine();
  let fired = "nothing fired";
  for (const [i, path] of assets.entries()) {
    const r = await engine.evaluate({ method: "GET", path, query: {}, headers: CHROME, ip: "198.51.100.44" }, { now: new Date(start + i * 50), activityStatus });
    if (r.detections.length > 0) { fired = `request ${i + 1}: ${r.detections.map((d) => d.detectorId).join(", ")}`; break; }
  }
  console.log(`${activityStatus.padEnd(6)} ${fired}`);
}
```

### Checkpoint

```
seen   request 15: path-bruteforce
passed nothing fired
```

Counted as `seen`, a reader loading one Pantry page trips enumeration. The middleware
([lesson 10](10-in-front-of-an-app.md)) marks a request it hands to Pantry as `passed`, and
promotes it to a counted path only if **Pantry answers 404**. A wordlist walk still trips
the detector, because a wordlist is made of paths that do not exist; a page load does not.

## One tool, many addresses

An address is a weak identity. Attackers rotate through proxies and cloud ranges. So for
every request the engine also computes an **actor fingerprint**: a short hash of the header
order and the User-Agent family. The same tool, driven the same way, produces the same
fingerprint from a hundred addresses.

`pantry/lesson-09c.mjs`:

```js
import { HoneypotEngine } from "@osqd/hackerpot";

const engine = new HoneypotEngine();
const start = Date.UTC(2026, 8, 15, 9, 0, 0);
const tool = { host: "pantry.example", "user-agent": "Mozilla/5.0 zgrab/0.x", accept: "*/*" };
let t = 0;
const at = () => ({ now: new Date(start + (t += 1000)) });

async function send(ip, path, headers = tool) {
  const r = await engine.evaluate({ method: "GET", path, query: {}, headers, ip }, at());
  const actor = r.detections.find((d) => d.detectorId === "repeat-actor");
  console.log(`${ip.padEnd(14)} ${path.padEnd(14)} fp ${r.fingerprint}  ${actor ? `repeat-actor +${actor.score}` : r.detections.map((d) => d.detectorId).join(", ") || "nothing fired"}`);
}

await send("203.0.113.131", "/.env");
await send("203.0.113.132", "/.git/config");
await send("203.0.113.133", "/.aws/credentials");
await send("203.0.113.133", "/wp-login.php");
await send("203.0.113.134", "/recipes/42");
```

### Checkpoint

```
203.0.113.131  /.env          fp d3b81bb2daf1837f  decoy-path, scanner-signature
203.0.113.132  /.git/config   fp d3b81bb2daf1837f  decoy-path, scanner-signature
203.0.113.133  /.aws/credentials fp d3b81bb2daf1837f  decoy-path, scanner-signature
203.0.113.133  /wp-login.php  fp d3b81bb2daf1837f  repeat-actor +7
203.0.113.134  /recipes/42    fp d3b81bb2daf1837f  scanner-signature
```

One fingerprint, three addresses, and on the fourth request `repeat-actor` says they are
one actor. (When `repeat-actor` fires the script prints only that detection;
`decoy-path` and `scanner-signature` fired on that request too.)

## Why a fingerprint cannot manufacture suspicion

A fingerprint is a heuristic, not an identity: every user of one browser build on one site
shares one. Two rules keep `repeat-actor` safe in front of Pantry.

**The registry is written only by requests that already scored.** A reader nothing flagged
never enters it, so readers who share a browser build are never correlated.

**The current address must itself already be in the registry.** Without that rule, two real
attackers were enough to make every later request with their fingerprint fire — and
because firing is itself a hit, each such request wrote its own address in and guaranteed
the next one fired too. Measured before the fix: after two attackers probed a decoy, a
single ordinary visitor passed the block threshold in seven page views.

## Exercise

Look at the last line of the checkpoint. `203.0.113.134` has the same fingerprint, and the
registry holds three addresses under it. Why did `repeat-actor` not fire?

<details>
<summary>Answer</summary>

Because `203.0.113.134` was not in the registry when its request was judged. Its first
request is its first appearance, and the registry records an address only after that
address's own request has scored. `repeat-actor` confirms that addresses **already
suspicious** are one actor; it never reaches out and flags a newcomer on the strength of a
shared fingerprint.

A genuine rotating attacker is barely slowed by this: each new address enters the registry
on its own first scoring request, and the correlation fires from its second.
</details>

## What you learned

- Three detectors read a per-address sliding window; one correlates across addresses
- `now` makes time deterministic, which is how replays and the corpus test windows
- Volume is suspicion and scores low, because one address is often many people
- In front of an app, a served path counts toward enumeration only once it turns out to be a 404
- A fingerprint confirms that suspicious addresses are one actor, and never creates suspicion

## Where to read more

- [Actors](../concepts/actors.md) — what is remembered per address, fingerprints, sessions
- [The detectors](../detection/detectors.md#behaviour-over-time) — the stateful ones in detail
- [Adapters](../integration/adapters.md#path-bruteforce-in-front-of-real-users) — the 404 gating

Next: [In front of an app](10-in-front-of-an-app.md).
