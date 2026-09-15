# Lesson 4 — The guard

**Goal:** watch the policy ask to block an address and get a tarpit instead, and understand
why that is the most valuable behaviour in the library.

← [Course](index.md) · Prev: [Scores and responses](03-scores-and-responses.md) · Next: [The detectors](05-detectors.md)

---

## A block is not a response to one request

It writes the address to the blocklist — and to the firewall, if an enforcer is wired — so
**every later request from that address is refused**, Pantry's own recipe pages included.
Standalone, where nothing legitimate arrives, that is the point. In front of Pantry it is the
most expensive mistake the library can make.

And from [lesson 3](03-scores-and-responses.md), the ladder blocks on a *sum*. From
[lesson 2](02-proof-and-suspicion.md), a sum of suspicion is still suspicion.

So between the policy and the response sits one check:

```ts
if (actionId === "block" && blockRequiresProof && !detections.some((d) => d.certain === true)) {
  downgradedFrom = "block";
  actionId = unprovenBlockFallback;        // "tarpit" by default
}
```

## Do this

Two clients walk the same five decoys. One is `curl`; one is `sqlmap`. The engine is asked to
judge them as the middleware would, with `blockRequiresProof: true`.

`pantry/lesson-04.mjs`:

```js
import { HoneypotEngine } from "@osqd/hackerpot";

const engine = new HoneypotEngine();
const decoys = ["/.env", "/.git/config", "/.aws/credentials", "/.ssh/id_rsa", "/wp-login.php"];

async function walk(ip, userAgent) {
  console.log(userAgent);
  for (const path of decoys) {
    const r = await engine.evaluate(
      { method: "GET", path, query: {}, headers: { host: "pantry.example", "user-agent": userAgent }, ip },
      { blockRequiresProof: true },
    );
    console.log(`  ${path.padEnd(18)} total ${String(r.totalScore).padStart(3)}  ${r.actionId.padEnd(13)} ${r.downgradedFrom ? `(downgraded from ${r.downgradedFrom})` : ""}`);
  }
  console.log("  blocked:", await engine.isBlocked(ip));
}

await walk("203.0.113.50", "curl/8.4.0");
await walk("203.0.113.51", "sqlmap/1.7.2#stable (https://sqlmap.org)");
```

### Checkpoint

```
curl/8.4.0
  /.env              total  16  decoy-content 
  /.git/config       total  32  decoy-content 
  /.aws/credentials  total  48  tarpit        (downgraded from block)
  /.ssh/id_rsa       total  64  tarpit        (downgraded from block)
  /wp-login.php      total  75  tarpit        (downgraded from block)
  blocked: false
sqlmap/1.7.2#stable (https://sqlmap.org)
  /.env              total  16  decoy-content 
  /.git/config       total  32  decoy-content 
  /.aws/credentials  total  48  block         
  /.ssh/id_rsa       total  64  block         
  /wp-login.php      total  75  block         
  blocked: false
```

**Identical walks, identical totals, and the policy asked to block both clients three
times.** `curl` was tarpitted each time. `sqlmap` was blocked.

## Reading it

The difference is not the score. It is the one detection on every `sqlmap` request that is
proof: `scanner-signature` on a tool that named itself. Nothing on the `curl` walk is proof —
`curl` is also every legitimate script calling Pantry's API — so the guard replaced each
block with the fallback, and recorded what it replaced in `downgradedFrom`.

Three things that follow:

- **Nothing about the refusal is silent.** The incident carries `downgradedFrom: "block"`, a
  metric counts it, and the audit watches the count.
- **It is per request.** The next request from the `curl` address is judged again, and is
  blocked the moment it carries proof — a replayed honeytoken, a sprung trap.
- **`blocked: false` for both** is lesson 3 again: `evaluate` decides, and the front end acts.
  Mounted in front of Pantry, the `sqlmap` address would now be on the blocklist and the
  `curl` address would not.

## What a tarpit costs a person

If the `curl` client had been somebody's integration, a tarpit costs it a few seconds on each
flagged request. A block would have cost it every request, to every page, for fifteen
minutes, with no way to tell a block from an outage. The guard trades a slower answer for an
attacker against a recoverable outcome for a person, and that trade is the design.

## Why it lives in the engine

The guard runs **after** the policy chooses, inside the engine, not inside the policy. A
check that every policy author has to remember is a check somebody forgets, at 3am, during an
incident, in a custom policy copied from a blog post. Here it cannot be forgotten in a policy,
worked around by one, or bypassed by someone who has not read this lesson.

## Where it is on

| Front end | Default |
| --- | --- |
| `createMiddleware`, `koaHoneypot`, `fastifyHoneypot`, `fetchHoneypot`, `withFetchHoneypot`, `trapFormGuard` | **on** |
| `hackerpot replay` | on: a log comes from an application serving real users |
| `HoneypotServer`, the standalone service | off: nothing legitimate reaches it |
| `engine.evaluate()` called directly | off, unless you pass `blockRequiresProof: true` |

Relaxing it is one explicit, greppable setting: `createMiddleware(engine, { blockRequiresProof: false })`.
Read [the threat model](../concepts/threat-model.md) before you write it.

## The fallback cannot be `block`

`pantry/lesson-04b.mjs`:

```js
import { HoneypotEngine, createMiddleware } from "@osqd/hackerpot";
try {
  createMiddleware(new HoneypotEngine(), { unprovenBlockFallback: "block" });
} catch (error) {
  console.log(error.message);
}
```

### Checkpoint

```
unprovenBlockFallback cannot be "block": it is the action an unproven block is replaced with
```

A `block` fallback would make every downgrade block the very request the downgrade existed
to protect, while still recording it as a guard refusal — so the metric meant to catch this
would report success. It is refused when the middleware is built, not when the first
visitor meets it.

## Exercise

Pantry would rather an unproven block look like ordinary rate limiting than a slow page. Run
the `curl` walk with `unprovenBlockFallback: "rate-limit"`, then count the incidents that
record a refused block. What is that count for?

<details>
<summary>Checkpoint</summary>

```js
import { HoneypotEngine } from "@osqd/hackerpot";

const engine = new HoneypotEngine();
for (const path of ["/.env", "/.git/config", "/.aws/credentials", "/.ssh/id_rsa"]) {
  const r = await engine.evaluate(
    { method: "GET", path, query: {}, headers: { host: "pantry.example", "user-agent": "curl/8.4.0" }, ip: "203.0.113.52" },
    { blockRequiresProof: true, unprovenBlockFallback: "rate-limit" },
  );
  console.log(`${path.padEnd(18)} total ${String(r.totalScore).padStart(3)}  ${r.actionId.padEnd(13)} ${r.downgradedFrom ? `(downgraded from ${r.downgradedFrom})` : ""}`);
}
const refused = (await engine.store.list()).filter((hit) => hit.downgradedFrom === "block").length;
console.log("hits recording a refused block:", refused);
```

```
/.env              total  16  decoy-content 
/.git/config       total  32  decoy-content 
/.aws/credentials  total  48  rate-limit    (downgraded from block)
/.ssh/id_rsa       total  64  rate-limit    (downgraded from block)
hits recording a refused block: 2
```

That count is exported as **`hackerpot_downgrades_total`**, and it is the single most
informative number the library exposes. A rising count means scores are reaching the block
threshold on evidence that proves nothing. In front of Pantry, that is the shape of
detectors adding up on real visitors — which is exactly how people get blocked when the guard
is off.

Alert on it. If it climbs after a deploy, you changed a detector or a threshold; if it climbs
on its own, your traffic changed. Either way the guard is the only reason nobody has been
wrongly blocked yet. [Lesson 12](12-operating-it.md) wires it up.
</details>

## What you learned

- A block refuses every later request from an address, so in front of an app it needs proof
- The guard runs after the policy, in the engine, and cannot be forgotten in a policy
- A refused block becomes the fallback for that one request, and says so in `downgradedFrom`
- It is on in every front end that sits in front of real users, and off standalone
- The fallback cannot be `block`, and `hackerpot_downgrades_total` is the number to watch

## Where to read more

- [The proof guard](../concepts/the-guard.md) — where it is on, what counts as proof
- [Design decisions](../design/decisions.md#blocks-in-middleware-need-proof) — the trade, recorded
- [Metrics](../operations/metrics.md) — the downgrade counter and the alert to build on it

Next: [The detectors](05-detectors.md) — where the evidence comes from.
