# Lesson 3 — Scores and responses

**Goal:** watch one address climb from a quiet 404 to a block, and know every response it
can draw on the way.

← [Course](index.md) · Prev: [Proof and suspicion](02-proof-and-suspicion.md) · Next: [The guard](04-the-guard.md)

---

## Three numbers

| Number | Where | Means |
| --- | --- | --- |
| a detection's `score` | each detection | how much this one finding is worth |
| the request's `score` | the result, and the incident | what this request added: its detections, one per family |
| `totalScore` | the result, and the incident | this **address's** cumulative score after the request |

A detector says *"this is a `.env` probe, score 10."* It does not decide what happens next.
A **policy** does, looking at everything that fired and the address's `totalScore`, and it
returns the id of one **response action**. Keeping those apart is what lets you add a
detector without touching responses, and change the whole retaliation strategy without
touching detection.

## Do this

One address, walking Pantry the way a scanner does.

`pantry/lesson-03.mjs`:

```js
import { HoneypotEngine } from "@osqd/hackerpot";

const engine = new HoneypotEngine();
const headers = { host: "pantry.example", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/127.0", accept: "*/*", "accept-language": "en", "accept-encoding": "gzip" };

const walk = [
  ["/.env", {}],
  ["/wp-login.php", {}],
  ["/phpinfo.php", {}],
  ["/recipes", { id: "1' OR '1'='1" }],
  ["/.git/config", {}],
  ["/recipes/1", {}],
];

console.log("request                    score  total  response");
for (const [path, query] of walk) {
  const r = await engine.evaluate({ method: "GET", path, query, headers, ip: "203.0.113.40" });
  const label = path + (Object.keys(query).length ? "?id=…" : "");
  console.log(`${label.padEnd(26)} ${String(r.score).padStart(5)}  ${String(r.totalScore).padStart(5)}  ${r.actionId || "(passed through)"}`);
}
console.log("blocked now?", await engine.isBlocked("203.0.113.40"));
```

The client claims to be a browser, so `scanner-signature` stays out of it and only the
probes themselves score.

### Checkpoint

```
request                    score  total  response
/.env                         10     10  decoy-content
/wp-login.php                  5     15  decoy-content
/phpinfo.php                   5     20  not-found
/recipes?id=…                 10     30  tarpit
/.git/config                  10     40  block
/recipes/1                     0     40  (passed through)
blocked now? false
```

## Reading the ladder

The default policy is four lines, and every row above is one of them:

```js
// defaultResponsePolicy(blockThreshold = 40, tarpitThreshold = 15)
(ctx) => {
  if (ctx.totalScore >= blockThreshold) return "block";
  if (ctx.detection.respondWith) return ctx.detection.respondWith;
  if (ctx.totalScore >= tarpitThreshold) return "tarpit";
  return "not-found";
};
```

- **`/.env` and `/wp-login.php`** are decoys that ask for `decoy-content`: a fake `.env`, a
  fake WordPress login. Below the block line a decoy's own choice wins, so decoys keep
  serving convincing bait instead of escalating early.
- **`/phpinfo.php`** is a decoy that asks for `not-found`. Its total is 20, past the tarpit
  line, and it still gets a quiet 404, for the same reason.
- **The injection** carries no preference, so the ladder decides, and 30 is past 15:
  `tarpit`, a multi-second wait.
- **`/.git/config`** takes the total to 40, and a persistent attacker is blocked **whatever**
  a detector asked for.
- **`/recipes/1`** is an ordinary page. Nothing fired, so nothing was added, and the total
  stays 40. An address's history does not make its ordinary requests suspicious.

Scores **only go up**, unless the store says otherwise. The Redis store can let a quiet
address's score expire ([lesson 13](13-scaling.md)); the memory store never forgets while
the process runs.

## Deciding is not acting

`blocked now? false` — after the policy chose `block`. That is not a bug.

`evaluate` decides. The response action is what *does* something, and the `block` action is
what writes the address to the blocklist, when a front end runs it on a real response. In a
plain script nothing runs it. From [lesson 10](10-in-front-of-an-app.md) on, the middleware
runs every action for real, and from then on a blocked address is refused with a 403 before
any detector runs — so a blocked attacker costs almost nothing to serve.

## The twelve responses

`pantry/lesson-03b.mjs`:

```js
import { HoneypotEngine } from "@osqd/hackerpot";
console.log([...new HoneypotEngine().actions.keys()].join(" "));
```

### Checkpoint

```
decoy-content not-found redirect block tarpit drip-feed large-payload fake-success fake-data gzip-bomb chaos rate-limit
```

Grouped by what each is for:

| Goal | Actions | What it costs you |
| --- | --- | --- |
| **Reveal nothing** | `not-found`, `rate-limit` | nothing |
| **Keep them engaged** | `decoy-content`, `fake-success`, `fake-data`, `redirect` | nothing, if the fakes are invented |
| **Waste their time** | `tarpit`, `drip-feed` | a connection slot each, capped |
| **Waste their resources** | `large-payload`, `gzip-bomb` | real bandwidth, or a one-off allocation |
| **Break their tooling** | `chaos` | nothing |
| **Stop serving them** | `block` | whatever the address was also doing legitimately |

The time-wasting actions hold a connection on **your** side too, so each has a concurrency
cap and degrades to an immediate answer at capacity. A flood cannot turn retaliation into a
self-inflicted outage.

The default policy chooses only four of these — `block`, `tarpit`, `not-found`, and whatever
a decoy asks for. The others are registered but have to be selected, by a decoy, a
detector's `respondWith`, or a policy of your own ([lesson 14](14-extending.md)).

Everything here acts on the connection the attacker opened, and nothing else. Nothing in
this library reaches out to an attacker's infrastructure.

## `respondWith` reads the top detection only

When several detectors fire, the default policy reads `detections[0]`, the highest-scoring
one, and ignores any lower detection's preference. A low-scored detector whose routing you
rely on can therefore be overruled by whatever co-fires with it. Raise its score, or put the
routing in a policy, which sees every detection.

## Exercise

Pantry wants a tighter ladder: block at 30, tarpit at 10. Before running anything, predict
each row. Then pass `policy: defaultResponsePolicy(30, 10)` to the engine and run the same
walk.

<details>
<summary>Checkpoint</summary>

```js
import { HoneypotEngine, defaultResponsePolicy } from "@osqd/hackerpot";

const engine = new HoneypotEngine({ policy: defaultResponsePolicy(30, 10) });
// …the same walk as above
```

```
request                    score  total  response
/.env                         10     10  decoy-content
/wp-login.php                  5     15  decoy-content
/phpinfo.php                   5     20  not-found
/recipes?id=…                 10     30  block
/.git/config                  10     40  block
/recipes/1                     0     40  (passed through)
blocked now? false
```

The injection is now a block, and the tarpit rung is never reached on this walk at all:
every request below the block line was a decoy with a preference of its own.

The cost of the tighter ladder is the one that matters most in front of Pantry. A lower
block line blocks on **less evidence**, and none of the evidence on this walk is proof. The
next lesson is about what stands between that line and a real visitor.
</details>

## What you learned

- A detector scores; a policy chooses one response by id; an action carries it out
- The default ladder: block past 40, else a decoy's own choice, else tarpit past 15, else 404
- Scores accumulate per address and do not decay unless the store says so
- `evaluate` decides; the `block` action writes the blocklist only when a front end runs it
- Twelve responses, grouped by what they are for and what they cost you

## Where to read more

- [Scores and escalation](../concepts/scoring.md#the-escalation-ladder) — the ladder and thresholds
- [Response actions](../responses/actions.md) — all twelve, every option
- [Writing a policy](../responses/policy.md) — replacing the ladder

Next: [The guard](04-the-guard.md) — what happens when the ladder asks for more than the
evidence supports.
