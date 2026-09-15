# Lesson 14 — Extending it

**Goal:** add a detector, a response action, a store and a policy of your own — and meet the
certainty test from the other side.

← [Course](index.md) · Prev: [Scaling and changing it live](13-scaling.md) · Next: [Proving it](15-proving-it.md)

---

## Every layer is an interface

A detector, a response action and a store are each a small object, and a policy is a
function. There is no registration step and nothing to fork. Pantry has a problem nothing
shipped knows about: its recipe API documents at most fifty recipes a page, and scrapers
ask for five thousand.

## Do this

All four pieces in one file.

`pantry/lesson-14.mjs`:

```js
import { HoneypotEngine, checkResponseActions, defaultResponsePolicy } from "@osqd/hackerpot";

// A detector: Pantry's API documents at most 50 recipes a page.
function oversizedPageDetector({ max = 50, score = 5 } = {}) {
  return {
    id: "oversized-page",
    description: "Asks the recipe API for more per page than it documents",
    inspect(ctx) {
      const raw = ctx.query.per_page;
      if (raw === undefined || !/^\d{1,9}$/.test(raw)) return undefined;
      const perPage = Number(raw);
      if (perPage <= max) return undefined;
      return {
        detectorId: "oversized-page",
        reason: `Asked for ${perPage} recipes per page; the API documents at most ${max}`,
        score,              // suspicion: a careless integration does this too
        metadata: { perPage },
      };
    },
  };
}

// A response: an empty page, which looks like the end of the data.
function emptyRecipesAction() {
  return {
    id: "empty-recipes",
    description: "An empty, well-formed recipe page",
    execute(ctx) {
      ctx.res.statusCode = 200;
      ctx.res.setHeader("content-type", "application/json");
      ctx.res.end(JSON.stringify({ recipes: [], next: null }));
    },
  };
}

// A store: whatever Pantry already runs. Here, a Map.
class MapStore {
  hits = [];
  scores = new Map();
  record(hit) {
    this.hits.push(hit);
    this.scores.set(hit.ip, (this.scores.get(hit.ip) ?? 0) + hit.score);
  }
  list() { return this.hits.slice(-1000); }
  scoreFor(ip) { return this.scores.get(ip) ?? 0; }
}

// A policy: the default ladder, plus Pantry's routing.
const ladder = defaultResponsePolicy(40, 15);
const policy = (ctx) => {
  const chosen = ladder(ctx);
  if (chosen === "block") return chosen;
  if (ctx.detections.some((d) => d.detectorId === "oversized-page")) return "empty-recipes";
  return chosen;
};

const store = new MapStore();
const engine = new HoneypotEngine({
  store,
  policy,
  extraDetectors: [oversizedPageDetector()],
  extraResponseActions: [emptyRecipesAction()],
});

const browser = { host: "pantry.example", "user-agent": "Mozilla/5.0 Chrome/126.0.0.0", accept: "application/json", "accept-language": "en", "accept-encoding": "gzip" };
for (const perPage of ["20", "5000"]) {
  const r = await engine.evaluate({ method: "GET", path: "/api/recipes", query: { per_page: perPage }, headers: browser, ip: "203.0.113.150" });
  console.log(`per_page=${perPage.padEnd(5)} ${r.detections.map((d) => `${d.detectorId} +${d.score}: ${d.reason}`).join("; ") || "nothing fired"}${r.actionId ? ` -> ${r.actionId}` : ""}`);
}
console.log("stored", store.hits.length, "score", store.scoreFor("203.0.113.150"));
console.log(await checkResponseActions([emptyRecipesAction()]));
```

### Checkpoint

```
per_page=20    nothing fired
per_page=5000  oversized-page +5: Asked for 5000 recipes per page; the API documents at most 50 -> empty-recipes
stored 1 score 5
[ { id: 'empty-recipes', outcome: 'ok', status: 200 } ]
```

The scraper asked for everything and was told there was nothing: a well-formed, empty page
that looks like the end of the data.

## The detector

A detector returns a **detection**, never a decision. It has no idea what the policy will do
with what it finds, and that separation is what keeps the proof model intact.

```ts
interface Detector {
  id: string;                    // stable: config, metrics, shadow_detectors, routing
  description?: string;          // shown by `hackerpot detectors`
  needsBody?: boolean;           // take part in the body-reading second pass
  inspect(ctx): Detection | undefined | Promise<Detection | undefined>;
}
```

The rules every built-in detector keeps:

- **Never throw.** The engine isolates a throwing detector, but one that throws on crafted
  input has handed an attacker a way to switch it off. Wrap every parse.
- **Bound what you scan.** Everything in the context is attacker-controlled. Note the
  `^\d{1,9}$` above: the value is checked for shape and length before it becomes a number.
- **Do not reason from absence on partial facts.** If a detector fires because something is
  *missing*, return nothing when `ctx.partialHeaders` is true: a header missing from a log
  line was never recorded ([lesson 15](15-proving-it.md)).
- **Report, do not record.** Never write to `ctx.tracker`; the engine records each request
  exactly once.
- **Stay synchronous if you can.** An async `inspect` runs under a deadline, and a slow one is
  skipped for that request.

## The certainty test, from the inside

Look at the comment on `score`: suspicion. Try the sentence from
[lesson 2](02-proof-and-suspicion.md) — "no legitimate client could ask for more recipes per
page than the API documents". A developer who never read the documentation does exactly
that, on the first day of an integration. So the detection is not `certain`, and adding
`certain: true` would let it block that developer the moment their score crossed the line.

If the sentence needs "usually", "almost never" or "unless", the detection is suspicion.
Nearly every attempt to mark something certain fails at this step, which is the point.

## The response

```ts
interface ResponseAction {
  id: string;
  description?: string;
  execute(ctx: ResponseContext): Promise<void> | void;   // ctx.res is a Node ServerResponse
}
```

- **Never let a side effect fail the response.** Report it through `ctx.onError` and still
  answer. A 500 from a honeypot is a tell: every other response is plausible.
- **Bound what you hold.** An action that delays or streams holds a connection on your side
  too. Cap active executions and degrade to an immediate answer past the cap.
- **Release on disconnect**, and respect backpressure.
- **Serve nothing real.** A fake must be invented.

`checkResponseActions` serves each action once over a loopback socket with a throwaway
blocklist, and reports `ok`, `held` (still delaying or streaming at the budget) or `failed`.
Put it in your tests; `hackerpot check` runs the same thing over a configuration's actions.

## The store

```ts
interface HitStore {
  record(hit): void | Promise<void>;
  list(): HoneypotHit[] | Promise<HoneypotHit[]>;    // bounded, oldest first
  scoreFor(ip): number | Promise<number>;
  query?(query): HoneypotHit[] | Promise<HoneypotHit[]>;   // optional, a performance interface
}
```

`scoreFor` is on the request path: the engine reads it for every flagged request. Keep it
fast and give it a deadline — a promise that never settles never reaches the code that would
have degraded it to 0. Keep `list()` bounded, because the aggregate endpoints read all of it.

## The policy

Wrapping `defaultResponsePolicy` keeps its block rung and its decoy handling and adds routing
on top. Three rules:

- **Return an id that is registered.** A missing action falls back to `not-found`.
- **Keep it pure.** No awaits, no I/O. It runs on every flagged request.
- **The guard still applies.** A policy that returns `block` in front of Pantry without proof
  gets the fallback, exactly as in [lesson 4](04-the-guard.md).

## Exercise

Pantry decides that proof should block **at once**, rather than waiting for the ladder's 40.
Write the policy, and run it against three requests: a `curl` client reading `/.env`, the
same client replaying the planted key, and `sqlmap`'s first probe. Is the third result what
Pantry wants?

<details>
<summary>Checkpoint</summary>

```js
import { HoneypotEngine, defaultResponsePolicy, honeytokenDetector } from "@osqd/hackerpot";

const ladder = defaultResponsePolicy(40, 15);
const policy = (ctx) => (ctx.detections.some((d) => d.certain === true) ? "block" : ladder(ctx));

const engine = new HoneypotEngine({ policy, extraDetectors: [honeytokenDetector({ tokens: ["AKIA_PANTRY_7Q2XK4"] })] });

const steps = [
  ["curl reads /.env", "203.0.113.160", { "user-agent": "curl/8.4.0" }, "/.env"],
  ["curl replays the key", "203.0.113.160", { "user-agent": "curl/8.4.0", "x-api-key": "AKIA_PANTRY_7Q2XK4" }, "/api/recipes"],
  ["sqlmap's first probe", "203.0.113.161", { "user-agent": "sqlmap/1.7.2#stable" }, "/.env"],
];
for (const [label, ip, headers, path] of steps) {
  const r = await engine.evaluate({ method: "GET", path, query: {}, headers: { host: "pantry.example", ...headers }, ip }, { blockRequiresProof: true });
  console.log(`${label.padEnd(22)} total ${String(r.totalScore).padStart(2)} -> ${r.actionId}`);
}
```

```
curl reads /.env       total 16 -> decoy-content
curl replays the key   total 37 -> block
sqlmap's first probe   total 16 -> block
```

The replayed key now blocks at 37, which is what lesson 7 wanted.

**The `sqlmap` line is a decision, not an accident.** Its first request is blocked, before it
has seen a single fake file. That is defensible — a self-declared attack tool is proof — but it
also means the decoys never engage it, and Pantry learns less about what it was looking for.
A policy that blocks only on *planted* proof keeps the decoys working:
`ctx.detections.some((d) => d.detectorId === "honeytoken" || d.detectorId === "trap")`.

Branching on proof has one more property worth having: the policy now behaves the same in
front of Pantry and standalone, because it never asks the guard for anything it would refuse.
</details>

## What you learned

- A detector returns evidence, never a decision, and must never throw on crafted input
- If you cannot write why no legitimate client could produce it, it is not `certain`
- A response must never fail, must bound what it holds, and must serve nothing real
- A store's `scoreFor` is on the request path and needs a deadline
- A policy wraps the ladder, returns registered ids, stays pure — and the guard still applies

## Where to read more

- [Writing a detector](../detection/writing-a-detector.md) — the contract and the tests it must pass
- [Writing a response](../responses/writing-a-response.md) · [Writing a policy](../responses/policy.md)
- [Stores](../operations/stores.md#a-store-of-your-own)

Next: [Proving it](15-proving-it.md).
