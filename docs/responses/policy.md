# Writing a policy

The default ladder, `respondWith`, and a policy of your own.

← [Documentation](../index.md) · [Responses](index.md)

---

A **policy** is a function from what fired to one response action id:

```ts
type ResponsePolicy = (ctx: PolicyContext) => string | ResponseDecision;

interface PolicyContext {
  detection: Detection;      // the highest-scoring detection
  detections: Detection[];   // every detection, highest score first
  ip: string;
  path: string;
  method?: string;
  score?: number;            // what this request scored on its own
  totalScore: number;        // the address's cumulative score, including this request
  tracker: IpTracker;        // its activity window
}

interface ResponseDecision {
  actionId: string;          // the response action to run
  rule: string;              // which rule chose it — recorded on the incident
  reason: string;            // one sentence, shown to an operator
}
```

Returning an id is the short form. Returning a `ResponseDecision` records **why** on the incident, so
the dashboard and the log can say "rule `admin-bruteforce`: password guessing against the admin login"
instead of only "rate-limit". [Rules](#rules) produce decisions for you.

It is called only when at least one detector fired. It must be synchronous, and it should be cheap: it
runs on every flagged request.

## The default

`defaultResponsePolicy(blockThreshold = 40, tarpitThreshold = 15)`:

```ts
(ctx) => {
  if (ctx.totalScore >= blockThreshold) return "block";
  if (ctx.detection.respondWith) return ctx.detection.respondWith;
  if (ctx.totalScore >= tarpitThreshold) return "tarpit";
  return "not-found";
};
```

In TOML that is the whole of `[policy]`:

```toml
[policy]
block_threshold = 40
tarpit_threshold = 15    # must not exceed block_threshold
```

Why this order: a confirmed persistent attacker is blocked **whatever** a detector asked for; below
that, a decoy's own choice wins, so decoys keep serving convincing bait instead of escalating early;
then middling scores are slowed and first touches get a plain 404. See
[scoring](../concepts/scoring.md#the-escalation-ladder) for a worked example.

## `respondWith`

A detection's `respondWith` is how a detector or decoy routes without a policy of its own: set it on a
decoy, a factory (`webShellDetector({ respondWith: "fake-success" })`) or a TOML section
(`respond_with = "fake-success"`).

The default policy reads it from **the top detection only**. When several detectors fire, a
lower-scoring detector's routing is ignored. If you rely on a particular detector's `respondWith`, raise
its score above the detectors that co-fire with it, or write the routing into a policy, which sees every
detection.

## Rules

A policy can also be written as data. Rules are consulted in order, the first that matches decides,
and the one that decided is recorded on the incident:

```ts
import { HoneypotEngine, rulePolicy } from "@osqd/hackerpot";

const policy = rulePolicy([
  { id: "proof", match: { certain: true }, respondWith: "block", reason: "Proof, not suspicion." },
  { id: "bait", match: { detector: ["decoy-path", "sensitive-file"] }, respondWith: "@detector", fallbackAction: "decoy-content" },
  { id: "admin-bruteforce", match: { detector: "credential-bruteforce", path: ["/admin", /wp-login/] }, respondWith: "rate-limit",
    reason: "Password guessing against the admin login: answered like an ordinary rate limit." },
]);

new HoneypotEngine({ policy });
```

A match holds when every field present holds; absent fields constrain nothing, so `match: {}` is a
last-resort rule. The fields are `detector`, `certain`, `minScore`/`maxScore` (this request),
`minTotalScore`/`maxTotalScore` (the address),
[`minConfidence`/`maxConfidence`](../concepts/scoring.md#confidence-how-strong-not-how-much) (how
*strong* the evidence is, rather than how much of it), `path` (a string is a prefix, a RegExp is a
pattern), `method` and `ip` (addresses or CIDR ranges).

Matching on confidence is the way to say "act on strong evidence" rather than "act on the number
40": a pile of forgivable findings cannot reach a `minConfidence` bar the way it can reach a score
threshold, because suspicion alone is capped below certainty. `match` can also be a predicate of your own; one that
throws is treated as a rule that did not match, not as a failed request.

`respondWith: "@detector"` defers to the detection's own `respondWith`, which is how decoys keep
serving their own bait under a rule list. Anything no rule matches falls through to `fallback` —
by default the ladder above — so a handful of rules only overrides what it names.

### Presets

`observe()`, `protectApp()` and `standalone()` are rule lists to start from, read and edit:

| Preset | For | What it does |
| --- | --- | --- |
| `observe` | a first deployment in front of real users | records and scores everything, serves a plain 404 every time; nobody can notice it |
| `protect-app` | in front of a real application | blocks on proof, keeps decoys serving bait, tarpits exploitation attempts and persistent probing, never refuses on a score alone |
| `standalone` | its own address or ports | blocks confirmed attackers and proof, otherwise lets each detector serve its own expensive response |

```ts
import { protectApp, rulePolicy } from "@osqd/hackerpot";

const policy = rulePolicy([
  { id: "partner-api", match: { ip: ["198.51.100.0/24"] }, respondWith: "not-found", reason: "A partner range: recorded, never delayed." },
  ...protectApp(),
]);
```

### In TOML

```toml
[policy]
preset = "protect-app"

[[policy.rules]]
id = "admin-bruteforce"
detector = ["credential-bruteforce"]
path_prefix = ["/admin", "/wp-login.php"]
respond_with = "rate-limit"
reason = "Password guessing against the admin login: answered like an ordinary rate limit."
```

Your rules are consulted first, then the preset's, then the thresholds; a rule sharing an `id` with
one of the preset's replaces it. A `respond_with` naming an action that is unknown or switched off is
a startup error rather than a quiet 404. Every key is listed in
[the configuration reference](../reference/configuration.md#policyrules).

## A policy of your own

```ts
import { HoneypotEngine, defaultResponsePolicy, type ResponsePolicy } from "@osqd/hackerpot";

const ladder = defaultResponsePolicy(40, 15);

const policy: ResponsePolicy = (ctx) => {
  const ids = new Set(ctx.detections.map((d) => d.detectorId));

  if (ids.has("honeytoken") || ids.has("trap")) return "block";          // proof: stop serving at once
  const chosen = ladder(ctx);
  if (chosen === "block") return "block";                                 // keep the default's block

  if (ids.has("web-shell")) return "fake-success";                        // let them think the shell landed
  if (ids.has("ssrf-probe")) return "gzip-bomb";
  if (ids.has("credential-bruteforce")) return "rate-limit";              // looks ordinary; reveals nothing
  if (ctx.tracker.countIn(60_000) > 100) return "drip-feed";              // a flood: pin its connections
  return chosen;
};

new HoneypotEngine({ policy });
```

Wrapping the default keeps its block rung and its `respondWith` handling, and adds routing on top. The
demo (`npm run demo`) runs a policy shaped like this, which is how the dashboard shows the showier
responses working.

Rules worth keeping:

- **Return an id that is registered.** A missing action falls back to `not-found`. If you disable an
  action in TOML, make sure your policy no longer names it.
- **Do not reach for `block` on suspicion.** In middleware mode the [proof guard](../concepts/the-guard.md)
  will downgrade it anyway and count a refusal; in standalone mode nothing will. Branch on proof
  (`ctx.detections.some((d) => d.certain)`) if you want a policy that behaves the same in both.
- **Keep it pure.** No awaits, no I/O, no mutation of the tracker. A slow or throwing policy is on the
  request path.

## Replacing the thresholds at runtime

`engine.reconfigure({ policy })` swaps the policy for the next request, and `[policy]` reloads on
SIGHUP. See [runtime changes](../operations/runtime-changes.md).

## Related

- [Response actions](actions.md) — what a policy can return
- [Scores and escalation](../concepts/scoring.md) — what `totalScore` is
- [The proof guard](../concepts/the-guard.md) — what happens to `block` after the policy
