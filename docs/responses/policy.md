# Writing a policy

The default ladder, `respondWith`, and a policy of your own.

← [Documentation](../index.md) · [Responses](index.md)

---

A **policy** is a function from what fired to one response action id:

```ts
type ResponsePolicy = (ctx: PolicyContext) => string;

interface PolicyContext {
  detection: Detection;      // the highest-scoring detection
  detections: Detection[];   // every detection, highest score first
  ip: string;
  path: string;
  totalScore: number;        // the address's cumulative score, including this request
  tracker: IpTracker;        // its activity window
}
```

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
