# Responses

How a detection becomes a reply, and why the two are kept apart.

← [Documentation](../index.md)

---

A detector says what a request is. A **response action** decides what the attacker gets back. The
**policy** connects them: given every detection and the address's cumulative score, it returns one
action id.

```
detections + totalScore  ──►  policy  ──►  "tarpit"  ──►  tarpitAction.execute(ctx)
```

Keeping them apart is what lets you add a detector without touching responses, and change the whole
retaliation strategy without touching detection.

## What a response can be for

| Goal | Actions |
| --- | --- |
| **Reveal nothing** | `not-found`, `rate-limit` |
| **Keep them engaged** (probing appears to succeed) | `decoy-content`, `fake-success`, `fake-data`, `redirect` |
| **Waste their time** | `tarpit`, `drip-feed` |
| **Waste their resources** | `large-payload`, `gzip-bomb` |
| **Break their tooling** | `chaos` |
| **Stop serving them** | `block` |

Everything here acts on the connection the attacker opened, and nothing else. hackerpot never reaches
out to an attacker's infrastructure. See [the threat model](../concepts/threat-model.md#out-of-scope).

## The default wiring

`defaultResponseActions()` registers all twelve, and `defaultResponsePolicy()` chooses between
`block`, a detector's `respondWith`, `tarpit` and `not-found` by score. So out of the box an attacker
climbs a ladder: quiet 404s and convincing fakes, then multi-second tarpits, then a block. See
[scoring](../concepts/scoring.md#the-escalation-ladder).

`fake-success`, `fake-data`, `gzip-bomb`, `chaos` and `rate-limit` are registered but **never chosen by
the default policy**. A decoy's `respondWith`, a detector's `respond_with`, or a policy of your own has
to select them.

In middleware mode, `block` passes through [the proof guard](../concepts/the-guard.md) first.

## Configuring

```ts
import { HoneypotEngine, blockAction, defaultResponseActions, tarpitAction } from "@osqd/hackerpot";

new HoneypotEngine({ responseActions: [...defaultResponseActions().filter((a) => a.id !== "tarpit" && a.id !== "block"),
  tarpitAction({ delayMs: [3000, 12000] }), blockAction({ durationMs: 3_600_000 })] });   // replace some
new HoneypotEngine({ extraResponseActions: [teapotAction()] });                         // add one
```

`responseActions` replaces the registry; `extraResponseActions` appends to the defaults. Actions are
keyed by id, so a later action with the same id replaces an earlier one.

```toml
[responses.tarpit]
delay_ms = [3000, 12000]

[responses.chaos]
enabled = false
```

**Disabling an action removes it from the registry.** Make sure nothing still names it through
`respond_with`, a decoy, or your policy. A request routed to a missing action falls back to
`not-found`.

## Exercise them before traffic does

A config can validate and still produce an action that breaks once a request is routed to it.
`hackerpot check` serves every enabled action once over a loopback socket, with a throwaway
blocklist:

```bash
npx hackerpot check --config ./hackerpot.toml
```

```
ok     decoy-content (200)
ok     not-found (404)
ok     redirect (302)
ok     block (403)
held   tarpit
held   drip-feed (200)
ok     large-payload (200)
…
all 12 response actions answered
```

`held` means still delaying or streaming when the check stopped waiting, which is the job of
`tarpit`, `drip-feed` and `large-payload`. A deliberate 5xx from `chaos` is not a failure. It exits 1
if any action failed. For custom actions: `checkResponseActions(actions, { budgetMs })`.

## Related

- [Response actions](actions.md) — every action and option
- [Writing a policy](policy.md) — replacing the ladder
- [Writing a response](writing-a-response.md)
