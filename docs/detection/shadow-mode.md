# Shadow mode

Run a detector on every request and let it decide nothing. Then read what it would have done.

← [Documentation](../index.md) · [Detection](index.md)

---

## The problem it solves

Every detector ships with thresholds somebody chose against somebody else's traffic. In
standalone mode that rarely matters. In front of a real application it is the whole
question: will this new detector, or this lowered threshold, start tarpitting customers?

Shadow mode is how to find out without anybody being turned away while you do.

```toml
[engine]
shadow_detectors = ["target-integrity", "client-anomaly"]
```

```ts
const engine = new HoneypotEngine({
  shadowDetectors: ["target-integrity"],
  onShadow: (event) => console.info("[shadow]", event.ip, event.path, event.detections.map((d) => d.detectorId)),
});
```

Those detectors now run on every request exactly as they otherwise would. What they find is
reported. And they decided nothing.

## What "decided nothing" means

A shadowed detection:

| | |
| --- | --- |
| adds no score | not to the request, not to the address's total |
| chooses no response | the policy never sees it |
| triggers no body read | a shadowed body detector firing on the first pass does not start a second |
| records no hit of its own | a request only shadowed detectors fired on leaves no incident |
| counts as no proof | a shadowed `certain` detection cannot make a block stick |

It is not a weight of zero. It is kept out of the decision entirely, so that a shadowed
detector emitting proof cannot block anyone while its score is nominally ignored.

## Where the findings go

- **`onShadow(event)`**, once per request a shadowed detector fired on:
  `{ timestamp, ip, method, path, detections, alsoHit }`. `alsoHit` says whether live
  detectors fired too, so the request was recorded anyway.
- **`shadowDetections`** on any hit that live detectors caused, so the dashboard and the
  management API show them next to the evidence that did decide.
- **The service log**, as `kind: "shadow"` lines:

```json
{"ts":"2026-09-15T10:02:11.417Z","kind":"shadow","ip":"198.51.100.23","method":"GET","path":"/assets/app.js","detectors":["target-integrity"],"alsoHit":false}
```

Lines with `alsoHit: false` are the interesting ones: requests the detector would have
flagged that nothing else did. Those are the requests it would add to your incidents, and
the ones to read.

`hackerpot detectors` marks shadowed detectors in its third column, so you can confirm the
setting took before any traffic arrives.

## How to use it

1. Add the detector (or its retuned settings) and list its id in `shadow_detectors`.
2. Leave it a week, not a day. The traffic that catches a threshold out is the Monday
   morning, the campaign, the release.
3. Read the `alsoHit: false` shadow lines as requests, one at a time, not as a count. If any
   of them is a person, the detector or its threshold is wrong for your site.
4. Adjust and repeat, or take it out of `shadow_detectors` and let it count.

`[engine] shadow_detectors` **reloads on SIGHUP**, so promoting a detector needs no restart.

This complements [log replay](../testing/replay.md): a replay tells you what a detector
would have done to yesterday; shadow mode tells you what it does to today, including the
headers and bodies an access log never recorded.

## The honest limits

**A shadowed detector still costs what it costs.** It runs, it is timed against
`detector_timeout_ms`, and a throw or timeout is reported and counted like any other failure.
Shadowing is about influence, not about cost.

**A shadowed body detector only sees bodies something else caused to be read.** In
middleware mode the second pass happens only when a live detector fires on the first, so a
shadowed `payload-injection` sees only the bodies of requests already flagged.

**An unknown id is a startup error** in TOML, naming the valid ids, because a typo here would
otherwise shadow nothing, silently. In code, an unknown id simply matches nothing.

## Related

- [The detectors](detectors.md) — what each one reads
- [Replaying your logs](../testing/replay.md) — the same question, asked of the past
- [Runtime changes](../operations/runtime-changes.md) — promoting without a restart
