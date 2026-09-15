# The traffic audit

Noticing that traffic changed shape, and spotting a probe campaign as it starts.

← [Documentation](../index.md) · [Operations](index.md)

---

## Why this exists

[Counters](metrics.md) say what is happening. They do not say it is *unusual*, and an attack is
an event, not a level: a scanner sweeps, a flood starts, a wave of probes for yesterday's CVE
arrives. The number that matters is not "30% of requests are flagged" but "30% now, 3% for the
hour before".

So the audit keeps a short **window** (default 5 minutes) and the **baseline** that precedes it
(default 1 hour), compares them on a schedule, and raises an anomaly when a check clears its bar.

```toml
[audit]
enabled = true
window_seconds = 300
baseline_seconds = 3600     # must be at least window_seconds
interval_seconds = 60
min_samples = 50
cooldown_seconds = 900
campaign_min_ips = 10       # 0 turns the campaign check off
```

It is **on by default**. The service logs each anomaly as `kind: "anomaly"` and sends it to
every webhook without `anomalies = false`.

```json
{"ts":"…","kind":"anomaly","id":"flagged-share-spike","severity":"critical","summary":"Detectors flagged 64.2% of requests, against 2.1% in the baseline (30.6x).","value":0.642,"baseline":0.021}
```

**The baseline ends where the window begins.** A baseline containing the window would be partly
made of the spike, and a large enough spike would raise its own bar.

## The checks

| Check | Fires when | Severity |
| --- | --- | --- |
| `flagged-share-spike` | at least 25% of requests are flagged, and at least twice the baseline share (or the baseline had none) | critical at 60% |
| `traffic-spike` | the request rate is at least 3× the baseline and at least 10 a minute | critical at 10× |
| `block-spike` | at least 10 blocks, 5% of traffic, and 3× the baseline share | warning |
| `downgrade-spike` | the proof guard refused at least 10 blocks, 5% of traffic, 3× the baseline | warning |
| `detector-failures` | detectors threw or timed out on at least 1% of requests (and at least 5 times) | critical at 10% |
| `probe-campaign` | `campaign_min_ips` different addresses started probing, inside one window, a path nothing probed before | critical at 3× the minimum |

### `block-spike` and `downgrade-spike` are about you

`block-spike` says to check that everything blocked is an attacker. `downgrade-spike` says
scores are reaching the block threshold without proof: that is about your detectors and
thresholds, not about the traffic, and it is how real visitors end up blocked. Read which
detectors are adding up.

### `probe-campaign`

A path many unrelated sources start probing at once is what a freshly published vulnerability
looks like from inside a honeypot: everybody is running the same new list. One source running
one probe looks like nothing; the union is the signal.

- Only **flagged** requests count, so a page launch many people visit is not a campaign.
- "New" means first probed inside the window; a path probed all day is background.
- The cooldown is per path, so two campaigns in an hour are two anomalies.
- The anomaly's `details.path` is the path, which is attacker-chosen: the Slack and Discord
  renderings escape it.

## Floors and cooldowns

**No check speaks until the window holds `min_samples` requests.** A quiet site at 3am produces
"800% more probes" from four requests, and an alert that cries wolf at 3am gets muted, which is
worse than not having one. Every check also has an absolute floor beside its ratio.

**Each check is then silent for `cooldown_seconds`.** A spike lasting an hour is one event, not
sixty.

## Cost

A few integer increments per request, into a fixed ring of time buckets (at most 512), and at most
2,000 probed paths with 256 addresses each for the campaign check. The audit counts each request
once, on the pass that decides it. The comparison runs on a timer that never keeps the process
alive, never in the request path.

## In code

```ts
import { HoneypotEngine, ManagementServer, TrafficAudit } from "@osqd/hackerpot";

const audit = new TrafficAudit({ windowMs: 300_000, baselineMs: 3_600_000 });
const engine = new HoneypotEngine({ audit });
audit.start(60_000, (anomaly) => management.announce(anomaly));
```

| Option | Default |
| --- | --- |
| `windowMs` | `300000` |
| `baselineMs` | `3600000` |
| `minSamples` | `50` |
| `cooldownMs` | `900000` |
| `campaignMinIps` | `10` |
| `checks` | replaces `DEFAULT_AUDIT_CHECKS` |
| `extraChecks` | appended to them |

`audit.evaluate(now?)` runs the checks now and returns anomalies, which is what a health endpoint
or a test with a fixed clock wants. `audit.summary(now?)` returns the window and baseline
counters. `audit.stop()` clears the timer.

### Your own checks

```ts
const audit = new TrafficAudit({
  extraChecks: [{
    id: "sustained-flagging",
    description: "A steady share of flagged traffic, whatever the baseline",
    evaluate: ({ window }) =>
      window.flaggedShare > 0.5
        ? { id: "sustained-flagging", severity: "warning", metric: "flagged share", value: window.flaggedShare, baseline: 0,
            summary: `Half of all traffic is flagged (${(window.flaggedShare * 100).toFixed(0)}%).` }
        : undefined,
  }],
});
```

Each window carries `requests`, `flagged`, `blocks`, `downgrades`, `failures`, `rate` (per
minute) and `flaggedShare`. A check that throws is skipped, never fatal.

Changing `[audit]` needs a restart: its windows and timer are built at startup.

## Related

- [Metrics](metrics.md) — the counters
- [Webhooks](webhooks.md) — where anomalies are delivered
- [The proof guard](../concepts/the-guard.md) — what `downgrade-spike` is about
