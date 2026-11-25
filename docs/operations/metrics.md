# Metrics

The Prometheus exposition, and the two series worth alerting on.

← [Documentation](../index.md) · [Operations](index.md)

---

`GET /metrics` on the [management API](management-api.md), authenticated like every endpoint but
`/health`:

```yaml
scrape_configs:
  - job_name: hackerpot
    authorization: { credentials: "a-long-random-string" }
    static_configs: [{ targets: ["127.0.0.1:9500"] }]
```

**Scrape it from somewhere only your scraper can reach.** The per-detector series describe how
detection behaves, which is exactly what someone tuning a scanner would like to read.

## A listener for metrics only

Scraping through the management API means standing up a REST API over every captured request, a
live feed, and an API key the scraper has to hold. A Prometheus server needs none of that.
`[metrics]` serves the same exposition at one path and nothing else, so it can sit on a network the
management API never should:

```toml
[metrics]
enabled = true
host = "0.0.0.0"                     # the honeypot's own network, not the public one
port = 9502
allowed_clients = ["10.0.0.0/24"]    # your Prometheus; anyone else is disconnected unanswered
```

```yaml
scrape_configs:
  - job_name: hackerpot
    static_configs: [{ targets: ["honeypot:9502"] }]
```

It is counted from published incidents like the management API's own `/metrics`, so both report the
same numbers. Any path but `path` is a 404, and any method but `GET` and `HEAD` a 405. In the
library, `new MetricsListener({ broker, engineCounters: () => engine.counters(), gauges })`.

## What is exposed

| Series | Type | |
| --- | --- | --- |
| `hackerpot_incidents_total` | counter | incidents recorded |
| `hackerpot_incidents_by_detector{detector}` | counter | incidents in which each detector fired |
| `hackerpot_incidents_by_response{response}` | counter | incidents by the response served |
| `hackerpot_unique_ips` | gauge | distinct source addresses seen (at most 100,000 remembered) |
| `hackerpot_top_offender_score` | gauge | the highest cumulative score of any one address |
| `hackerpot_downgrades_total` | counter | blocks the [proof guard](../concepts/the-guard.md) refused |
| `hackerpot_detector_failures_total{detector}` | counter | detector runs that threw or timed out |
| `hackerpot_proven_total` | counter | incidents resting on at least one detection that is [proof](../concepts/the-guard.md) |
| `hackerpot_shadow_firings_total{detector}` | counter | findings from [shadowed](../detection/shadow-mode.md) detectors — present only when something is shadowed, and counted apart from `incidents_by_detector` because a shadowed finding decided nothing |
| `hackerpot_score` | histogram | the address's cumulative score when each incident was recorded, bucketed at 5, 10, 15, 20, 30, 40, 60 and 100 — around the tarpit and block lines, where "how close does traffic run to a block?" is answered |
| `hackerpot_refused_blocked_total` | counter | requests refused because their address was already blocked. A refusal runs no detector and records no incident, so this is the only place a block's effect shows; the service also logs a `refused` line, at most once a minute per address |
| `hackerpot_bypassed_total{reason}` | counter | requests exempted from detection — `allowlist`, `service-token` or `ignored-path` (`ignorePaths`) — counted once, at the front end that decided it. Every reason is present from the first scrape |
| `hackerpot_evaluation_duration_ms` | histogram | time spent evaluating a request, per evaluation (a request whose body is inspected is evaluated twice), bucketed at bothandlerjs's own bounds from 0.05 to 100 ms |
| `hackerpot_stream_dropped_total` | counter | live-feed incidents dropped for viewers that stopped reading |
| `hackerpot_active_blocks` | gauge | standalone: current blocklist size |
| `hackerpot_tracked_ips` | gauge | standalone: addresses with an activity window |

Any gauge you pass as `metrics: () => ({ name: value })` to `ManagementServer` is emitted as
`hackerpot_<name>`. `hackerpot_detector_failures_total` needs `detectorFailures: () =>
engine.detectorFailures`; the standalone service wires both.

## Counted in memory, not read from the store

The counters are incremented once per incident as it is published, so a scrape never reads the
store. That matters twice. A scrape used to read the whole retained hit log every fifteen seconds.
And the "counters" used to fall whenever retention trimmed old hits, which Prometheus reads as a
counter reset, so `rate()` and every alert built on it were wrong.

Now they only rise until the process restarts, which Prometheus handles as an ordinary reset.
Label values are escaped (a CR or LF would end the sample and forge another).

`renderMetrics(store, extra)` still renders from a store, for callers without a management server;
its numbers fall with retention.

## The two worth alerting on

**`hackerpot_downgrades_total`** — blocks the proof guard refused. A rising count means scores are
reaching the block threshold on evidence that proves nothing. In middleware mode that is the shape
of detectors adding up on real visitors, which is precisely how people get blocked when the guard
is off. It is the guard's own report card.

```yaml
- alert: HackerpotBlocksWithoutProof
  expr: increase(hackerpot_downgrades_total[15m]) > 20
```

**`hackerpot_detector_failures_total`** — detection is degraded. The cause is usually a resolver
(`crawler-verification`) or a custom detector, not the traffic.

```yaml
- alert: HackerpotDetectorFailing
  expr: sum by (detector) (increase(hackerpot_detector_failures_total[10m])) > 0
```

The [traffic audit](audit.md) raises both as anomalies too, with a baseline and a cooldown, which is
often the better alert: a counter cannot tell you a number is *unusual*.

## Related

- [The audit](audit.md) — anomalies rather than counts
- [Management API](management-api.md) — the other place `/metrics` lives
- [Edge bans](edge-bans.md) — turning `verdict` lines into firewall bans
- [The proof guard](../concepts/the-guard.md) — what `downgrades_total` counts
