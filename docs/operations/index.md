# Operations

What to watch, and where each signal goes.

← [Documentation](../index.md)

---

A honeypot that nobody reads is a log file. This section is about getting what hackerpot sees
to the people and systems that act on it, without that path becoming something an attacker can
exploit.

## Where incidents go

```
                                 ┌──► store ──► management API (REST) ──► your tools, the dashboard
                                 │         └──► /metrics ──────────────► Prometheus
  engine / protocol honeypots ───┤
                                 ├──► onHit / service log ─────────────► your log pipeline
                                 ├──► live feed (WebSocket, SSE) ──────► dashboard, your consumers
                                 ├──► webhooks ────────────────────────► your endpoint, Slack, Discord
                                 └──► syslog ──────────────────────────► your SIEM
```

| Page | For |
| --- | --- |
| [The dashboard](dashboard.md) | a person watching: feed, statistics, sessions, actors, indicators |
| [Embedding it](embedding.md) | the dashboard inside an admin page you already have |
| [Management API](management-api.md) | programs reading incidents: REST and a live WebSocket |
| [Webhooks](webhooks.md) | pushing incidents to an endpoint, signed, deduplicated, throttled |
| [Alert sinks](alert-sinks.md) | Slack, Discord, and syslog or CEF for a SIEM |
| [Metrics](metrics.md) | Prometheus counters and the two series worth alerting on |
| [The traffic audit](audit.md) | anomalies: when traffic changes shape, and probe campaigns |
| [Stores](stores.md) | where incidents and scores live, and how long |
| [Threat intel](threat-intel.md) | consuming other honeypots' indicator feeds |
| [Firewall enforcement](firewall.md) | pushing blocks out to iptables, nftables or a WAF |
| [Runtime changes](runtime-changes.md) | changing configuration without a restart |

## What to alert on

Most of what hackerpot records is not worth waking anyone for: the internet probes every
address constantly. Three things are:

1. **A replayed honeytoken or a sprung trap.** Somebody read bait and used it. Route
   `min_score` high on a [webhook](webhooks.md), or match `detectorId` in `onHit`.
2. **`hackerpot_downgrades_total` rising** (or the audit's `downgrade-spike`). Scores are
   reaching the block threshold without proof: in middleware mode, the shape of detectors adding
   up on real visitors. See [metrics](metrics.md).
3. **`hackerpot_detector_failures_total` rising** (or `detector-failures`). Detection is
   degraded, usually because of a resolver or a custom detector.

And one worth a look during working hours: the audit's **`probe-campaign`**, many unrelated
addresses starting to probe a path nothing probed before, which is what a newly published
exploit looks like from inside a honeypot.

## Keep the operator surfaces private

Everything in this section except syslog and webhooks is a listener, and every one of them
shows captured attacker data: addresses, request bodies, credentials an attacker tried, and
which detector fired on what. For an attacker probing your deployment that is a map of what to
avoid next.

- The **management API** binds `127.0.0.1` by default and requires an API key on everything
  but `/health`.
- The **dashboard** is a separate listener, binds `127.0.0.1` by default, and refuses to start
  on any other address without authentication.
- **Never** put either on the attacker-facing interface. A typical shape: the honeypot faces the
  internet behind [nginx](../integration/nginx.md), and your services read `:9500` over a
  private network.

## The service log

The standalone service writes one JSON object per event to stdout (`[logging] format = "text"`
for key=value lines, with control characters escaped). The kinds:

| Kind | When |
| --- | --- |
| `startup` | once, with every listener, the store, detectors, responses and policy |
| `hit` | every incident; headers and body only with `include_headers` / `include_body` |
| `shadow` | a [shadowed detector](../detection/shadow-mode.md) fired |
| `anomaly` | the [audit](audit.md) raised one |
| `port-touch`, `port-scan` | the [sentinel](../protocols/port-scan.md) |
| `intel`, `crawler-ranges` | a feed or range refresh |
| `reload`, `reload-requires-restart`, `reload-failed` | [SIGHUP](runtime-changes.md) |
| `warning` | a weak service token, an enforced intel feed |
| `engine-error`, `store-error`, `enforce-error`, `management-error`, `syslog-error`, `protocol-error`, `dashboard-error`, `intel-error`, `crawler-ranges-error` | a failure the service absorbed |
| `shutdown` | a signal |

A swallowed failure is the invisible kind: a store that rejects every write leaves the honeypot
looking healthy while recording nothing. The service logs every one, and that is deliberately
not configurable.

## Related

- [Threat model](../concepts/threat-model.md) — why each surface is bounded the way it is
- [Configuration](../reference/configuration.md) — `[management]`, `[dashboard]`, `[syslog]`, `[audit]`
