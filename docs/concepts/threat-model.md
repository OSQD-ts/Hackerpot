# Threat model

What hackerpot defends against, what it does not, and what it costs to be wrong.

← [Documentation](../index.md)

---

The short form, with the reporting address, is [SECURITY.md](../../SECURITY.md). This page
expands it: each threat, why it matters here, and where the defence lives.

## What hackerpot is, in security terms

A **deception and detection layer**: decoys that attract automated attacks, detectors that
recognise them, and responses that waste the attacker's time. It is **not a security
boundary**. It does not replace authentication, authorisation, input validation, patching
or a WAF, and nothing protected by those should depend on it. An attacker who avoids every
decoy should find nothing behind them that the decoys were protecting.

It is also not a high-interaction honeypot. It emulates responses and scripted shells; it
does not stand up real vulnerable services for an attacker to exploit.

## Two positions, two risks

| Position | What reaches it | The main risk |
| --- | --- | --- |
| **Standalone**, on its own address or ports | only unsolicited traffic | to the honeypot host itself |
| **Middleware**, in front of an application | real users | harming them: blocking a person, slowing a page, taking the app down |

Most of the design follows from taking the second row seriously.

## Defended against

### Blocking a real visitor on accumulated suspicion

In middleware mode a block needs proof: a replayed honeytoken, a hidden trap, a protocol
violation no client stack emits, a self-declared attack tool, or a refuted crawler claim.
Without it the request is tarpitted and nothing is blocklisted. Refusals are counted
(`hackerpot_downgrades_total`) and a spike is raised by the audit. See
[the proof guard](the-guard.md).

The false-positive suite (`tests/false-positives.test.ts`) runs real browser and API-client
traffic, static assets, OAuth redirects, proxied requests with internal addresses in
`X-Forwarded-For`, and queries that merely resemble payloads (`union station`,
`drop off locations`) through every default detector, over real HTTP, and fails if anything
fires. A detection there is treated as a bug in the detector.

### The honeypot taking the application down

Middleware fails open: an internal error is reported and the request continues to your
routes. Every detector, store call, enricher, webhook, alert sink and subscriber is
failure-isolated. Asynchronous detectors run under a deadline. Stores that sit on the
request path (Redis, Elasticsearch) have command timeouts, because a promise that never
settles never reaches the handler that would have degraded it. See
[adapters](../integration/adapters.md#failing-open).

### Path spelling used to evade decoys

Paths are decoded exactly once, backslashes normalised, duplicate slashes collapsed and dot
segments resolved before any detector matches. The raw spelling is kept for
`target-integrity`, which reports targets spelled to evade. Prefix decoys match only at a
`/` or `.` boundary.

### Allowlist bypass by address spelling

Addresses are compared by value: IPv4-mapped IPv6, compressed and expanded IPv6 and letter
case all match the same entry. An entry that cannot be matched at runtime is a startup error.

### Address spoofing through `X-Forwarded-For`

Ignored unless `trust_proxy` is on, and a forwarded value must parse as an IP address.
Enable it only behind a proxy that overwrites the header. See
[the client IP](../integration/client-ip.md).

### Crawler impersonation

Forward-confirmed reverse DNS and operator-published address ranges. A refuted claim is
proof; a DNS timeout proves nothing. Range lists are fetched over HTTPS, capped in size and
refused whole if they contain a block wider than any crawler owns. See
[verification](../detection/verification.md).

### Memory exhaustion

A honeypot is fed at a rate the attacker chooses, so every structure keyed by client input
has a ceiling: per-address activity, fingerprints, port-scan state, authentication
failures, webhook dedupe, audit campaign paths, blocklist entries, score caches, store
retention. Query parameters past 256 are not inspected, and a request that sends more is
flagged. The file store streams its log rather than loading it, so a log the attacker
inflated cannot stop the process from starting.

### CPU exhaustion through detection

Regex signatures are linear and matched against bounded input (16 KB per value by
convention). Values containing none of the characters a payload needs skip the payload
patterns entirely. `npm run bench:guard` holds the request path to budgets in CI.

### Connection exhaustion

`hardenHttpServer` sets a 20 s headers deadline, a 30 s request deadline, a 5 s keep-alive,
a 60 s socket timeout and a 10,000-connection cap. The protocol listeners cap concurrent
connections and session lifetime. `tarpit`, `drip-feed` and `large-payload` cap concurrency
and degrade to an immediate answer at capacity, so a flood cannot turn retaliation into a
self-inflicted denial of service.

### Alerting used as an amplifier

Webhooks deduplicate per address, throttle per hook, cap deliveries globally and in flight,
and send a summary of what they held back. Audit anomalies have a per-check cooldown. The
syslog sink drops rather than queues. See [webhooks](../operations/webhooks.md).

### Injection into logs, alerts and metrics

Every captured value is escaped for the sink it reaches: text log lines, Slack and Discord
messages (mentions neutered, link previews off), syslog and CEF (one message is always one
line), Prometheus label values. Captured shell commands cannot forge log lines.

### Leaking captured credentials

Webhook payloads and the dashboard redact by default: credential headers, secret-named
headers and body fields, and those values wherever detectors quoted them. `hackerpot config`
redacts secrets from the printed configuration. Service-token secrets are compared in
constant time and never logged.

### Exposure of the management API and the dashboard

The management API binds loopback by default, requires an API key on everything but
`/health`, and rate-limits failed authentication per peer. The dashboard is a separate
listener, refuses to bind beyond loopback without authentication, checks the `Host` header
against DNS rebinding, and runs under a strict CSP. See the
[management API](../operations/management-api.md).

### A poisoned threat-intel feed

Feeds must use HTTPS, are size- and entry-capped, never override the allowlist, expire, and
by default cannot reach the firewall enforcer. An address ingested from a feed is never
republished on this honeypot's own `/ioc`, so poison cannot spread from one honeypot to the
next. See [threat intel](../operations/threat-intel.md).

### Command injection through firewall enforcement

The enforcer runs an argv array through `execFile` with no shell, and substitutes only an
address that `net.isIP` validated. Spawn rate is capped. See
[firewall enforcement](../operations/firewall.md).

## Out of scope

- **An attacker who avoids the decoys.** Detection is of automated probing and known attack
  shapes. A careful human who requests only real pages and sends no payload is not what
  this finds.
- **Distributed low-and-slow traffic.** One request per address per hour from a large pool
  defeats every per-address signal by construction. The audit's campaign check sees some of
  it in aggregate, and nothing more.
- **Signature accuracy over time.** Scanner User-Agents, exploit paths and crawler ranges
  describe populations that change. Keep the package updated, and trial retuned detectors in
  [shadow mode](../detection/shadow-mode.md).
- **Retaliation.** Response actions waste an attacker's time and resources on connections
  they opened. Nothing here reaches out to an attacker's infrastructure.
- **The host it runs on.** Isolate a standalone honeypot from anything valuable. The
  interactive SSH, FTP and Telnet shells are scripted and execute nothing, but the listeners
  are internet-facing code. The compose file drops every capability, mounts the root
  filesystem read-only and caps memory and processes for that reason.

## What it costs to be wrong

| Mistake | Cost | Mitigation |
| --- | --- | --- |
| a real visitor blocked | lost customer, support ticket, and every later request refused | proof guard; allowlist; `downgrade-spike` |
| a real visitor tarpitted | seconds of latency on one request | thresholds; replay your logs first |
| `trust_proxy` wrongly on | attackers choose their address, impersonate your allowlist, get victims blocked | off by default; enable only behind an overwriting proxy |
| `trust_proxy` wrongly off behind a proxy | every visitor shares the proxy's address and score, and the proxy is eventually blocked | read [the client IP](../integration/client-ip.md) |
| the management API exposed | captured attacker data, including credentials, to anyone | loopback default; keys required |
| a feed enforced | someone else decides your firewall rules | `enforce = false` default |
| an attack missed | nothing, beyond what you already had | this is a detection layer; keep your real defences |

## Reporting a vulnerability

Email **platosz.michal@gmail.com** with `[hackerpot]` in the subject, and do not open a
public issue for anything exploitable. See [SECURITY.md](../../SECURITY.md).

## Related

- [The proof guard](the-guard.md) · [Design decisions](../design/decisions.md)
- [The client IP](../integration/client-ip.md) — the highest-consequence setting
