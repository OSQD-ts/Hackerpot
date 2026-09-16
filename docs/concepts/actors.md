# Actors

Fingerprints, cross-IP correlation, sessions, and what is remembered per address.

← [Documentation](../index.md)

---

An IP address is a weak identity. Attackers rotate through proxies, botnets and cloud
ranges; and behind a NAT, one address is many people. hackerpot keeps two views of who a
client is: the **address**, which everything is keyed on, and the **actor fingerprint**,
which correlates addresses that are already suspicious.

## What is remembered per address

| Structure | Holds | Bound |
| --- | --- | --- |
| cumulative score | in the store | `max_score_entries`, least recently updated shed first |
| activity window (`IpTracker`) | recent requests: method, path, whether the app served it | `activity_window_ms` (default 60 s), per-address history capped |
| blocklist entry | blocked until *T* | `[blocklist] max_entries` (memory), a TTL (Redis) |
| fingerprint registry | which addresses each fingerprint was *suspicious* from | `fingerprint_window_ms` (default 1 h) |

The activity window is what the stateful detectors read: `rate-spike`,
`path-bruteforce`, `credential-bruteforce`. A detector reaches it through `ctx.tracker`,
with `countIn(ms)`, `uniquePathsIn(ms)` and `countPathIn(path, ms)`. It lives in memory per
process and is deliberately **not** reloadable: a rebuild would hand every attacker a clean
window.

`activity_window_ms` must be at least as long as the longest detector window
(`credential-bruteforce`'s 60 s by default), or that detector sees less history than it
asks for.

## Naming the ones you know

An incident log is a list of addresses, and the first question about any of them is "who is
that?" — usually answered by pasting it into a lookup tool. Some answers you already have:
your uptime checker, a partner's integration, a vendor's scanner, the office. Label them once
and the feed reads in names, so the unfamiliar addresses are the ones that stand out.

```ts
import { ActorLabels, HoneypotEngine } from "@osqd/hackerpot";

const labels = new ActorLabels({
  labels: [
    { name: "Our uptime checker", match: { ip: ["198.51.100.10"], userAgent: "UptimeBot" },
      note: "Every 30s against /healthz", hideFromFeed: true },
    { name: "Acme security scan", match: { org: "Acme Security" }, note: "Contracted, weekly" },
  ],
});

new HoneypotEngine({ labels });
```

```toml
[[actors]]
name = "Our uptime checker"
ip = ["198.51.100.10"]
user_agent = "UptimeBot"
hide_from_feed = true
```

Match on `ip` (addresses or CIDR ranges), `asn`, `org`, `userAgent` or `hostname`; every key
you give must match, so a label can be as narrow as one client on one network. A value in
`/slashes/` is a regular expression, anything else is a case-insensitive substring. The first
label that matches wins, and the name lands on the incident as `actor`.

**A label names; it never exempts.** A labelled actor is detected, scored and answered exactly
as it would be otherwise — naming a scanner so you can watch what it does is the opposite of
trusting it. Exemption is the [allowlist](../reference/configuration.md#allowlist) or a
[service token](../integration/service-tokens.md). The one thing a label changes is
`hideFromFeed`, which mutes a known constant source in the dashboard's **live pane only**: it
is still detected, recorded, counted in the statistics and returned by the listings.

Matching on `hostname` needs reverse DNS, which is never awaited on the request path — a
honeypot that waits on DNS before answering has been handed a way to slow it down. The lookup
starts in the background, is cached (1 h by default), and the name is available from the next
request that address makes.

## Markers

A fingerprint correlates a rotating attacker only while their tooling stays identical. Swap
one tool for another, or drive the attack from a browser, and one actor looks like several. In
middleware mode — where clients keep cookies — a **marker** survives that: the same signed
value comes back from wherever the next request is made.

```toml
[markers]
secret = "a-long-random-secret"   # required; turns markers on
name = "__hp"
max_age_seconds = 86400
secure = true
same_site = "Lax"

[detectors.marker-drift]
enabled = true                    # one marker, several addresses
```

The rules are the fingerprint's rules, applied harder, because a cookie is a stronger
identifier than a heuristic:

- **Only somebody the honeypot already answered gets one.** The marker is set on the
  honeypot's own responses to probes, never on a response your application produced. A visitor
  who trips nothing is never marked — this is a tag on requests that were already incidents,
  not analytics attached to your traffic.
- **It correlates, it never accuses.** `marker-drift` fires on one marker presented from
  several addresses and adds a modest score. It is never proof: a cookie can be copied,
  including out of somebody else's traffic.
- **It never exempts.** A marker is not a token and grants nothing.
- **It is signed and carries nothing.** A random id plus an HMAC over it, `HttpOnly`, so a
  forged or edited marker is rejected rather than inventing an actor, and the value holds no
  address, no timestamp, nothing about the person. An unsigned marker would be one anybody
  could mint, which is why `secret` is required rather than defaulted.

A rejected marker is indistinguishable from no marker at all: treating a forgery as its own
event would hand an attacker a signal they can raise whenever they like.

In code: `new MarkerCookie({ secret })`, passed to `HoneypotEngine` as `markers`. The marker a
request carried is on the incident as `marker`.

## The actor fingerprint

For every request the engine computes a short hash of:

- the **header order**: the ordered list of header names the client sent, from Node's
  `rawHeaders`, which preserves order and casing;
- a coarse **User-Agent family** (`uaClass`): all of an actor's curl, all of their Chrome,
  without splitting on version noise.

The order and set of headers a client sends is characteristic of the software driving it,
and far more stable across addresses than the address. The same tool driven by the same
actor produces the same fingerprint from a hundred different IPs.

```ts
import { computeFingerprint, headerOrder, uaClass } from "@osqd/hackerpot";
```

It is a **heuristic, not an identity**. Every user of one browser build on one site shares
a fingerprint too. So it is used to correlate traffic that is already suspicious, and never
to flag traffic on its own.

Behind a Fetch runtime the fingerprint has less to work with: the runtime normalises header
order before the handler sees it. A TLS (JA3) fingerprint would complement this without
needing header order, and is not implemented.

## Cross-IP correlation: `repeat-actor`

`repeatActorDetector` fires when one fingerprint has been seen attacking from
`distinct_ip_threshold` (default 3) addresses inside `window_ms` (default 10 minutes).

Two rules keep it from manufacturing suspicion:

1. **The registry is written only by requests that already scored.** A request nothing
   flagged is never recorded against its fingerprint, so ordinary visitors who share a
   browser build never enter it.
2. **The current address must itself be in the registry.** Without this, two real attackers
   were enough to make every later request with that fingerprint fire, and because firing
   is itself a hit, each such request wrote its own address in and guaranteed the next one
   fired too. Measured before the fix: after two attackers probed a decoy, six of six
   ordinary browser requests to an ordinary page were flagged, and one visitor reached a
   total of 49, past the block threshold, in seven page views.

With both, it only ever confirms that suspicious addresses are one actor. A rotating
attacker still trips it: each new address enters the registry on its own first scoring
request, and the correlation fires from that address's next request on.

The registry is bounded and windowed, so an attacker shuffling header order to mint
unlimited fingerprints cannot exhaust memory.

## Actors in the management API

Every recorded hit carries its `fingerprint`, and two endpoints group by it:

- `GET /actors` — incidents grouped by fingerprint, each listing **every address one actor
  used**, most addresses first, so the rotators surface at the top.
- `GET /actors/:fingerprint` — one actor.

The dashboard's Actors screen is the same view. See the
[management API](../operations/management-api.md).

## Sessions

A **session** is one address's incidents as an ordered narrative: what it did, which
detectors fired, which responses it drew, and its score climbing with each step.

- `GET /sessions` — every address's session, newest activity first.
- `GET /sessions/:ip` — one address, `404` if it has no incidents.

Reading a session is usually faster than reading a flat incident list: a scanner's walk
through decoys, the tarpits it drew and the block it ended on read in order.

## Shared addresses

Behind CGNAT, a corporate gateway or a VPN exit, "one address" is many people, and nothing
here can tell them apart. That is why:

- the volume detectors score low (`rate-spike` 4) and exist mostly to corroborate;
- middleware blocks need [proof](the-guard.md), which a neighbour's behaviour cannot supply;
- `RedisStore` offers `scoreTtlSeconds`, so a shared address's score decays.

## Related

- [How it works](how-it-works.md) — where the window and the fingerprint are computed
- [The client IP](../integration/client-ip.md) — getting the address right in the first place
- [The detectors](../detection/detectors.md) — the stateful ones, and their windows
