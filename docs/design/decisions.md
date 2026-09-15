# Design decisions

The trade-offs the library makes, and what each one costs.

← [Documentation](../index.md)

---

Everything here is a trade rather than a free win. They are recorded together so that a future change
can weigh what it is undoing.

---

## Detection and response are decoupled

**The decision.** A detector returns a scored finding and never decides what happens. A policy picks one
response action from every finding and the address's cumulative score.

**Why.** A new detector should not have to know about tarpits, and a new retaliation strategy should not
have to know about SQL injection. Decoupling lets both grow independently, and lets one policy route
twenty detectors.

**The cost.** Routing by a single detector goes through `respondWith`, which the default policy reads
from the top detection only, so a low-scoring detector's routing is lost when a higher one co-fires. The
fix is a policy of your own, which is more code than a per-detector setting would be.

See [writing a policy](../responses/policy.md).

## Blocks in middleware need proof

**The decision.** In front of an application, a `block` runs only when a detection is `certain`.
Otherwise it becomes a tarpit, nothing is blocklisted, and the refusal is counted.

**Why.** A block refuses every later request from the address, the application's own pages included,
and scores are sums of guesses. A shared browser fingerprint, one page load of asset paths, a scripting
User-Agent: each reached the default block threshold for real visitors before it was fixed. Points do not
compose into proof. The guard lives in the engine, after the policy, so it cannot be forgotten in a custom
policy or bypassed by one.

**The cost.** A persistent attacker who never trips proof is tarpitted indefinitely rather than blocked,
and costs a held connection each time instead of a cheap 403. That is intended: the cost of a missed
block is some server time, and the cost of a wrong one is a customer.

See [the proof guard](../concepts/the-guard.md).

## Standalone blocks on score

**The decision.** The standalone service does not require proof.

**Why.** Nothing legitimate should reach a honeypot on its own address. There, a sum of probes is a good
enough reason, and a cheap 403 is worth having.

**The cost.** Two behaviours for one policy, and a real person who does reach a standalone honeypot (a
typo'd hostname, a stale DNS record) can be blocked from it. They were never going to be served anything
real there.

## Decoys score; they do not prove

**The decision.** A request for `/.env` is suspicion, not proof.

**Why.** No link leads there, but a URL is text a client typed, and the client might be your own security
engineer, a vulnerability scanner you pay for, or somebody following a link in a bug report. Proof is kept
for things no legitimate client can produce: a planted honeytoken, a hidden trap, a protocol violation, an
attack tool naming itself, a refuted crawler claim.

**The cost.** The most obvious probe cannot on its own block anyone in middleware mode. Planting a
honeytoken in the decoy's payload is the intended upgrade.

## The middleware fails open

**The decision.** An error in the honeypot's own machinery calls `next()` and reports it. Every detector,
store call, enricher, subscriber, webhook and sink is isolated; async detectors run under a deadline.

**Why.** A honeypot that can take its host application down is worse than no honeypot. And an async
middleware that rejects is not caught by Express 4 at all: the request hangs.

**The cost.** During an outage of the honeypot's backends, detection is degraded or absent and requests
pass unexamined. Correct: the honeypot is a detection layer, not a security boundary.

See [adapters](../integration/adapters.md#failing-open).

## A body is read only for a request the honeypot will answer

**The decision.** Middleware evaluates headers first, and reads and re-evaluates the body only if
something fired, committing the hit exactly once.

**Why.** Reading a body consumes the stream the application needs. And committing both passes once
double-counted every probe, so an attacker crossed the block threshold on half the evidence.

**The cost.** A request clean on its headers but hostile in its body reaches the application unexamined.
And a shadowed body detector only sees bodies something else caused to be read.

## Everything keyed by client input is bounded

**The decision.** Every per-address map, registry, cache and log has a ceiling and an eviction rule:
activity windows, fingerprints, blocklist entries, score caches, port-scan state, authentication failures,
webhook dedupe, audit campaign paths, store retention, query parameters, captured commands.

**Why.** A honeypot is fed at a rate the attacker chooses, and an unbounded map keyed by anything a client
controls is a remote out-of-memory.

**The cost.** Evicted state is forgotten: a shed block is re-detected on the next request, a trimmed hit is
gone from the API, a long-quiet address loses its window. Each bound is chosen so that what is shed first
is what matters least (the soonest-expiring block, the least recently updated score).

## Drop, never queue

**The decision.** Webhooks past their caps, syslog to a stalled collector, firewall enforcement past its
rate, and live-feed viewers that stop reading all drop and report, rather than queue.

**Why.** Every one of these is driven by incidents, which an attacker creates at will. A queue in front of
a slow consumer is the same unbounded growth moved somewhere less visible.

**The cost.** Alerts, SIEM events and firewall rules can be lost during a flood. Each loss is counted, and
webhooks send a summary of what they held back, so a quiet channel is never mistaken for quiet traffic.

## No retaliation beyond the connection

**The decision.** Response actions act on the connection the attacker opened: delay it, stream at it, lie
to it, close it. Nothing reaches out to an attacker's infrastructure, and the protocol shells execute
nothing.

**Why.** An address is not an identity, and a scanner's source is often somebody else's compromised
machine. Hacking back is unlawful in most places and wrong about the target often enough to matter.

**The cost.** Retaliation is limited to wasting time and bandwidth, which a well-built scanner shrugs off
with a timeout.

## Retaliation is capped on our side

**The decision.** `tarpit`, `drip-feed` and `large-payload` have concurrency caps and degrade to an
immediate answer; `gzip-bomb` is built once and bounded at 256 MB; the protocol listeners cap connections
and session lifetime; hardening values are fixed.

**Why.** Every held connection holds one of ours too, and a flood would otherwise turn retaliation into a
self-inflicted denial of service.

**The cost.** Under a large enough flood, the showier responses stop working and everyone gets a plain
answer.

## Redaction by default, on the way out

**The decision.** The store keeps everything. Webhooks, the dashboard and `hackerpot config` redact
credentials by default.

**Why.** A captured password is a real person's password as often as it is a guess, and alert channels and
dashboards are screen-shared, screenshotted and forwarded far more than a store is read. Detection needs the
full request; its viewers usually do not.

**The cost.** An investigator who needs to see what was tried has to turn redaction off or read the store.

## Operator surfaces are separate listeners, private by default

**The decision.** The management API and the dashboard never share the attacker-facing port. Both bind
loopback by default. The API needs a key on everything but `/health`; the dashboard refuses to bind beyond
loopback without authentication, and checks `Host` against DNS rebinding.

**Why.** The honeypot's port is the one attackers are invited to, and these surfaces describe them: which
detector fired on what is a map of what to avoid next.

**The cost.** More ports to run, and a dashboard that will not start until somebody says something explicit
about access.

## `trust_proxy` is off by default, and reads the leftmost entry

**The decision.** `X-Forwarded-For` is ignored unless enabled, and when enabled the leftmost entry is used,
if it parses as an address.

**Why.** Defaulting on made every directly exposed deployment spoofable. Reading one entry keeps the rule
simple and requires the proxy to overwrite the header.

**The cost.** Behind a proxy that appends, or several proxies, the operator has to configure the edge to
overwrite. Leaving it off behind a proxy silently collapses every client into one score.

See [the client IP](../integration/client-ip.md).

## No IP intelligence, and no crawler ranges, ship with the package

**The decision.** No geo or ASN database; crawler range lists are URLs fetched on a schedule you start.

**Why.** An address mapping baked into a release is stale by the time it is installed, and a stale range
verifies whoever has since been handed the address.

**The cost.** Geo and ASN need an enricher of your own; published-range verification makes outbound
requests.

## Hearsay does not reach the firewall, and is not republished

**The decision.** Ingested feed entries go to a non-enforcing blocklist by default, the allowlist is checked
first with no way to disable it, and an ingested address is never published on this honeypot's own feed.

**Why.** One peer with `trust_proxy` wrongly on can be made to list a victim's address, and without these
rules a whole fleet would firewall it.

**The cost.** A fleet reacts to a shared offender by short-circuiting requests, not by dropping packets,
until the offender attacks each honeypot first-hand.

See [threat intel](../operations/threat-intel.md).

## The fingerprint correlates; it never flags

**The decision.** The fingerprint registry is written only by requests that already scored, and
`repeat-actor` requires the current address to be in it.

**Why.** A fingerprint is shared by every user of one browser build. Without both rules, two attackers were
enough to flag every later visitor with the same browser, each flag writing another address in.

**The cost.** Rotation is detected one request late per address.

## The config is strict, and describes rather than restates

**The decision.** Unknown keys, wrong types and contradictions are startup errors. List-valued defaults are
owned by the library and appear in the shipped file only as comments. A reload refuses, by name, what it
cannot apply.

**Why.** A typo that silently switches a detector off, a restated default that silently goes stale, and a
reload that silently ignores a port change all look like success and are not.

**The cost.** A config written for a newer version fails on an older one, and the shipped file cannot be
edited by uncommenting a default list and expecting it to merge.

## Stores fail soft, with deadlines

**The decision.** A store read that fails degrades to a score of 0, a write that fails is reported, and the
network stores have command timeouts.

**Why.** `scoreFor` is on the request path, and a promise that never settles never reaches the handler that
would have degraded it. A dead logging backend should cost the log, not the service.

**The cost.** During a store outage nothing accumulates and nothing is recorded, and from outside the
honeypot looks healthy; the service logs every `store-error` so it does not stay invisible.

## Syslog is independent of the management API

**The decision.** `[syslog]` forwards from the hit path directly.

**Why.** Shipping to a SIEM should not also require exposing a REST API over captured attacker data.

**The cost.** Two delivery paths to keep consistent.

## The nginx edge is a different trade, and says so

**The decision.** The generated edge config diverts by extension and User-Agent, without knowing whether the
client is legitimate, and the documentation leads with that.

**Why.** At the edge, "a browser would never ask for this" is the only signal available, and it catches a
great deal cheaply.

**The cost.** A site that serves archives, or a public API with `curl` clients, has real traffic diverted
unless it edits the maps.

See [nginx edge capture](../integration/nginx.md).

## Shadowing is exclusion, not a weight of zero

**The decision.** A shadowed detection adds no score, chooses nothing, triggers no body read, records no hit
and counts as no proof.

**Why.** A weight of zero would still let a shadowed `certain` detection make a block stick.

**The cost.** A shadowed detector sees less than it will when live, since nothing it finds causes a body to be
read.

## Related

- [The proof guard](../concepts/the-guard.md) · [Threat model](../concepts/threat-model.md)
- [Configuration](../reference/configuration.md) — where these show up as settings
