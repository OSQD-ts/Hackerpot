# How it works

The request lifecycle, the two-pass body evaluation, and what is recorded.

← [Documentation](../index.md)

---

Two pluggable layers, mirrored by two source directories:

```
src/detectors/   how attacks are recognised     (the "honeypots")
src/responses/   what to do about them           (the retaliation actions)
```

A **detector** says *"this is a `.env` probe, score 10."* It does not decide what happens
next. A **policy** does, looking at everything that fired plus the address's cumulative
score, and picks one **response action**. A **store** holds the incidents and the scores.
You can add a detector without touching responses, and rewire responses without touching
detection.

## The lifecycle

```
  request
     │
     ├─ resolve the client IP          socket address, or X-Forwarded-For with trustProxy
     │
     ├─ allowlisted? service token? ──► pass through, nothing recorded, nothing counted
     │
     ├─ already blocked? ─────────────► 403, before any detector runs
     │
     ├─ normalise                      path decoded once, dot segments resolved,
     │                                 query bounded to 256 parameters
     │
     ├─ track                          append to this IP's sliding activity window
     │
     ├─ DETECT                         every detector, in order, each isolated:
     │                                 a throw or a timeout skips that detector only
     │
     │     nothing fired? ────────────► pass through (middleware) or 404 (standalone)
     │
     ├─ SCORE                          sum this request's detections, one per family,
     │                                 add to the IP's running total from the store
     │
     ├─ POLICY                         choose ONE response action id
     │     └─ PROOF GUARD (middleware) block without a certain detection ─► tarpit
     │
     ├─ RECORD                         enrich the IP, write the hit, onHit, subscribers
     │
     └─ RESPOND                        run the chosen action on the response
```

Four properties fall out of that order.

**Suspicion accumulates per address.** A single odd request is cheap noise; the same
address hitting ten decoys, brute-forcing a login and replaying a honeytoken is an attacker.
The running total lives in the [store](../operations/stores.md), so it can be shared
across replicas, and the sliding window lives in memory for the stateful detectors. See
[scoring](scoring.md).

**Blocked addresses are free to serve.** A request from a blocked address is answered
`403` before any detector runs, so an attacker who tripped the block costs almost nothing.

**Exempt traffic leaves no trace.** An allowlisted address or a valid
[service token](../integration/service-tokens.md) bypasses the block check, detection,
the activity window, the audit and the store. It is not judged leniently; it is not judged.

**Nothing on the path can take the request down.** Each detector runs in its own
`try`; an asynchronous detector runs under `detectorTimeoutMs` (default 2000). The store
read degrades to a score of 0 if it throws; the store write, the enricher and `onHit` are
each isolated. Every one of those failures goes to `onError` with a `source` naming what
failed.

## Two passes, so a body is never read for nothing

Reading a request body consumes the stream. In middleware mode the application behind the
honeypot needs that stream, so the middleware must not read it for a request it is going to
pass on. But several detectors (`payload-injection`, `ssrf-probe`, `nosql-injection`,
`prototype-pollution`, `insecure-deserialization`, `graphql-abuse`, `honeytoken`) look at
bodies.

So a body-bearing request is evaluated twice:

1. **Headers only.** Every detector runs without a body. The request is counted in the
   activity window, but the hit is **deferred**: nothing is written, scored or announced.
2. **If anything fired**, the request is the honeypot's to answer, so reading the body can
   no longer disturb a downstream route. It is read (capped at 64 KB) and evaluated again,
   this time committing the hit exactly once, without counting the request a second time.

If nothing fired on the first pass, the request goes to your application with its body
untouched. A request that is clean on its headers but hostile in its body therefore
reaches your application: the honeypot is a detection layer, not a request filter. The
standalone service has no downstream, so it reads the body up front and evaluates once.

Committing exactly once matters more than it looks. With both passes recording, one probe
against a decoy became two incidents, two alerts, two activity entries and double the
score, so an attacker crossed the block threshold on half the evidence.

A detector declares `needsBody: true` to be considered for the second pass. The engine
exposes `needsBodyPhase`, true when any installed detector does.

## What a hit records

An **incident** is a `HoneypotHit`: exactly what the store holds, the REST API returns,
the live feed pushes and a webhook posts.

| Field | What it is |
| --- | --- |
| `id`, `timestamp` | a UUID and an ISO 8601 time |
| `ip` | the resolved client address |
| `method`, `path` | the method, and the path detection matched (normalised) |
| `rawPath` | the target as sent, only when it differs from `path` (`//.env`, `/%2eenv`) |
| `headers` | every request header, as received |
| `body` | the body, when one was read (capped at 64 KB) |
| `fingerprint` | the [actor fingerprint](actors.md) |
| `enrichment` | the address's special-use category, plus geo or ASN from your enricher |
| `detections` | everything that fired, highest score first |
| `shadowDetections` | findings from [shadowed detectors](../detection/shadow-mode.md), which added nothing |
| `score`, `totalScore` | points this request added, and the address's total after it |
| `respondedWith` | the response action that ran |
| `downgradedFrom` | `"block"`, when the proof guard refused a block |

The full shape with an example is in [data shapes](../reference/data-shapes.md).
Headers and bodies are attacker-controlled; the store keeps them whole, and redaction
happens on the way out, to webhooks and the dashboard.

## Enrichment

Each recorded hit's address is annotated. The dependency-free `defaultIpEnricher()`
classifies it as `loopback`, `private`, `cgnat`, `link-local`, `documentation`,
`benchmarking`, `multicast`, `reserved` or `public`, and whether it is globally routable.
A private or loopback source reaching an internet-facing honeypot is itself a signal:
usually a proxy leaking internal clients, or `X-Forwarded-For` trusted when it should not be.

No geo or ASN database ships, because that would mean shipping and maintaining megabytes of
data that go stale. Implement the one-method `IpEnricher` over your own source:

```ts
import type { IpEnricher } from "@osqd/hackerpot";

const geo: IpEnricher = {
  enrich: async (ip) => {
    const record = await myGeoLite.lookup(ip);
    return record ? { category: "public", global: true, asn: record.asn, org: record.org, country: record.country } : undefined;
  },
};

new HoneypotEngine({ enricher: geo });   // or enricher: null to disable enrichment
```

## Related

- [Scores and escalation](scoring.md) — what `score` and `totalScore` add up to
- [The proof guard](the-guard.md) — the step between the policy and the response
- [Adapters](../integration/adapters.md) — the same lifecycle on Koa, Fastify and Fetch
