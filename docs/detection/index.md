# Detection

Detectors, what they read, and how to find out which ones a configuration installs.

← [Documentation](../index.md)

---

A **detector** looks at one request and either returns nothing or returns a `Detection`: a
detector id, a human-readable `reason`, a `score`, and optionally `certain`, `family`,
`respondWith` and `metadata`. It never decides what happens next. That is the
[policy](../responses/policy.md)'s job.

```ts
import { HoneypotEngine, defaultDetectors, honeytokenDetector, trapDetector } from "@osqd/hackerpot";

new HoneypotEngine();                                                    // the default set
new HoneypotEngine({ extraDetectors: [honeytokenDetector({ tokens: ["AKIA_FAKE"] })] }); // add to it
new HoneypotEngine({ detectors: [...defaultDetectors(), trapDetector()] });              // replace it
```

`detectors` replaces the set **entirely**; `extraDetectors` is appended to the defaults and
is ignored when `detectors` is given.

## Four kinds

| Kind | What it reads | Examples |
| --- | --- | --- |
| **per-request** | this request alone | `decoy-path`, `payload-injection`, `header-integrity` |
| **stateful** | this address's recent activity window | `rate-spike`, `path-bruteforce`, `credential-bruteforce` |
| **correlating** | the registry of suspicious fingerprints | `repeat-actor` |
| **verifying** | DNS or published address ranges | `crawler-verification` |

Per-request detectors work unchanged on a replayed log line. Stateful ones need the
sequence and the timestamps, which a [replay](../testing/replay.md) supplies line by line.

Beside the HTTP chain, the [protocol honeypots](../protocols/index.md) and the
[port-scan sentinel](../protocols/port-scan.md) are TCP listeners with findings of their own.
They share the store, not the detector list.

## The default set

`defaultDetectors()` returns 23 detectors, in this order:

```
decoy-path  payload-injection  ssrf-probe  nosql-injection  prototype-pollution
insecure-deserialization  graphql-abuse  jwt-weakness  crlf-injection  web-shell
header-anomaly  header-integrity  target-integrity  host-header-injection  sensitive-file
open-redirect  suspicious-method  credential-bruteforce  path-bruteforce  scanner-signature
client-anomaly  rate-spike  repeat-actor
```

Three more ship and are **opt-in**, each for a reason:

| Detector | Why it is off |
| --- | --- |
| `honeytoken` | it needs the token values you planted |
| `trap` | a trap is proof only once you have hidden it in your markup and disallowed it in robots.txt |
| `crawler-verification` | it makes DNS lookups, and optionally outbound HTTPS requests |

The reliable answer for your own configuration is the command:

```bash
npx hackerpot detectors --config ./hackerpot.toml
```

```
decoy-path                 headers         Request targeted a decoy path that no legitimate client would know about
payload-injection          body            Request contains a recognizable exploitation payload
…
repeat-actor               headers         One actor fingerprint seen attacking from several distinct IPs (IP rotation)

23 detectors installed from /srv/hackerpot/hackerpot.toml.
```

The second column says whether a detector reads the body (and so takes part in the
[second pass](../concepts/how-it-works.md#two-passes-so-a-body-is-never-read-for-nothing));
a third column marks shadowed detectors.

## Settings every detector shares

| Option | TOML | |
| --- | --- | --- |
| `score` | `score` | its contribution to the address's total |
| `respondWith` | `respond_with` | a response action id that overrides the policy, for the top detection only (see [scoring](../concepts/scoring.md#respondwith-reads-the-top-detection-only)) |
| — | `enabled` | switch it off without losing its settings |

In TOML each detector is a `[detectors.<id>]` table, with the detector's own options in
snake_case. Section names accept hyphens or underscores: `[detectors.rate-spike]` is
`[detectors.rate_spike]`. Regex-valued keys take a bare pattern, compiled
case-insensitively, or a `/pattern/flags` literal.

## Normalisation happens once, before any detector

Every detector matches `ctx.path`, which the engine has decoded exactly once, with
backslashes normalised, duplicate slashes collapsed and dot segments resolved. So `//.env`,
`/./.env` and `/%2eenv` all reach `decoy-path` as `/.env`. The spelling as sent survives in
`ctx.rawPath`, which only `target-integrity` and `honeytoken` read. The query arrives as a
null-prototype object bounded to 256 parameters; `header-anomaly` flags a request that sent
more.

## Detection never throws into a request

Each detector runs in its own `try`. A throwing detector is skipped for that request and
reported through `onError` with its id as the source, and counted in
`hackerpot_detector_failures_total{detector}`. An asynchronous detector that takes longer
than `detector_timeout_ms` (default 2000) is treated the same way. Every built-in detector is
synchronous except `crawler-verification`.

## Related

- [The detectors](detectors.md) — every one, in detail
- [Decoys](decoys.md) · [Traps and honeytokens](traps-and-honeytokens.md) · [Verification](verification.md)
- [Shadow mode](shadow-mode.md) — trial a detector before it counts
- [Writing a detector](writing-a-detector.md)
