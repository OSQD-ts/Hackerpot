# Writing a detector

The contract, the rules, and the tests a new detector has to pass.

← [Documentation](../index.md) · [Detection](index.md)

---

Every layer is an interface, so a detector is a small object: no fork, no registration.

```ts
import { HoneypotEngine, type Detection, type DetectionContext, type Detector } from "@osqd/hackerpot";

export interface RefererTrapOptions {
  hosts: string[];
  score?: number;
  respondWith?: string;
}

export function refererTrapDetector(options: RefererTrapOptions): Detector {
  const score = options.score ?? 5;
  const hosts = options.hosts.map((host) => host.toLowerCase());
  return {
    id: "referer-trap",
    description: "Referer from a host that links only to decoys",
    inspect(ctx: DetectionContext): Detection | undefined {
      const raw = ctx.headers["referer"];
      const referer = (Array.isArray(raw) ? raw[0] : raw)?.slice(0, 2048).toLowerCase();
      if (!referer) return undefined;
      const host = hosts.find((candidate) => referer.includes(candidate));
      if (!host) return undefined;
      const detection: Detection = { detectorId: "referer-trap", reason: `Referer from ${host}`, score, metadata: { host } };
      if (options.respondWith) detection.respondWith = options.respondWith;
      return detection;
    },
  };
}

new HoneypotEngine({ extraDetectors: [refererTrapDetector({ hosts: ["evil.example"] })] });
```

## The contract

```ts
interface Detector {
  id: string;                       // stable; used in config, metrics, shadow_detectors, respond_with routing
  description?: string;             // shown by `hackerpot detectors`
  needsBody?: boolean;              // take part in the second, body-reading pass
  inspect(ctx: DetectionContext): Detection | undefined | Promise<Detection | undefined>;
}

interface Detection {
  detectorId: string;
  reason: string;                   // human-readable; quoted in logs, alerts and the dashboard
  score: number;
  respondWith?: string;             // a response action id; honoured only for the top detection
  certain?: boolean;                // proof: see below
  family?: string;                  // one root cause shared with other detections counts once
  metadata?: Record<string, unknown>;
}
```

`DetectionContext` is the request facts plus what the engine knows about the client:

| Field | |
| --- | --- |
| `method`, `path` | the method, and the normalised path |
| `rawPath` | the target as sent, only when it differs from `path` |
| `query` | a null-prototype object, at most 256 parameters |
| `queryParamsDropped` | how many parameters past 256 were not included |
| `headers`, `rawHeaders` | parsed headers; Node's ordered `[name, value, …]` array when the front end has it |
| `httpVersion` | `"1.1"`, `"2.0"`, when known |
| `ip` | the resolved client address |
| `body` | only in the second pass, and only if `needsBody` |
| `formFields` | fields `trapFormGuard` passed from your body parser |
| `partialHeaders` | true for facts rebuilt from a log line |
| `tracker` | this address's activity window: `countIn(ms)`, `uniquePathsIn(ms)`, `countPathIn(path, ms)` |
| `fingerprint`, `fingerprintRegistry` | the [actor fingerprint](../concepts/actors.md), and which addresses each was suspicious from |
| `timestamp` | when the request happened (a replay passes the logged time) |
| `verifiedCrawler` | set by `crawler-verification` when DNS confirmed the claimed crawler |

## The rules

**Never throw.** The engine isolates a throwing detector, skips it, reports it and counts it
in `hackerpot_detector_failures_total`, but a detector that throws on crafted input has handed
an attacker a way to switch it off. Wrap parsing (JSON, base64, URLs) in `try`/`catch`.

**Bound what you scan.** Everything in the context is attacker-controlled. Cap the length of
any value before a regex sees it (16 KB is the convention), and prefer linear patterns: no
nested quantifiers over the same characters. `npm run bench:guard` holds the request path to
budgets.

**Do not reason from absence on partial facts.** A header missing from a log line was never
recorded. If your detector fires because something is missing, return `undefined` when
`ctx.partialHeaders` is true.

**Report, do not record.** Do not write to `ctx.tracker` or the registry from `inspect`; the
engine records activity and fingerprints around the detectors, exactly once per request.

**Ask for the body only if you need it.** `needsBody: true` makes the middleware eligible to
read a body for your detector, but only after something fired on headers.

**Stay synchronous if you can.** An async `inspect` runs under `detectorTimeoutMs` and a
timeout skips it for that request. Anything slow (DNS, HTTP) needs a cache.

**Use a stateless regex.** A `g` or `y` flag keeps `lastIndex` between calls and matches only
every other request.

## When a detection may be `certain`

`certain: true` is what lets a middleware block stick. Mark a detection certain only if you
can write down, in one sentence, why **no legitimate client can produce it**. The built-in
cases are a planted secret replayed, a hidden trap reached, a protocol violation no stack
emits, an attack tool naming itself, and a crawler claim DNS refutes. See
[the proof guard](../concepts/the-guard.md#what-counts-as-proof).

If the sentence needs "usually", "almost never" or "unless", the detection is suspicion.
Nearly every attempt to mark something certain fails at this step, which is the point.

## Families

If your detector can fire on the same root cause as an existing one, give both detections the
same `family` so the request's score counts it once. The built-in family is `path-traversal`,
shared by `payload-injection` and `target-integrity`.

## Configuration

A library detector needs no config. To add one to the TOML surface in this repository:

1. Write `src/detectors/your-thing.ts`, a factory with an options interface and defaults.
2. Export it from `src/detectors/index.ts`, and add it to `defaultDetectors()` if it should be
   on by default.
3. Parse its section in `src/config/schema.ts` and build it in `src/config/build.ts`.
4. Document it in `hackerpot.toml`, with list-valued defaults as **commented examples**: the
   library owns semantics, and the config file describes and defers. A restated default goes
   stale silently, and the file wins.

A drift test fails if `defaultDetectors()` and the schema's detector sections disagree.

## The tests it has to pass

- **A detection test**: the attack shapes it exists for fire, with the reason and score you
  expect.
- **The false-positive suite**, `tests/false-positives.test.ts`: real browser and API-client
  traffic, over real HTTP, through every default detector, asserting nothing fires. Add
  legitimate cases that stress your detector's boundary. If it trips one, tighten the
  signature; the test is not wrong.
- **The corpus**: add a hostile case expecting your detector. `tests/corpus.test.ts` fails if
  a default detector has no hostile case. See [the corpus](../testing/corpus.md).
- **Shadow it** on real traffic before it counts. See [shadow mode](shadow-mode.md).

## Related

- [The detectors](detectors.md) — forty-odd examples of the contract
- [Writing a response](../responses/writing-a-response.md) — the other half
- [CONTRIBUTING.md](../../CONTRIBUTING.md) — conventions for a pull request
