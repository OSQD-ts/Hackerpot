# The traffic corpus

159 shapes of real HTTP traffic — people, wanted bots, infrastructure and attacks —
paired with what the honeypot's detectors ought to conclude about each, and a harness
that runs them against **your** detector configuration.

```bash
npx tsx scripts/corpus.ts                    # middleware mode (the proof guard on)
npx tsx scripts/corpus.ts --standalone       # no proof guard
npx tsx scripts/corpus.ts --audience human --verbose
npx tsx scripts/corpus.ts --tag verification
npx tsx scripts/corpus.ts --json
```

The section to read first is **FALSE POSITIVES**. Everything else is diagnostics; that
one is benign traffic your configuration would have caught in a decoy.

---

## What it is for

A detector set is a claim about traffic you have not seen yet. Unit tests check that a
detector does what its author intended; they cannot tell you whether the *policy* built
from those detectors is safe to point at the internet. This corpus can, because it is
made of the internet: real User-Agent strings, real header sets in the order real clients
send them, real attack payloads lifted from the CVEs that named them, each traced to
where it came from.

The single most important part is the `human` audience. Every case marked that way is an
ordinary customer, and the harness enforces the rule that **nothing may fire on one** —
regardless of what the case's own expectations say. Adding a human case therefore protects
the library the moment it is added, without anyone having to remember to write the
assertion.

---

## Layout

| File | What is in it |
| ---- | ------------- |
| `schema.ts` | The case shape, the `human()`/`benign()`/`hostile()`/`infrastructure()` helpers, the seeded honeytoken and trap constants |
| `headers.ts` | Real browser profiles **in the order each engine sends headers**, plus common HTTP clients (curl, wget, python-requests, Go, okhttp, undici, Java) in their real orders; the `browser()` and `client()` builders |
| `humans.ts` | People: every engine, SPA and form traffic, privacy browsers, screen readers, stripped-header proxies, CGNAT — and the one honest known cost |
| `benign-bots.ts` | Search crawlers (verified by controlled DNS or published range), uptime monitors, link unfurlers, feeds, archives; the fictional crawler ranges |
| `infrastructure.ts` | Health probes, CDN origin pulls, load-balancer checks, Stripe/GitHub/Shopify webhooks |
| `scanners.ts` | sqlmap, nikto, nuclei, zgrab, gobuster/ffuf/feroxbuster wordlist walks, wpscan, and the rest |
| `exploits.ts` | One or more per default detector: Log4Shell, SSRF metadata, NoSQL, prototype pollution, Java/PHP/.NET deserialization, GraphQL introspection, JWT alg:none, web shells, several traversal spellings, host-header injection, CL.TE smuggling, a query-parameter flood |
| `adversarial.ts` | Forged crawlers refuted by DNS, honeytoken replays, traps, credential stuffing, address rotation, a rate flood |
| `runner.ts` | The harness, the scorecard, and `addressFor` / `factsFor` for a wire replayer |
| `index.ts` | `CORPUS` (frozen), and the re-exports the published subpath exposes |

---

## Two details that make it honest

**Header order is a fingerprint, so the profiles reproduce it.** Chromium leads with
`Host, Connection, sec-ch-ua…`; Gecko leads with identity and closes with the Fetch
Metadata block; `python-requests` sends `Accept-Encoding` before `Accept`. A fixture that
invents an order is testing a client that does not exist — and `client-anomaly`,
`header-integrity` and the actor fingerprint all read from it.

**DNS is controlled, not mocked away.** Each crawler case declares the answers it wants,
so the difference between *"the operator's DNS disproves this claim"* (an impersonator)
and *"our resolver was briefly unhappy"* (the real Googlebot during a blip) can actually
be tested. Those reach different verdicts, and only a controlled resolver can prove it.

---

## Reading the scorecard

- **False positives** — benign traffic penalised. Must be zero. For a human, anything
  firing at all; for a benign bot or infrastructure, a `certain` detection, a block, or a
  detector the case named in `neverDetectors`.
- **By audience** — pass rate and the spread of response actions each group received. This
  is where you see the *shape* of a policy: how much hostile traffic is blocked versus
  tarpitted, and that no wanted traffic is touched.
- **Detector coverage** — how many cases each detector fired on, and which installed
  detectors nothing exercised. An unexercised detector is a gap in the corpus, not the
  library: it is one whose next regression nobody will notice.
- **Known costs** — human traffic the design knowingly cannot serve cleanly (a WordPress
  author at the `/wp-login.php` decoy). Reported rather than failed, because the honeypot
  cannot both bait scanners with a path and serve authors on it, and the corpus is honest
  about that instead of hiding it.
- **Skipped** — cases needing a capability the engine under test does not provide
  (`honeytoken`, `trap`, `crawler-verification`, `published-ranges`). Reported, never
  counted as a pass, because "we did not check" and "it passed" must not look the same.

---

## Adding a case

```ts
human({
  id: "kebab-case-and-unique",
  title: "What a reader needs to picture it",
  category: "page-load",
  provenance: "Where this shape came from: a UA list, a vendor doc, a CVE, a log line",
  requests: [browser("chromeWindows", { path: "/checkout" })],
  expect: { neverDetectors: ["client-anomaly"] },
});
```

`provenance` is required and enforced. A fixture nobody can trace is a fixture nobody can
update when the world moves — and this is a corpus about a world that moves.

A case that needs configuration the defaults do not supply declares it, and is **skipped
and reported** rather than silently passing:

```ts
requires: ["honeytoken"],          // the engine must watch for the seeded token
requires: ["crawler-verification"], // the engine must run the verification detector
```

A crawler case pins its source address and declares the DNS answer that confirms or
refutes it:

```ts
requests: [{ ip: "198.51.100.10", headers: [...], httpVersion: "1.1" }],
dns: { reverse: { "198.51.100.10": ["crawl-….googlebot.com"] }, forward: { "crawl-….googlebot.com": ["198.51.100.10"] } },
```

Addresses are drawn from the RFC 5737 documentation ranges, so nothing collides with a
real host.

---

## Replaying it over a real socket

The harness above calls `evaluate()` in process. The wire replayer sends the same cases
down a real TCP connection to a running honeypot and asks its management API what fired,
so a case that behaves differently on the wire than in process points at the front end
rather than a detector:

```bash
npm run demo              # terminal 1
npm run simulate:corpus  # terminal 2
```

`addressFor(caseIndex, from)` and `factsFor(testCase, request, index)` are exported so the
replayer builds the same source addresses and the same request facts the in-process runner
does.

---

## Testing your own configuration

```ts
import { runCorpus } from "@osqd/hackerpot/corpus";
import { HoneypotEngine } from "@osqd/hackerpot";

const scorecard = await runCorpus({
  create: ({ resolver }) => new HoneypotEngine({ ...myConfig, /* wire the resolver into crawler-verification */ }),
  provides: ["honeytoken", "trap", "crawler-verification", "published-ranges"],
});

if (scorecard.falsePositives.length > 0) throw new Error("this configuration penalises people");
```

Which *action* a case receives is a property of your policy; the false-positive rule, the
`certain` verdict and the never-fire guarantee are properties of the traffic and hold
everywhere. Set `middleware: false` to evaluate without the proof guard, as standalone
mode does.
