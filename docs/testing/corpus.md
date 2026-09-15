# The traffic corpus

Labelled human and hostile traffic, run against your configuration.

← [Documentation](../index.md) · [Testing](index.md)

---

A detector set is a claim about traffic you have not seen yet. Unit tests check that each detector does
what its author intended; they cannot tell you whether the configuration built from those detectors is
safe to put in front of real people. The corpus can, because it is made of real traffic: real
User-Agent strings, real header sets in the order real clients send them, real attack payloads from the
tools and CVEs that named them, each traced to where it came from, and each labelled with what the
honeypot ought to conclude.

```bash
npm run corpus
```

The section to read first is **FALSE POSITIVES**. Everything else is diagnostics; that one is benign
traffic your configuration would have caught in a decoy.

## What is in it

159 cases, 323 requests, in five audiences. The audience is what it costs to be wrong about a case:

| Audience | Cases | Who | Being wrong costs |
| --- | ---: | --- | --- |
| `human` | 38 | every browser engine, mobile, search and forms, single-page apps, privacy browsers, a screen reader, a stripped-header proxy, a shared address, an in-app browser | a customer caught in a decoy: a hard failure |
| `benign-bot` | 26 | search crawlers (10, verified by DNS or published ranges), link unfurlers, uptime monitors, feed readers, SEO crawlers, an archive, GPTBot | ranking, share previews, a monitor that lies about being green |
| `unwanted-bot` | 2 | automation most sites decline but which is not an attack | a business decision; the library only has to not prove it a threat |
| `infrastructure` | 12 | health probes, load-balancer checks, CDN origin pulls, Stripe, GitHub and Shopify webhooks | your own machinery; usually belongs in the allowlist |
| `hostile` | 81 | 9 scanners, 6 wordlist walks, 51 exploits, 6 crawler impersonations, 4 breach replays, 2 traps, credential stuffing, address rotation, a flood | catching these is the point |

Those counts come from `CORPUS` itself, and so will yours after you add a case. The cases live in
`src/corpus/`: `humans.ts`, `benign-bots.ts`, `infrastructure.ts`, `scanners.ts`, `exploits.ts` and
`adversarial.ts`, with the browser and client header profiles in `headers.ts`.

## The invariants

The harness enforces these whatever a case's own expectations say, so a case protects the library the
moment it is added, without anyone remembering to write the assertion.

- **Human: nothing fires.** Any detection on a `human` case is a false positive, proven or not.
- **Benign bots and infrastructure: nothing certain, never blocked, and nothing the case forbids.** A
  `certain` detection, a `block` (or a block the guard downgraded), or a detector named in the case's
  `neverDetectors` is a false positive. A suspicion that stays a suspicion is allowed; these clients are
  often unusual.
- **Hostile: the attack is caught.** Every detector in `expect.detectors` must fire somewhere in the
  case, and `expect.certain` must hold when given.

And one about reporting: a case that needs a capability the engine under test does not provide is
**skipped and reported, never passed**, because "we did not check" and "it passed" must not look the
same.

### Known costs

One human case fires, and passes: `wordpress-author-wp-login`, a real WordPress author signing in at
`/wp-login.php`. That path is a decoy, so `decoy-path` catches them. The library cannot both bait
scanners with the path and serve authors on it. The case is tagged `known-cost` and reported in its own
section rather than hidden; a site that runs WordPress should exclude the path (`ignorePaths` or the
allowlist) or drop that decoy. See [decoys](../detection/decoys.md).

## Two details that make it honest

**Header order is a fingerprint, so the profiles reproduce it.** Chromium leads with `Host`,
`Connection`, `sec-ch-ua…`; Gecko closes with the Fetch Metadata block; `python-requests` sends
`Accept-Encoding` before `Accept`. Headers in a case are an ordered list of pairs, never an object, and
the runner passes that order through as `rawHeaders`. A fixture that invented an order would be testing a
client that does not exist, and `client-anomaly`, `header-integrity` and the [actor
fingerprint](../concepts/actors.md) all read it.

**DNS is controlled, not mocked away.** Each crawler case declares the answers it wants, and the runner
hands the engine a resolver that answers only from that map. A name absent from it is NXDOMAIN, a
definitive negative; a timeout happens only when the case asks for one. So "the operator's DNS disproves
this Googlebot" (an impersonator) and "our resolver was briefly unhappy" (the real Googlebot during a
blip) are both tested, and they reach different verdicts. See [crawler verification](../detection/verification.md).

Time is controlled the same way: every request is evaluated at `start + atMs`, so the sliding-window
detectors (`rate-spike`, `path-bruteforce`, `credential-bruteforce`, `repeat-actor`) run
deterministically in milliseconds. Each case gets a fresh engine, and its own addresses from
`198.18.0.0/15`, so no case inherits another's history.

---

## Running it

```text
$ npm run corpus

──────────────────────────────────────────────────────────────────────────────
  traffic corpus — 159 cases, middleware mode
──────────────────────────────────────────────────────────────────────────────

  FALSE POSITIVES: none. No benign traffic was penalised.

  by audience
    human            38/ 38 pass   allow 37, decoy-content 1
    benign-bot       26/ 26 pass   allow 26
    unwanted-bot      2/  2 pass   allow 2
    infrastructure   12/ 12 pass   allow 12
    hostile          81/ 81 pass   not-found 39, tarpit 34, decoy-content 5, block 2, allow 1

  detector coverage
    scanner-signature           67 cases  █████████
    payload-injection           12 cases  ██
    decoy-path                  11 cases  ██
    header-anomaly               5 cases  █
    crawler-verification         5 cases  █
    ssrf-probe                   4 cases  █
    open-redirect                4 cases  █
    honeytoken                   4 cases  █
    path-bruteforce              3 cases
    sensitive-file               3 cases
    insecure-deserialization     3 cases
    web-shell                    3 cases
    suspicious-method            3 cases
    target-integrity             2 cases
    nosql-injection              2 cases
    prototype-pollution          2 cases
    graphql-abuse                2 cases
    jwt-weakness                 2 cases
    crlf-injection               2 cases
    header-integrity             2 cases
    host-header-injection        2 cases
    trap                         2 cases
    credential-bruteforce        1 cases
    repeat-actor                 1 cases
    rate-spike                   1 cases
    client-anomaly               1 cases

  known costs (1) — people the design knowingly cannot serve cleanly:
    wordpress-author-wp-login -> decoy-path
      This is a genuine cost, written down rather than hidden. /wp-login.php is a decoy, so a legitimate WordPress author who hits it is caught. The library cannot both bait scanners with this path and serve authors on it; a site that runs WordPress should exclude the path (ignorePaths / allowlist) or drop the decoy. Reported as a known cost, not a false positive.
──────────────────────────────────────────────────────────────────────────────
  159/159 cases pass  ·  0 false positives  ·  0 skipped  ·  54ms
──────────────────────────────────────────────────────────────────────────────
```

That is the whole corpus against the default detectors, with the corpus's honeytoken and trap seeded and
crawler verification wired to the controlled resolver and the corpus's fictional crawler ranges. The
timing varies from run to run; nothing else does.

### Reading the scorecard

| Section | What it says |
| --- | --- |
| **False positives** | Benign traffic penalised under the [invariants](#the-invariants), each with what fired and why it counts. Must be none. |
| **By audience** | Pass rate, and the response action the last request of each case received. This is the shape of a policy: how much hostile traffic is blocked, tarpitted or answered with a 404, and that no wanted traffic is touched. |
| **Detector coverage** | How many cases each detector fired on, with a bar, and which installed detectors nothing exercised: a gap in the corpus, not the library, and the detector whose next regression nobody would notice. |
| **Known costs** | Human cases tagged `known-cost` that fired, with the case's note. Reported, not failed. |
| **Skipped** | Cases needing `honeytoken`, `trap`, `crawler-verification` or `published-ranges` when the engine was not given it. |
| **Expectation mismatches** | Every other failure: a hostile case whose detector did not fire, a forbidden detector, a `certain` that did not hold. |

Read the hostile row with [the guard](../concepts/the-guard.md) in mind. In middleware mode only proof may
block, so most hostile cases end in a tarpit or a `not-found`; the two blocks are the gobuster and
feroxbuster wordlist walks. The tally counts the action on each case's **last** request, so `allow 1` is
`wpscan-enumeration`, whose earlier requests fired `decoy-path` and `sensitive-file` and whose final
request fired nothing. It still passes: the case's detectors fired.

### Flags

| Flag | Does |
| --- | --- |
| `--standalone` | evaluate without the proof guard, as the standalone service does |
| `--audience <name>` | only `human`, `benign-bot`, `unwanted-bot`, `infrastructure` or `hostile`; also prints what that audience's stakes are |
| `--tag <tag>` | only cases with a tag: `verification` (10), `ranges` (2), `regression` (1), `known-cost` (1) |
| `--verbose` | add each reported case's provenance to its entry |
| `--json` | the scorecard as JSON: totals, by audience and category, coverage, and the ids of false positives, known costs and skipped cases |

Pass them after `--` with npm (`npm run corpus -- --standalone`), or call `npx tsx scripts/corpus.ts`
directly. The exit code is `1` when there is a false positive or any failure, so it fits in CI as it is.

```text
$ npx tsx scripts/corpus.ts --standalone --audience human

──────────────────────────────────────────────────────────────────────────────
  traffic corpus — 38 cases, standalone mode
──────────────────────────────────────────────────────────────────────────────

  FALSE POSITIVES: none. No benign traffic was penalised.

  by audience
    human            38/ 38 pass   allow 37, decoy-content 1

  detector coverage
    decoy-path     1 cases  █

    not exercised by any case: crawler-verification, payload-injection, ssrf-probe, nosql-injection, prototype-pollution, insecure-deserialization, graphql-abuse, jwt-weakness, crlf-injection, web-shell, header-anomaly, header-integrity, target-integrity, host-header-injection, sensitive-file, open-redirect, suspicious-method, credential-bruteforce, path-bruteforce, scanner-signature, client-anomaly, rate-spike, repeat-actor, honeytoken, trap
    (a gap in the corpus, not the library — an untested detector regresses unnoticed)

  known costs (1) — people the design knowingly cannot serve cleanly:
    wordpress-author-wp-login -> decoy-path
      This is a genuine cost, written down rather than hidden. …
──────────────────────────────────────────────────────────────────────────────
  38/38 cases pass  ·  0 false positives  ·  0 skipped  ·  26ms
──────────────────────────────────────────────────────────────────────────────

  human: A person. Anything firing here is a customer the honeypot would have caught in a decoy — a hard failure.
```

Coverage is computed over the cases that ran, so a filtered run lists nearly every detector as "not
exercised". For people that is the goal. `--tag verification` does the same for the ten genuine
crawlers: `crawler-verification` is listed as not exercised because a verified crawler is served, and
nothing fires on it.

### Middleware and standalone

The corpus runs the way a front end runs, because the same request can deserve different treatment
depending on where the honeypot sits.

| | Middleware (default) | `--standalone` / `middleware: false` |
| --- | --- | --- |
| Blocking | only on proof; an unproven block becomes a tarpit and nothing is blocklisted | a block is allowed on score alone |
| Bodies | a first pass on headers, and a second with the body only when the first fired | one pass with everything |
| `path-bruteforce` | counts a path only once the app answered `404` or a detector fired | counts every path |

That is exactly `src/middleware.ts`. The two modes must catch the same attacks; they differ only in what
an unproven guess is allowed to do. A human false positive is a false positive in both.

---

## Against your own configuration

The script above tests the defaults. The point of the corpus is to test **the configuration you run**:

```ts
import { runCorpus, CORPUS_CRAWLER_RANGES, CORPUS_HONEYTOKEN, CORPUS_TRAP_FIELD, CORPUS_TRAP_PATH } from "@osqd/hackerpot/corpus";
import {
  CrawlerRanges,
  HoneypotEngine,
  crawlerVerificationDetector,
  defaultDetectors,
  honeytokenDetector,
  trapDetector,
  verifiableCrawlers,
} from "@osqd/hackerpot";

const ranges = new CrawlerRanges();
for (const [id, prefixes] of Object.entries(CORPUS_CRAWLER_RANGES)) ranges.update(id, prefixes);

const scorecard = await runCorpus({
  create: ({ resolver }) =>
    new HoneypotEngine({
      enricher: null,
      policy: myPolicy,
      detectors: [
        crawlerVerificationDetector({ resolver, ranges, crawlers: verifiableCrawlers }),
        ...defaultDetectors(),
        ...myDetectors,
        honeytokenDetector({ tokens: [CORPUS_HONEYTOKEN] }),
        trapDetector({ paths: [CORPUS_TRAP_PATH], formFields: [CORPUS_TRAP_FIELD] }),
      ],
    }),
  provides: ["honeytoken", "trap", "crawler-verification", "published-ranges"],
});

if (scorecard.falsePositives.length > 0) {
  throw new Error(`penalises ${scorecard.falsePositives.map((r) => r.case.id).join(", ")}`);
}
```

`runCorpus(options): Promise<Scorecard>`:

| Option | Default | |
| --- | --- | --- |
| `create({ resolver })` | required | builds a fresh engine for each case. Wire `resolver` into `crawlerVerificationDetector`, or the crawler cases resolve against nothing. |
| `cases` | the whole `CORPUS` | a subset; `casesByAudience(audience)` and `casesByTag(tag)` are exported |
| `provides` | `[]` | the capabilities your engine has. Seed the corpus's own honeytoken, trap path and trap field, and its fictional crawler ranges, before you claim them. |
| `middleware` | `true` | `false` evaluates as standalone mode does |
| `startedAt` | a fixed instant | epoch milliseconds the first request of every case is stamped with |

The `Scorecard` has `total`, `passed`, `failed`, `falsePositives`, `knownCosts` and `skipped` (each a list
of `CaseResult` with the case, what `fired`, per-request `detections` and `actionId`, and readable
`failures`), `byAudience`, `byCategory`, `detectorCoverage`, `unexercisedDetectors` and `durationMs`.
`runCorpus` checks the cases first and throws on a duplicate or non-kebab-case id, a missing provenance, a
case with no requests, or a malformed header pair.

Which **action** a case receives is a property of your policy, so expect the hostile row to look
different from the defaults'. The false-positive rule, the `certain` verdict and the never-fire guarantee
are properties of the traffic, and hold for any configuration worth running.

---

## Adding a case

```ts
import { browser, human } from "@osqd/hackerpot/corpus";

human({
  id: "checkout-with-saved-card",
  title: "Chrome on Windows returning to a saved checkout",
  category: "forms",
  provenance: "Chrome 122 on Windows 11, captured from a staging checkout, headers in wire order",
  requests: [browser("chromeWindows", { path: "/checkout", kind: "form-post", cookie: "cart=8f2c" })],
  expect: { neverDetectors: ["client-anomaly"] },
});
```

- **Pick the helper for the audience**: `human()`, `benign()`, `unwanted()`, `infrastructure()` or
  `hostile()`. The audience decides which invariant applies.
- **`provenance` is required** and must say something. A fixture nobody can trace is one nobody can
  update when the world moves.
- **Build requests from the profiles.** `browser(name, options)` gives a real browser's headers in its
  real order (`chromeWindows`, `chromeMac`, `chromeAndroid`, `edgeWindows`, `firefoxWindows`,
  `firefoxAndroid`, `safariMac`, `safariIos`, `samsungInternet`), shaped by `kind` (a navigation, a form
  post, an XHR, a subresource). `client(name, options)` does the same for `curl`, `wget`,
  `pythonRequests`, `pythonUrllib`, `goHttp`, `okhttp`, `nodeFetch` and `javaHttp`. `repeat(request,
  count, everyMs)` spreads a request over time for the rate and enumeration shapes.
- **Several clients** use `from`: the same `from` is one address, a different one is another.
- **A capability the defaults lack** is declared, so an engine without it skips the case:

  ```ts
  requires: ["honeytoken"],
  ```

- **A crawler** pins its address with `ip` and declares the DNS answer that confirms or refutes it:

  ```ts
  requests: [{ ip: "198.51.100.10", headers: [...], httpVersion: "1.1" }],
  dns: { reverse: { "198.51.100.10": ["crawl-198-51-100-10.googlebot.com"] }, forward: { "crawl-198-51-100-10.googlebot.com": ["198.51.100.10"] } },
  ```

Then add it to the audience's array in `src/corpus/`, run `npm run corpus`, and `npm test`:
`tests/corpus.test.ts` runs every case and fails if a default detector has no hostile case expecting it.

A wrongly flagged request from the [dashboard](../operations/dashboard.md) or a [replayed
log](replay.md) is the best source of a new human case: it is real, and it is exactly the shape that
regressed.

---

## Replaying it over real sockets

`runCorpus` calls the engine in process. `npm run simulate:corpus` sends the same cases down real TCP
connections to the running [demo](try-it.md), then asks its management API what fired. That tests what
the in-process run cannot: the HTTP front end, Node's header parsing, whether wire order survives into
`rawHeaders`, and address resolution through `X-Forwarded-For`. A case that passes in process and fails
on the wire has found a front-end bug.

```bash
npm run demo              # terminal 1
npm run simulate:corpus   # terminal 2
```

```text
# corpus — 159 cases over raw sockets, checked against the management API at http://127.0.0.1:9500


  131 passed, 0 failed on the wire.
  2 refused by Node's HTTP parser before reaching the honeypot: request-smuggling-cl-te, missing-host-header
  known cost: wordpress-author-wp-login (fired decoy-path)
  9 skipped: is paced over time, which only the in-process clock reproduces
  12 skipped: needs crawler-verification
  3 skipped: needs crawler-verification, published-ranges
  1 skipped: is HTTP/2, which this raw HTTP/1.1 client cannot send
```

On the wire a human case passes when nothing fired from its addresses, and any other case passes when
every expected detector fired; the benign invariants about `certain` and blocking are the in-process
run's job. What is not replayed, and why:

| Reported | Why |
| --- | --- |
| refused by Node's HTTP parser | every request drew a `400` and nothing reached the honeypot: the smuggling framing and the request with no `Host`. That is the parser protecting the application. |
| paced over time | a request more than five seconds into its case; only the in-process clock reproduces it without waiting |
| needs crawler-verification, published-ranges | the demo loads no controlled DNS and no corpus ranges |
| declares its own DNS answers | the same reason |
| is HTTP/2 | the replayer speaks HTTP/1.1 |

The demo seeds the corpus's honeytoken and trap, so those cases do run. Addresses come from the same
`addressFor(caseIndex, from)` the in-process run uses. `npm run simulate:corpus:human` replays only the
human cases, and `--verbose` prints a line for every passing case too. The exit code is `1` on any wire
failure, or when the management API does not answer.

---

## Related

- [Try it locally](try-it.md): the demo the wire replay runs against, and the attack simulator
- [Replaying your logs](replay.md): the same question, asked of your own traffic
- [The guard](../concepts/the-guard.md): why middleware mode tarpits what standalone mode blocks
- [Traps and honeytokens](../detection/traps-and-honeytokens.md): the capabilities the corpus seeds
- [The course](../course/index.md)
