# Lesson 15 — Proving it

**Goal:** find out who Pantry's configuration would catch *before* it catches them — one
request at a time, over yesterday's log, and against labelled human and hostile traffic.

← [Course](index.md) · Prev: [Extending it](14-extending.md) · Next: [The capstone](16-capstone.md)

---

## The question this library is organised around

*If I mount this configuration in front of Pantry, who gets caught who should not?*

Four tools answer it, cheapest first, and they answer different halves:

| | Answers |
| --- | --- |
| `hackerpot explain` | Why was this one request flagged, or not? |
| `hackerpot replay` | What would these detectors have made of yesterday's traffic? |
| `runCorpus` | Against labelled human and hostile traffic, does anything misfire? |
| the demo and the simulator | What does it look like working, end to end? |

## `explain` — the question that arrives by ticket

A reader writes in: Pantry is slow for them. Paste what you have into `explain`: a
User-Agent, a `curl` command copied from a browser's developer tools, or a block of raw
headers. Run these in `pantry/`, where lesson 11's `hackerpot.toml` is.

```bash
npx hackerpot explain "sqlmap/1.7.2#stable" --url /.env
npx hackerpot explain "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36" --url "/recipes?q=union+station"
npx hackerpot explain "curl 'https://pantry.example/api/recipes?id=1%27%20OR%20%271%27=%271' -H 'accept: application/json'"
```

### Checkpoint

```
Request   GET /.env
From      203.0.113.10, User-Agent "sqlmap/1.7.2#stable"

2 detector(s) fired, score 16:
  +10  decoy-path               Exposed .env file probe
  +6   scanner-signature        User-Agent matches known tooling signature: sqlmap/1.7.2#stable  [proof]

Response  decoy-content
```

```
Request   GET /recipes (1 query parameter(s))
From      203.0.113.10, User-Agent "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

No detector fired. The honeypot would leave this request alone.
```

```
Request   GET /api/recipes (1 query parameter(s))
From      203.0.113.10, User-Agent "curl/8.4.0"

2 detector(s) fired, score 16:
  +10  payload-injection        sql-injection payload detected in query.id
  +6   scanner-signature        User-Agent matches known tooling signature: curl/8.4.0

Response  tarpit
```

The reader searching for "union station" is left alone: a query that merely resembles SQL
is not a payload.

`explain` is a **dry run** on an engine of its own, with a fresh store and no history, so it
answers *what would this look like as a first request* — which is what a ticket is usually
asking. The volume detectors therefore never fire here. It binds nothing and looks nothing
up: `crawler-verification` gets a resolver that answers nothing, so a crawler claim reads as
unverifiable rather than refuted.

## `replay` — against traffic that is actually yours

The corpus below knows what the internet looks like. Only Pantry's logs know what *Pantry's*
visitors look like. `pantry/access.log`, twelve lines of an ordinary morning:

```
198.51.100.7 - - [15/Sep/2026:09:00:01 +0000] "GET / HTTP/1.1" 200 5120 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
198.51.100.7 - - [15/Sep/2026:09:00:03 +0000] "GET /recipes/42 HTTP/1.1" 200 8812 "https://pantry.example/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
198.51.100.7 - - [15/Sep/2026:09:00:09 +0000] "GET /admin HTTP/1.1" 200 2210 "https://pantry.example/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
192.0.2.10 - - [15/Sep/2026:09:01:00 +0000] "GET /healthz HTTP/1.1" 200 2 "-" "UptimeMonitor/2.1"
203.0.113.9 - - [15/Sep/2026:09:02:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"
203.0.113.9 - - [15/Sep/2026:09:02:01 +0000] "GET /.git/config HTTP/1.1" 404 0 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"
203.0.113.9 - - [15/Sep/2026:09:02:02 +0000] "GET /recipes?id=1'%20OR%20'1'='1 HTTP/1.1" 200 0 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"
203.0.113.9 - - [15/Sep/2026:09:02:03 +0000] "GET /.aws/credentials HTTP/1.1" 404 0 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"
192.0.2.44 - - [15/Sep/2026:09:03:00 +0000] "GET /.env HTTP/1.1" 404 0 "-" "curl/8.4.0"
192.0.2.44 - - [15/Sep/2026:09:03:01 +0000] "GET /.git/config HTTP/1.1" 404 0 "-" "curl/8.4.0"
192.0.2.44 - - [15/Sep/2026:09:03:02 +0000] "GET /.aws/credentials HTTP/1.1" 404 0 "-" "curl/8.4.0"
192.0.2.44 - - [15/Sep/2026:09:03:03 +0000] "GET /.ssh/id_rsa HTTP/1.1" 404 0 "-" "curl/8.4.0"
```

```bash
npx hackerpot replay access.log
```

### Checkpoint

```
Replayed 12 log lines: 12 parsed, 0 skipped (unrecognised format).
Flagged 8 requests (66.7%).

By detector:
  scanner-signature          8
  decoy-path                 7
  payload-injection          1

Responses it would have sent:
  decoy-content              4
  block                      2
  tarpit                     2

Blocks refused for lack of proof: 2

Top sources:
  203.0.113.9                4 flagged of 4 requests, total score 64
  192.0.2.44                 4 flagged of 4 requests, total score 64
```

Read it as requests, not as percentages. The reader's three lines were not flagged — including
`/admin`, because lesson 11's file drops that decoy. The monitor was not flagged. The two
blocks are `sqlmap`, which is proof. The two tarpits are `curl` crossing the block line twice
with nothing but suspicion. If an address under *Top sources* is a person, a monitor or a
partner, that is the finding, and you learned it from a log file rather than from a support
ticket. `--json` prints the same summary for a script.

**A replay under-reports, and its silence is not a clean bill of health.** A log line carries a
User-Agent and a Referer at most, and no body. Detectors that reason from a *missing* header
stand down on replayed requests — a header missing from a record is not a header missing from
the request — and body detectors see nothing. Configure the access log as JSON Lines with the
headers you care about, and the replay sees more.

## The corpus — against traffic you do not have yet

The package ships a labelled traffic corpus: real browser profiles in the order real browsers
send their headers, crawlers with controlled DNS, infrastructure, scanners, exploit payloads.
Each case has an audience, and the harness applies one rule regardless of what the case
expects: **nothing may fire on a case marked `human`.**

It runs against **your** configuration, so Pantry's detector set belongs in one module that
both the server and its tests import. `pantry/pantry-honeypot.mjs`:

```js
import {
  HoneypotEngine,
  crawlerVerificationDetector,
  decoyPathDetector,
  defaultDecoyPaths,
  defaultDetectors,
  honeytokenDetector,
  trapDetector,
} from "@osqd/hackerpot";

export const PANTRY = {
  honeytokens: [{ value: "AKIA_PANTRY_7Q2XK4", label: "decoy-env-aws-key" }],
  trapPath: "/internal/export.csv",
  trapField: "website",
  realRoutes: ["admin-panel", "swagger"],   // decoys Pantry serves for real
};

/** Pantry's detector set. `extra` lets a test watch for its own planted values too. */
export function pantryDetectors({ resolver, ranges, extra = {} } = {}) {
  const decoys = defaultDecoyPaths.filter((d) => !PANTRY.realRoutes.includes(d.id));
  return [
    crawlerVerificationDetector({ ...(resolver ? { resolver } : {}), ...(ranges ? { ranges } : {}) }),
    ...defaultDetectors().map((d) => (d.id === "decoy-path" ? decoyPathDetector(decoys) : d)),
    honeytokenDetector({ tokens: [...PANTRY.honeytokens, ...(extra.honeytokens ?? [])] }),
    trapDetector({ paths: [PANTRY.trapPath, ...(extra.trapPaths ?? [])], formFields: [PANTRY.trapField, ...(extra.trapFields ?? [])] }),
  ];
}

export function createPantryEngine(options = {}) {
  const { resolver, ranges, extra, ...config } = options;
  return new HoneypotEngine({ ...config, detectors: pantryDetectors({ resolver, ranges, extra }) });
}
```

`crawler-verification` comes first so a verified crawler is known before the volume detectors
run.

`pantry/lesson-15.mjs`:

```js
import { CrawlerRanges } from "@osqd/hackerpot";
import { CORPUS, CORPUS_CRAWLER_RANGES, CORPUS_HONEYTOKEN, CORPUS_TRAP_FIELD, CORPUS_TRAP_PATH, runCorpus } from "@osqd/hackerpot/corpus";
import { createPantryEngine } from "./pantry-honeypot.mjs";

const ranges = new CrawlerRanges();
for (const [id, prefixes] of Object.entries(CORPUS_CRAWLER_RANGES)) ranges.update(id, prefixes);

const scorecard = await runCorpus({
  create: ({ resolver }) =>
    createPantryEngine({
      enricher: null,
      resolver,
      ranges,
      // The corpus plants values of its own; watch for them beside Pantry's.
      extra: { honeytokens: [CORPUS_HONEYTOKEN], trapPaths: [CORPUS_TRAP_PATH], trapFields: [CORPUS_TRAP_FIELD] },
    }),
  provides: ["honeytoken", "trap", "crawler-verification", "published-ranges"],
});

console.log(`${CORPUS.length} cases: ${scorecard.passed} passed, ${scorecard.failed} failed, ${scorecard.skipped.length} skipped`);
for (const [audience, tally] of Object.entries(scorecard.byAudience)) {
  console.log(`  ${audience.padEnd(15)} ${String(tally.passed).padStart(3)}/${String(tally.total).padEnd(3)} ${JSON.stringify(tally.actions)}`);
}
console.log("false positives:", scorecard.falsePositives.map((r) => r.case.id));
console.log("known costs:    ", scorecard.knownCosts.map((r) => r.case.id));
for (const r of scorecard.results.filter((r) => r.failures.length > 0)) console.log("  x", r.case.id, r.failures.join("; "));
```

### Checkpoint

```
159 cases: 159 passed, 0 failed, 0 skipped
  human            38/38  {"allow":37,"decoy-content":1}
  benign-bot       26/26  {"allow":26}
  unwanted-bot      2/2   {"allow":2}
  infrastructure   12/12  {"allow":12}
  hostile          81/81  {"not-found":39,"block":2,"tarpit":34,"allow":1,"decoy-content":5}
false positives: []
known costs:     [ 'wordpress-author-wp-login' ]
```

Three things the harness controls that a live deployment does not, and why they matter:

- **DNS.** No lookup leaves the process. Each case declares its own answers and `create` is
  handed a resolver built from them, so "the operator's DNS disproves this claim" and "our
  resolver was briefly unhappy" can be told apart — they must reach different verdicts.
- **Time.** Each request carries an explicit `now`, so the sliding-window detectors are
  exercised deterministically, the way [lesson 9](09-actors-and-volume.md) did by hand.
- **Capabilities.** A case needing a honeytoken, a trap or published ranges is **skipped and
  reported** if you do not say the engine provides it, never passed. "We did not check" and
  "it passed" must not look the same. That is why the corpus's own planted values are added
  through `extra`.

**The one human who fired is a known cost, not a false positive**: a WordPress author at
`/wp-login.php`, which is a decoy. The library cannot both bait scanners with that path and
serve authors on it, and it writes the cost down rather than hiding it. Pantry does not run
WordPress, so Pantry accepts it.

`runCorpus` is also a published entry point for a reason: the capstone puts it in Pantry's
test suite.

## Exercise

A colleague has a theory: most of Pantry's scrapers are Android phones. They propose adding
`/Android/` to `scanner-signature`'s patterns. Before arguing, run the corpus against it.

<details>
<summary>Checkpoint</summary>

```js
import { HoneypotEngine, defaultDetectors, scannerSignatureDetector } from "@osqd/hackerpot";
import { runCorpus } from "@osqd/hackerpot/corpus";

// A colleague's idea: "most of our scrapers are Android phones".
const scorecard = await runCorpus({
  create: () =>
    new HoneypotEngine({
      enricher: null,
      detectors: defaultDetectors().map((d) => (d.id === "scanner-signature" ? scannerSignatureDetector({ extraPatterns: [/Android/] }) : d)),
    }),
});
console.log(`false positives: ${scorecard.falsePositives.length}`);
for (const r of scorecard.falsePositives) console.log(`  ${r.case.id}: ${r.failures.at(-1)}`);
```

```
false positives: 7
  chrome-android-home: FALSE POSITIVE: a person had scanner-signature fire (on suspicion)
  samsung-internet-home: FALSE POSITIVE: a person had scanner-signature fire (on suspicion)
  firefox-android-home: FALSE POSITIVE: a person had scanner-signature fire (on suspicion)
  cgnat-shared-address: FALSE POSITIVE: a person had scanner-signature fire (on suspicion)
  in-app-webview-support-contact: FALSE POSITIVE: a person had scanner-signature fire (on suspicion)
  emoji-search: FALSE POSITIVE: a person had scanner-signature fire (on suspicion)
  samsung-product-page: FALSE POSITIVE: a person had scanner-signature fire (on suspicion)
```

Seven people, including a reader on a mobile carrier's shared address and one opening a
support link inside another app. The argument is over, and it was over in the time it took to
run a script rather than after a week of support tickets.

Note "(on suspicion)": a pattern you add is never proof, so the guard would have stopped these
readers being blocked. They would still have been tarpitted and recorded as attackers, and
Pantry's alerting would have told you about them.
</details>

## Watching it work

A clone of the repository has a demo that runs every listener and the dashboard at once, and a
simulator that fires a realistic attack for each detector at it:

```bash
npm run demo              # terminal 1: honeypot, dashboard, management API, SSH, SMTP, FTP, Telnet
npm run simulate          # terminal 2: every scenario
npm run simulate:list     # what there is
```

```
decoys                     paths only an attacker would know: .env and its variants, .git, cloud credentials, framework debug endpoints
path-bruteforce            a wordlist walk: twenty paths that do not exist, fast
credential-bruteforce      ten guesses against one login endpoint
rate-spike                 eighty requests at once from one address
scanner-signature          tools that announce themselves in the User-Agent
…
ssh                        password brute force
ftp                        brute force, an FTP bounce and a traversal
telnet                     the default credentials the Mirai lineage sprays, then a dropper
```

Open the dashboard the demo prints while the simulator runs; that is the view the operator of a
real Pantry has. `npm run corpus` runs the same corpus as above against the default detectors and
prints a scorecard ending:

```
  159/159 cases pass  ·  0 false positives  ·  0 skipped  ·  54ms
```

(the duration will differ). `npm run simulate:corpus` sends the corpus down real sockets, which
tests what the in-process run cannot: the HTTP front end and Node's header parsing.

## The order to use them in

1. **`explain`** — one request, when somebody writes in
2. **`runCorpus`** — in CI, on every change to the configuration
3. **`replay`** — before mounting anything, over a real week of logs
4. **[shadow mode](13-scaling.md)** — for any new or retuned detector, on live traffic, for a week

The first three do not replace the fourth. A replay sees neither bodies nor most headers; a
corpus is not your audience. Shadow mode is the only one that sees today's traffic in full.

## What you learned

- `explain` is a dry run with no history; it answers what a ticket is asking
- `replay` evaluates each line at its logged time with middleware rules, and under-reports
- The corpus runs against your configuration, with controlled DNS and time, and skips what it cannot check
- A known cost is written down; a false positive fails
- An idea about detection is a hypothesis until the corpus has run against it

## Where to read more

- [The command line](../testing/cli.md#explain) · [Replaying your logs](../testing/replay.md)
- [The traffic corpus](../testing/corpus.md) · [Try it locally](../testing/try-it.md)
- [Testing overview](../testing/index.md)

Next: [The capstone](16-capstone.md).
