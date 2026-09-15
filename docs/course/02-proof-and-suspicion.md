# Lesson 2 — Proof and suspicion

**Goal:** understand the distinction the entire library is built on, and why every other
design decision follows from it.

← [Course](index.md) · Prev: [Your first detection](01-first-detection.md) · Next: [Scores and responses](03-scores-and-responses.md)

---

## The problem every honeypot in front of real users has

Most of what a honeypot sees is *suspicious* rather than *conclusive*. A scripting
User-Agent is suspicious, and it is also every monitoring script. A burst of distinct
paths is enumeration, and it is also one page load of a modern single-page app. An
injection-shaped query is an attack, and it is also somebody searching Pantry for
"union station sourdough".

Standalone, on an address nothing links to, that hardly matters: whatever arrives was not
invited. In front of Pantry it is the whole question, because a block does not refuse one
request. It refuses every later request from that address, Pantry's own recipe pages
included.

The usual answer is to add the signals into a score and block above a threshold. **Points
do not compose into proof.** Two unrelated suspicions about an ordinary visitor reach the
threshold as readily as two well-founded ones.

So every detection is one of two kinds.

| | Proof (`certain: true`) | Suspicion |
| --- | --- | --- |
| Rests on | something no legitimate client can produce | a pattern attackers usually show |
| Can it be wrong about a real visitor? | only if the deployment broke its own guarantee | yes |
| Adds to the score | yes | yes |
| Can make a block stick in front of an app | **yes** | **no** |

## See it

`pantry/lesson-02.mjs`:

```js
import { HoneypotEngine } from "@osqd/hackerpot";

const engine = new HoneypotEngine();
const ask = (ip, userAgent) =>
  engine.evaluate({ method: "GET", path: "/.env", query: {}, headers: { host: "pantry.example", "user-agent": userAgent }, ip });

for (const [ip, ua] of [["203.0.113.10", "curl/8.4.0"], ["203.0.113.11", "sqlmap/1.7.2#stable (https://sqlmap.org)"]]) {
  const result = await ask(ip, ua);
  console.log(ua);
  for (const d of result.detections) console.log(`  ${String(d.certain === true).padEnd(5)} +${d.score} ${d.detectorId}`);
}
```

### Checkpoint

```
curl/8.4.0
  false +10 decoy-path
  false +6 scanner-signature
sqlmap/1.7.2#stable (https://sqlmap.org)
  false +10 decoy-path
  true  +6 scanner-signature
```

The same detector, the same score, and a different kind of evidence. `sqlmap` naming
itself is the client's own statement of what it is, and nobody honest is harmed by being
believed. `curl` is also every legitimate script and integration Pantry's API has.

And note the first column for `decoy-path`: **false** in both. A request for `/.env` looks
conclusive and is not. A URL is text the client typed, and the client typing it might be
your own security engineer checking the site.

## The five things that earn `certain`

1. **A replayed honeytoken** (`honeytoken`). A fake credential you planted. No legitimate
   client was ever given it — [lesson 7](07-traps-and-honeytokens.md).
2. **A hidden trap** (`trap`). A link or form field no sequence of clicks, keystrokes or
   screen-reader gestures reaches, disallowed in robots.txt. Detection by construction —
   [lesson 7](07-traps-and-honeytokens.md).
3. **A protocol violation no client stack emits** (`header-integrity`): a repeated `Host` or
   `Content-Length`, or a connection-specific header over HTTP/2. A client that sends one
   cannot talk to a compliant proxy.
4. **A self-declared attack tool** (`scanner-signature`): `sqlmap`, `nikto`, `nuclei`,
   `gobuster` and the rest. A bare `curl` or `python-requests` is only suspicion.
5. **A refuted crawler claim** (`crawler-verification`): "Googlebot" from an address
   Google's DNS disowns — [lesson 8](08-identity.md).

## What does not

Everything else, including findings that look conclusive: a decoy path, an injection
payload, volume from one address (a university is one address), a missing header (a proxy
may have stripped it), and one fingerprint across several addresses (every user of one
browser build shares it).

> **If you cannot write down, in one sentence, why no legitimate client could produce the
> finding, it is suspicion.**

That sentence is the test every built-in detector passed or failed, and it is the test
you will apply to your own in [lesson 14](14-extending.md).

## One cause, counted once

A request's score is the sum of its detections, with one exception. A detection may carry
a **`family`**, a shared root cause, and within a family only the highest score counts.

`pantry/lesson-02b.mjs`:

```js
import { HoneypotEngine } from "@osqd/hackerpot";
import { CHROME } from "./browser.mjs";

const engine = new HoneypotEngine();
const result = await engine.evaluate({
  method: "GET",
  path: "/recipes/..%2f..%2fetc/passwd",
  query: {},
  headers: CHROME,
  ip: "203.0.113.30",
});
for (const d of result.detections) console.log(`${d.detectorId.padEnd(18)} +${String(d.score).padEnd(3)} family ${d.family ?? "-"}`);
console.log("path ", result.path);
console.log("score", result.score);
```

### Checkpoint

```
payload-injection  +10  family path-traversal
target-integrity   +7   family path-traversal
path  /etc/passwd
score 10
```

Two detectors saw one act. `payload-injection` saw a traversal payload; `target-integrity`
saw a target spelled to slip past a path filter. Adding both would score one encoded
traversal as two independent reasons, so the score is 10, not 17.

Note `path`: the engine decoded the target once and resolved its dot segments before any
detector ran, so every detector matched `/etc/passwd`. The spelling as sent survives for
the one detector that cares how a target was written.

## Exercise

Answer these without running anything.

1. A `curl` client walks ten decoys and reaches a total of 90. Is any of that proof?
2. Pantry's login is hit by the same password forty times in a minute from one address.
   Can that be `certain`?

<details>
<summary>Answers</summary>

1. **No.** Every detection is `decoy-path` or `scanner-signature` on `curl`, and neither is
   proof. Ninety points of suspicion are still suspicion. [Lesson 4](04-the-guard.md) shows
   what the engine does when a policy asks to block on them.

2. **No.** Try the sentence: "no legitimate client could send the same password forty
   times from one address in a minute". A shared office behind one NAT address, or one
   person with a broken password manager, produces exactly that. It is a strong signal,
   and `credential-bruteforce` scores it 9 — as suspicion.
</details>

## What you learned

- Detections are proof or suspicion, and only proof may close a door in front of real users
- Exactly five things earn `certain`, and a decoy path is not one of them
- The test is one sentence: why could no legitimate client produce this?
- One root cause counts once, through `family`

## Where to read more

- [The proof guard](../concepts/the-guard.md) — the model in full, and what counts as proof
- [Scores and escalation](../concepts/scoring.md) — families and accumulation
- [Threat model](../concepts/threat-model.md) — what it costs to be wrong in each direction

Next: [Scores and responses](03-scores-and-responses.md).
