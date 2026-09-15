# Lesson 5 — The detectors

**Goal:** know what each detector reads, what it scores and whether it can be proof — then
turn one off and watch the score move.

← [Course](index.md) · Prev: [The guard](04-the-guard.md) · Next: [Decoys](06-decoys.md)

---

## What is installed

`pantry/lesson-05.mjs`:

```js
import { HoneypotEngine } from "@osqd/hackerpot";

const engine = new HoneypotEngine();
for (const d of engine.detectors) console.log(`${d.id.padEnd(26)} ${d.needsBody ? "body" : "headers"}`);
console.log(`\n${engine.detectors.length} detectors`);
```

### Checkpoint

```
decoy-path                 headers
payload-injection          body
ssrf-probe                 body
nosql-injection            body
prototype-pollution        body
insecure-deserialization   body
graphql-abuse              body
jwt-weakness               headers
crlf-injection             headers
web-shell                  headers
header-anomaly             headers
header-integrity           headers
target-integrity           headers
host-header-injection      headers
sensitive-file             headers
open-redirect              headers
suspicious-method          headers
credential-bruteforce      headers
path-bruteforce            headers
scanner-signature          headers
client-anomaly             headers
rate-spike                 headers
repeat-actor               headers

23 detectors
```

**Twenty-three ship on by default.** Three more ship **off** — `honeytoken`, `trap` and
`crawler-verification` — each because it needs something from you: the values you
planted, markup you hid, or permission to make DNS lookups. You switch all three on in
lessons 7 and 8.

The command line answers the same question for a configuration file, which is the reliable
answer once you have one:

```bash
npx hackerpot detectors
```

```
…
rate-spike                 headers         Abnormally high request rate from a single IP
repeat-actor               headers         One actor fingerprint seen attacking from several distinct IPs (IP rotation)

23 detectors installed from <defaults>.
```

## Headers, and body

The second column matters more than it looks. In front of Pantry, reading a request body
consumes the stream Pantry's own routes need. So a request is judged on its **headers
first**, and the body is read — and the body detectors run — only if something already
fired. A request that is clean on its headers and hostile only in its body therefore
reaches Pantry untouched.

That is a trade, stated rather than hidden: the honeypot is a detection layer, not a
request filter. Standalone, with nothing behind it, the body is read up front.

## Four kinds

| Kind | Reads | Examples |
| --- | --- | --- |
| **per-request** | this request alone | `decoy-path`, `payload-injection`, `header-integrity` |
| **stateful** | this address's recent activity | `rate-spike`, `path-bruteforce`, `credential-bruteforce` |
| **correlating** | the registry of suspicious fingerprints | `repeat-actor` |
| **verifying** | DNS or published address ranges | `crawler-verification` |

## What each one scores, and which can be proof

| Detector | Catches | Score | Proof |
| --- | --- | --- | --- |
| `decoy-path` | bait paths only an attacker would know | per decoy, 3–10 | no |
| `payload-injection` | traversal, SQLi, XSS, command and template injection, Log4Shell | 10 | no |
| `ssrf-probe` | a value pointing the server at metadata, loopback or `file://` | 9 | no |
| `nosql-injection` | MongoDB operators in a query key or JSON body | 9 | no |
| `prototype-pollution` | `__proto__` or `constructor.prototype` | 8 | no |
| `insecure-deserialization` | a serialized-object blob in query, cookie or body | 9 | no |
| `graphql-abuse` | introspection, pathologically deep queries | 7 | no |
| `jwt-weakness` | a JWT with `alg:none` or no signature | 9 | no |
| `crlf-injection` | a CRLF smuggled into path, query or header | 8 | no |
| `web-shell` | web-shell filenames and command-exec parameters | 9 | no |
| `header-anomaly` | Shellshock, CL+TE smuggling, absolute targets, missing Host | 7–10 | no |
| `header-integrity` | repeated framing headers, connection headers over HTTP/2 | 9 | **yes** |
| `target-integrity` | a target spelled to evade path filters | 7 or 3 | no |
| `host-header-injection` | a malformed, duplicated or off-list Host | 6 | no |
| `sensitive-file` | backups, dumps, VCS and IDE metadata | 6 | no |
| `open-redirect` | a redirect parameter carrying an off-site target | 5 | no |
| `suspicious-method` | WebDAV, `TRACE`, `DEBUG`, `CONNECT` | 6 | no |
| `credential-bruteforce` | repeated attempts against one login endpoint | 9 | no |
| `path-bruteforce` | many distinct paths in a short window | 8 | no |
| `scanner-signature` | scanner and scripting-client User-Agents | 6 | **attack tools** |
| `client-anomaly` | a browser User-Agent missing every browser header | 4 | no |
| `rate-spike` | an abnormal request rate | 4 | no |
| `repeat-actor` | one fingerprint attacking from several addresses | 7 | no |
| `honeytoken` | a planted credential, replayed | 15 | **yes**, off by default |
| `trap` | a hidden link, field or header | 15 | **yes**, off by default |
| `crawler-verification` | a crawler claim DNS or ranges refute | 10 | **yes**, off by default |

Scores are small integers chosen by hand: 3–5 for a finding with ordinary innocent
explanations, 6–8 for a clear probe, 9–10 for an exploit payload, 15 for something no
legitimate client can produce.

## Do this: turn one off

`pantry/lesson-05b.mjs`:

```js
import { HoneypotEngine, defaultDetectors } from "@osqd/hackerpot";

const probe = { method: "GET", path: "/.env", query: {}, headers: { host: "pantry.example", "user-agent": "curl/8.4.0" }, ip: "203.0.113.10" };

const withAll = new HoneypotEngine();
const without = new HoneypotEngine({ detectors: defaultDetectors().filter((d) => d.id !== "scanner-signature") });

console.log("with   ", (await withAll.evaluate(probe)).score);
console.log("without", (await without.evaluate(probe)).score);
```

### Checkpoint

```
with    16
without 10
```

The six points `curl` earned by naming itself are gone, and `decoy-path` stands alone.

Note that `detectors:` **replaces** the set entirely. To add without removing anything,
use `extraDetectors`, which is appended to the defaults (and ignored when `detectors` is
given).

## A detector that fails is skipped, not the request

Each detector runs in its own `try`. One that throws is skipped for that request, reported
through `onError` with its id, and counted in `hackerpot_detector_failures_total`. An
asynchronous one that takes longer than `detectorTimeoutMs` (2000 by default) is treated
the same way. A honeypot that fails closed in front of an application is an outage.

## Exercise

Pantry emails password-reset links built from the request's `Host`, which is exactly what
a Host-header injection poisons. Configure `host-header-injection` so that only
`pantry.example` is expected, and try three `POST /password-reset` requests: one to
`pantry.example`, one to `pantry.example:443`, and one claiming `evil.example`.

<details>
<summary>Checkpoint</summary>

```js
import { HoneypotEngine, defaultDetectors, hostHeaderInjectionDetector } from "@osqd/hackerpot";
import { CHROME } from "./browser.mjs";

const engine = new HoneypotEngine({
  detectors: defaultDetectors().map((d) =>
    d.id === "host-header-injection" ? hostHeaderInjectionDetector({ expectedHosts: ["pantry.example"] }) : d,
  ),
});

for (const host of ["pantry.example", "pantry.example:443", "evil.example"]) {
  const r = await engine.evaluate({ method: "POST", path: "/password-reset", query: {}, headers: { ...CHROME, host }, ip: "203.0.113.70" });
  console.log(host.padEnd(20), r.detections.map((d) => `${d.detectorId} +${d.score}: ${d.reason}`).join("; ") || "nothing fired");
}
```

```
pantry.example       nothing fired
pantry.example:443   nothing fired
evil.example         host-header-injection +6: Host "evil.example" is not an expected hostname
```

Replacing one detector inside the default list is the pattern to remember: `map` over
`defaultDetectors()` and swap the one you are configuring.

The port is stripped before comparison, which is why `pantry.example:443` passes — and why
an `expectedHosts` entry written *with* a port could never match anything. Without the
list, only structural problems fire, because behind a proxy a differing host is normal.
</details>

## What you learned

- Twenty-three detectors are on by default; three that need something from you are off
- Headers first, body only for requests something already flagged
- Four kinds: per-request, stateful, correlating, verifying
- Five detectors can produce proof: two on by default (one only for attack tools), three off
- `detectors` replaces; `extraDetectors` adds; a failing detector is skipped

## Where to read more

- [The detectors](../detection/detectors.md) — every detector, every option
- [Detection overview](../detection/index.md) — normalisation, and settings every detector shares
- [How it works](../concepts/how-it-works.md#two-passes-so-a-body-is-never-read-for-nothing) — the two passes

Next: [Decoys](06-decoys.md).
