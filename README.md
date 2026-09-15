# 🍯 hackerpot

**A customizable honeypot for TypeScript/Node.** Plant convincing decoys, detect
the probes and exploits that hit them, retaliate (block, tarpit, waste bandwidth),
and stream every incident to your own tooling — as a library inside your existing
server, or as a standalone service in front of it.

hackerpot is built to be **safe to run next to production**: requests that don't
match a trap fall straight through untouched, detection and response are fully
decoupled and individually configurable, and the operator API that exposes captured
data runs on its own private listener, never mixed with the attacker-facing port.

```bash
npm install                        # get set up
npm run dev:gui                    # honeypot :4004 + management API :9500 + GUI :8080
npm run attack:all                 # simulate every attack type against it (2nd terminal)
```

---

## Contents

- [What it is (and isn't)](#what-it-is-and-isnt)
- [Quick start](#quick-start)
- [Installation & setup](#installation--setup)
- [How it works](#how-it-works) — the request lifecycle, scoring, escalation
- [Detectors](#detectors) — every detector and its options
- [Response actions](#response-actions) — every retaliation and its options
- [The scoring policy](#the-scoring-policy)
- [Stores](#stores) — where incidents and scores live
- [Actor fingerprinting & cross-IP correlation](#actor-fingerprinting--cross-ip-correlation)
- [Source-IP enrichment](#source-ip-enrichment)
- [Threat-intel ingest](#threat-intel-ingest-consuming-other-honeypots-ioc-feeds) — consuming other honeypots' IOC feeds
- [Protocol honeypots](#mail-defense--smtp-honeypot) — SMTP, SSH, FTP, Telnet
- [Deployment modes](#deployment-modes) — middleware, programmatic, standalone
- [Configuration reference](#configuration-reference) — the full TOML surface
- [Environment variables](#environment-variables)
- [Incidents management API](#incidents-management-api) — REST, WebSocket, webhooks
- [Alert sinks](#alert-sinks) — Slack, Discord, syslog/SIEM
- [The dashboard](#the-dashboard)
- [nginx edge capture](#nginx-edge-capture)
- [Docker](#docker)
- [Data shapes](#data-shapes) — what an incident looks like
- [Testing & the attack simulator](#testing--the-attack-simulator)
- [Extending hackerpot](#extending-hackerpot) — custom detectors, responses, stores
- [Project layout](#project-layout)
- [Development](#development)
- [License](#license)
- [Security notes](#security-notes)

---

## What it is (and isn't)

A **honeypot** is bait. It exposes things an attacker wants — a leaked `.env`, an
admin panel, a database backup — that a legitimate user would never request. Anyone
who touches them has, by definition, revealed themselves. hackerpot turns that
signal into structured incidents you can act on, and (optionally) makes the
attacker's life harder while they're engaged.

**hackerpot is:**

- A **detection layer** — it recognizes probes, enumeration, brute force, scanners,
  injection payloads, protocol abuse, port sweeps, and the replay of seeded
  credentials.
- A **response layer** — it can serve convincing fakes, block, tarpit, drip-feed,
  or dump large payloads at an attacker, escalating as suspicion grows.
- An **observability layer** — every incident is scored, stored, and available over
  a REST API, a live WebSocket feed, and webhooks.

**hackerpot is not:**

- A replacement for real access control, a WAF, or authentication. Decoys detect
  and slow down recon; they are not a security boundary. Keep your real defenses.
- A high-interaction honeypot. It emulates responses; it does not stand up real
  vulnerable services for an attacker to fully exploit.

---

## Quick start

Prerequisites: **Node.js ≥ 20** and npm.

```bash
git clone <this-repo> hackerpot && cd hackerpot
npm install
```

No build step: the dev commands below run straight from the TypeScript sources via
`tsx`. Build only when you want the compiled service or the library — `npm run build`,
or `npm run build:gui` to compile and launch in one go.

Start everything — the honeypot, the port-scan sentinel, the SMTP and SSH honeypots,
the management API, and the web dashboard — with one command:

```bash
npm run dev:gui
#
#   hackerpot is up
#
#   dashboard   http://127.0.0.1:8080
#   honeypot    http://localhost:4004
#   management  http://127.0.0.1:9500
#   API key     dev-key  (pre-filled)
```

The banner appears only once the management API actually answers, so the dashboard URL
is live the moment you see it, and the API key is already filled in — open the link and
it is connected. `Ctrl-C` stops both halves together.

In a second terminal, throw the whole attack catalogue at it:

```bash
npm run attack:all
```

That's the entire loop: bait → detect → score → respond → observe.

Prefer the two halves in separate terminals (independent restarts, separate logs)?
`npm run dev` and `npm run dashboard` still do exactly that — you just enter the key
`dev-key` in the GUI yourself.

---

## Installation & setup

hackerpot is a TypeScript library plus a runnable standalone service. It isn't on
npm yet; use it from this repo, from a monorepo, or via `npm pack`:

```bash
npm pack                              # → hackerpot-0.1.0.tgz
npm install ../hackerpot/hackerpot-0.1.0.tgz   # in another project
```

It ships **dual ESM + CommonJS** builds with type declarations, so both
`import` and `require` work:

```ts
import { HoneypotEngine } from "hackerpot";          // ESM
const { HoneypotEngine } = require("hackerpot");     // CommonJS
```

**Runtime dependencies:** [`ioredis`](https://github.com/redis/ioredis) (only used
if you choose `RedisStore`), [`ws`](https://github.com/websockets/ws) (the
management WebSocket feed), [`ssh2`](https://github.com/mscdex/ssh2) (the SSH
honeypot's transport layer), and [`smol-toml`](https://github.com/squirrelchat/smol-toml)
(the standalone config parser). Everything else is Node's standard library.

The npm scripts you'll use most:

| Script | What it does |
| --- | --- |
| `npm run dev:gui` | **everything at once** — honeypot + management API + dashboard, from source |
| `npm run build` | compile `dist/` (ESM + CJS + `.d.ts`) |
| `npm run build:start` | compile, then run the built service |
| `npm run build:gui` | compile, then run the built service + dashboard |
| `npm start` | run the built service (`dist/standalone.js`) — no `tsx`, the production entry point |
| `npm run start:gui` | run the built service + dashboard together |
| `npm run dev` | run the local honeypot + management API via `tsx` (no build needed) |
| `npm run dashboard` | serve the management-API test GUI on its own |
| `npm run attack:all` | fire the whole attack simulator at a running honeypot |
| `npm run config:check` | validate a TOML config and print the resolved settings |
| `npm run generate:nginx` | emit includable nginx edge-capture config files |
| `npm test` | run the test suite |
| `npm run typecheck` | type-check without emitting |

---

## How it works

Two pluggable layers, mirrored by two source directories:

```
src/detectors/   how attacks are recognized  (the "honeypots")
src/responses/   what to do about them        (the retaliation actions)
```

Every request flows through the engine like this:

```
                    ┌─────────────────────────────────────────────┐
   request  ─────▶  │ 1. resolve source IP (X-Forwarded-For aware) │
                    │ 2. is this IP already blocked? ── yes ──▶ 403 (short-circuit,
                    │              │ no                            │   no detectors run)
                    │              ▼                               │
                    │ 3. record the request in the IP's            │
                    │    sliding-activity window (src/state.ts)    │
                    │              ▼                               │
                    │ 4. run every DETECTOR → collect Detections   │
                    │    (each has a reason + a score)             │
                    │              ▼                               │
                    │   any fired? ── no ──▶ pass through / 404    │
                    │              │ yes                           │
                    │              ▼                               │
                    │ 5. sum scores, add to the IP's running total │
                    │ 6. POLICY picks ONE response action id       │
                    │ 7. record the incident + fire onHit()        │
                    │              ▼                               │
                    │ 8. run the chosen RESPONSE ACTION            │
                    └─────────────────────────────────────────────┘
```

The key ideas:

- **Detection and response are decoupled.** A detector says *"this is a `.env`
  probe, score 10."* It does not decide what happens next. The **policy** does,
  looking at everything that fired plus the IP's cumulative score. You can add a
  detector without touching responses, and rewire responses without touching
  detection.
- **Suspicion accumulates per IP.** A single odd request is cheap noise; the same
  IP hitting ten decoys, brute-forcing a login, and replaying a honeytoken is an
  attacker. The engine keeps a running score per source IP (in the [store](#stores))
  and a short **sliding window** of recent activity (for the stateful detectors).
- **Blocked IPs are free to serve.** Once an IP is blocked, further requests are
  answered `403` *before any detector runs* — an attacker who tripped the block
  costs you almost nothing.
- **Middleware is body-safe.** In middleware mode the request body is only read
  after a first-phase detector already flagged the request, so a legitimate
  downstream route always receives an intact, unconsumed stream. (The standalone
  service has no downstream, so it reads the body up front.)

---

## Detectors

Detectors live in [`src/detectors/`](src/detectors/) — one file each, plus a barrel
that assembles the default set. Each is a small factory you call with options; each
returns a `Detector` you can pass to the engine or list in the config file.

| Detector | Catches | Kind | Default score |
| --- | --- | --- | --- |
| `decoyPathDetector` | requests to bait paths only an attacker would know (`.env`, `.git`, admin panels, framework debug endpoints, known RCE probes) | per-request | per-decoy (3–10) |
| `payloadInjectionDetector` | exploitation payloads — path traversal, SQLi, XSS, command/template injection, Log4Shell, XXE — in the path, query, headers, or body | per-request | 10 |
| `ssrfProbeDetector` | a param/header/body pointing the server at an internal address (cloud metadata, loopback, RFC1918) or a non-HTTP scheme (`file://`, `gopher://`) | per-request | 9 |
| `insecureDeserializationDetector` | a serialized-object payload (Java `rO0AB…`, PHP `O:…`, .NET, Python pickle, Ruby Marshal, `node-serialize`) in the query, a cookie/ViewState header, or the body — a top RCE class | per-request | 9 |
| `webShellDetector` | a request for a known web-shell filename, an executable script in an upload dir, or a script URL with a command-exec parameter | per-request | 9 |
| `prototypePollutionDetector` | `__proto__` / `constructor.prototype` in query keys/values or a JSON body — polluting `Object.prototype` for privilege escalation or RCE | per-request | 8 |
| `hostHeaderInjectionDetector` | a malformed or duplicated `Host`, or (with `expectedHosts` set) a `Host` / `X-Forwarded-Host` off your canonical set — cache poisoning, password-reset link poisoning | per-request | 6 |
| `credentialBruteforceDetector` | repeated auth attempts against one login endpoint from one IP | stateful | 9 |
| `crlfInjectionDetector` | a CRLF sequence smuggled into the path, query, or a header (header injection / response splitting) | per-request | 8 |
| `pathBruteforceDetector` | one IP requesting many distinct paths fast (directory enumeration) | stateful | 8 |
| `headerAnomalyDetector` | protocol abuse: absolute-form request target (open-proxy probing), Shellshock in headers, Content-Length + Transfer-Encoding smuggling, missing Host | per-request | 7 |
| `sensitiveFileDetector` | requests for risky file types anywhere (backup/dump/source copies, `.sql`/`.bak`/`~`, VCS/IDE metadata like `/.svn/`, `.DS_Store`) | per-request | 6 |
| `suspiciousMethodDetector` | HTTP verbs no normal client sends (WebDAV, `TRACE`/`TRACK`/`DEBUG`) | per-request | 6 |
| `scannerSignatureDetector` | scanner/tool User-Agents (sqlmap, nikto, nmap, gobuster, …) and bare scripting clients | per-request | 6 |
| `openRedirectDetector` | a `redirect`/`next`/`url` param carrying an off-site target (phishing bounce, OAuth `redirect_uri` abuse) | per-request | 5 |
| `rateSpikeDetector` | abnormally high request rate from one IP | stateful | 4 |
| `repeatActorDetector` | one **actor fingerprint** (header order + UA family) attacking from several distinct IPs — an actor rotating addresses to dodge per-IP blocking | stateful | 7 |
| `honeytokenDetector` | a seeded fake credential/key/id replayed in any request — the highest-confidence breach signal | per-request | 15 |
| `PortScanSentinel` | TCP connections to decoy ports (port sweeps) — runs at the socket level, independent of HTTP | TCP | — |
| `SmtpHoneypot` | mail-server abuse — AUTH brute-force, open-relay, spam, VRFY/EXPN enumeration — on a decoy SMTP port (see [Mail defense](#mail-defense--smtp-honeypot)) | SMTP | — |
| `SshHoneypot` | SSH credential brute-force, public-key probes, and version-grab scans — completes a real handshake and captures the creds (see [SSH honeypot](#ssh-honeypot)) | SSH | — |

All the per-request and stateful detectors above are in the **default set**
(`defaultDetectors()`). `honeytokenDetector` is opt-in — it needs the token values
you planted. `PortScanSentinel`, `SmtpHoneypot`, and `SshHoneypot` are separate TCP
listeners, not part of the HTTP detector chain.

Every per-request detector accepts a `score` (its contribution to the IP's total)
and a `respondWith` (an explicit response-action id that overrides the policy).
Stateful detectors additionally read the engine's per-IP sliding window.

### Detector options

**`decoyPathDetector(decoys?)`** — matches a list of `DecoyPath` objects. Called with
no argument it uses the 21 built-in decoys; pass your own array to replace them.
Each decoy: `{ id, description, path | RegExp, method?, score, respondWith?, payload? }`,
where `payload` is the fake content served (`{ status?, contentType?, body?, location? }`).

**`payloadInjectionDetector({ score?, inspectBody?, inspectHeaders? })`**
- `score` (default `10`)
- `inspectBody` (default `true`) — also scan the request body
- `inspectHeaders` (default `["user-agent","referer","x-forwarded-for","x-api-version","cookie"]`) — header names to scan (Log4Shell and friends arrive via headers)

**`ssrfProbeDetector({ score?, inspectBody?, inspectHeaders? })`**
- `score` (default `9`) · `inspectBody` (default `true`)
- `inspectHeaders` (default `["referer","destination","x-original-url","x-rewrite-url"]`) — the `X-Forwarded-*`/`Forwarded` family is deliberately excluded, since a proxy legitimately puts internal IPs there and scanning them would false-positive on every proxied request

**`webShellDetector({ patterns?, score? })`**
- `patterns` — override the built-in web-shell / upload-dir / exec-param regex list · `score` (default `9`)

**`crlfInjectionDetector({ score?, inspectHeaders? })`**
- `score` (default `8`) · `inspectHeaders` (default `["referer","x-forwarded-for","user-agent"]`)

**`openRedirectDetector({ params?, trustedHosts?, score? })`**
- `params` — redirect-style query params to check (default `redirect`, `redirect_uri`, `url`, `next`, `return`, `goto`, `dest`, `continue`, `target`, …) · `score` (default `5`)
- Only *off-site* targets fire: an absolute or protocol-relative URL whose host is considered same-site (a legitimate self-redirect / OAuth `redirect_uri` to your own domain) is not flagged.
- `trustedHosts` — pin your own domain(s) as an authoritative allowlist. When set, only these count as same-site; when omitted, the detector falls back to the request's own `Host` header (convenient, but Host is client-controllable, so pin `trustedHosts` if you care).

**`credentialBruteforceDetector({ authPaths?, windowMs?, attemptThreshold?, score? })`**
- `authPaths` (default matches `login|signin|auth|token|oauth|session|password|wp-login.php`)
- `windowMs` (default `60000`) · `attemptThreshold` (default `8`) · `score` (default `9`)

**`pathBruteforceDetector({ windowMs?, uniquePathThreshold?, score? })`**
- `windowMs` (default `30000`) · `uniquePathThreshold` (default `15`) · `score` (default `8`)

**`headerAnomalyDetector({ score?, flagMissingHost? })`**
- `score` (default `7`, but specific findings score higher: smuggling `9`, Shellshock `10`, absolute-URI `8`)
- `flagMissingHost` (default `true`) — HTTP/2 `:authority` counts as present

**`sensitiveFileDetector({ patterns?, score? })`**
- `patterns` — override the built-in risky-extension regex list · `score` (default `6`)

**`suspiciousMethodDetector({ methods?, score? })`**
- `methods` (default the WebDAV + `TRACE`/`TRACK`/`DEBUG`/`CONNECT` verbs) · `score` (default `6`)

**`scannerSignatureDetector({ extraPatterns?, flagMissingUserAgent?, score? })`**
- `extraPatterns` — extra User-Agent regexes to treat as scanners
- `flagMissingUserAgent` (default `true`, scored at half) · `score` (default `6`)

**`rateSpikeDetector({ windowMs?, requestThreshold?, score? })`**
- `windowMs` (default `10000`) · `requestThreshold` (default `60`) · `score` (default `4`)

**`repeatActorDetector({ score?, distinctIpThreshold?, windowMs?, respondWith? })`**
- `score` (default `7`) · `distinctIpThreshold` (default `3`) · `windowMs` (default `600000`, the correlation window)
- Fires when one actor fingerprint has been seen attacking from `distinctIpThreshold` distinct IPs within `windowMs`. See [Actor fingerprinting](#actor-fingerprinting--cross-ip-correlation).
- **Safe in middleware mode:** it only ever correlates IPs whose requests *already scored a detection* — the fingerprint registry is written solely from suspicious traffic — so ordinary users sharing a browser fingerprint from different IPs are never recorded and never falsely correlated. It confirms two suspicious IPs are one actor; it never manufactures suspicion on its own.

**`insecureDeserializationDetector({ score?, inspectBody?, inspectHeaders? })`**
- `score` (default `9`) · `inspectBody` (default `true`)
- `inspectHeaders` (default `["cookie","x-serialized","viewstate","__viewstate"]`) — the usual carriers of a serialized blob
- Matches signatures for Java (`rO0AB…`), PHP (`O:<n>:"…"`), .NET BinaryFormatter, Python pickle, Ruby Marshal, and `node-serialize`

**`prototypePollutionDetector({ score?, inspectBody? })`**
- `score` (default `8`) · `inspectBody` (default `true`)
- Scans query keys, query values, and the body for `__proto__` and `constructor`→`prototype` access, including the JSON-nested form `{"constructor":{"prototype":…}}`

**`hostHeaderInjectionDetector({ score?, expectedHosts?, respondWith? })`**
- `score` (default `6`)
- `expectedHosts` — your canonical hostnames, **lowercase and without a port** (the incoming Host's port is stripped before comparison). When set, any `Host` / `X-Forwarded-Host` off this list is flagged. When omitted, only structurally-malformed or duplicated Host headers fire — a differing `X-Forwarded-Host` is normal behind a proxy and can't be judged without knowing your real hostnames.

**`honeytokenDetector({ tokens, score? })`**
- `tokens` — the seeded bait values: `["AKIA…"]` or `[{ value, label }]`
- `score` (default `15`) — very high; no legitimate client ever possesses these
- Matches the path, query values, every header and the body. A token replayed as an HTTP Basic credential is caught too: `Authorization` and `Proxy-Authorization` Basic values are base64-decoded before matching. Nothing else is decoded, since guessing at base64 inside arbitrary values would produce false positives.

**`PortScanSentinel({ ports, host?, scanThreshold?, banner?, onEvent? })`**
- `ports` — decoy TCP ports nothing legitimate should touch
- `scanThreshold` (default `2`) — distinct ports one IP must touch to count as a sweep
- `banner` — a fake service banner sent on connect (e.g. `"SSH-2.0-OpenSSH_8.4"`)

---

## Response actions

Response actions live in [`src/responses/`](src/responses/). The policy selects one
by id per incident; the engine runs it to produce the HTTP response.

| Action id | What it does |
| --- | --- |
| `decoy-content` | serves the fake content attached to the detection (a fake `.env`, a fake admin login page) so probing appears to succeed |
| `not-found` | a flat `404` — the probe itself was the signal, reveal nothing |
| `redirect` | bounces the attacker toward another decoy |
| `tarpit` | holds the response open (delay scales with suspicion) to waste the attacker's time |
| `drip-feed` | trickles a never-ending response out byte by byte, pinning the attacker's connection |
| `large-payload` | streams a large response to soak up the attacker's bandwidth and storage |
| `block` | marks the IP blocked for a period; further requests are short-circuited before any detector runs |
| `fake-success` | returns a plausible success with a fake session token, as if the exploit/login worked — a sticky decoy that keeps the attacker engaging |
| `fake-data` | serves **freshly-synthesized** fake secrets tailored to the request — a fake `.env`, an AWS credentials file, or a user table with bcrypt-shaped hashes; every hit randomizes values so responses are undiffable and any exfiltrated credential is noise |
| `gzip-bomb` | serves a few KB of gzip that inflates to tens of MB on the client, punishing naive scrapers |
| `chaos` | answers unpredictably (a random 5xx, or random bytes) to confuse automated tooling |
| `rate-limit` | a standard `429 Too Many Requests` + `Retry-After` — a low-cost throttle that reveals nothing |

### Response options

**`blockAction({ durationMs?, status?, body?, sendRetryAfter? })`**
- `durationMs` (default `900000` = 15 min) · `status` (default `403`) · `body` (default `"Forbidden"`) · `sendRetryAfter` (default `true`)

**`tarpitAction({ delayMs?, status?, body?, escalate? })`**
- `delayMs` (default `[2000, 8000]`, a randomized range; a single number is a fixed delay)
- `status` (default `404`) · `body` (default `"Not Found"`)
- `escalate` (default `true`) — scale the delay with the IP's cumulative score, up to 4×

**`dripFeedAction({ chunkBytes?, intervalMs?, maxDurationMs?, status? })`**
- `chunkBytes` (default `1`) · `intervalMs` (default `1000`) · `maxDurationMs` (default `120000`) · `status` (default `200`)

**`largePayloadAction({ totalBytes?, chunkBytes?, throttleMs?, contentType? })`**
- `totalBytes` (default `52428800` = 50 MB) · `chunkBytes` (default `65536` = 64 KB) · `throttleMs` (default `0`) · `contentType` (default `"application/octet-stream"`)

**`fakeSuccessAction({ status?, body?, contentType?, setSessionCookie? })`**
- `status` (default `200`) · `setSessionCookie` (default `true`)
- `body` (default a fake auth-success JSON with a random token) — a string or a `(ctx) => string`

**`fakeDataAction({ names?, domain?, rows? })`**
- `names` — seed first-names for the synthesized user records (default a small built-in set) · `domain` (default `"corp.internal"`) — the fake internal domain in emails/hostnames · `rows` (default `8`) — rows a listing-style decoy returns
- The shape is chosen from the request path: `.env` → a fake dotenv, `aws`/`credentials` → an `~/.aws/credentials` file, `user`/`account`/`member`/`dump` → a JSON user table, otherwise a generic secrets blob.
- ⚠️ **Never seed `names` with real employee names, or point `domain` at an internal name you don't own.** This action *serves that data to attackers by design* — real names or a real internal domain turn a decoy into genuine reconnaissance disclosure (useful for spear-phishing). Plausibility is the goal, not identity; everything here should be invented.

**`gzipBombAction({ decompressedBytes?, contentType? })`**
- `decompressedBytes` (default `10485760` = 10 MB) — the inflated size; the compressed payload is built once and cached · `contentType` (default `text/html`)

**`chaosAction({ statuses?, garbageChance?, maxGarbageBytes? })`**
- `statuses` (default `[500, 502, 503, 504]`) · `garbageChance` (default `0.5`) · `maxGarbageBytes` (default `4096`)

**`rateLimitAction({ retryAfterSeconds?, status?, body? })`**
- `retryAfterSeconds` (default `60`) · `status` (default `429`) · `body` (default `"Too Many Requests"`)

`decoyContentAction`, `notFoundAction`, and `redirectAction` take no options — they
read what they need from the detection.

> ⚠️ `drip-feed`, `large-payload`, and `gzip-bomb` deliberately hold connections or
> push data. Use them judiciously behind a proxy — they consume a connection slot on
> your side too, and payload served to a spoofed source is wasted bandwidth. They
> shine against automated scrapers that save (or decompress) what they download.
> `fake-success`, `fake-data`, `chaos`, and `rate-limit` aren't chosen by the default
> policy — a detector's `respondWith` or a custom policy has to select them.

---

## The scoring policy

The **policy** is the brain of the escalation. It's a function of the detections and
the IP's cumulative score that returns a single response-action id. The built-in
`defaultResponsePolicy(blockThreshold = 40, tarpitThreshold = 15)` implements this
ladder:

1. **Cumulative score ≥ `blockThreshold` (40)** → `block`. A confirmed persistent
   attacker is blocked regardless of what any single detector requested.
2. Otherwise, if a detector asked for a specific action (`respondWith`) → honor it.
   This is how decoys keep serving convincing bait instead of escalating too early.
3. Otherwise, **score ≥ `tarpitThreshold` (15)** → `tarpit`.
4. Otherwise → `not-found`.

> **`respondWith` only applies to the *highest-scoring* detection.** When several
> detectors fire on one request, the policy reads the top-scoring one
> (`detections[0]`), so a lower-scoring detector's `respondWith` is ignored if a
> higher-scoring detector also fired. This bites the low-scored detectors most —
> e.g. `open-redirect` (5) is outranked by `scanner-signature` (6), so a scripted
> request (bare User-Agent) to an open-redirect gets scanner-signature's outcome,
> while the same request from a browser UA honors the open-redirect `respondWith`.
> If you rely on a specific detector's `respondWith`, raise its `score` above the
> others that co-fire, or encode the routing in a custom policy instead.

Because scores accumulate, an attacker climbs the ladder naturally: the first probe
gets a quiet `404`, a few more draw multi-second tarpits, and once they've proven
persistent they're blocked outright and cost nothing to serve. You can watch this
exact progression in the [dashboard](#the-dashboard).

Write your own policy to change the strategy entirely:

```ts
import { HoneypotEngine, type ResponsePolicy } from "hackerpot";

const aggressive: ResponsePolicy = (ctx) => {
  if (ctx.detections.some((d) => d.detectorId === "honeytoken")) return "block"; // instant
  if (ctx.totalScore >= 20) return "large-payload";                             // punish
  return ctx.detection.respondWith ?? "not-found";
};

new HoneypotEngine({ policy: aggressive });
```

---

## Stores

The **store** is where incidents and per-IP scores live. All implement the small
`HitStore` interface (`record` / `list` / `scoreFor`), so they're interchangeable via
the `store` option — swap persistence without touching detection or response.

| Store | Use it for |
| --- | --- |
| `MemoryStore` | default — fast, in-process; state is lost on restart |
| `FileStore` | a single instance that must survive restarts — append-only JSONL log, scores rebuilt from the file on startup; zero dependencies |
| `RedisStore` | multiple instances / behind a load balancer — shares scores and the hit log across replicas via Redis, with an optional per-IP score TTL so suspicion decays |
| `ElasticStore` | long-term, searchable retention — indexes hits as documents in Elasticsearch or OpenSearch for dashboarding in Kibana / OpenSearch Dashboards; dependency-free (talks to the REST API over `fetch`) |
| `CompositeStore` | fan-out — e.g. a fast primary (Memory/Redis) for scoring *and* a durable `FileStore` audit log at once |

```ts
import { MemoryStore, FileStore, RedisStore, ElasticStore, CompositeStore } from "hackerpot";

new MemoryStore();
new FileStore({ path: "./data/hits.jsonl", loadOnStart: true });
new RedisStore({ redisOptions: { host: "127.0.0.1", port: 6379 }, keyPrefix: "hackerpot:", scoreTtlSeconds: 3600, maxHits: 10_000 });
new ElasticStore({ node: "http://localhost:9200", index: "hackerpot-hits", apiKey: "…", onError: console.error });
new CompositeStore(/* primary */ redisStore, /* audit */ fileStore);
```

`ElasticStore` computes an IP's score with a `sum` aggregation over its documents (no
decay, matching `MemoryStore`) and **never throws out of `record()`** — a honeypot must
keep serving even if its log sink is unreachable, so indexing failures go to the
`onError` callback rather than propagating. Auth is `apiKey` (sent as `ApiKey …`) or
`username`/`password` (Basic). Pair it in a `CompositeStore` with a `RedisStore` if you
want both fast shared scoring *and* searchable retention.

Why a **score TTL** matters: without it, an IP's suspicion only ever grows. A TTL on
the Redis score key (refreshed on each hit) lets a quiet IP's score decay, so a
shared address that tripped a detector once doesn't stay blocked forever.

### Reading a store: `list()` and `query()`

`list()` returns the retained hits **oldest first**, on every backend, bounded by that
backend's retention cap. `ElasticStore` still *queries* newest-first — with `size`, that
is what selects which documents come back — and reverses before returning, so callers
never have to know which store is behind them.

Stores may also implement the optional `query(q: HitQuery)`, a bounded, filtered read
with the same ordering contract:

```ts
interface HitQuery {
  ip?: string;          // only this source IP
  detector?: string;    // only hits where this detector fired
  fingerprint?: string; // only this actor fingerprint
  sinceMs?: number;     // at or after this epoch-ms timestamp
  limit?: number;       // at most this many — the MOST RECENT ones
}
```

All five built-in stores implement it, and each pushes down what its backend can do:
Elasticsearch turns `ip`/`sinceMs` into a real query instead of transferring up to
`maxHits` documents and filtering them client-side, Redis slices the list server-side
for a plain `limit`, and the file store streams into a bounded window instead of parsing
the whole log into memory. That last one is the difference between a constant cost and
one the attacker sets: on a 72 MB hit log, a single `/incidents?ip=…&limit=100` went from
**96 MB retained to 25 MB**.

A custom store can omit `query()` entirely — callers fall back to `list()` with
identical filtering semantics, so it is a performance interface, never a correctness
one. The aggregate endpoints (`/stats`, `/metrics`, `/ioc`, and the all-IPs `/sessions`)
still read `list()` by design: they summarize the whole corpus, so there is nothing to
push down.

---

### Hit-log rotation and retention

The file store is append-only and writes one record per malicious request — headers and
body included — so **the attacker decides how fast it grows**. Left unrotated it fills
the volume, which takes down considerably more than the honeypot. So the live file rolls
into a timestamped, gzipped archive at `max_bytes`, and old archives are pruned by
`max_archives` and/or `max_archive_age_seconds`:

```
/data/hits.jsonl                                  # live segment, always < max_bytes
/data/hits-2026-08-29T11-28-22-411Z.jsonl.gz      # archives, newest first
/data/hits-2026-08-29T11-28-22-338Z.jsonl.gz
/data/hits.jsonl.scores.json                      # score checkpoint (see below)
```

Writes are **batched and asynchronous** — the request path never blocks on the disk, and
`record()` still resolves only once the line is durable, so read-after-write is unchanged.

Reads (`/incidents`, `/stats`, `/metrics`, `/ioc`, `/sessions`, `/actors`) are served from
the live segment and are therefore bounded by `max_bytes`. Archives are for your own
pipeline — ship them, grep them, load them into cold storage:

```bash
zcat /data/hits-*.jsonl.gz | jq -r 'select(.score >= 10) | .ip' | sort -u
```

**Scores survive rotation.** Rotation empties the live segment, and `load_on_start`
replays the live segment — so on its own, rotation would silently reset every attacker's
accrued suspicion on the next restart, and cumulative score is what crosses
`block_threshold`. A small checkpoint (`<path>.scores.json`) is written at each roll, at
the one moment the live segment is empty, so `checkpoint + live segment` is the complete
history with nothing double-counted. It survives archive pruning too: an IP's score is
retained even after the records that produced it have been deleted.

Set `max_bytes = 0` only when something else rotates the file for you (logrotate, a
sidecar). The config refuses `max_bytes = 0` together with `max_archives > 0`, since
nothing would ever create or prune an archive.

## Actor fingerprinting & cross-IP correlation

An IP address is a weak identity — attackers rotate through proxies, botnets, and cloud
ranges. hackerpot computes an **actor fingerprint** for every request from the client's
*header ordering* plus a coarse *User-Agent family* (`computeFingerprint`). The order and
set of headers a client sends is characteristic of the software driving it and far more
stable across IPs than the source address, so the same tool driven by the same actor
produces the same fingerprint from a hundred different IPs.

Every recorded hit carries its `fingerprint`, and the management API exposes actor views:

- `GET /actors` — incidents grouped by fingerprint, each with **all the IPs that one actor
  used**, most-IPs-first (the rotators surface at the top).
- `GET /actors/:fingerprint` — the single actor.

The `repeatActorDetector` turns this into a live signal, firing when one fingerprint attacks
from several distinct IPs in a window. It is deliberately conservative: it correlates **only
IPs whose traffic already scored a detection** (the fingerprint→IP registry is written
solely from suspicious requests), so it can never sweep in benign users who merely share a
browser fingerprint. The registry is bounded and windowed (`fingerprintWindowMs`, default
1h), so an attacker shuffling header order to mint unlimited fingerprints can't exhaust
memory. Fingerprinting is a heuristic for *correlating already-suspicious traffic*, never a
reason to flag traffic on its own.

## Source-IP enrichment

Each hit's source IP is annotated with an `enrichment`. The dependency-free
`defaultIpEnricher()` classifies the IP's special-use category — `loopback`, `private`,
`cgnat`, `link-local`, `documentation`, `multicast`, `reserved`, or `public` — and whether
it's globally routable. A *private* or *loopback* source reaching an internet-facing
honeypot is itself a signal: usually a misconfigured proxy leaking internal clients, or an
`X-Forwarded-For` chain being trusted when it shouldn't be.

```ts
new HoneypotEngine({ enricher: myGeoLiteEnricher }); // add asn/org/country from your own data
new HoneypotEngine({ enricher: null });              // disable enrichment entirely
```

There's no bundled geo/ASN database (that would mean shipping and maintaining megabytes of
data). For geo/ASN, implement the tiny `IpEnricher` interface over your own source (e.g. a
MaxMind GeoLite2 reader) and pass it as `enricher`; its `asn`/`org`/`country` ride alongside
the built-in classification.

## Threat-intel ingest (consuming other honeypots' IOC feeds)

The [`/ioc.txt` feed](#rest--query-recorded-incidents) one hackerpot publishes, another can
consume — so a fleet shares confirmed offenders. This is powerful and, wired naively,
**dangerous**, and it's worth seeing the concrete attack rather than a vague "only trust
good feeds": a peer running `trust_proxy = true` takes its source IP from
`X-Forwarded-For`, so anyone who can send that peer a handful of decoy probes with a forged
header can plant an *arbitrary victim IP* into its `/ioc` feed. Subscribe to that feed and
you inherit the poisoning — and composed with the firewall
[enforcer](#firewall-enforcement-opt-in), a single poisoned honeypot could make the whole
fleet `iptables`-block a bank, a CDN edge, or your own monitoring. hackerpot's ingest is
built so that amplifier is *structurally absent* in the default wiring:

```ts
import { fetchIocFeed, applyIocEntries, CompositeBlocklist, MemoryBlocklist } from "hackerpot";

const feed = new MemoryBlocklist();                         // hearsay lives here — NON-enforcing
engine.blocklist = new CompositeBlocklist(localBlocklist, feed);  // reads see both; block() writes only to local

// per refresh, per feed URL:
const ips = await fetchIocFeed("https://peer.example/ioc.txt?min_score=40", { apiKey });
applyIocEntries(ips, { blocklist: feed, allowlist: engine.allowlist, ttlMs: 3_600_000, maxEntries: 10_000 });
```

The guarantees, each enforced in the library:

- **The allowlist is consulted before every ingested block, always** — no flag can disable
  it — so a poisoned feed can never take out your own monitoring or office ranges.
- **Ingested blocks never reach the firewall enforcer by default.** `CompositeBlocklist`
  reads across children but `block()` writes only to the primary; ingest writes into the
  non-enforcing `feed` child, so the honeypot short-circuits those IPs but nothing hits
  `iptables`. Locally-observed blocks are first-hand evidence and *do* enforce; ingested
  ones are hearsay. Escalation still works — once that IP actually attacks you, a detector
  blocks it on its own merits.
- **Bounded**: `fetchIocFeed` requires https (loopback exempted), caps the response body
  (default 2 MB), and times out; `applyIocEntries` caps entries per refresh and TTLs every
  block so stale hearsay ages out.

In the standalone service this is the `[intel]` config section (feeds, refresh, `min_score`,
TTL, cap), with a poller that refreshes on an interval. Enforcing ingested blocks is a
separate, explicit opt-in — treat any feed you enforce as root on your host.

---

## Deployment modes

Same engine underneath; three ways to run it.

### 1. Middleware — alongside your existing server

Mount it ahead of your real routes. Anything no detector flags falls through to
`next()` untouched, body included — the request stream is never consumed on your
behalf.

> **Tune the volume detectors before putting this in front of real users.** The
> per-request detectors are conservative, but `path-bruteforce` and `rate-spike` count
> *traffic*, and in middleware mode they see every request your app serves — static
> assets included. A single ordinary page load of a modern SPA is easily 20+ distinct
> paths, which is past `path-bruteforce`'s default of 15 in 30s: measured against the
> shipped defaults, one 22-request page load scores a visitor 64, and the default block
> threshold is 40. Standalone mode does not have this problem — nothing there serves
> real assets, so many distinct paths genuinely is probing — which is why the defaults
> are set for it. For middleware, raise `unique_path_threshold` well above your
> heaviest page, or disable `path-bruteforce` and let the per-request detectors do the
> work:
>
> ```toml
> [detectors.path-bruteforce]
> enabled = false           # or: unique_path_threshold = 200
> ```

```ts
import express from "express";
import { HoneypotEngine, createMiddleware, hardenHttpServer } from "hackerpot";

const engine = new HoneypotEngine({
  onHit: (hit) => console.warn("[honeypot]", hit.ip, hit.respondedWith, hit.detections.map((d) => d.detectorId)),
});

const app = express();
app.use(createMiddleware(engine));   // mount FIRST
// ...your real routes below
const server = app.listen(3000);

// Your server, your timeouts: `HoneypotServer` hardens itself, but in middleware mode
// the listener is yours, so Node's permissive defaults (no connection cap, a 5-minute
// request timeout) still apply — a Slowloris invitation on anything internet-facing.
// One call fixes it; see "Slowloris / connection hardening" below.
hardenHttpServer(server);
```

If a detector's own machinery ever throws — a blocklist backend that is down, say —
the middleware routes it to `next(err)` rather than rejecting, so your error handler
sees it and the request never hangs. It is never the honeypot that takes your app down.

#### Slowloris / connection hardening

`hardenHttpServer(server)` applies conservative timeouts and a connection ceiling to
any `http.Server`: a 20s headers deadline (the core Slowloris defense), a 30s whole-request
deadline, a 5s keep-alive idle, and a 10 000-connection cap. The values are deliberately
not configurable — no legitimate request needs 20s to send its headers, and there is no
safe way to relax them into the vulnerable case. `HoneypotServer` and `ManagementServer`
call it on themselves; in middleware mode you own the listener, so you make the call.

### 2. Standalone — programmatic

Run it as its own `HoneypotServer` on a separate port or host — same repo, separate
service, wherever.

```ts
import { HoneypotServer, PortScanSentinel } from "hackerpot";

const server = new HoneypotServer({ onHit: (hit) => console.warn("[honeypot]", hit.ip, hit.respondedWith) });
await server.listen(4004);

// Optional: watch decoy TCP ports for scans (pick ports your real services don't use)
const sentinel = new PortScanSentinel({
  ports: [2222, 8022, 9200],
  banner: "SSH-2.0-OpenSSH_8.4",
  onEvent: (e) => console.warn("[port-scan]", e.ip, e.port, e.isScan),
});
await sentinel.listen();
```

#### Configuring the engine in code

`HoneypotEngine` (and `HoneypotServer`, which wraps it) take a single options object:

| Option | Default | Meaning |
| --- | --- | --- |
| `detectors` | the default set | the exact detector list to run, in order |
| `extraDetectors` | `[]` | detectors appended to the defaults (ignored if `detectors` is set) |
| `responseActions` | the default set | the response actions available to the policy |
| `extraResponseActions` | `[]` | actions appended to the defaults |
| `policy` | `defaultResponsePolicy()` | chooses which action id runs per incident |
| `store` | `new MemoryStore()` | where incidents and scores live |
| `onHit` | — | called on every incident; wire in your logging/alerting |
| `activityWindowMs` | `60000` | the sliding window the stateful detectors read |
| `trustProxy` | `false` | resolve the client IP from `X-Forwarded-For` (only behind a trusted proxy) |

```ts
import {
  HoneypotEngine, decoyPathDetector, payloadInjectionDetector, pathBruteforceDetector,
  honeytokenDetector, blockAction, tarpitAction, defaultResponsePolicy,
  RedisStore, FileStore, CompositeStore,
} from "hackerpot";

new HoneypotEngine({
  detectors: [
    decoyPathDetector(),
    payloadInjectionDetector(),
    pathBruteforceDetector({ uniquePathThreshold: 25, windowMs: 20_000 }),
  ],
  extraDetectors: [
    honeytokenDetector({ tokens: [{ value: "AKIA_FAKE_SEEDED_KEY", label: "decoy-env-aws-key" }] }),
  ],
  responseActions: [blockAction({ durationMs: 60 * 60_000 }), tarpitAction({ delayMs: [3000, 12000] })],
  policy: defaultResponsePolicy(50, 20),   // (blockThreshold, tarpitThreshold)
  store: new CompositeStore(
    new RedisStore({ redisOptions: { host: "127.0.0.1", port: 6379 }, scoreTtlSeconds: 3600 }),
    new FileStore({ path: "./data/honeypot-hits.jsonl" }),
  ),
  onHit: async (hit) => {/* forward to Slack / PagerDuty / a SIEM */},
  trustProxy: true,

  // Exempt known-good sources from all detection (IPs + CIDRs, v4/v6):
  allowlist: ["127.0.0.1", "10.0.0.0/8"],
  // Opt-in shared blocklist so blocks survive restarts and apply across replicas:
  // blocklist: new RedisBlocklist({ client: myRedisClient }),  // default is in-memory
});
```

`HoneypotEngine` config options added by the hardening pass: **`allowlist`** (never-flag
IPs/CIDRs) and **`blocklist`** (`MemoryBlocklist` default, or `RedisBlocklist` for a
shared/persistent blocklist). The SMTP/SSH honeypots take **`maxConnections`**, and
`tarpit`/`dripFeed`/`largePayload` take **`maxConcurrent`** — all bounding the
honeypot's own resource use under a flood.

#### Hot-reloading detection at runtime

`engine.reconfigure({ detectors?, responseActions?, policy?, allowlist? })` swaps those
four parts **in place**, taking effect on the very next request with no restart:

```ts
engine.reconfigure({
  detectors: rebuildDetectorsFromNewConfig(),
  allowlist: ["127.0.0.1", "10.0.0.0/8", "192.0.2.0/24"],
});
```

Only the fields you pass are replaced. What's deliberately **not** reconfigurable — the
`store`, the `blocklist`, and the activity windows — holds live state (accrued scores,
active blocks, per-IP history) that a rebuild would throw away, so it's preserved across
the swap. Listeners (host/port, SMTP/SSH, port-scan ports) likewise can't be re-bound
without dropping connections. This is the primitive behind config hot-reload: re-read
your config, rebuild detectors/responses/policy/allowlist, and `reconfigure()`; refuse
(loudly) any change to a listener or store rather than silently ignoring it.

### 3. Standalone — from a TOML config file

For deployments, run the built entrypoint and let it read a config file instead of
code. This is what the container runs. See the next section.

```bash
node dist/standalone.js --config /etc/hackerpot/hackerpot.toml
```

---

## Configuration reference

The standalone service is configured by a **TOML file**, so a deployment changes
without touching code or rebuilding an image. [hackerpot.toml](hackerpot.toml) at the
repo root is the shipped default — every value in it *is* a built-in default,
annotated, so it doubles as the living reference for the whole option surface.

### Loading, precedence, and validation

```bash
node dist/standalone.js --config ./hackerpot.toml
HACKERPOT_CONFIG=./hackerpot.toml node dist/standalone.js
```

- **Discovery** — with no `--config`/`HACKERPOT_CONFIG`, the first of these that
  exists is used, in order: `./hackerpot.toml`, `./hackerpot.config.toml`,
  `./config/hackerpot.toml`, `/etc/hackerpot/hackerpot.toml`. If none exist, the
  built-in defaults apply — the file is entirely optional. Discovery is relative to
  the **working directory**: the [hackerpot.toml](hackerpot.toml) that ships inside
  the npm package is a **reference to copy, not auto-loaded** — `npx hackerpot` reads
  *your* `./hackerpot.toml`, never the one in `node_modules`. Copy it to your project
  root (or `/etc/hackerpot/`) and edit. An installed dependency silently imposing its
  own config would be the wrong behavior.
- **An explicitly named file that is missing is an error**, not a silent fallback to
  discovery.
- **Precedence: built-in defaults < config file < environment variables.** The
  environment *wins* — the file carries a deployment's real configuration, and `-e`
  handles the last mile per container.
- **Unknown keys are a hard error.** A honeypot that silently ignores
  `[detectors.rate-spke]` is a honeypot with a detector quietly switched off, so a
  typo fails startup — with the key named and **exit code 2** (distinct from `1` for
  a runtime fatal), printed as `hackerpot: <path>: <message>` on stderr. The same
  strictness applies to wrong types, unparsable regexes, a `tarpit_threshold` above
  `block_threshold`, a store enabled with no path/url, and the management API enabled
  with no API keys.
- **Validate without binding a port** — the fastest way to debug a config, and a good
  CI check. `--print-config` resolves and validates, then prints the result as JSON
  (rendering regex values back as `/pattern/flags` literals):

  ```bash
  npm run config:check -- --config ./hackerpot.toml
  # or: node dist/standalone.js --print-config
  ```

- **Section names accept hyphens or underscores** interchangeably
  (`[detectors.rate-spike]` = `[detectors.rate_spike]`). **Regex-valued keys** take a
  bare pattern (compiled case-insensitively) or a `/pattern/flags` literal for
  explicit flags.

### The sections

| Section | Controls |
| --- | --- |
| `[server]` | `host`, `port`, `trust_proxy` |
| `[logging]` | `format` (`json`/`text`), `startup`, `include_headers`, `include_body` |
| `[engine]` | `activity_window_ms` — the sliding window the stateful detectors read |
| `[policy]` | `block_threshold`, `tarpit_threshold` — the escalation ladder |
| `[store.file]` | `path`, `load_on_start` (setting `path` enables it), plus rotation: `max_bytes` (roll point, `0` = off), `max_archives`, `max_archive_age_seconds`, `compress_archives`, `max_score_entries` |
| `[store.memory]` | `max_hits`, `max_score_entries` |
| `[store.redis]` | `url`, `key_prefix`, `score_ttl_seconds` (`0` = never expire), `max_hits` (setting `url` enables it; both stores enabled → `CompositeStore`) |
| `[store.elastic]` | `node`, `index`, `api_key` **or** `username`+`password`, `max_hits`, `refresh` (setting `node` enables it) |
| `[allowlist]` | `ips` — IPs and CIDRs (v4/v6) exempt from all detection: never scored, never blocked, no incident recorded |
| `[blocklist]` | `backend` (`memory`/`redis`), `key_prefix`, `max_entries` — where "this IP is blocked until T" lives |
| `[blocklist.enforcer]` | push blocks to the OS firewall or a WAF — `enabled`, `command`+`args` (`{ip}` is substituted, run without a shell), `timeout_ms`, `max_per_window`, `window_ms`, or `webhook`+`secret`+`headers` |
| `[intel]` | consume peer IOC feeds — `enabled`, `feeds`, `refresh_seconds`, `min_score`, `api_key`, `ttl_seconds`, `max_entries`, `enforce` |
| `[detectors.<id>]` | one table per detector — `enabled`, `score`, `respond_with`, plus that detector's own thresholds (same names as the [detector options](#detector-options), in snake_case) |
| `[[detectors.decoy-path.decoys]]` | your own bait paths (see below) |
| `[detectors.decoy-path]` | `replace_defaults` (bool), `disabled` (ids of built-ins to drop) |
| `[detectors.honeytoken]` | `tokens` — the seeded fake credentials to watch for |
| `[responses.<id>]` | one table per response action — `enabled` plus its settings (same names as the [response options](#response-options), snake_case) |
| `[port-scan]` | `ports`, `host`, `scan_threshold`, `banner`, `max_tracked_ips`, `retention_ms` (listing any port enables it) |
| `[smtp]` | the SMTP honeypot — `enabled`, `port`, `host`, `banner`, `hostname`, `local_domains`, `drop_above_score` (see [Mail defense](#mail-defense--smtp-honeypot)) |
| `[ssh]` | the SSH honeypot — `enabled`, `port`, `host`, `ident`, `max_auth_attempts`, `drop_above_score` (see [SSH honeypot](#ssh-honeypot)) |
| `[ftp]` | the FTP honeypot — `enabled`, `port`, `host`, `banner`, `max_auth_attempts`, `interactive`, `drop_above_score` (see [FTP honeypot](#ftp-honeypot)) |
| `[telnet]` | the Telnet honeypot — `enabled`, `port`, `host`, `banner`, `hostname`, `max_auth_attempts`, `interactive`, `drop_above_score` (see [Telnet honeypot](#telnet-honeypot)) |
| `[syslog]` | forward every incident to a SIEM — `host`, `port`, `protocol`, `format`, `facility`, `severity`, `min_score`, `max_bytes` (see [Alert sinks](#alert-sinks)) |
| `[management]` | the operator API — see [Incidents management API](#incidents-management-api) |
| `[[management.webhooks]]` | `url`, `format` (`hackerpot`/`slack`/`discord`), `secret`, `headers`, `min_score`, `max_retries`, `timeout_ms`, `max_in_flight`, `dedupe_window_seconds`, `throttle_window_seconds`+`max_per_window`, `omit_body` |

### A worked example

```toml
[server]
port = 4004
trust_proxy = true                # only because a proxy we control fronts this listener

[policy]
block_threshold = 30            # a stricter ladder than the 40 / 15 default
tarpit_threshold = 10

[store.file]
path = "/data/hits.jsonl"       # setting a path enables the store
max_bytes = 134217728           # roll into a gzipped archive at 128 MB
max_archives = 10               # keep ten; the oldest are deleted

[detectors.path-bruteforce]
unique_path_threshold = 25
window_ms = 20000

[detectors.rate-spike]
enabled = false                 # too noisy behind our CDN

[detectors.honeytoken]
tokens = ["AKIA_HACKERPOT_HONEYTOKEN_DEMO"]

# A custom decoy, appended to the built-in set:
[[detectors.decoy-path.decoys]]
id = "internal-backup"
description = "Fake internal backup endpoint"
path = "/internal/backup.sql"   # or `pattern = "^/internal/.*\\.sql$"` for a regex
score = 9
respond_with = "large-payload"  # let them download 50 MB of nothing

[responses.tarpit]
delay_ms = [3000, 12000]

[port-scan]
ports = [2222, 8022, 9200]
```

> The shipped `hackerpot.toml` is asserted against the code in
> `src/config.test.ts` to behave identically to the built-in defaults — so if you
> edit its values, that test will flag any drift from the factory defaults. That's
> intentional: the file is a reference, and the test keeps it honest.

### Sharing a config with a library deployment

The loader is exported, so a middleware deployment can share one config file with a
standalone one:

```ts
import { HoneypotEngine, loadConfig, buildHoneypotConfig } from "hackerpot";

const config = loadConfig({ path: "./hackerpot.toml" });
const { config: honeypot } = buildHoneypotConfig(config, (hit) => console.warn("[honeypot]", hit.ip));
const engine = new HoneypotEngine(honeypot);
```

---

## Environment variables

Environment variables override the config file. `(off)` below means "not set, so
whatever the config file (or default) says stands".

| Var | Default | Meaning |
| --- | --- | --- |
| `HACKERPOT_CONFIG` | *(auto-discovered)* | path to the TOML config file |
| `PORT` / `HOST` | `4004` / `0.0.0.0` | HTTP honeypot listener |
| `TRUST_PROXY` | `false` | resolve client IP from `X-Forwarded-For` (only behind a proxy that overwrites it) |
| `SCAN_PORTS` | *(off)* | comma-separated decoy TCP ports for the port-scan sentinel |
| `SCAN_BANNER` | `SSH-2.0-OpenSSH_8.4` | fake banner sent on a sentinel connect |
| `HIT_LOG` | *(off)* | path to a JSONL audit file (enables `FileStore`) |
| `REDIS_URL` | *(off)* | e.g. `redis://redis:6379` (enables `RedisStore`; combined with `HIT_LOG` → `CompositeStore`) |
| `REDIS_SCORE_TTL` | *(none)* | seconds; per-IP score TTL so suspicion decays |
| `HONEYTOKENS` | *(off)* | comma-separated seeded token values to watch for |
| `LOG_FORMAT` | `json` | `json` (one object per hit, for log aggregation) or `text` |
| `MANAGEMENT_API_KEYS` | *(off)* | comma-separated keys; setting any enables the operator API |
| `MANAGEMENT_HOST` / `MANAGEMENT_PORT` | `127.0.0.1` / `9500` | where the operator API listens |

---

## Incidents management API

The standalone service can expose a **separate operator API** for pulling captured
incidents out — an *incident* being a recorded hit: the detections that fired plus
the response that was served (see [Data shapes](#data-shapes)). It runs on **its own
listener, distinct from the attacker-facing honeypot**, and is protected by API keys.

> 🔒 **Bind it to a private network.** It defaults to `host = "127.0.0.1"` (loopback
> only). Point it at an internal/VPC address so your own services can reach it, but
> **never a public interface** — this API hands out captured attacker data and must
> not be reachable by the attackers themselves. It's off until you set at least one
> API key (enabling it with none is a hard config error).

```toml
[management]
enabled = true
host = "127.0.0.1"          # the network it is reachable on — keep it private
port = 9500
api_keys = ["a-long-random-string"]   # via Authorization: Bearer or X-API-Key
websocket = true
```

A typical shape: the honeypot faces the internet behind [nginx](#nginx-edge-capture),
and your service reads detections from `:9500` on a private network while attackers
only ever touch the public site. Three ways to consume incidents:

### REST — query recorded incidents

Every route except `/health` requires an API key, sent as `Authorization: Bearer <key>`
or `X-API-Key: <key>`.

| Method & path | Returns |
| --- | --- |
| `GET /health` | `{ "status": "ok" }` — unauthenticated liveness probe |
| `GET /incidents` | recent incidents, newest first. Filters: `?ip=`, `?detector=`, `?since=<ISO8601>`, `?limit=` (default 100, max 1000) |
| `GET /incidents/:id` | a single incident by id (`404` if unknown) |
| `GET /stats` | summary: totals, unique IPs, counts by detector and by response, top offender IPs by score, first/last seen |
| `GET /metrics` | Prometheus text-format metrics — `hackerpot_incidents_total`, `_by_detector`/`_by_response`, `_unique_ips`, `_top_offender_score`, plus any injected gauges (e.g. `active_blocks`) |
| `GET /ioc` | **Indicators of Compromise** — every source IP aggregated with cumulative `score`, incident count, the detectors it tripped, and first/last seen, highest score first. Filter with `?min_score=`. A feed your firewall or other honeypots can pull. |
| `GET /ioc.txt` | the same IPs as a plain newline-separated list (`?min_score=` too) — pipe straight into an `ipset`, a firewall rule, or a blocklist |
| `GET /sessions` | every IP's activity grouped into an **attack session**: an ordered timeline of what it did plus the detectors/responses seen and its score, newest activity first |
| `GET /sessions/:ip` | the single session for one IP (`404` if that IP has no incidents) — read the attack as a narrative instead of scanning a flat incident list |
| `GET /actors` | incidents grouped by [actor fingerprint](#actor-fingerprinting--cross-ip-correlation), each listing **every IP one actor used**, most-IPs-first — the view that exposes an attacker rotating addresses |
| `GET /actors/:fingerprint` | the single actor (`404` if unknown) |

```bash
curl -H "Authorization: Bearer $KEY" "http://127.0.0.1:9500/incidents?detector=honeytoken&limit=20"
curl -H "X-API-Key: $KEY"           "http://127.0.0.1:9500/stats"

# Feed confirmed offenders straight into a firewall set:
curl -s -H "X-API-Key: $KEY" "http://127.0.0.1:9500/ioc.txt?min_score=40" \
  | while read ip; do ipset add hackerpot-block "$ip" 2>/dev/null; done
```

### SIEM output — CEF & syslog

For shipping incidents into a SIEM (Splunk, QRadar, ArcSight, Elastic), `hackerpot`
formats a hit as **CEF** (Common Event Format) or wraps it in an **RFC 3164 syslog**
envelope — both pure functions you call from your own `onHit`:

```ts
import { HoneypotServer, cefFormat, syslogLine } from "hackerpot";

new HoneypotServer({
  onHit: hit => {
    console.log(cefFormat(hit));
    // CEF:0|hackerpot|hackerpot|0.1.0|nosql-injection|NoSQL operator injection|9|src=203.0.113.7 requestMethod=POST request=/login cs1=nosql-injection cn1=45 act=block …

    udpSocket.send(syslogLine(hit, { host: "sensor1" }), 514, "siem.internal");
    // <108>Aug 27 12:34:56 sensor1 hackerpot: CEF:0|hackerpot|…
  },
});
```

`syslogLine` defaults to wrapping the CEF line; pass `{ message }` to ship something
else, and `{ facility, severity, host }` to set the envelope.

### WebSocket — live feed

Connect to `GET /stream` for incidents pushed the moment they happen. The API key
goes in the `Authorization`/`X-API-Key` header, or as a `?api_key=` query parameter
for browser clients that can't set headers. The first frame is
`{ "type": "connected" }`; each incident is `{ "type": "incident", "incident": { … } }`.

```js
const ws = new WebSocket("ws://127.0.0.1:9500/stream?api_key=" + KEY);
ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  if (msg.type === "incident") console.log(msg.incident.ip, msg.incident.detections.map((d) => d.detectorId));
};
```

### Webhooks — push to your endpoint

Each configured URL receives an HTTP `POST` with body
`{ "type": "incident", "incident": { … } }` per incident. With a `secret`, the body is
signed HMAC-SHA256 and the hex digest is sent in `X-Hackerpot-Signature: sha256=<digest>`,
so the receiver can verify authenticity. `min_score` only delivers incidents at or
above a cumulative score; failed deliveries retry with exponential backoff.

**Danger alerts to a chat/paging endpoint.** A webhook with a high `min_score` *is* an
alert channel — it fires only when an IP crosses into confirmed-attacker territory. For
Slack and Discord specifically, set `format` and hackerpot renders a readable, escaped
message rather than raw JSON — see [Alert sinks](#alert-sinks). Whatever the destination,
three options make one safe to point at a channel somebody is watching:

- `dedupe_window_seconds` — suppress repeat alerts for the same source IP within the window,
  so one noisy attacker is one alert, not hundreds.
- `throttle_window_seconds` + `max_per_window` — cap total deliveries per window; beyond the
  cap, incidents are dropped (not queued) so a flood can't page you into the ground.
- `omit_body` — strip the attacker-controlled request `body` from the payload before it
  reaches a client that renders content. (It strips the body only — detection `reason`
  strings and captured headers still quote attacker input, so render alert text as plain
  text, not markup.)

```toml
# A general webhook — every incident, signed:
[[management.webhooks]]
url = "https://hooks.example.com/hackerpot"
secret = "shared-signing-secret"
max_retries = 3
min_score = 20
[management.webhooks.headers]
X-Team = "security"

# A danger-alert webhook to a chat channel — high bar, de-duped, throttled, body omitted:
[[management.webhooks]]
url = "https://hooks.slack.example/services/…"
min_score = 40
dedupe_window_seconds = 300
throttle_window_seconds = 3600
max_per_window = 20
omit_body = true
```

Verifying the signature on the receiving end (Node):

```ts
import { createHmac, timingSafeEqual } from "node:crypto";

function verify(rawBody: string, signatureHeader: string, secret: string): boolean {
  const expected = `sha256=${createHmac("sha256", secret).update(rawBody).digest("hex")}`;
  const a = Buffer.from(signatureHeader);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}
```

The `ManagementServer` class is also exported, so you can attach the same API to a
middleware deployment. Env overrides for the last mile: `MANAGEMENT_API_KEYS`
(comma-separated), `MANAGEMENT_HOST`, `MANAGEMENT_PORT`.

---

## Alert sinks

An incident feed is only useful if it reaches somebody. Three destinations ship with
hackerpot, and all three assume every field they carry is hostile — because every field
is: the request path, the User-Agent, a captured shell command, and the detector `reason`
strings that quote them back.

### Slack and Discord

Point a webhook at the platform's own incoming-webhook URL and set `format`:

```toml
[[management.webhooks]]
url = "https://hooks.slack.com/services/T000/B000/xxxx"
format = "slack"          # or "discord"; default "hackerpot" = the native incident JSON
min_score = 20            # only the ones worth interrupting somebody for
dedupe_window_seconds = 300
```

This reuses the whole delivery path the native webhook already had — HMAC signing, retries
with backoff, per-IP de-duplication, throttling, and the in-flight cap — and changes only
the body. What the rendering adds is the escaping each platform actually needs:

| Risk | What the renderer does |
| --- | --- |
| `GET /@everyone` pages your entire Discord server | the text is markdown-escaped **and** the payload carries `allowed_mentions: {parse: []}` — the platform's own guarantee that no mention in the body can resolve |
| `<!channel>` in a path pings a Slack channel | Slack builds mentions out of angle brackets, so `&`, `<` and `>` are HTML-escaped |
| a URL in a captured path gets *fetched* by your chat provider, telling the attacker their probe landed | link previews are disabled on both (`unfurl_links`/`unfurl_media` off, Discord's `SUPPRESS_EMBEDS` flag set) |
| a newline in a captured value forges an extra field in the alert | every value is flattened to one line before it is placed in the message |
| a huge capture blows the platform's message limit | fields and the whole message are truncated to fit |

`omit_body` **defaults to `true`** for these two formats and `false` for `hackerpot`. The
request body is raw attacker payload — a serialized exploit, a malware stager, sometimes
somebody else's data — and a chat client renders it to everyone in the channel. Set
`omit_body = false` if you genuinely want it.

> Escaping is not a promise that alert text is attacker-*free*. Detector `reason` strings
> quote slices of the request by design. Render alerts as plain text wherever they land.

### Syslog / SIEM

```toml
[syslog]
host = "siem.internal"
port = 514
protocol = "udp"          # or "tcp" — reconnects with backoff and reports what it lost
format = "cef"            # "cef" (SIEM-native) | "json" | "text"
min_score = 0
```

This is **deliberately independent of `[management]`**: shipping to your SIEM should not
also require exposing a REST API over your captured attacker data. Setting `host` turns it
on. It sits directly on the hit path, so it forwards HTTP incidents and protocol-honeypot
incidents alike.

Three properties the transport holds, all because it is fed at a rate the attacker chooses:

1. **One message is always one line.** Syslog is line-framed, so a newline inside a
   captured value would end our record and let whatever follows be read as a separate
   event — with a source IP of the attacker's choosing, indistinguishable from a real
   detection. The formatters escape; the transport strips again anyway.
2. **Messages are bounded.** RFC 3164 only obliges a receiver to accept 1024 bytes, and a
   UDP datagram past the path MTU is silently lost, so a long capture is truncated rather
   than sent into a hole. Truncation is byte-aware and never splits a UTF-8 character.
3. **Drop, never queue.** When a TCP collector is down, messages are discarded and the
   outage is reported **once** — not once per lost message. A queue in front of an
   unavailable consumer is just unbounded memory growth moved somewhere less visible.

The library form takes a broker or a direct feed:

```ts
import { SyslogSink } from "hackerpot";

const sink = new SyslogSink({ host: "siem.internal", protocol: "tcp", minScore: 20 });
sink.start();                          // open the TCP connection now, not on the first hit
sink.attach(management.broker);        // or call sink.send(hit) from your own onHit
```

`start()` matters for TCP: without it the connection is opened by the first `send()`,
which is then dropped for want of a ready socket — so the first thing an attacker does
becomes the one event that never reaches the SIEM. The standalone service calls it
before any listener binds. It is a no-op for UDP.

---

## The dashboard

A styled test console for the management API — the fastest way to confirm the server
is up and watch detections roll in. Start the honeypot (`npm run dev` enables the
management API with the key `dev-key`), then:

```bash
npm run dashboard          # → http://127.0.0.1:8080
```

Enter the API key and you get six tabs. Each is linkable — the tab lives in the URL
hash (`#stats`), so a bookmark or a shared link opens where you left off.

**Overview** — the headline count, unique IPs, actor fingerprints, active blocks and
tracked IPs, plus stat tiles for the top offender, last-seen, peak request rate,
median score and blocked share. Below them an incident-volume chart over the whole
observation window (with the distinct source IPs active in each bucket), detections
by type, top offenders by score, the response mix, and the five most recent hits.

**Incidents** — the searchable table. Filter by detector or IP; click any row to
expand a plain-language explanation of *why it fired* (what each detector's attack is
trying to do and how it was detected), *what the response did and why*, what this IP
has been doing overall, the full request headers, and the raw incident JSON.

- **Payload auto-decode** — the expanded row peels layered URL-, base64- and
  hex-encoding off the request's header and body values, and off the payload samples
  the detectors captured, then shows what was hidden inside (e.g. a base64'd
  `cat /etc/passwd`) so you read the actual intent without hand-decoding.

**Statistics** — the analysis view, scoped by a time window (5m → 24h) and by
protocol, with a data-table view behind every chart:

- *Volume & tempo* — incidents over time, cumulative unique IPs and actors,
  request cadence (the inter-arrival gap distribution plus a coefficient of variation
  that separates a script on a timer from irregular human traffic), and an activity
  clock heatmap of hour-of-day × day-of-week.
- *Detections* — detector frequency, total score contributed per detector, and a
  co-occurrence matrix showing which detectors corroborate each other on the same
  request.
- *Severity* — the per-incident score histogram, per-incident and per-IP score
  percentiles, the response mix by class, and an escalation funnel counting how many
  source IPs were merely seen, deceived, slowed, or blocked outright.
- *Attack surface* — most-probed paths, HTTP methods, the HTTP/SSH/SMTP split,
  client User-Agents, and the structural shape of the captured requests.
- *Sources* — address class, country and ASN (the latter two once you configure a
  data-backed enricher), and a sortable per-IP breakdown with an activity sparkline.
- *Obfuscation* — the encodings observed and the share of incidents that hid a
  payload behind one.

**Sessions** — each source IP's incidents in order, as a narrative: click one to
expand the timeline and watch the score climb and the response escalate with it.

**Actors** — incidents grouped by actor fingerprint instead of by IP, so an attacker
who rotated through addresses collapses into one actor with every IP they used.

**Threat intel** — the IOC feed at a chosen minimum score, with copy-to-clipboard for
the IP list or the JSON, and the raw Prometheus exposition.

A **Live feed** toggle streams new incidents over the WebSocket as they happen,
flashing each new row and refreshing the statistics as they arrive.

It's a small proxy server ([scripts/dashboard.ts](scripts/dashboard.ts)) that
forwards REST **and** WebSocket to the management API, so the browser stays
same-origin and the security API needs no CORS. Point it at a different honeypot with
`MGMT_URL` (default `http://127.0.0.1:9500`); change its own port with `DASHBOARD_PORT`.

---

## nginx edge capture

If nginx sits in front of your app, you can catch the *statically-recognizable*
attacks at the edge and reverse-proxy them to the honeypot, so they never touch your
real backend:

```bash
npm run generate:nginx                              # writes 3 files into nginx/
npm run generate:nginx -- --upstream 10.0.0.5:4004  # point at your honeypot host
npm run generate:nginx -- --server-name shop.example.com --app-upstream 127.0.0.1:8000
npm run generate:nginx -- --stdout                  # print instead of writing
npm run generate:nginx -- --no-injection            # skip the URI-injection map
```

`include` in nginx is a verbatim textual splice, so a file can only be included into
the context its directives belong to. The generator emits one file per context, each
carrying its own install instructions in the header:

| file | goes to | context |
| --- | --- | --- |
| `hackerpot-http.conf` | `/etc/nginx/conf.d/` | `http {}` — once per host |
| `hackerpot-server.conf` | `/etc/nginx/snippets/` | `server {}` — once per protected vhost |
| `hackerpot-site.conf.example` | `/etc/nginx/sites-available/` | a complete worked vhost |

### What the edge diverts — read this before enabling it

The in-process middleware is conservative: anything no detector flags falls through
untouched. **The nginx edge is not the same trade.** It classifies on `$uri`,
`$request_method`, `$http_user_agent` and `$request_uri` alone, with no knowledge of
whether the client is legitimate, so two rules divert real traffic:

- **`$hp_bad_file` matches by extension**, anywhere on the vhost: `.zip`, `.tar`,
  `.tar.gz`, `.tgz`, `.gz`, `.rar`, `.7z`, `.bz2`, `.sql`, `.sqlite`, `.db`, `.dump`,
  `.bak`, `.old`, `.orig`, `.save`, `.swp`, `.tmp`, `.log`, `.DS_Store`, and
  `.git`/`.svn`/`.idea`/`.vscode` paths. A site that serves release archives, database
  exports, or log downloads will have those requests answered by the honeypot instead of
  by the app — from a real browser, with a real session.
- **`$hp_bad_ua` matches the client, not the request**: `curl/`, `wget/`,
  `python-requests`, `go-http-client`, `libwww-perl` and the scanner list. If you run a
  public API, every legitimate `curl` and `requests` client is diverted on *every* path.

Both are deliberate — at the edge, "a browser would never ask for this" is the whole
signal — but they are the difference between "safe next to production" and "safe next to
*your* production". Before enabling:

```bash
# Dry-run the classification against your real access log.
awk '{print $7}' /var/log/nginx/access.log | sort -u > /tmp/paths.txt
grep -Ei '\.(zip|tar|tar\.gz|tgz|gz|rar|7z|bz2|sql|sqlite|db|dump|bak|old|orig|save|swp|tmp|log)$' /tmp/paths.txt
```

Anything that returns is a path your users request today and the edge would take away.
Either drop that rule from the generated `map`, or serve those files from a hostname you
do not include `hackerpot-server.conf` into. `--no-injection` only removes the
`$hp_bad_uri` map; the file and UA maps are separate.

The honeypot's own detectors still see everything either way — the edge only decides
what reaches your app.

### Wiring it into sites-enabled

```bash
sudo cp nginx/hackerpot-http.conf   /etc/nginx/conf.d/
sudo cp nginx/hackerpot-server.conf /etc/nginx/snippets/
```

`/etc/nginx/nginx.conf` already ends its `http {}` block with
`include /etc/nginx/conf.d/*.conf;` and `include /etc/nginx/sites-enabled/*;`, so the
http half needs no edit anywhere. Then add **one line** to the vhost you want
protected, in `/etc/nginx/sites-available/<yoursite>`:

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    include snippets/hackerpot-server.conf;   # <-- anywhere inside server {}

    location / {
        proxy_pass http://127.0.0.1:3000;     # your app, untouched
    }
}
```

```bash
sudo ln -s ../sites-available/<yoursite> /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Include paths are relative to the nginx prefix, so `snippets/…` resolves to
`/etc/nginx/snippets/…`. Include the **http** file exactly once — two vhosts pulling
it in would define `upstream hackerpot_backend` twice and nginx would refuse to start.
On RHEL/Alpine there is no `sites-enabled`; the http file still goes in `conf.d/`, but
give the server file a non-`.conf` suffix (`hackerpot-server.inc`) so the automatic
`conf.d/*.conf` include does not try to load server-context directives at http level.

### How the diversion works

The config is derived directly from the detector definitions (one source of truth), so
regenerating keeps it in sync.

- **http context** — the `hackerpot_backend` upstream plus `map`s that flag scanner
  User-Agents, suspicious HTTP methods, risky file extensions, and (best-effort)
  injection payloads in the request URI, combined into one `$hp_flagged` variable.
- **server context** — a `location` per decoy path, and a server-level
  `if ($hp_flagged)` covering every other path. Both just `return 418`, an internal
  marker `error_page` turns into a redirect to a single `@hackerpot` location. `return`
  is the one construct that is always safe inside `if`, the status never reaches the
  client, and the snippet sets no `proxy_*` at server level — your own `location`
  blocks are left exactly as they were.

Flagged requests are `proxy_pass`ed to the honeypot (not HTTP-redirected), so the
attacker is transparently served by the decoy and can't tell they were diverted. The
request line is forwarded raw, so the honeypot's own detectors see the original
encoding, and real client IPs arrive via `X-Forwarded-For`.

> **You must also set `trust_proxy = true` on the honeypot.** This is the half of the
> pair that is easy to miss, because nothing *looks* broken without it. The
> `X-Forwarded-For` nginx sets is ignored unless the honeypot trusts it, so every
> diverted request is attributed to **nginx's own address** rather than the attacker's.
> Hits are still recorded and the dashboard still fills up — but every attacker shares
> one score bucket, per-IP scoring stops meaning anything, `/ioc.txt` exports the
> proxy's address, and once that shared score crosses the block threshold the honeypot
> blocks the proxy: a 403 for every diverted request from everyone, first probe
> included. Enable it *only* with this proxy in front — `trust_proxy` with nothing
> overwriting the header lets any client forge its own source IP.

Two details worth knowing, both handled in the generated file. nginx rejects `TRACE`
and `CONNECT` itself during request-line parsing, before any config runs, so `405` is
routed to `@hackerpot` alongside the marker code — otherwise those two verbs would get
a stock error page and never be recorded. (Only nginx-generated 405s are caught; a 405
from your proxied app passes through untouched. If the vhost serves static files, note
that nginx answers `POST` to a static file with 405 too.) And because nginx has no
urldecode, the injection signatures are automatically widened to match percent-encoded
payloads — `union%20select` and `%3Cscript` are what real tooling actually sends.

**What nginx can't do statically**, so the running honeypot still owns these: path
and credential brute-force, rate spikes (per-IP state), the TCP port-scan sentinel
(below HTTP), and injection payloads in bodies/headers (nginx can't decode them at
this layer). The generated config validates with `nginx -t`.

---

## Mail defense — SMTP honeypot

`SmtpHoneypot` is a **low-interaction SMTP listener** — the mail-server equivalent
of the port-scan sentinel. It speaks just enough of the protocol (`EHLO`, `AUTH`,
`MAIL FROM`, `RCPT TO`, `DATA`, `VRFY`/`EXPN`, …) to look usable and keep an attacker
talking, while recognizing the four things that only ever come from abuse:

| Finding (detector id) | What it catches |
| --- | --- |
| `smtp-auth-bruteforce` | credential guessing via `AUTH LOGIN`/`PLAIN` — captures the submitted user/pass, always answers `535` |
| `smtp-open-relay` | a `MAIL FROM` external sender → `RCPT TO` external recipient — trying to relay spam through you |
| `smtp-spam` | a message body actually delivered over `DATA` — the spam/phishing payload, captured, never sent |
| `smtp-user-enumeration` | `VRFY`/`EXPN` probing for which mailboxes exist |

**Nothing is ever authenticated or relayed.** Incidents are mapped into the same
`HoneypotHit` shape as HTTP hits (`method: "SMTP"`), so they share per-IP scoring and
appear in the [management API](#incidents-management-api) and [dashboard](#the-dashboard)
right next to HTTP incidents — a brute-forcer on SMTP raises the same IP's suspicion
that could get it blocked on HTTP.

```ts
import { SmtpHoneypot, MemoryStore } from "hackerpot";

const store = new MemoryStore(); // share this with your HoneypotServer for unified scoring
const smtp = new SmtpHoneypot({
  port: 2525,                    // 25 needs privileges; 2525 is a common unprivileged stand-in
  banner: "Postfix",
  hostname: "mail",
  localDomains: ["mycorp.test"], // mail for anything else, from an external sender, is relay abuse
  store,
  onHit: (hit) => console.warn("[smtp]", hit.detections[0]?.detectorId, hit.path),
  dropAboveScore: 40,            // refuse connections from IPs already deep in the block range
});
await smtp.listen();
```

| Option | Default | Meaning |
| --- | --- | --- |
| `port` | — | TCP port to listen on |
| `host` | all interfaces | bind address |
| `banner` | `"Postfix"` | server name in the `220` greeting and `EHLO` reply |
| `hostname` | `"mail"` | hostname advertised in `EHLO`/`HELO` responses |
| `localDomains` | `[]` | domains this server would legitimately accept mail for; anything else (from an external sender) is open-relay abuse |
| `store` | — | share the honeypot's store so SMTP incidents contribute to per-IP scoring |
| `onHit` | — | called with each incident in `HoneypotHit` form (wire to the management feed) |
| `onIncident` | — | protocol-native `SmtpIncident` callback, if you want the raw SMTP detail |
| `dropAboveScore` | — | refuse + drop connections from IPs whose cumulative score is at least this (needs `store`) |
| `captureBody` | `true` | store the raw `DATA` message body; set `false` for privacy/safety (the parsed `Subject` and byte count are still recorded, but the raw body — which may carry malware — is not) |
| `maxBodyChars` | `2000` | max bytes of the message body retained on the incident when captured |

The `DATA`-phase message is captured (the spam/phishing payload itself), with the parsed
`Subject` surfaced in `headers["smtp-subject"]` and the size in
`headers["smtp-message-bytes"]` for quick triage. Set `captureBody: false` when you don't
want the raw payload stored — the Subject and size still land, so you can triage without
retaining attacker content.

`npm run dev` starts the SMTP honeypot on `:2525` alongside everything else; drive it
with `npm run attack:smtp`.

For the standalone service, enable it in the config file — it listens and shuts down
alongside the honeypot, and its incidents publish to the management API on the same
path as HTTP hits:

```toml
[smtp]
enabled = true
port = 2525            # 25 needs privileges
host = "0.0.0.0"
banner = "Postfix"
hostname = "mail"
local_domains = ["mycorp.test"]   # external→external mail is relay abuse; lowercased at parse time
drop_above_score = 0              # refuse IPs at/above this cumulative score (0 = never)
```

---

## SSH honeypot

`SshHoneypot` catches the internet's single most common automated attack:
**SSH credential brute-force.** It's a **medium-interaction** honeypot — it completes
the real SSH transport handshake (built on the [`ssh2`](https://github.com/mscdex/ssh2)
library, so the key exchange and crypto are battle-tested) and then captures what
attackers send at the auth layer, rejecting every attempt by default. Opt into
[interactive mode](#interactive-mode--capturing-what-attackers-do) and it accepts the login
into a **fake shell** that captures commands — but nothing is ever really authenticated and
no command ever executes on the host.

| Finding (detector id) | What it catches |
| --- | --- |
| `ssh-auth-bruteforce` | password guessing — captures the exact **username and password** the bot tried |
| `ssh-publickey-probe` | offered public keys — captures the username, key algorithm, and a SHA256 fingerprint |
| `ssh-scan` | a connection that handshakes and grabs the version banner without trying to log in (recon) |
| `ssh-shell-command` | (interactive mode) a command the attacker ran in the fake shell — the command lands in `body` |
| `ssh-shell-session` | (interactive mode) the full ordered command transcript, emitted when the session closes |

The captured password lands in the incident's `body` and the client's SSH version
string in `headers["ssh-client"]`, so you can see exactly what software is hitting you
and which credentials are in circulation. Incidents map into the same `HoneypotHit`
shape (`method: "SSH"`) and share per-IP scoring with the HTTP honeypot, so a
brute-forcer on SSH raises the same reputation that gets it blocked on HTTP.

```ts
import { SshHoneypot, MemoryStore } from "hackerpot";

const store = new MemoryStore(); // share with your HoneypotServer for unified scoring
const ssh = new SshHoneypot({
  port: 2222,                    // 22 needs privileges; 2222 is the common unprivileged stand-in
  ident: "OpenSSH_8.4",          // the client sees "SSH-2.0-OpenSSH_8.4"
  store,
  onHit: (hit) => console.warn("[ssh]", hit.headers["ssh-user"], "→", hit.body /* the password */),
  maxAuthAttempts: 6,            // drop the connection after this many tries
  dropAboveScore: 40,           // refuse IPs already deep in the block range
});
await ssh.listen();              // generates an ephemeral RSA host key if none is given
```

| Option | Default | Meaning |
| --- | --- | --- |
| `port` | — | TCP port to listen on |
| `host` | all interfaces | bind address |
| `ident` | `"OpenSSH_8.4"` | server software id — the client sees `SSH-2.0-<ident>` |
| `hostKeys` | ephemeral RSA | host private key(s) in PEM/OpenSSH form; generated at startup if omitted |
| `maxAuthAttempts` | `6` | close the connection after this many credential attempts |
| `store` | — | share the honeypot's store so SSH incidents contribute to per-IP scoring |
| `onHit` / `onIncident` | — | `HoneypotHit` callback (wire to the management feed) / raw `SshIncident` callback |
| `dropAboveScore` | — | refuse connections from IPs whose cumulative score is at least this (needs `store`) |
| `interactive` | `false` | accept the login and drop the attacker into a **fake shell** that captures the commands they run |
| `acceptOnAttempt` | `1` | in interactive mode, accept the login on this attempt (earlier ones are captured + rejected) |
| `shellHostname` | `"srv01"` | hostname shown in the fake shell prompt |
| `maxCommands` | `100` | max commands captured per interactive session before it's closed |
| `maxCommandLength` | `4096` | max bytes captured per command line (longer is truncated) |

### Interactive mode — capturing what attackers *do*

By default the SSH honeypot is auth-only: it captures credentials and rejects every login.
Set `interactive: true` and, after `acceptOnAttempt` attempts, it **accepts** the login and
presents a fake shell that records each command the attacker runs (`ssh-shell-command`) plus
the full transcript when they disconnect (`ssh-shell-session`). This captures what an
attacker actually does with a foothold — the URLs they `wget`, the droppers they run, their
recon sequence — not merely that they knocked.

**Nothing executes.** The shell is a scripted stream the honeypot writes canned output to;
there is no PTY to any real shell and no path from a typed command to the host. Captured
commands are length-bounded (`maxCommandLength`) and count-capped (`maxCommands`) per
session. In the standalone service, enable it with `interactive` under `[ssh]`.

`npm run dev` starts the SSH honeypot on `:2222` alongside everything else; drive it
with `npm run attack:ssh`. For the standalone service, enable it in the config file
(it listens, shuts down, and publishes incidents alongside the SMTP honeypot):

```toml
[ssh]
enabled = true
port = 2222              # 22 needs privileges
host = "0.0.0.0"
ident = "OpenSSH_8.4"    # the client sees "SSH-2.0-OpenSSH_8.4"
max_auth_attempts = 6
drop_above_score = 0     # refuse IPs at/above this cumulative score (0 = never)
# Omit both for an ephemeral RSA host key (all a honeypot needs), or pin one:
host_key_files = []      # ["/etc/hackerpot/ssh_host_rsa_key"] — read from disk
host_keys = []           # inline PEM strings
```

> ⚠️ The SSH honeypot depends on `ssh2` (added as a runtime dependency). It never
> authenticates a client or opens a shell — it captures the attempt and rejects it.

---

## FTP honeypot

`FtpHoneypot` is a **low-interaction FTP listener**. FTP is old, is still swept
constantly — it turns up on appliances nobody administers — and it carries its
credentials in the clear, which is exactly what makes a fake one pay. It speaks enough
of RFC 959 to keep a client working through its script, and reports the things that
only ever come from abuse:

| Finding (detector id) | What it catches |
| --- | --- |
| `ftp-auth-bruteforce` | credential guessing via `USER`/`PASS` — captures the pair in plaintext, answers `530` |
| `ftp-anonymous-login` | an `anonymous`/`ftp`/`guest` login attempt — the oldest reconnaissance question there is |
| `ftp-bounce` | a `PORT`/`EPRT` naming an address that is **not the client's** — asking us to open a connection to a third party |
| `ftp-traversal` | `../`, an encoded equivalent, a null byte or an absolute system path in any command that takes a filename |
| `ftp-command` | in interactive mode, each command issued after the login was granted |
| `ftp-scan` | a connection that takes the banner and leaves without offering a credential |

**The FTP bounce is the one worth understanding.** `PORT h1,h2,h3,h4,p1,p2` tells a real
server where to open the data connection — and nothing in the protocol says that address
has to be the client's. Historically that let an attacker use an FTP server to port-scan
or attack a third party from *its* address. hackerpot parses the command, compares the
address to the peer's, reports the mismatch, and **never opens the connection**; there is
no code path from that command to a `connect()`.

Detection does not wait for a login. In the default (non-interactive) configuration every
post-auth command is refused with `530`, so gating the bounce and traversal findings on a
successful login would mean never reporting either one — the ask is the evidence, not
whether we honoured it.

**No data connection is ever opened in either direction**, no file is served or accepted,
and there is no filesystem behind the fake directory. Incidents map into the same
`HoneypotHit` shape as HTTP hits (`method: "FTP"`), so they share per-IP scoring and appear
in the [management API](#incidents-management-api) and [dashboard](#the-dashboard).

```ts
import { FtpHoneypot, MemoryStore } from "hackerpot";

const store = new MemoryStore(); // share with your HoneypotServer for unified scoring
const ftp = new FtpHoneypot({
  port: 2121,                    // 21 needs privileges; 2121 is the usual stand-in
  banner: "(vsFTPd 3.0.3)",
  store,
  onHit: (hit) => console.warn("[ftp]", hit.detections[0]?.detectorId, hit.path),
  dropAboveScore: 40,
});
await ftp.listen();
```

| Option | Default | Meaning |
| --- | --- | --- |
| `port` | — | TCP port to listen on |
| `host` | all interfaces | bind address |
| `banner` | `"(vsFTPd 3.0.3)"` | server name in the `220` greeting |
| `maxAuthAttempts` | `6` | close the connection after this many credential attempts |
| `store` | — | share the honeypot's store so FTP incidents contribute to per-IP scoring |
| `onHit` / `onIncident` | — | `HoneypotHit` callback / raw `FtpIncident` callback |
| `dropAboveScore` | — | refuse + drop connections from IPs at or above this cumulative score (needs `store`) |
| `interactive` | `false` | accept the login and capture the commands issued against the fake tree |
| `acceptOnAttempt` | `1` | in interactive mode, accept on this attempt number |
| `maxCommands` | `100` | max commands captured per session before it's closed |
| `maxCommandLength` | `512` | max characters retained per command |
| `maxConnections` | `256` | cap on simultaneous open connections |
| `maxSessionMs` | `120000` | hard lifetime for one connection, bounding a slow connection-hold |

`npm run dev` starts it on `:2121`; drive it with `npm run attack:ftp`. For the standalone
service:

```toml
[ftp]
enabled = true
port = 2121              # 21 needs privileges
host = "0.0.0.0"
banner = "(vsFTPd 3.0.3)"
max_auth_attempts = 6
drop_above_score = 0     # refuse IPs at/above this cumulative score (0 = never)
interactive = false      # accept the login and record what they do with it
```

---

## Telnet honeypot

`TelnetHoneypot` is the highest-yield trap in this project, for an unglamorous reason:
Telnet has no transport security, so credentials arrive in the clear, and the IoT botnet
families descended from Mirai sweep ports 23 and 2323 continuously with a hard-coded list
of vendor defaults. What you collect is **the live default-credential list being sprayed
at your netblock** — and, in interactive mode, the staging URL the dropper reaches for the
moment it believes it is in.

| Finding (detector id) | What it catches |
| --- | --- |
| `telnet-auth-bruteforce` | a `login:`/`Password:` pair, captured in the clear |
| `telnet-command` | in interactive mode, each command run in the fake shell |
| `telnet-session` | the full ordered transcript, emitted when the session closes |
| `telnet-scan` | a connection that takes the banner and leaves without submitting a password |

Each failed login **re-prompts**, exactly as `telnetd` does — so a botnet working through
its list hands over the whole list rather than one pair.

### Option negotiation is handled, not skipped

Telnet interleaves control commands with the data stream: an `IAC` byte (`0xFF`) starts a
two- or three-byte command, or a variable-length sub-negotiation. A honeypot that reads the
stream as plain text ends up with `0xFF` sequences embedded in the credentials it captured.
`TelnetCodec` (exported, and tested on its own) strips and answers them, holding two
properties that matter under hostile input:

- **Resumable across chunks** — an attacker can send one byte at a time; the parser state
  survives between reads, so a split command is still parsed as one command.
- **Bounded replies** — negotiation is symmetric, and a hostile peer can answer each of our
  refusals with another request forever. Past a cap we stop replying and keep reading. A
  honeypot that can be made to generate unbounded traffic is an amplifier.

Because the honeypot announces `WILL ECHO`, it controls the echo — which is what lets it
echo the username keystroke by keystroke and **withhold the password**, like a real login.

**Nothing executes.** The fake shell is a scripted stream shared with the SSH honeypot
([`src/shell.ts`](src/shell.ts)) — the same botnets run the same recon down either pipe, so
one implementation means one place to make the illusion better. It answers the BusyBox
applet probe (`/bin/busybox <APPLET>` → `applet not found`) that IoT droppers use to
fingerprint a live device, and it fetches nothing for a `wget` or `curl`: the URL has
already been captured, which is the entire value.

```ts
import { TelnetHoneypot, MemoryStore } from "hackerpot";

const store = new MemoryStore();
const telnet = new TelnetHoneypot({
  port: 2323,                    // 23 needs privileges; 2323 is itself heavily swept
  banner: "Ubuntu 22.04.3 LTS",
  hostname: "srv01",
  interactive: true,             // capture what they run once they think they are in
  store,
  onHit: (hit) => console.warn("[telnet]", hit.detections[0]?.detectorId, hit.body),
});
await telnet.listen();
```

| Option | Default | Meaning |
| --- | --- | --- |
| `port` | — | TCP port to listen on |
| `host` | all interfaces | bind address |
| `banner` | the fake MOTD | printed before the login prompt; a device-shaped one draws the sweeps |
| `hostname` | `"srv01"` | hostname in the `login:` and shell prompts |
| `maxAuthAttempts` | `3` | what `telnetd` allows; each failure re-prompts |
| `store` | — | share the honeypot's store so Telnet incidents contribute to per-IP scoring |
| `onHit` / `onIncident` | — | `HoneypotHit` callback / raw `TelnetIncident` callback |
| `dropAboveScore` | — | refuse connections from IPs at or above this cumulative score (needs `store`) |
| `interactive` | `false` | accept the login and drop them into the fake shell |
| `acceptOnAttempt` | `1` | in interactive mode, accept on this attempt number |
| `maxCommands` | `100` | max commands captured per session |
| `maxCommandLength` | `4096` | max characters retained per line |
| `maxConnections` | `256` | cap on simultaneous open connections |
| `maxSessionMs` | `120000` | hard lifetime for one connection |

`npm run dev` starts it on `:2323` in interactive mode; drive it with
`npm run attack:telnet`, which replays a Mirai-style default-credential sweep followed by
the BusyBox fingerprint and a payload fetch. For the standalone service:

```toml
[telnet]
enabled = true
port = 2323              # 23 needs privileges
host = "0.0.0.0"
banner = "Ubuntu 22.04.3 LTS"
hostname = "srv01"
max_auth_attempts = 3
interactive = false      # the post-login capture is the reason to run this
```

> Captured commands are attacker-controlled text that lands in your logs, your store, and
> any webhook you forward to. Length is capped, and the text log escapes control characters
> so a captured command cannot forge log lines.

---

## Docker

The image runs the standalone service ([src/standalone.ts](src/standalone.ts)) — a
production entrypoint distinct from the tsx dev server. It ships with
[hackerpot.toml](hackerpot.toml) baked in at `/app/hackerpot.toml`; bind-mount your own
over it, and use environment variables for per-deployment overrides.

```bash
docker build -t hackerpot .
docker run --rm -p 4004:4004 hackerpot                          # memory store
docker run --rm -p 4004:4004 -e HIT_LOG=/data/hits.jsonl \
  -v "$PWD/data:/data" hackerpot                                 # durable audit log
docker run --rm -p 4004:4004 \
  -v "$PWD/hackerpot.toml:/app/hackerpot.toml:ro" hackerpot       # your own config

# Full stack — honeypot + Redis for shared scoring, a hit-log volume,
# and decoy TCP ports for the port-scan sentinel:
docker compose up --build
```

The image is multi-stage (build → slim runtime with prod deps only), runs as the
non-root `node` user, shuts down gracefully on `SIGTERM`, and its `HEALTHCHECK` is a
plain TCP connect — deliberately not an HTTP request, so the probe never registers as
a honeypot hit or trips the scanner-signature detector.

---

## Data shapes

An **incident** is a `HoneypotHit`. This is exactly what the REST API returns, the
WebSocket pushes, and the webhook posts:

```jsonc
{
  "id": "86610780-8cbe-449d-aa2d-f2602b5b2f53",  // uuid
  "timestamp": "2026-08-25T17:47:16.859Z",       // ISO 8601
  "ip": "203.0.113.7",                            // source IP (proxy-aware)
  "method": "GET",
  "path": "/.env",
  "headers": { "host": "…", "user-agent": "curl/8.5.0" },
  "body": "…",                                    // present for POST/PUT/PATCH, size-capped
  "detections": [                                 // everything that fired, highest score first
    {
      "detectorId": "decoy-path",
      "reason": "Exposed .env file probe",
      "score": 10,
      "metadata": { "decoyId": "dotenv", "payload": { "status": 200, "contentType": "text/plain" } }
    }
  ],
  "score": 10,                                    // points this request added
  "totalScore": 10,                               // this IP's cumulative score after it
  "respondedWith": "decoy-content"                // the response action that ran
}
```

`GET /stats` returns:

```jsonc
{
  "totalIncidents": 42,
  "uniqueIps": 10,
  "byDetector": { "decoy-path": 5, "rate-spike": 10, "payload-injection": 5, /* … */ },
  "byResponse": { "not-found": 12, "tarpit": 22, "block": 4, "decoy-content": 4 },
  "topOffenders": [ { "ip": "203.0.113.11", "score": 40, "incidents": 5 } ],
  "firstSeen": "2026-08-25T17:47:16.859Z",
  "lastSeen": "2026-08-25T18:02:21.531Z"
}
```

---

## Testing & the attack simulator

The repo ships a simulator that reproduces one realistic attack per detector, so you
can see the whole system react.

```bash
npm run dev            # start the honeypot + management API
npm run attack:all     # fire every scenario
npm run attack -- path-bruteforce     # or a single scenario
```

Scenarios: `decoys`, `path-bruteforce`, `credential-bruteforce`, `rate-spike`,
`scanner-signature`, `payload-injection`, `suspicious-method`, `sensitive-file`,
`header-anomaly`, `ssrf-probe`, `open-redirect`, `crlf-injection`, `web-shell`,
`honeytoken`, `port-scan`, `smtp` (mail-server abuse), and `ssh` (SSH credential
brute-force against the SSH honeypot).
Each HTTP scenario runs from its own spoofed source IP (via `X-Forwarded-For`, which
the dev server trusts) so you can watch each detector — and the full escalation
ladder — independently. The dev server seeds a demo honeytoken so the `honeytoken`
scenario has something to replay, and its demo policy routes several of the new
probes to the newer responses (`web-shell` → `fake-success`, `ssrf-probe` →
`gzip-bomb`, `open-redirect` → `rate-limit`, `crlf-injection` → `chaos`) so you can
see those in the dashboard.

Run the unit/integration suite with `npm test` (Vitest). It covers the detectors, the
stores, the config parser, the SMTP/SSH honeypots, and the management API (REST auth,
filtering, the live WebSocket feed, and webhook HMAC signatures).

It also includes a **false-positive suite** ([src/false-positives.test.ts](src/false-positives.test.ts))
that runs a corpus of *legitimate* traffic — real browser and API-client requests,
static assets, OAuth redirects, proxied requests with internal IPs in
`X-Forwarded-For`, search queries that superficially resemble payloads (`union
station`, `drop off locations`) — through the full default detector set (and over
real HTTP) and asserts that **nothing fires**. Since flagging a real user is the
worst failure mode for something running next to production, any detection there is
treated as a bug.

---

## Extending hackerpot

Every layer is an interface, so you extend by writing a small object — no forking.

**A custom detector** — return `undefined` to pass, or a `Detection` to flag:

```ts
import type { Detector } from "hackerpot";

export function refererTrapDetector(): Detector {
  return {
    id: "referer-trap",
    inspect(ctx) {
      const referer = ctx.headers["referer"];
      if (typeof referer === "string" && referer.includes("evil.example")) {
        return { detectorId: "referer-trap", reason: `Referer from ${referer}`, score: 5 };
      }
      return undefined;
    },
  };
}

new HoneypotEngine({ extraDetectors: [refererTrapDetector()] });
```

Stateful detectors read `ctx.tracker` — the source IP's sliding window
(`countIn(ms)`, `uniquePathsIn(ms)`, `countPathIn(path, ms)`).

**A custom response action** — implement `execute(ctx)` and write to `ctx.res`:

```ts
import type { ResponseAction } from "hackerpot";

export function teapotAction(): ResponseAction {
  return {
    id: "teapot",
    execute(ctx) { ctx.res.statusCode = 418; ctx.res.end("I'm a teapot"); },
  };
}

new HoneypotEngine({ extraResponseActions: [teapotAction()] });
```

**A custom store** — implement `record` / `list` / `scoreFor` (sync or async) against
any backend (Postgres, DynamoDB, a message queue, …):

```ts
import type { HitStore, HoneypotHit } from "hackerpot";

class MyStore implements HitStore {
  record(hit: HoneypotHit) { /* persist */ }
  list() { return []; }
  scoreFor(ip: string) { return 0; }
}
```

**A custom policy** — see [The scoring policy](#the-scoring-policy).

---

## Project layout

```
src/
  core.ts            HoneypotEngine — runs detectors, scores, picks a response
  middleware.ts      Express/Connect middleware (two-phase, body-safe)
  server.ts          standalone HTTP server
  http-request.ts    shared request parsing: bounded body read, null-prototype query
  standalone.ts      TOML/env-configured production entrypoint (the container CMD)
  state.ts           per-IP sliding-window activity tracking
  config/            TOML config: parsing, validation, and building the engine from it
  detectors/         one file per detector + a barrel with defaultDetectors()
  responses/         one file per response action + policy + defaultResponseActions()
  stores/            HitStore implementations: memory, file, redis, composite
  management/        incidents API: REST + WebSocket feed + webhooks, API-key auth
                     (alerts.ts renders the Slack/Discord webhook formats)
  smtp/              low-interaction SMTP honeypot (mail defense)
  ssh/               medium-interaction SSH honeypot (credential capture, via ssh2)
  ftp/               low-interaction FTP honeypot (credentials, bounce, traversal)
  telnet/            medium-interaction Telnet honeypot (+ codec.ts: IAC negotiation)
  shell.ts           the scripted fake shell SSH and Telnet share — nothing executes
  syslog.ts          syslog/SIEM forwarding, independent of the management API
Dockerfile           multi-stage image running src/standalone.ts
docker-compose.yml   honeypot + redis + hit-log volume
hackerpot.toml       default standalone config — every built-in default, annotated
scripts/
  dev-server.ts      local honeypot for manual testing (+ management API)
  attack.ts          attack simulator driving every detector
  generate-nginx.ts  emits includable nginx edge configs from the detector definitions
  dashboard.ts       proxy dev server for the management-API test GUI
  dashboard.html     the styled dashboard single-page app
tests/               the Vitest suites (unit, integration, false-positive, hardening)
```

---

## Development

```bash
npm run build       # emit dist/ (ESM + CJS + .d.ts) — src only, no test declarations
npm run typecheck   # type-check src + tests + examples (tsconfig.typecheck.json)
npm test            # run the Vitest suite
npm run example     # a tiny app with hackerpot mounted (examples/basic-server.ts)
```

Tests live in [`tests/`](tests/) and import the library from `../src`. The build
config (`tsconfig.json`) stays `src`-only so no test declarations reach `dist`; a
separate `tsconfig.typecheck.json` covers `src` + `tests` + `examples` for
`npm run typecheck`. CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs
typecheck + test + build on Node 20 and 22 against a fresh checkout of each commit.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the conventions — the false-positive suite,
the "library owns semantics, config defers" rule, and verifying commits with
`git archive`. Detection and response are decoupled, so the natural way to contribute
is a new detector or response file plus a test — see [Extending hackerpot](#extending-hackerpot).

## License

hackerpot is **free to use, modify, and distribute — but not to sell**. See
[LICENSE](LICENSE) for the exact terms; in short:

- **Free for everyone**, including commercial businesses and production use. Run it in
  front of your own product, deploy it for a client, fork it, modify it, keep your
  changes private — all fine, at no charge.
- **You may not sell it.** No paid copies, no paid hosted version of it, and no
  bundling it into a product where it is a substantial part of what the customer is
  paying for. Charging for *your own* services around it is fine.
- **Keep the notice.** Any copy or modified version you distribute must ship the
  copyright notice and the license text intact.

Want to do something the license doesn't allow? Ask
[Michał Płatosz](mailto:platosz.michal@gmail.com) about separate commercial terms.

> Note: this is a source-available license, not an OSI-approved open-source one.
> Tools that expect a standard SPDX identifier will show it as unrecognized.

---

## Security notes

- **Decoys are detection, not defense.** Nothing here replaces authentication, access
  control, or a real WAF. Keep your actual protections; hackerpot tells you who's
  probing and slows them down.
- **Keep the management API private.** It exposes captured attacker data. Bind it to
  loopback or an internal network, never a public interface, and use long random API
  keys.
- **Set `trust_proxy` correctly.** It is **off by default** — enable it only when a
  trusted proxy *overwrites* `X-Forwarded-For` (a proxy that merely appends leaves the
  leftmost value attacker-controlled). The resolved IP is what the allowlist exempts,
  the blocklist blocks, and the firewall enforcer acts on, so with it wrongly on a
  client can spoof its source IP to dodge per-IP scoring, impersonate an allowlisted
  source and bypass detection entirely, or frame another address. Values that aren't a
  valid IP are ignored outright and the socket address is used instead.
- **Exempt known-good sources with the allowlist.** `allowlist` (IPs + CIDRs, v4/v6)
  skips detection entirely for uptime monitors, health checkers, and office/VPC
  ranges — they never score, block, or leave an incident. The best final guard
  against false positives on infrastructure you control.
- **Blocking is per-instance by default, opt-in shared.** By default a block lives in
  an in-memory `MemoryBlocklist` on the instance that issued it (lost on restart).
  Pass a `RedisBlocklist` (`config.blocklist`) to make blocks **survive restarts and
  apply across every replica** — the block is a Redis key with a native TTL.
- **The honeypot bounds its own resource use.** Detector regexes are length-capped
  and ReDoS-audited; the SMTP/SSH listeners cap concurrent connections
  (`maxConnections`); and `tarpit`/`drip-feed`/`large-payload` cap concurrency
  (`maxConcurrent`), degrading to an immediate response at capacity — so a flood
  can't invert these defenses and exhaust *your* sockets. Still size them for your
  capacity.

### Firewall enforcement (opt-in)

Blocks are honeypot-internal by default (a request from a blocked IP is short-circuited
with a `403`). To push a block **out to the OS firewall or a cloud WAF**, wrap any blocklist
in an `EnforcingBlocklist` so every block also fires a `BlockEnforcer`: `commandEnforcer`
runs `iptables`/`nft` via `execFile` (never a shell), or `webhookEnforcer` POSTs JSON
(optionally HMAC-signed) to a privileged helper. The IP is validated with `net.isIP`
centrally before any enforcer runs, so a hostile `X-Forwarded-For` can't inject a command.

```ts
import { EnforcingBlocklist, MemoryBlocklist, commandEnforcer } from "hackerpot";

new HoneypotEngine({
  trustProxy: true,
  blocklist: new EnforcingBlocklist(
    new MemoryBlocklist(),
    commandEnforcer({ argv: ["iptables", "-w", "-A", "INPUT", "-s", "{ip}", "-j", "DROP"] }),
    (err) => console.error("[firewall]", err.message),
  ),
});
```

**Two caveats:** enforcement acts on the *resolved* client IP, so only enable it with
`trust_proxy` correct and a trusted proxy in front (else a spoofed `X-Forwarded-For` could
firewall-block an arbitrary victim), and the webhook URL is operator-set (mind SSRF to
internal services). Blocking awaits the enforcer, so each blocked request spawns a process
(command enforcer) and waits up to `timeout_ms` — keep it short, and under a flood of
distinct IPs prefer the **webhook** form (a small privileged helper does the dropping) over
running the honeypot itself with `CAP_NET_ADMIN`.

This is also the enforcement path that [threat-intel ingest](#threat-intel-ingest-consuming-other-honeypots-ioc-feeds)
deliberately keeps *ingested* (hearsay) blocks away from by default — only locally-observed
blocks reach it, unless you explicitly opt in.

### Ideas not yet implemented

- **`robots.txt` lures** — advertise trap paths as `Disallow`; anything that fetches
  them anyway is not a legitimate crawler.
- **TLS/JA3 fingerprinting** — cluster by the TLS ClientHello, complementing the
  [header-ordering fingerprint](#actor-fingerprinting--cross-ip-correlation) already in place
  (which needs no TLS termination).
