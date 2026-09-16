# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Versions are published by
[the release workflow](CONTRIBUTING.md#releasing).

## [Unreleased]

### Added

- **Runtime changes are marked on the traffic charts.** The Notices panel answers "was there
  a change?"; a dashed mark on the incident-volume chart answers "did the traffic change
  because of it", which is the question somebody actually has after tuning a rule. Marks are
  placed from the bucket span rather than by index, so one lands where it happened however
  coarse the buckets are, and a change outside the window is dropped rather than clamped to
  the edge — a clamped mark would claim a change happened inside a range it did not. Both the
  Overview and Statistics volume charts carry them, since both draw the same corpus.
- **The dashboard shows what the honeypot has said about itself.** The engine already kept a
  bounded history of notices — startup warnings, an allowlist entry that matches nothing, a
  service token short enough to guess, and every `reconfigure` with the part it changed and
  who made it — and nothing ever surfaced it, so the only way to learn a rule was swapped at
  14:02 was to have been tailing the log at 14:02. There is now a Notices panel on Overview,
  behind `/api/notices` and the `overview` section, with repeats grouped into one row and a
  count so a recurring setting cannot bury the startup warning under it. It is engine-backed
  only: a dashboard reading another process's management API has no notices to show and is
  told so, rather than shown an empty panel that looks like silence.
- **Alerts can go to a NotifyJS hub.** `notifyJsSink({ url, token })` publishes to the hub's
  HTTP ingest, so honeypot alerts reach the same devices as the rest of your operational
  notifications. Written against `POST /api/notify` as the hub actually implements it, and
  each refusal is reported as itself — a hub with ingest switched off answers 404 by design,
  which must not read as a wrong URL, and 421/401/403/429 are a TLS problem, a revoked token,
  a role that cannot publish and a rate limit respectively. What is sent is thin on purpose:
  who, what and what the honeypot did, with no headers, no captured body and the path clipped,
  because it lands on a lock screen and the store already has the request in full.
- **The notification module has bothandlerjs's shape, and its safety properties.** `notify/` is
  split into `types` (the event contract), `hub` (the fan-out) and `sinks` (the destinations),
  so the two libraries are read the same way. Every sink now receives an **event** — `hit`,
  `downgrade`, `anomaly` or `error` — rather than a bare incident, `consoleNotifier()` ships as
  the sink to start with, and a `filter` (`types`, `minScore`, `certainOnly`) says what reaches
  each hub. The hub also gained the bounds that previously existed only inside the webhook
  dispatcher: repeats of one address and response collapse per window, a global per-window
  ceiling catches distributed traffic where every event differs, and what was suppressed is
  reported when the window rolls. Syslog and any sink you write are now covered by them too.
  Proof passes a `minScore` gate it would not otherwise clear, and failures and anomalies are
  never deduplicated.
- **Tune a policy against the traffic you just watched.** Three endpoints, each off unless the
  deployment grants it: `POST /api/test` runs a pasted curl command, header block or User-Agent
  through the detectors as a dry run (nothing recorded, no score moved, no response served);
  `POST /api/policy/preview` replays recent incidents against a candidate rule set and reports
  what would be answered differently; `POST /api/policy/apply` replaces the running policy,
  attributed to the viewer. Previewing is possible because a policy is pure, and the module says
  plainly what it is faithful about — the decision and the proof guard — and what it cannot be,
  namely what an action would have *done* and anything a rule reads off the live activity window.
- **`controls`: what a dashboard viewer may do, beside `sections` for what they may see.**
  `testRequest`, `previewPolicy` and `editPolicy`, every one off unless turned on — the opposite
  default to sections, because a section reveals what the dashboard already holds while a control
  reaches back into the engine. `editPolicy` refuses to start alongside `auth: false`: deciding
  what the honeypot does to every later request is a larger power than reading the captured data
  that page already shows. There is no role model, deliberately — a role is one listener per
  capability over the same handler.
- **A search box on the Incidents screen.** Fielded terms (`ip:`, `path:`, `detector:`, `action:`,
  `rule:`, `score:>20`, `ua:`, `actor:`), quoted phrases, parentheses and `$and`/`$or`/`$not`,
  with adjacent terms meaning `$and`. The operators carry a `$` because a bare "or" is a word that
  appears in User-Agents and paths, and nothing in the grammar throws — it backs a box somebody is
  still typing into. The vocabulary is a parameter, so a second screen reuses the grammar rather
  than growing a second dialect.
- **Addresses can be sent as networks, and secret headers can be named.** `redactIncident`
  now takes options: `maskIp` replaces the source address with its network (`/24`, `/48`),
  `secretHeaders` names the headers a deployment knows are secret, and `guessSecretHeaders`
  turns off the name-shape guess. Credentials and addresses are independent — a receiver may
  be trusted with one and not the other. Wired as `mask_ip` on `[syslog]` and on each webhook,
  and the masking helper the dashboard already used is now the one everything shares, so
  "masked" cannot come to mean two different things.
- **A corpus run can be compared against an earlier one.** `corpus --json` records one entry
  per case (served or not, which action, which detectors), and `corpus --baseline before.json`
  reports what changed side since — exiting non-zero when traffic that used to be served no
  longer is, or a case stopped meeting its expectations. This is the question a passing corpus
  cannot answer on its own, because cases are deliberately not pinned to exact actions.
- **The state caps are public, and a threshold above one is refused.** `MAX_IPS_PER_FINGERPRINT`,
  `DEFAULT_MAX_EVENTS` and `MAX_PATH_CHARS` are exported, and the config rejects a detector
  threshold the bounded state behind it can never reach — `distinct_ip_threshold` above what
  the registry remembers, `unique_path_threshold` above what an activity window holds. Such a
  setting is not a strict detector, it is a switched-off one that looks configured.
- **Evidence strength, alongside scores.** Every detection now has a tier — weak, moderate,
  strong, certain — derived from its score and `certain` flag unless it sets one, and the
  engine combines them by noisy-OR into a `confidence` in [0, 1] recorded on each incident.
  Each finding is worth less than the last, one root cause still counts once, and suspicion
  alone is capped at 0.95: only proof reaches 1. This closes the gap addition cannot — a pile
  of forgivable findings summing to a number that looks like proof, which once took a real
  visitor past the block threshold in seven page views. Rules can match `min_confidence` /
  `max_confidence`. Scores are unchanged and still drive the ladder and the stored totals.
- **A marker for whoever probes.** In middleware mode the honeypot can hand a signed,
  `HttpOnly` cookie to clients it answers as probes, so one actor stays correlated across
  changing addresses even when their fingerprint shifts — which is where `repeat-actor`
  stops working. The opt-in `marker-drift` detector fires on one marker presented from
  several addresses. It is set only on the honeypot's own responses (a visitor who trips
  nothing is never marked), never exempts anybody, and is never proof, since a cookie can be
  copied. `[markers] secret` is required rather than defaulted: a marker anybody can mint
  invents actors instead of correlating them.
- **One place incidents leave the process, and webhooks without the REST API.** A
  `NotificationHub` owns the fan-out, so the service publishes each incident once and every
  sink — the management feed and its counters, webhooks, syslog — receives it, with a failing
  sink isolated from its neighbours and from the request. Syslog was previously called by
  hand at two hit-path call sites because the broker belonged to the optional management
  server, which also meant **webhook alerting required enabling the management API**. Webhooks
  can now be configured at the top level (`[[webhooks]]`) and are delivered whether or not it
  is; `[[management.webhooks]]` still works, and the service now says so at startup when they
  are configured with the API switched off.
- **Names for sources you already know.** `ActorLabels` (and `[[actors]]`) puts a name on the
  addresses you can already identify — your uptime checker, a partner's integration, a
  vendor's scanner — matching on address ranges, ASN, organisation, User-Agent or reverse-DNS
  name, and recording it on the incident as `actor`. A label **never exempts**: a named actor
  is detected, scored and answered exactly as it would be otherwise; exemption remains the
  allowlist's job. `hideFromFeed` mutes a known constant source in the dashboard's live pane
  only — it is still recorded, counted and listed. Hostname matching resolves out of band and
  is never awaited on the request path, so no response waits on DNS.
- **The honeypot can learn what your site actually serves.** `engine.reportOutcome()` feeds a
  `SiteBaseline` with the status your application answered each request with — the middleware
  reports every request it passes through — and the baseline turns "unusual path" from a
  guess about your site into a measurement against it. The opt-in `path-novelty` detector
  reads it: one address asking for several paths the site has never served, or one such path
  being walked by many addresses at once, which no per-address volume threshold sees. It
  learns only from what the application served (never from what was requested), stays inert
  until warm, and shares the `path-probing` family with `path-bruteforce` so one walk is
  scored once.
- **A policy can be written as data, and every incident says which rule decided it.**
  `rulePolicy([...])` takes first-match-wins rules — matching on detectors, proof, either
  score, path prefixes or patterns, method and address ranges — and each one carries an id
  and a sentence, both recorded on the hit and returned from `evaluate`. `observe()`,
  `protectApp()` and `standalone()` are rule sets to start from and edit. In TOML:
  `[policy] preset` and `[[policy.rules]]`, with your rules consulted before the preset's and
  a `respond_with` naming an unknown or disabled action refused at startup rather than
  degrading to a silent 404. A `block` a rule asks for is still subject to the proof guard,
  and the refusal is now written into the incident's reason instead of being silent.
- **The engine announces what it does.** `engine.on("hit" | "shadow" | "error" | "warning" |
  "change", listener)` returns its own unsubscribe, and a listener that throws or hands back
  a rejected promise can only break itself — the remaining listeners still hear the event and
  the request is unaffected. `reconfigure(patch, { by })` reports what it replaced and by
  whom, `warn()` and `notices()` keep a bounded history for a dashboard opened later, and
  settings that would quietly do nothing (an unmatchable allowlist entry, a guessable service
  token) say so.
- **Time is injectable.** `clock` on the engine, the registries, the blocklists, the DNS
  cache, the audit, the webhooks and the dashboard, with `ManualClock` for tests.
- **The dashboard ships in the library, three ways and from two kinds of source.**
  `startDashboard(engine)` serves it on a listener of its own (loopback by default),
  `createDashboardHandler(engine, { basePath, auth })` mounts it on a server you run, and
  `<hackerpot-dashboard>` from `@osqd/hackerpot/element` embeds it in an admin page of yours.
  It reads either this process (an engine, a management server, a store) or another
  HackerPot's management API (`managementApiSource`). Authentication is required anywhere
  but loopback (basic, token or your own check), with a DNS-rebinding host check, a client
  allowlist, throttled credentials, concealed refusals if you want them, a nonce CSP,
  sections withheld on the server, and credentials redacted from captured requests by
  default. The standalone service serves it from a `[dashboard]` section, and
  **`hackerpot dashboard`** runs it as its own service beside a running stack, holding the
  management API key itself; `docker compose --profile dashboard up` does the same in
  containers. The old development proxy (`scripts/dashboard.ts`) and launcher are gone.
- **A command line.** `hackerpot serve | dashboard | check | config | replay | explain |
  detectors | robots`, published as the package's `bin` and as `@osqd/hackerpot/cli`. The
  flags the service took before (`--check`, `--replay`, `--explain`, `--print-config`) still
  work.
- **The traffic corpus is a package entry**, `@osqd/hackerpot/corpus`, with a runner and a
  scorecard: `npm run corpus`, and `runCorpus` against your own configuration.
- **Package layout** follows bothandlerjs: subpath exports (`/adapters`, `/cli`, `/corpus`,
  `/element`), `bin/hackerpot.mjs`, documentation in `docs/` shipped with the package, and a
  course.
- `HoneypotEngine.subscribe(listener)` and `publish(hit)`, for consumers attached after
  construction.
- **Published as `@osqd/hackerpot`, with a container image.** Every qualifying push to
  `main` publishes a version derived from its commits, a `v*` tag publishes exactly that
  version, and each release pushes `ghcr.io/osqd-ts/hackerpot`. `main` also pushes `edge`.
- **Decoy prefixes.** A decoy can match everything under a path at a `/` or `.` boundary.
  The built-in set uses it, so `/.env.production`, `/.git/index`, `/.aws/config` and
  `/actuator/env/...` are caught, and it gains decoys for heap dumps, Spring Cloud Gateway,
  CouchDB, Solr, Tomcat, Jenkins, Druid, GeoServer, router exploits, Fortinet, Yii and
  package-registry credentials.
- **Hidden traps** (`trapDetector`, opt-in): trap links, form fields and a header that no
  person can reach, treated as proof. `renderTrapLink`, `renderTrapField`, `trapFormGuard`
  for POST forms in middleware mode, and `generateRobotsTxt({ trapPaths })`.
- **Traffic audit** (`[audit]`, on by default): compares recent traffic with the hour before
  and reports spikes in flagged traffic, request rate, blocks, proof-guard refusals and
  detector failures, plus probe campaigns (many addresses suddenly probing a new path).
  Anomalies are logged and sent to webhooks.
- **Published crawler ranges** (`published_ranges`, opt-in): verifies Googlebot, Bingbot,
  GPTBot, OAI-SearchBot, ChatGPT-User and DuckDuckBot against the address lists their
  operators publish.
- **Service tokens** (`[service_tokens]`): a header secret that exempts your own monitors
  from detection, compared in constant time.
- **`hackerpot --explain`**: which detectors fire on one request, from a User-Agent, a curl
  command or raw headers. **`hackerpot --replay`**: what the configured detectors would have
  made of an access log.
- **Metrics**: `hackerpot_downgrades_total` and `hackerpot_detector_failures_total{detector}`.
- **Detectors**: `header-integrity`, `target-integrity`, `crawler-verification` (DNS).
- **Middleware**: proof required to block, fail-open on internal errors, shadow detectors,
  a detector deadline, and adapters for Koa, Fastify and Fetch-style handlers.
- **Webhooks**: timestamped signature (`X-Hackerpot-Signature-V2`), redaction by default, no
  retries on refusals, a global delivery cap and suppression summaries.
- **Tooling**: labelled traffic corpus, public-API pin, package load check, performance
  budgets, coverage thresholds, documentation link check, `SECURITY.md`.

### Changed

- The payload-injection detector skips values containing none of the characters a payload
  needs, which makes long query strings much cheaper to evaluate.
- Detectors that reason from a missing header skip requests rebuilt from logs
  (`RequestFacts.partialHeaders`).

### Fixed

- **The Incidents count was the number of rows on the page.** It showed `incidents.length` —
  bounded by the page size, by retention and by what the live feed had dropped — so a busy
  honeypot displayed the same number all day while reading as a count of incidents. Counts are
  now kept separately in minute buckets (`/api/counts`), which hold no addresses and no
  headers, so a window far longer than the retained entries can be counted honestly; the
  pill's title says what the table itself is showing. An actor muted with `hideFromFeed` is
  still counted — hiding a known source from the pane must not delete it from the tally.
- **Syslog forwarding stripped no credentials.** The dashboard and webhooks redact the copy
  that leaves the process; the syslog sink did not, so a captured `Authorization` header or a
  submitted password was shipped to the collector verbatim — indexed, retained for as long as
  the retention policy says, and readable by more people than ever touch the honeypot. It now
  applies the same redaction, with `[syslog] redact = false` to opt out.
- A path spelled with encoding, doubled slashes or dot segments no longer bypasses decoys.
- Regex options with the `g` or `y` flag no longer match only every other request.
- A slow live-feed viewer can no longer make the management server buffer without limit.
- Querying `/metrics` no longer reads the whole store, and its counters no longer fall
  when retention trims old hits.
- A client that disconnects before a delaying response starts no longer holds its slot.
