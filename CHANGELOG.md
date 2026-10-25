# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Versions are published by
[the release workflow](CONTRIBUTING.md#releasing).

## [Unreleased]

### Changed

- **The dashboard is built from the OSQD UI kit (`@osqd/ui`), as bothandlerjs's is.** The kit's
  stylesheet is read at build time (a devDependency, like `@osqd/jql`) and stamped ahead of the
  page's own rules in the same nonced `<style>` and the same adopted sheet, so the CSP, the
  runtime dependencies and the offline page are unchanged. Panels are the kit's cards, counters
  its stat tiles, ranked bars its bar list, badges its chips — detectors wear its hue tags, held to
  4.5:1 in every theme — and tables, buttons, fields, segmented ranges, tabs and toasts its own.
  The categorical series and the sequential and ordinal ramps are the kit's too. The shared
  computed-style contract now pins the kit's look, and bothandlerjs's suite holds its page to the
  same values.
- **Seven themes instead of two.** The theme button is a picker: `auto` (the default, following
  the system's light or dark setting), `light`, `dark`, `graphite`, `midnight`, `contrast`,
  `paper` and `slate`. A choice stored by the old toggle still applies. `<hackerpot-dashboard>`'s
  `scheme` takes the same names. The accessibility pass now runs in four of them.

### Deprecated

- **The dashboard's own colour tokens as an override surface** (`--accent`, `--text`, `--page`,
  `--surface`, `--s1`…`--s8`, `--q0`…`--q12`, `--o1`…`--o5`, …). They still work in this release —
  they are aliases of the kit's `--oq-*` tokens now — but set the kit's tokens instead; see
  [embedding](docs/operations/embedding.md#theming). The old names will be removed in a later
  release.

### Added

- **The dashboard is tested in a real browser.** `npm run test:browser` drives the page with
  Playwright under every engine in CI — the feed opens with a keyboard, filters and groups and
  pages, saves a filter the next page finds, fits a 390px screen without scrolling sideways, and
  has no serious axe violation on any screen. It also pins the shared look as computed styles, so
  a rule that stops applying fails here rather than being noticed in a screenshot months later.
  The DOM half of the client had string matching before this — "the bundle contains the word
  ArrowDown" — which passes just as happily against a handler wired to the wrong element, and
  which let a stylesheet ship truncated with every test green.
- **A detector or an action named anywhere opens its entry.** The Reference screen is now an
  index beside one open entry, the shape bothandlerjs's has, and the names in an opened incident
  are links into it: the card says what that detector saw here, and the entry says what it looks
  at in general.
- **The Policy screen says what has already been changed.** Beside the editor, a Changes panel
  lists what was replaced in this process at runtime and by whom where authentication could say,
  and Export downloads the rules being edited.

- **A Policy screen, and a Reference screen.** The policy endpoints had no page: `previewPolicy`
  and `editPolicy` were served and nothing used them. Now there is an editor for the rules, a
  preview that replays them against the incidents on screen and lists what each would answer
  differently, an Apply that needs `editPolicy` (and so authentication), and a Draft a rule button
  on an opened incident. Reference explains every detector and response action on a screen of its
  own, filterable, with nothing fetched — both screens bothandlerjs has had.
- **The Incidents toolbar is bothandlerjs's, with its saved filters.** Save the search and the
  outcome chip under a name, load it from the list, delete it; the dashboard keeps them for anybody
  who opens it (`savedFilters.file` keeps them across restarts, `GET`/`POST /api/filters`), and the
  browser keeps a copy for a dashboard that comes back empty. Alongside: completion in the search
  box, a From/To window, Order and Group with roll-up and *Only this*, a pager with a page size above
  and below the table, confirmations as toasts, `outcome:` in the query language, and the counter
  strip bothandlerjs keeps above its views.
- **An opened incident ends with what can be done with it,** as a bothandlerjs row does: copy or
  download its replay line (the same JSON line the Incidents export writes, which `hackerpot
  replay` reads), and — where the `testRequest` control is granted — test this request, which
  puts its method, target, headers and body into Test a request. Below that, a quiet footer with
  the time, the rule that chose the response and the incident id.
- **`LegacyDetection`,** the old detection shape, exported as a deprecated type for code that has
  to name it while it moves over.
- **Incidents can be exported, and the dashboard has bothandlerjs's keys.** Export downloads the
  incidents the filter shows as JSON Lines that `hackerpot replay` reads as they are, so a set of
  requests seen on one honeypot can be run through another configuration. `/` searches the
  incidents, 1–6 switch screens, and Escape clears the search.
- **The dashboard can test a request, as bothandlerjs's can.** With the `testRequest` control
  granted, a Test a request panel sits beside the Incidents table: paste a User-Agent, a curl
  command or a request with its headers, press Try it (or Ctrl+Enter), and it shows the detectors
  that fire with their reasons, the score and confidence, and the response the policy would
  choose. The endpoint existed; nothing on the page used it. It is a dry run, and without the
  control the panel is not shown. The demo grants it.
- **Exemptions and evaluation time are measured.** A request let through by the allowlist or a
  service token used to leave no trace in `/metrics`, and an exemption nobody can observe is a
  control nobody can audit. `hackerpot_bypassed_total{reason}` counts them — once, at the front
  end that decided, so the form guard re-checking the same request does not count it again — and
  both reasons are present from the first scrape so an alert has a series to watch.
  `hackerpot_evaluation_duration_ms` is a histogram of time spent in detection, on bothandlerjs's
  own bounds, since a millisecond means the same thing in both. It is measured with a monotonic
  high-resolution timer rather than the injectable clock, whose millisecond resolution would put
  every sub-millisecond evaluation at zero. The dashboard's dry run is neither counted nor timed.
  An in-process dashboard now renders these too, and with them the detector failures it had
  always dropped by reading the store alone.
- **Shadow mode has a metric, and scores have a distribution.** Shadowed detectors exist to
  trial a detector on real traffic, and until now their findings were recorded on each incident
  and counted nowhere, so the one question shadow mode answers had to be reconstructed from the
  store by hand. `hackerpot_shadow_firings_total{detector}` counts them, apart from
  `incidents_by_detector` because a shadowed finding decided nothing. `hackerpot_proven_total`
  says how much of what was caught is proof rather than suspicion, and a `hackerpot_score`
  histogram shows how close traffic runs to a block across the whole run rather than the
  dashboard's last thousand incidents. The buckets share bothandlerjs's name and not its values:
  a cumulative score here is unbounded and decided at 15 and 40, so the bounds sit there.
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

- **The Incidents search box speaks `@osqd/jql`'s text syntax.** The page kept a filter language
  of its own, adapted from bothandlerjs's; it is now the shared one, parsed into a JQL query and
  run by that engine, with this dashboard's fields as its vocabulary. What a saved filter says
  mostly means what it did, and a few things mean more:
  - `ip:` matches an address as a whole, so `ip:203.0.113.4` no longer finds `203.0.113.45` and
    excluding one address no longer excludes its neighbours. A prefix that ends on a boundary,
    `ip:203.0.113`, still finds the network; one that ends mid-octet, `ip:203.0.11`, does not.
  - `method:` and `outcome:` match exactly, ignoring case: `outcome:time` no longer finds
    `time cost`, which is written `outcome:"time cost"` (completion quotes it).
  - `score:` and `total:` compare as numbers: a bare `score:10` is equality where it was a
    substring that `score:1` also matched, and ranges (`score:10..20`, `score:40..`) and `=` work.
  - `-term` and `!term` negate, `field:$in(a, b)` and `field:$notin(a, b)` take a set, and
    `has:rule` / `-has:rule` ask whether a field is set. Each used to be searched for as text.
  - A quote after a field name holds the value together — `reason:"bait path"` is one term, where
    it was two — single and typographic quotes included.
  - A value that cannot be read as its field's kind (`score:high`, an empty `$in(`) matches
    nothing, and on a text field `path:>5` looks for the characters `>5`.

  Saved filters are still stored as the text that was typed, and the page still reads the first
  512 characters of it. JQL is bundled into the dashboard's browser script rather than installed
  beside it: `@osqd/jql` is a development dependency, and the package's runtime dependencies are
  unchanged.

- **The two dashboards look alike where they do the same work.** Both feeds put the row's colour
  at its left edge, print the date above the time, and lay their tables out with container queries
  against the panel rather than media queries against the window — which is the difference between
  a feed that survives being embedded in a 320px column and one that amputates its right-hand
  columns on an ordinary desktop. The panel, the note, the emphasised button and the counter strip
  are the same rules in both, and the Incidents screen carries a Reading this legend for the
  colours it uses.

- **Six dashboard modules are now the same file as bothandlerjs's,** byte for byte: the DOM and
  selector helpers, the pager, the saved-filter client and its server-side store, and the feed
  counts. `FeedCounts` takes an options object, and the saved-filter store is told which chips
  this dashboard draws.
- **The dashboard uses bothandlerjs's colours throughout,** its blue accent included; the amber
  accent is gone, and so is the page's narrower width. The Detector and Source IP boxes and Clear
  filter are replaced by the search language (`detector:`, `ip:`) and the chips, as in bothandlerjs;
  *Show only this address* now fills in `ip:` rather than refetching, and Show is called Load.
- **The dashboard shares bothandlerjs's colours and type.** The dark scheme uses the same neutral
  surfaces, lines and status inks (it had a blue cast of its own), tab counts are outlined pills,
  and badges, bar labels and a request's method use the same faces and weights.
- **Sessions, Actors and Threat intel are framed like the Incidents feed:** a titled panel with its
  count at the far end, the description and filters inside it, then the list — the frame
  bothandlerjs puts round its actor registry.
- **More of the dashboard is drawn the way bothandlerjs draws it.** A titled panel has a header
  strip: the title on a ruled line, with its scope and the table-view toggle at the far end. A
  counter tile leads with the number, then what it counts (a screen reader still hears the label
  first). Section headings lose their amber bar, time-window choices are a row of pills, and the
  Incidents screen has one-click outcome chips — All, Decoy, Time cost, Block, Protocol capture,
  Silent 404 — above its filters, with the `/` shortcut shown in the search box it focuses.
- **The internal clock, LRU, emitter, deadline, pattern and DNS helpers are the same files as
  bothandlerjs's,** byte for byte, each merged from the better of the two copies. What that brings
  here: `node:dns` is loaded on first use rather than at import, a deadline no longer assumes the
  runtime's timers have `unref`, and the DNS result type is named `VerificationOutcome`
  (`DnsVerification` still works, deprecated). Address comparison moved from `allowlist.ts` to
  `internal/ip.ts`, and `sameAddress` is still exported from where it was.
- **Breaking: a detection's fields are `detector` and `summary`,** bothandlerjs's names, where they
  were `detectorId` and `reason`. Nothing already written needs migrating: the file, Redis and
  Elasticsearch stores upgrade hits recorded under the old names as they read them, a dashboard
  upgrades what an older management API sends it, and a custom detector still returning the old
  shape is upgraded by the engine. TypeScript naming the old fields no longer type-checks, and
  webhook receivers and readers of the management API now see the new names. See
  [Upgrading](docs/start/upgrading.md#names-shared-with-bothandlerjs).
- **The rest of the shared vocabulary matches bothandlerjs's too,** with the old names kept,
  deprecated, for a release: `Certainty`, `certainty`, `certaintyOf`, `certaintyOfConfidence` and
  `CERTAINTY_WEIGHT` (were `EvidenceTier`, `tier`, `tierOf`, `tierOfConfidence`, `TIER_WEIGHT`);
  `SiteProfile` and its option, property and context field `site` (were `SiteBaseline` and
  `baseline`); and `parseRequest` (was `parseRequestText`). The certainty weights keep this
  library's own values, which the docs explain.
- **The source follows bothandlerjs's module map.** The front ends are in `adapters/` (`node.ts`
  is the middleware, `server.ts` the standalone server), choosing a response is `policy/` and the
  responses themselves `actions/`, alert delivery including syslog is `notify/`, the protocol
  honeypots are under `protocols/`, the site profile is `site/`, and helpers with no public API of
  their own are in `internal/`. Every import path the package publishes is unchanged.
- **Tests are filed by the module they test,** in `<module>.test.ts`, with shared builders in
  `tests/helpers.ts`, instead of by the review round that added them.
- **The npm scripts are fewer, and named the way bothandlerjs names them.** 65 became 29, in the
  same names and order as bothandlerjs's. The per-scenario `simulate:<scenario>` aliases are gone
  (`npm run simulate <scenario>`), as are `simulate:list` and `simulate:corpus:human`; the six
  shortcuts into the command — `serve`, `dashboard`, `replay`, `explain`, `config:check` and
  `config:verify` — are one, `npm run hackerpot -- <command>`; and `docker:build` and `docker:run`
  give way to the docker commands they wrapped. New: `npm run check`, which runs the typecheck,
  lint, tests and docs link check in one go. The upgrading guide maps every old name to its new
  form. None of this touches the published package.
- **The dashboard header is laid out like bothandlerjs's.** Two rows: the name, connection state
  and every control on the first; the tabs on the second, with the instance facts as plain text
  at its far end rather than styled like the buttons beside them. The Refresh button and the
  Live feed switch that took a row of their own under the tabs are now Pause/Resume in the
  header, and Refresh appears only while paused or when there is no live feed to follow, since
  otherwise the page is already current. The whole header sticks, so the tab strip no longer
  needs its own measured offset.
- **The rest of the dashboard follows bothandlerjs's styling too.** Buttons, fields, tiles, panel
  headings and table headers use the same sizes, weights and spacing, and a ranked bar now draws
  its name inside a tinted track rather than in a fixed-width column beside a thin bar, so a long
  detector id or address is no longer cut at a width chosen for the shortest. The palette,
  badges, charts and the other screens' contents are unchanged.
- **The Incidents screen is laid out like bothandlerjs's live feed.** The filters sit inside the
  table's panel, and each row reads as a request: method and path, then the address, actor name
  and User-Agent underneath, where the User-Agent had not been visible without opening the row.
  A coloured left edge says what the honeypot did — decoy, time cost, block or protocol capture,
  in the Overview's colours — so a run of blocks shows before a badge is read. Beside the table,
  Detectors firing and Busiest sources count the rows the filter shows. On a phone the detectors
  column gives way to the request, which is read in full rather than cut to a few characters.
- The payload-injection detector skips values containing none of the characters a payload
  needs, which makes long query strings much cheaper to evaluate.
- Detectors that reason from a missing header skip requests rebuilt from logs
  (`RequestFacts.partialHeaders`).

### Fixed

- **A feed row is no longer a control inside a control.** The `<tr>` carried `aria-expanded`,
  which ARIA allows only inside a treegrid, and held the keys while the actor link inside it held
  its own — two things for a screen reader to announce and no way to say which one Enter belongs
  to. The request is now one button with one name and one job; the row still opens on a click.
  Three more that the new browser suite found: a meter with no accessible name, a table and a
  metrics block that scrolled but no keyboard could reach, and the feed's date line failing the
  contrast floor.
- **Saved filters survive the upgrade that renamed their key.** Sharing the saved-filter module
  between the two dashboards renamed what the browser keeps them under; the old key is read when
  the new one is empty, so nothing anybody saved goes missing.

- **`header-integrity` and `target-integrity` had no explanation on the page.** An incident they
  flagged showed a dash where every other detection says what the attacker was after and how it
  was recognised. A test now fails if a shipped detector has no entry.
- **Redaction erased the payload of every prototype-pollution probe.** A JSON body was parsed and
  rebuilt to redact secret-named fields, and writing a `__proto__` key into a plain object sets
  its prototype rather than a key — so the dashboard, webhooks and the management API showed `{}`
  where the attacker sent `{"__proto__":{…}}`. The key is now kept, and a body with nothing to
  redact is passed on exactly as it arrived rather than re-serialised.
- **The empty Incidents table pointed at `npm run attack:all`**, a script that was renamed to
  `npm run simulate`.
- **The Overview's Notices panel was always blank.** It was drawn with the Threat intel screen
  rather than the Overview that holds it, so it stayed empty until somebody happened to open
  Threat intel first.
- **The Incidents tab no longer reads 0 on a honeypot that has recorded incidents.** Its count
  came from the dashboard's own minute counts, which start when the first viewer opens the page,
  so everything recorded before that was missing. It now takes the larger of those counts and
  the store's total, as the Overview already did.
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
