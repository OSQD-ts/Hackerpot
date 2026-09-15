# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Versions are published by
[the release workflow](CONTRIBUTING.md#releasing).

## [Unreleased]

### Added

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

- A path spelled with encoding, doubled slashes or dot segments no longer bypasses decoys.
- Regex options with the `g` or `y` flag no longer match only every other request.
- A slow live-feed viewer can no longer make the management server buffer without limit.
- Querying `/metrics` no longer reads the whole store, and its counters no longer fall
  when retention trims old hits.
- A client that disconnects before a delaying response starts no longer holds its slot.
