# Contributing to hackerpot

Thanks for helping. This project has a few hard-won conventions — following them
keeps the honeypot safe to run next to production and keeps the codebase honest.

## Development

```bash
npm install
npm run typecheck      # src + tests + examples (tsconfig.typecheck.json)
npm test               # Vitest
npm run lint           # Biome (biome check .); npm run format applies fixes
npm run build          # emit dist/ (ESM + CJS + .d.ts), src only
npm run demo           # every listener + the dashboard, from source
```

Node.js ≥ 20. TypeScript is `strict` with `exactOptionalPropertyTypes` and
`noUncheckedIndexedAccess` — expect the compiler to be picky, on purpose.

The scripts you will use most:

| Script | What it does |
| --- | --- |
| `npm run demo` | the HTTP honeypot :4004, SSH, SMTP, FTP, Telnet, port-scan sentinels, the management API :9500 (key `dev-key`) and the dashboard :9501 |
| `npm run demo:embedded` | the dashboard as `<hackerpot-dashboard>` inside a page |
| `npm run simulate` | fire every attack scenario at a running demo; `npm run simulate:<scenario>` for one, `npm run simulate:list` to list them |
| `npm run simulate:corpus` | send the labelled corpus over real sockets and check what fired; `simulate:corpus:human` for the human cases only |
| `npm run corpus` | run the corpus against a configuration |
| `npm run serve` | the real service from source (`hackerpot serve`) |
| `npm start` | the built service (`bin/hackerpot.mjs`) |
| `npm run dashboard` | `hackerpot dashboard`, reading a running management API |
| `npm run replay -- <log>` | `hackerpot replay` |
| `npm run explain -- "<UA\|curl\|headers>"` | `hackerpot explain` |
| `npm run config:check` | `hackerpot config`: validate and print the resolved configuration |
| `npm run config:verify` | `hackerpot check`: serve every enabled response action once |
| `npm run docs:check` | every local markdown link and heading anchor resolves |
| `npm run bench:guard` | fail if the request path got materially slower |
| `npm run check:package` | build, pack, install into an empty project, load as ESM, CJS and a command |
| `npm run client:build` / `client:check` | bundle the dashboard's browser code (runs before build, test and typecheck) |
| `npm run generate:nginx` | emit the nginx edge-capture files into `nginx/` |
| `npm run release:next` | the version the next automatic release would publish, and why |
| `npm run test:coverage` | the suite against the coverage thresholds |

## Documentation

The README is the argument and the index; the reference lives in [`docs/`](docs/index.md), one page per
question. When a change alters behaviour, update the page that describes it in the same commit, and run
`npm run docs:check`. Pages follow one shape: an H1, a one-line summary, a breadcrumb back to the index,
then prose that explains *why* as well as *how*, tables for option lists, examples that run against the
current API, and a "Related" list.

## The layers

Detection and response are decoupled. A **detector** ([`src/detectors/`](src/detectors/))
recognizes something and returns a scored `Detection`; it does not decide what
happens next. A **response action** ([`src/responses/`](src/responses/)) produces the
reply. A **policy** picks the action from the detections and the IP's cumulative
score. A **store** ([`src/stores/`](src/stores/)) holds incidents and scores. Add to a
layer without touching the others.

## Project layout

```
src/
  core.ts              HoneypotEngine: runs detectors, scores, picks a response
  middleware.ts        Express/Connect middleware (two-pass, body-safe) and trapFormGuard
  adapters/            Koa, Fastify, Fetch; the @osqd/hackerpot/adapters entry
  server.ts            the standalone HTTP server
  service.ts           the service `hackerpot serve` runs: every listener a config enables
  cli.ts               the command line; standalone.ts runs it (the container CMD)
  http-request.ts      bounded body read, null-prototype query, path normalisation
  http-hardening.ts    timeouts and a connection cap
  state.ts             per-IP sliding windows and the fingerprint registry
  fingerprint.ts       the actor fingerprint
  allowlist.ts         CIDR matching by value
  blocklist.ts         memory, Redis, composite blocklists
  firewall.ts          enforcing blocklist, command and webhook enforcers
  audit.ts             the traffic audit
  service-tokens.ts    constant-time service tokens
  crawler-ranges.ts    published crawler address ranges
  explain.ts           hackerpot explain
  replay.ts            hackerpot replay
  robots.ts            robots.txt generation
  enrichment.ts        special-use IP classification
  formats.ts           CEF and RFC 3164
  syslog.ts            syslog forwarding, independent of the management API
  logfmt.ts            the injection-safe text log
  shell.ts             the scripted fake shell SSH and Telnet share — nothing executes
  config/              TOML: schema, loading, environment, building the engine, reload planning
  detectors/           one file per detector + defaultDetectors()
  responses/           one file per response action + the default policy + the response check
  stores/              memory, file (with rotation), redis, elastic, composite, query semantics
  management/          REST, WebSocket, webhooks, metrics, redaction, Slack/Discord rendering
  dashboard/           the operator dashboard: server, sources, page
  dashboard/client/    its browser code, bundled into client.generated.ts
  intel/               threat-intel feed ingest
  smtp/ ssh/ ftp/      protocol honeypots
  telnet/              Telnet honeypot + codec.ts (IAC negotiation)
  internal/            DNS, deadlines, stateless patterns
bin/hackerpot.mjs      the published command
demo/                  the local demo stack
scripts/               simulator, corpus runner, nginx generator, benchmarks, link and package checks
examples/              a minimal integration to copy from
tests/                 Vitest suites: unit, integration, false-positive, corpus, hardening
hackerpot.toml         the default config — every built-in default, annotated
Dockerfile             multi-stage image running dist/standalone.js
docker-compose.yml     honeypot + redis + hit-log volume, and the dashboard profile
docs/                  the documentation
```

## Adding a detector

1. Write `src/detectors/your-thing.ts` — a factory returning a `Detector`. Return
   `undefined` to pass, a `Detection` to flag. Keep options in an interface with
   sensible defaults.
2. Export it from `src/detectors/index.ts` and, if it should be on by default, add
   it to `defaultDetectors()`.
3. Add a detection test **and** add legitimate cases to
   [`tests/false-positives.test.ts`](tests/false-positives.test.ts) (see below), and a hostile
   case to the corpus expecting it.
4. Wire the config surface in `src/config/*` and `hackerpot.toml` (see below).
5. Document it in [`docs/detection/detectors.md`](docs/detection/detectors.md) and
   [`docs/reference/configuration.md`](docs/reference/configuration.md).

**Never throw out of `inspect()`.** The engine isolates a throwing detector and skips it for
that request, but a detector that throws on crafted input has handed an attacker a way to
switch it off. If you parse (JSON, base64, a URL), wrap it in `try/catch`. Prefer regex
over parsing where you can, and cap the length of any attacker-controlled value you
scan (16 KB is the convention) so a crafted input can't become a CPU sink.

Only mark a detection `certain` if you can write down why no legitimate client can produce
it. See [the proof guard](docs/concepts/the-guard.md) and
[writing a detector](docs/detection/writing-a-detector.md).

## The false-positive suite is sacred

Flagging a real user is the worst thing a honeypot can do. Every detector must earn
its place against [`tests/false-positives.test.ts`](tests/false-positives.test.ts) —
a corpus of genuine browser and API-client traffic asserting that **nothing fires**.
If your detector trips a legitimate request, that's a bug in the detector, not the
test: tighten the signature. Add realistic legitimate cases that stress your
detector's boundary.

## The rule: the library owns semantics; config describes and defers

We have hit this three times, each time as a real bug. **The config layer must never
restate something the library owns** — a default list, an IP grammar, a detector
ordering. A restated value goes stale silently the moment the library changes, and
the config file (which wins) then runs the old behavior.

- List-valued defaults (header lists, patterns) live in the library. The TOML file
  *documents* them as commented examples, it does not set them as active keys.
- Validation that depends on library semantics (is this a valid IP/CIDR?) defers to
  the library — e.g. `new IpAllowlist(entries).invalid` is the authoritative check,
  not a parallel validator.
- A drift test asserts `Object.keys(config.detectors)` matches `defaultDetectors()`,
  so adding a detector to the library but not the schema fails loudly.

## Committing

- **Verify the commit, not just your working directory.** A green working tree does
  not prove the commit is green — staging can capture a stale state. Before pushing:

  ```bash
  git archive HEAD | tar -x -C /tmp/verify && ln -s "$PWD/node_modules" /tmp/verify/
  (cd /tmp/verify && npm test && npm run typecheck && npx tsup)
  ```

  CI does exactly this.
- **Green-together beats green-separately-with-a-red-middle.** If a change spans the
  library and the config layer (e.g. a new detector and its schema entry, whose tests
  need each other), land them in one commit. Don't leave an intermediate commit that
  fails its own suite.
- End commit messages with the `Co-Authored-By` trailer if pairing.

## Releasing

Releases are automated by [`.github/workflows/publish.yml`](.github/workflows/publish.yml);
there is no manual publish step.

- **Automatically, on every push to `main`.** The version comes from the commits since the
  last `v*` tag (`npm run release:next` shows the reasoning locally):
  - `feat:`, `fix:` or `perf:` → patch
  - `type!:` or a `BREAKING CHANGE:` footer → major (minor while the version is 0.x)
  - anything else, including a commit with no prefix → nothing is published
  - a `Release-As: 1.0.0` or `Release-As: minor` footer overrides the derived version

  The workflow publishes to npm, then commits `Release <version>` and tags it.
- **A specific version.** Push a tag: `git tag v1.2.0 && git push origin v1.2.0`. Exactly
  that version is published from the tagged commit. Nothing is committed back; later
  automatic releases build on the newest tag.
- **A dry run.** Run the Publish workflow by hand. It works out the version and packs the
  tarball without publishing.

Every release also pushes the container image `ghcr.io/osqd-ts/hackerpot` tagged
`<version>`, `<major>.<minor>` and, for stable versions, `latest`, for linux/amd64 and
linux/arm64. Every push to `main` pushes `edge`, after the image has been started and
probed in CI.

Record user-facing changes under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md) as part of the
change itself; at release time that section is renamed to the version.

Publishing needs an `NPM_TOKEN` repository secret with publish rights on the `@osqd` scope.
`npm run check:package` confirms locally that the packed tarball installs and loads.

## Licensing of contributions

hackerpot is under the [OSQD Non-Resale License](LICENSE) — free to use and
modify, but not to sell — and the copyright is held by Michał Płatosz rather than by
"the contributors" collectively. That is deliberate: a single holder is what makes it
possible to grant separate commercial terms to someone who asks, and to change the
license later without tracking down every past contributor for consent.

So: by opening a pull request you agree that your contribution is licensed under the
same terms as the project, and that the copyright holder may also license it under
different terms (including commercial ones). If you are not comfortable with that,
say so in the PR before it is merged rather than after.

If you contribute code you did not write — a snippet from a blog post, Stack Overflow,
or another project — say where it came from and under what license. Anything
incompatible with the terms above can't be merged, however good it is.

## Security-sensitive code

Anything that runs on attacker-controlled input (detectors, the protocol honeypots,
the firewall enforcer) gets extra scrutiny: no shells, validate IPs before they reach
a command (`net.isIP`), bound resource use (connection and concurrency caps), and
document the trust assumptions (e.g. enforcement acts on the resolved IP, so it needs
`trust_proxy` set correctly). When in doubt, read the code rather than trusting the
description.
