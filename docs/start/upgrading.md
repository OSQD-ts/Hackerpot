# Upgrading

What changed recently, and what you have to do about it.

← [Documentation](../index.md)

---

The authoritative list is [CHANGELOG.md](../../CHANGELOG.md). This page is the part of it
that asks something of you.

## The package name and the image

The library is published as **`@osqd/hackerpot`**, and each release pushes
`ghcr.io/osqd-ts/hackerpot` tagged `<version>`, `<major>.<minor>` and `latest`, with
`edge` following `main`. Update imports from any local path or earlier name to
`@osqd/hackerpot`.

## The command line has commands

The service used to be driven by flags on `dist/standalone.js`. It is now the `hackerpot`
command with subcommands:

| Before | Now |
| --- | --- |
| `node dist/standalone.js` | `hackerpot serve` (still the default with no command) |
| `node dist/standalone.js --print-config` | `hackerpot config` |
| `node dist/standalone.js --check` | `hackerpot check` |
| `node dist/standalone.js --replay access.log` | `hackerpot replay access.log` |
| `node dist/standalone.js --explain "…"` | `hackerpot explain "…"` |
| — | `hackerpot dashboard`, `hackerpot detectors`, `hackerpot robots` |

**The old flags still work.** `hackerpot --check`, `--replay`, `--explain` and
`--print-config` are accepted exactly as before, so a container or script written against
them keeps running. The image's `CMD` is `node dist/standalone.js`, which is `serve`.

## npm scripts were renamed

If you run hackerpot from a clone, the development scripts changed:

| Removed | Use instead |
| --- | --- |
| `npm run dev` | `npm run demo` (every listener, the dashboard, a management key of `dev-key`) or `npm run serve` (the real service from source) |
| `npm run dev:gui`, `npm run start:gui`, `npm run build:gui` | `npm run demo`: the dashboard is part of it |
| `npm run dashboard` (the old proxy on :8080, `MGMT_URL`, `DASHBOARD_PORT`) | `npm run dashboard`, which is now `hackerpot dashboard` on :9501 reading a management API |
| `npm run attack:all` | `npm run simulate` |
| `npm run attack -- <scenario>`, `npm run attack:<scenario>` | `npm run simulate:<scenario>` (`npm run simulate:list` lists them) |
| `npm run attack:corpus` | `npm run simulate:corpus` |
| `npm run docs:links` | `npm run docs:check` |
| `npm run build:start` | `npm run build && npm start` |

New ones: `npm run demo:embedded` (the dashboard as an element inside a page),
`npm run corpus` (the labelled corpus against a configuration), `npm run explain`,
`npm run replay`, `npm run lint` (Biome), `npm run format`. The full list is in
[CONTRIBUTING.md](../../CONTRIBUTING.md#development).

## The dashboard is part of the library

The styled test console that used to be a separate dev proxy (`scripts/dashboard.ts`) is
now a shipped, authenticated dashboard:

- inside the service: `[dashboard] enabled = true`, reading the engine directly;
- beside a running stack: `hackerpot dashboard`, reading a management API and holding its
  key server-side;
- in your own server: `startDashboard(engine)` or `createDashboardHandler(engine, { auth })`;
- in your own page: `<hackerpot-dashboard>` from `@osqd/hackerpot/element`.

A dashboard bound anywhere but loopback refuses to start without authentication. See
[the dashboard](../operations/dashboard.md).

## Behaviour changes that can surprise you

**Middleware blocks need proof.** `createMiddleware` now refuses a policy's `block` unless a
detection is `certain`, and serves `tarpit` instead. If you relied on score-based blocking
in middleware, pass `{ blockRequiresProof: false }`, and read
[the proof guard](../concepts/the-guard.md) first. Standalone is unchanged.

**Middleware fails open.** An internal error now calls `next()` instead of `next(err)`. Pass
`{ failOpen: false }` to get the old behaviour.

**`path-bruteforce` in middleware counts only 404s.** A path your app serves no longer
counts. An app that answers unknown paths with 200 needs `{ countOnlyMissedPaths: false }`
and a higher threshold. See [adapters](../integration/adapters.md#path-bruteforce-in-front-of-real-users).

**Webhooks are redacted by default.** Credential headers and secret-named fields become
`[redacted]` in the delivered copy. Set `redact = false` on a webhook whose receiver needs
the captured credentials.

**Webhooks do not retry refusals.** A 4xx other than 408, 425 or 429 is reported at once.

**Detectors that reason from absence skip replayed requests.** Facts rebuilt from a log are
marked `partialHeaders`.

**The traffic audit is on by default.** It logs anomalies and delivers them to webhooks.
`[audit] enabled = false` or `anomalies = false` per webhook.

## New things worth turning on

- [Hidden traps](../detection/traps-and-honeytokens.md#hidden-traps) — proof you plant in
  your markup.
- [Published crawler ranges](../detection/verification.md) — `published_ranges = true`.
- [Service tokens](../integration/service-tokens.md) — your monitors, without an allowlist.
- [Shadow mode](../detection/shadow-mode.md) — trial a detector before it acts.
- `X-Hackerpot-Signature-V2` on [webhooks](../operations/webhooks.md#verifying-a-delivery),
  which a captured delivery cannot be replayed against.

## Related

- [CHANGELOG.md](../../CHANGELOG.md) — everything, including fixes
- [The command line](../testing/cli.md) — the commands in full
