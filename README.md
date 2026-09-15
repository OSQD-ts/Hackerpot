# 🍯 hackerpot

**A honeypot for TypeScript servers.** Decoys, detectors and responses that catch the probes, exploits
and credential sprays aimed at your infrastructure, mounted beside your application or run as a service of
its own, with a dashboard to watch it.

A honeypot next to your application buys something a WAF log cannot: requests that **reveal intent**.
Nobody legitimate asks for `/.env`, replays a fake AWS key you planted, fills in a form field no person can
see, or tries `admin:admin` on a Telnet port. hackerpot turns those into scored, structured incidents,
wastes the attacker's time while they are engaged, and streams everything to your own tooling.

And it is built to sit in front of real users without hurting them:

> **A real visitor is never blocked on a guess, and the honeypot never takes your application down.**

In middleware mode a block needs **proof** (a replayed honeytoken, a hidden trap, a protocol violation, an
attack tool naming itself), not a pile of suspicion; without proof the request is merely slowed, and the
refusal is counted. And the middleware **fails open**: if the honeypot's own machinery breaks, your
routes are served as if it were not there.

```bash
npm install @osqd/hackerpot
```

---

## Documentation

The README is the argument and the shortest path to a working deployment. Everything else lives in
**[`docs/`](docs/index.md)**: a page per question, each explaining why a thing exists as well as how to use
it.

| | |
| --- | --- |
| **[The course](docs/course/index.md)** | One running example, from a first decoy to a deployment you can defend. Start here if the library is new to you. |
| **[Start here](docs/index.md)** | [Installation](docs/start/installation.md) · [Your first integration](docs/start/first-integration.md) · [Running it standalone](docs/start/standalone.md) · [Upgrading](docs/start/upgrading.md) |
| **Concepts** | [How it works](docs/concepts/how-it-works.md) · [Scores and escalation](docs/concepts/scoring.md) · [The proof guard](docs/concepts/the-guard.md) · [Actors](docs/concepts/actors.md) · [Threat model](docs/concepts/threat-model.md) |
| **[Detection](docs/detection/index.md)** | [The detectors](docs/detection/detectors.md) · [Decoys](docs/detection/decoys.md) · [Traps and honeytokens](docs/detection/traps-and-honeytokens.md) · [Verifying crawlers](docs/detection/verification.md) · [Shadow mode](docs/detection/shadow-mode.md) · [Writing a detector](docs/detection/writing-a-detector.md) |
| **[Responses](docs/responses/index.md)** | [Response actions](docs/responses/actions.md) · [Writing a policy](docs/responses/policy.md) · [Writing a response](docs/responses/writing-a-response.md) |
| **[Protocols](docs/protocols/index.md)** | [SSH](docs/protocols/ssh.md) · [SMTP](docs/protocols/smtp.md) · [FTP](docs/protocols/ftp.md) · [Telnet](docs/protocols/telnet.md) · [Port scans](docs/protocols/port-scan.md) |
| **[Operations](docs/operations/index.md)** | [The dashboard](docs/operations/dashboard.md) · [Embedding it](docs/operations/embedding.md) · [Management API](docs/operations/management-api.md) · [Webhooks](docs/operations/webhooks.md) · [Alert sinks](docs/operations/alert-sinks.md) · [Metrics](docs/operations/metrics.md) · [The audit](docs/operations/audit.md) · [Stores](docs/operations/stores.md) · [Threat intel](docs/operations/threat-intel.md) · [Firewall](docs/operations/firewall.md) · [Runtime changes](docs/operations/runtime-changes.md) |
| **[Integration](docs/integration/index.md)** | [Adapters](docs/integration/adapters.md) · [The client IP](docs/integration/client-ip.md) · [Service tokens](docs/integration/service-tokens.md) · [nginx](docs/integration/nginx.md) · [Docker](docs/integration/docker.md) |
| **[Testing](docs/testing/index.md)** | [The CLI](docs/testing/cli.md) · [The corpus](docs/testing/corpus.md) · [Log replay](docs/testing/replay.md) · [Try it locally](docs/testing/try-it.md) |
| **Reference** | [Configuration](docs/reference/configuration.md) · [Environment](docs/reference/environment.md) · [API](docs/reference/api.md) · [Data shapes](docs/reference/data-shapes.md) · [Design decisions](docs/design/decisions.md) |

---

## Why this design

**Bait is a better signal than inspection.** A WAF has to decide, for every request, whether an unusual
string is an attack. A honeypot does not: it plants things only an attacker would touch, and anyone who
touches them has revealed themselves. That is why a honeypot's findings are unusually clean, and why they
are worth acting on.

**But next to production, most findings are still suspicion.** A scripting User-Agent is every monitoring
script. A burst of distinct paths is one page load of a modern single-page app. A shared browser
fingerprint across flagged addresses is three people on the same browser build. Each of those, before it
was fixed, reached the block threshold for ordinary visitors. So hackerpot keeps two tiers apart:

|                              | Proof (`certain`)                                          | Suspicion                              |
| ---------------------------- | ---------------------------------------------------------- | -------------------------------------- |
| What it rests on             | something no legitimate client can produce                 | a pattern attackers usually show       |
| Examples                     | a replayed honeytoken, a hidden trap, a repeated `Host`, `sqlmap` naming itself, a forged Googlebot | a decoy path, an injection payload, volume, a missing header |
| Adds to the score            | yes                                                        | yes                                    |
| Can block in front of users  | **yes**                                                    | **no**: a tarpit instead               |

The guard that enforces the last row runs in the engine after the policy has chosen, so it cannot be
forgotten in a custom policy. `hackerpot_downgrades_total` counts every block it refused, and is the series
worth alerting on.

**Detection and response are decoupled.** A detector says *"this is a `.env` probe, score 10"* and nothing
more. A policy looks at everything that fired plus the address's cumulative score and picks one of twelve
responses: a convincing fake, a flat 404, a tarpit, a trickle, fifty megabytes of nothing, a block. Scores
accumulate, so an attacker climbs the ladder on their own.

**Everything an attacker can drive is bounded.** A honeypot is fed at a rate the attacker chooses. Every
map keyed by client input has a ceiling, every sink drops rather than queues, every retaliation caps its
own concurrency, and captured text is escaped for every place it lands: logs, Slack, syslog, Prometheus.

**The operator surfaces are not the attacker's.** The management API and the dashboard run on their own
listeners, bound to loopback by default, and never share the port attackers are invited to.

---

## What it cannot do

- **Replace authentication, a WAF or patching.** It detects and slows automated probing. It is not a
  security boundary, and nothing it protects should depend on it.
- **See an attacker who avoids the decoys.** A careful person who requests only real pages and sends no
  payload is not what a honeypot finds.
- **Be right about a shared address.** Behind CGNAT or a corporate gateway, one address is many people.
  That is why volume signals score low and why blocks in front of users need proof.
- **Catch distributed low-and-slow traffic.** One request per address per hour from a large pool defeats
  every per-address signal by construction; the audit's campaign check sees some of it in aggregate.
- **Read a body it was not given a reason to read.** In middleware mode a request clean on its headers
  reaches your application with its body unexamined.
- **Retaliate.** Responses waste time and bandwidth on the connection the attacker opened. Nothing here
  reaches out to anyone's infrastructure.

See the [threat model](docs/concepts/threat-model.md) and the
[design decisions](docs/design/decisions.md).

---

## Quick start: in front of your application

```ts
import express from "express";
import { HoneypotEngine, createMiddleware, hardenHttpServer, honeytokenDetector } from "@osqd/hackerpot";

const engine = new HoneypotEngine({
  allowlist: ["10.0.0.0/8"],                                    // your monitors, office, CI
  extraDetectors: [honeytokenDetector({ tokens: ["AKIA_HACKERPOT_HONEYTOKEN_DEMO"] })],  // proof you planted
  onHit: (hit) => console.warn("[honeypot]", hit.ip, hit.path, hit.respondedWith),
});

const app = express();
app.use(createMiddleware(engine));                              // mount FIRST
app.get("/", (_req, res) => res.send("the real app"));
hardenHttpServer(app.listen(3000));
```

| Request | Result |
| --- | --- |
| a browser loading `/` | your route; nothing recorded |
| `GET /.env` | a convincing fake `.env`, and an incident |
| `GET /.git/config` with `User-Agent: sqlmap/1.7` | a fake file; the incident carries proof |
| a `curl` walking twenty decoys | tarpitted once its score passes 40, never blocked: no proof |
| a request replaying `AKIA_HACKERPOT_HONEYTOKEN_DEMO` | proof; blocked once its score passes 40 |
| anything from `10.0.0.0/8` | untouched |

Behind a proxy? Read [the client IP](docs/integration/client-ip.md) first. Koa, Fastify, Hono or Next.js? See
[adapters](docs/integration/adapters.md).

## Quick start: on its own

```bash
npx hackerpot serve                                       # HTTP honeypot on :4004, built-in defaults
npx hackerpot serve --config ./hackerpot.toml             # SSH, SMTP, FTP, Telnet, the dashboard: all from the file
npx hackerpot explain "sqlmap/1.7.2#stable" --url /.env   # which detectors fire, and why
npx hackerpot replay /var/log/nginx/access.log            # what it would have made of yesterday

docker run --rm -p 4004:4004 ghcr.io/osqd-ts/hackerpot
docker compose up -d                                      # with Redis and a durable hit log
HACKERPOT_MANAGEMENT_API_KEY=… DASHBOARD_PASSWORD=… docker compose --profile dashboard up -d
```

The shipped [`hackerpot.toml`](hackerpot.toml) is every built-in default, annotated. See
[running it standalone](docs/start/standalone.md).

To watch it work locally, with every listener, the dashboard and a simulator firing an attack for each
detector: `npm run demo` in one terminal and `npm run simulate` in another. See
[try it locally](docs/testing/try-it.md).

---

## Development

```bash
npm install
npm test               # Vitest, including the false-positive suite and the corpus
npm run typecheck      # src, tests and examples
npm run lint           # Biome
npm run build          # ESM + CJS + declarations
npm run demo           # every listener and the dashboard, from source
npm run simulate       # an attack per detector against the demo
npm run docs:check     # every local link and heading anchor in the markdown
```

Conventions (the false-positive suite, "the library owns semantics, the config defers", verifying the commit
rather than the working tree) and the project layout are in [CONTRIBUTING.md](CONTRIBUTING.md). Release notes
are in [CHANGELOG.md](CHANGELOG.md).

---

## Security

See [SECURITY.md](SECURITY.md) for the threat model, what is and is not defended against, and how to report a
vulnerability. In short: decoys are detection, not defence; keep the management API and dashboard private;
set `trust_proxy` only behind a proxy that overwrites `X-Forwarded-For`.

---

## License

hackerpot is **free to use, modify, and distribute — but not to sell**. See [LICENSE](LICENSE) for the exact
terms; in short:

- **Free for everyone**, including commercial businesses and production use. Run it in front of your own
  product, deploy it for a client, fork it, modify it, keep your changes private — all fine, at no charge.
- **You may not sell it.** No paid copies, no paid hosted version of it, and no bundling it into a product
  where it is a substantial part of what the customer is paying for. Charging for *your own* services around
  it is fine.
- **Keep the notice.** Any copy or modified version you distribute must ship the copyright notice and the
  license text intact.

Want to do something the license doesn't allow? Ask [Michał Płatosz](mailto:platosz.michal@gmail.com) about
separate commercial terms.

> Note: this is a source-available license, not an OSI-approved open-source one. Tools that expect a standard
> SPDX identifier will show it as unrecognized.
