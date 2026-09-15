# Documentation

**hackerpot**: a honeypot for TypeScript servers. Decoys, detectors and responses that catch attacker probes, mounted beside your application or run as a service of its own.

← [Back to the README](../README.md)

---

## Start here

**New to this?** [**The course**](course/index.md) builds one deployment step by step, with something to run at every stage. The pages below are the reference: they answer "how does X work?" rather than "what do I do next?".

| | |
| --- | --- |
| [The course](course/index.md) | One running example, from a first decoy to a deployment you can defend. |
| [Installation](start/installation.md) | The package, the container image, and what each needs from your runtime. |
| [Your first integration](start/first-integration.md) | Ten lines of middleware in front of an application, and what each one does. |
| [Running it standalone](start/standalone.md) | The service from a TOML file, `hackerpot serve`, and Docker. |
| [Upgrading](start/upgrading.md) | What changed recently, including renamed commands and scripts. |

## The ideas the library is built on

Read these once and everything else follows from them.

| | |
| --- | --- |
| [How it works](concepts/how-it-works.md) | The request lifecycle, the two-pass body evaluation, and what is recorded. |
| [Scores and escalation](concepts/scoring.md) | Detection scores, families, cumulative per-IP totals and the escalation ladder. |
| [The proof guard](concepts/the-guard.md) | Why a block in front of real users needs proof, and what counts as proof. |
| [Actors](concepts/actors.md) | Fingerprints, cross-IP correlation, sessions and per-IP memory. |
| [Threat model](concepts/threat-model.md) | What this defends against, what it does not, and what it costs to be wrong. |

## Detection

| | |
| --- | --- |
| [Detection overview](detection/index.md) | Detectors, what they read, and how to see which ones a config installs. |
| [The detectors](detection/detectors.md) | Every HTTP detector: what it reads, its default score, its options, whether it is proof. |
| [Decoys](detection/decoys.md) | The forty built-in bait paths, prefix matching, your own decoys, and robots.txt lures. |
| [Traps and honeytokens](detection/traps-and-honeytokens.md) | Hidden links and form fields, and seeded credentials, the two kinds of proof you plant. |
| [Verifying crawlers](detection/verification.md) | Forward-confirmed reverse DNS and the address ranges operators publish. |
| [Shadow mode](detection/shadow-mode.md) | Run a detector on real traffic without letting it decide anything. |
| [Writing a detector](detection/writing-a-detector.md) | The contract, the rules, and the tests a new detector has to pass. |

## Responses

| | |
| --- | --- |
| [Responses overview](responses/index.md) | How a detection becomes a reply, and why the two are kept apart. |
| [Response actions](responses/actions.md) | All twelve, with every option and what each costs you as well as the attacker. |
| [Writing a policy](responses/policy.md) | The default ladder, `respondWith`, and a policy of your own. |
| [Writing a response](responses/writing-a-response.md) | The action contract and the resource bounds a new one must keep. |

## Protocol honeypots

| | |
| --- | --- |
| [Protocols overview](protocols/index.md) | The TCP listeners beside the HTTP honeypot, and the store they share. |
| [SSH](protocols/ssh.md) | Credential capture over a real handshake, and the optional fake shell. |
| [SMTP](protocols/smtp.md) | AUTH brute force, open relay, spam and mailbox enumeration. |
| [FTP](protocols/ftp.md) | Cleartext credentials, anonymous logins, traversal and the FTP bounce. |
| [Telnet](protocols/telnet.md) | The IoT botnet sweep, option negotiation, and what droppers run. |
| [Port-scan sentinel](protocols/port-scan.md) | Decoy TCP ports that report sweeps. |

## Running it

| | |
| --- | --- |
| [Operations overview](operations/index.md) | What to watch, and where each signal goes. |
| [The dashboard](operations/dashboard.md) | The operator view: what it shows and every option it takes. |
| [Embedding it](operations/embedding.md) | `<hackerpot-dashboard>` inside a page you already have. |
| [Management API](operations/management-api.md) | REST and the live WebSocket feed over captured incidents. |
| [Webhooks](operations/webhooks.md) | Signed pushes, retries, dedupe, throttles and redaction. |
| [Alert sinks](operations/alert-sinks.md) | Slack, Discord, and syslog or CEF for a SIEM. |
| [Metrics](operations/metrics.md) | The Prometheus exposition, and the two series worth alerting on. |
| [The traffic audit](operations/audit.md) | Noticing when traffic changes shape, and probe campaigns. |
| [Stores](operations/stores.md) | Memory, file with rotation, Redis, Elasticsearch, composites, and querying. |
| [Threat intel](operations/threat-intel.md) | Consuming peer IOC feeds without becoming an amplifier. |
| [Firewall enforcement](operations/firewall.md) | Pushing blocks to iptables, nftables or a WAF, safely. |
| [Runtime changes](operations/runtime-changes.md) | SIGHUP reload, `reconfigure()`, and what needs a restart. |

## Integrating it

| | |
| --- | --- |
| [Integration overview](integration/index.md) | Where the honeypot sits relative to your application. |
| [Adapters](integration/adapters.md) | Express and Connect, Koa, Fastify, Fetch handlers, trap forms, and failing open. |
| [The client IP](integration/client-ip.md) | `trust_proxy` and `X-Forwarded-For`: the highest-consequence setting. |
| [Service tokens](integration/service-tokens.md) | Letting your own monitors through without an allowlisted address. |
| [nginx edge capture](integration/nginx.md) | Diverting statically recognisable probes at the edge. |
| [Docker](integration/docker.md) | The image, the compose stack, and the dashboard profile. |

## Proving it before it meets anybody

| | |
| --- | --- |
| [Testing overview](testing/index.md) | The ways to find out what a configuration does before it does it. |
| [The command line](testing/cli.md) | `serve`, `dashboard`, `check`, `config`, `replay`, `explain`, `detectors`, `robots`. |
| [The traffic corpus](testing/corpus.md) | Labelled human and hostile traffic, run against your configuration. |
| [Replaying your own logs](testing/replay.md) | What the detectors would have made of yesterday. |
| [Try it locally](testing/try-it.md) | The demo, the simulator and the dashboard on your own machine. |

## Reference

| | |
| --- | --- |
| [Configuration](reference/configuration.md) | Every TOML section and key, with its default and its consequence. |
| [Environment variables](reference/environment.md) | Every variable that overrides the file. |
| [API](reference/api.md) | Every export, grouped by what it is for, and the package subpaths. |
| [Data shapes](reference/data-shapes.md) | Incidents, webhook payloads, live-feed messages. |
| [Design decisions](design/decisions.md) | The trade-offs the library makes, and what each one costs. |
