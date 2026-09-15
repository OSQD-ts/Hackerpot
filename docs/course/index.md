# The HackerPot course

Sixteen lessons that build one real deployment, from a first detection to a honeypot you can
defend.

← [Documentation](../index.md)

---

## What this is

The [reference documentation](../index.md) answers *"how does X work?"*. This answers
*"what do I do, and in what order?"* — every capability of the library, taught in the
order that makes each one make sense, with something to run at every step.

It is written to be worked through rather than read. Every lesson has code you paste and
output you can check yours against, and every checkpoint in it was produced by actually
running the code rather than by imagining what it would print.

**Time:** about four hours to do properly. Lessons 1–4 are the foundation and are worth
slowing down for; everything after them assumes you have those.

## Who it is for

A TypeScript or JavaScript developer who runs a web application on Node and has noticed
the requests for `/.env`, `/wp-login.php` and `/.git/config` in its access log — and would
rather learn something from them than ignore them. You need no background in security
tooling. You do need to be comfortable running `node` and reading a stack trace.

## The running example

You are building **Pantry**, a recipe-sharing site. It has public recipe pages, a JSON API
at `/api/recipes`, a signup form, a login and a real admin panel at `/admin`. It is worth
probing, worth scraping and worth not getting wrong in front of the people who cook from
it. Pantry gains a honeypot in lesson 1, and by lesson 16 it has a tested,
production-shaped deployment.

## Set up once

```bash
mkdir pantry && cd pantry
npm init -y && npm pkg set type=module
npm install @osqd/hackerpot
```

Every lesson's code goes in a `.mjs` file you run with `node`, and the command line is
`npx hackerpot`. Nothing needs a server until lesson 10. Lesson 13 wants a Redis to talk
to; `docker run --rm -p 6379:6379 redis:7-alpine` is enough.

---

## Part 1 — The ideas everything rests on

| | | |
|-|-|-|
| 1 | [Your first detection](01-first-detection.md) | Turn a request into a result, and read what comes back. |
| 2 | [Proof and suspicion](02-proof-and-suspicion.md) | The distinction the whole library is built on. **The most important lesson here.** |
| 3 | [Scores and responses](03-scores-and-responses.md) | How one address climbs from a quiet 404 to a block. |
| 4 | [The guard](04-the-guard.md) | The mechanism that stops a guess blocking a person. |

## Part 2 — Detection

| | | |
|-|-|-|
| 5 | [The detectors](05-detectors.md) | All twenty-six: what each reads, what each scores, which can be proof. |
| 6 | [Decoys](06-decoys.md) | Bait paths, prefix matching, decoys of your own, and the one that collides with Pantry. |
| 7 | [Traps and honeytokens](07-traps-and-honeytokens.md) | The two kinds of proof you plant yourself. |
| 8 | [Identity and crawler verification](08-identity.md) | Refuting a forged Googlebot, and staying silent when DNS says nothing. |
| 9 | [Actors and volume](09-actors-and-volume.md) | Sliding windows, deterministic time, and one tool across many addresses. |

## Part 3 — Running it

| | | |
|-|-|-|
| 10 | [In front of an app](10-in-front-of-an-app.md) | The middleware, the client IP, service tokens and trap forms. |
| 11 | [The standalone service and protocol honeypots](11-standalone-and-protocols.md) | A TOML file, `hackerpot serve`, and an SSH listener beside it. |
| 12 | [Operating it](12-operating-it.md) | The management API, webhooks, metrics, the audit and the dashboard. |

## Part 4 — Production and proof

| | | |
|-|-|-|
| 13 | [Scaling and changing it live](13-scaling.md) | Redis, shadow detectors, SIGHUP and the compose stack. |
| 14 | [Extending it](14-extending.md) | Your own detector, response action, store and policy. |
| 15 | [Proving it](15-proving-it.md) | `explain`, `replay`, the traffic corpus and the simulator. |
| 16 | [The capstone](16-capstone.md) | A finished Pantry, and the test that stops it catching people. |

---

## How to get the most out of it

**Type the code, do not paste it.** The examples are short on purpose.

**Do the exercises before reading the answer.** Each one has a checkpoint so you know
whether you got it.

**When something surprises you, chase it.** Every lesson ends with links into the
reference documentation for the thing you just used. The surprises are usually where the
library is protecting you from something.

## A promise, and its consequence

One sentence holds this library together, and it will explain most of what surprises you:

> **In front of real users, nothing is blocked on the strength of a guess.**

You will meet it first in [lesson 4](04-the-guard.md), where the policy asks to block an
address that has walked five decoys and the request is tarpitted instead. That is not a
bug, and the lesson explains why it is the most valuable behaviour here.

Start with [lesson 1](01-first-detection.md).
