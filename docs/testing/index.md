# Testing

The ways to find out what a configuration does before it does it.

← [Documentation](../index.md)

---

A honeypot in front of a real application makes a claim about your traffic: that it will catch
attackers and leave people alone. Four ways to check that claim before it meets anybody, from the
cheapest:

| | Answers | Page |
| --- | --- | --- |
| `hackerpot config` and `hackerpot check` | Is the config valid? Does every response action actually answer? | [The command line](cli.md) |
| `hackerpot explain` | Why was this one request flagged, or not? | [The command line](cli.md#explain) |
| `hackerpot replay` | What would these detectors have made of yesterday's traffic? | [Replaying your logs](replay.md) |
| `npm run corpus` | Against labelled human and hostile traffic, does anything misfire? | [The corpus](corpus.md) |

And once it is running, [shadow mode](../detection/shadow-mode.md) answers the same question for a
single detector against today's traffic.

## In CI

```bash
npx hackerpot config --config ./hackerpot.toml > /dev/null   # exit 2 on an invalid config
npx hackerpot check  --config ./hackerpot.toml               # exit 1 if a response action fails
```

Both bind no honeypot port and make no network calls beyond loopback.

## Watching it work

[Try it locally](try-it.md) runs the demo (every listener and the dashboard) and a simulator that fires
a realistic attack for each detector at it:

```bash
npm run demo              # terminal 1
npm run simulate          # terminal 2: every scenario
npm run simulate:ssh      # or one
npm run simulate:corpus   # the labelled corpus, over real sockets
```

## The project's own suites

For contributors, `npm test` runs the Vitest suites, including:

- **the false-positive suite** (`tests/false-positives.test.ts`): real browser and API-client traffic,
  static assets, OAuth redirects, proxied requests with internal addresses in `X-Forwarded-For`, and
  queries that merely resemble payloads, through every default detector and over real HTTP, asserting
  that **nothing fires**. Flagging a real user is the worst failure a honeypot next to production can
  have, so any detection there is a bug;
- **the corpus test** (`tests/corpus.test.ts`): every labelled case in-process, failing if a default
  detector has no hostile case expecting it;
- **the public-API pin** (`tests/public-api.test.ts`): the exact list of exports;
- detectors, stores, the config parser, the protocol honeypots, the management API, webhooks, the
  dashboard server, and the hardening rounds.

`npm run bench:guard` holds the request path to performance budgets, as ratios against a reference loop
so any machine works. `npm run check:package` packs the tarball, installs it into an empty project and
loads it as ESM, CommonJS and a command. See [CONTRIBUTING.md](../../CONTRIBUTING.md).

## Related

- [The command line](cli.md) · [Replaying your logs](replay.md) · [The corpus](corpus.md)
- [Shadow mode](../detection/shadow-mode.md)
