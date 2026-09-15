# Installation

The package, the container image, and what each needs from your runtime.

← [Documentation](../index.md)

---

hackerpot ships two ways: a library you import into a Node server you already run, and a
standalone service you run beside it. They are the same code. The service is the library
plus a config loader, a command line and every listener switched on from a file.

```bash
npm install @osqd/hackerpot                               # the library, and the `hackerpot` command
docker run --rm -p 4004:4004 ghcr.io/osqd-ts/hackerpot    # the standalone service
```

## Requirements

- **Node.js 20 or later.** The engine uses Node built-ins (`node:crypto`, `node:net`,
  `node:http`), so edge runtimes without them are not supported.
- Nothing else for the HTTP honeypot. A Redis server only if you choose the Redis store
  or blocklist; an Elasticsearch or OpenSearch cluster only if you choose that store.

## Module formats

The package ships dual ESM and CommonJS builds with type declarations:

```ts
import { HoneypotEngine } from "@osqd/hackerpot";          // ESM
const { HoneypotEngine } = require("@osqd/hackerpot");     // CommonJS
```

| Import path | What it holds |
| --- | --- |
| `@osqd/hackerpot` | Everything: the engine, detectors, responses, stores, protocol honeypots, management API, dashboard, config loader. |
| `@osqd/hackerpot/adapters` | Only the ways to put the honeypot in front of an application: `createMiddleware`, `koaHoneypot`, `fastifyHoneypot`, `fetchHoneypot`, `withFetchHoneypot`, `trapFormGuard`, `createDashboardHandler`. Everything here is also exported from the root. |
| `@osqd/hackerpot/cli` | `main(argv)`, the command line as a function. |
| `@osqd/hackerpot/corpus` | The labelled traffic corpus and the harness that runs it. See [the corpus](../testing/corpus.md). |
| `@osqd/hackerpot/element` | `<hackerpot-dashboard>`, the dashboard as a custom element. See [embedding](../operations/embedding.md). |

See the [API reference](../reference/api.md) for every export.

## Runtime dependencies

Four, each for one feature:

| Package | Used by |
| --- | --- |
| [`ioredis`](https://github.com/redis/ioredis) | `RedisStore` and `RedisBlocklist` only |
| [`ws`](https://github.com/websockets/ws) | the management API's live feed, and the dashboard's remote source |
| [`ssh2`](https://github.com/mscdex/ssh2) | the SSH honeypot's transport layer |
| [`smol-toml`](https://github.com/squirrelchat/smol-toml) | the standalone config parser |

Everything else is Node's standard library. The Elasticsearch store talks to the cluster's
REST API over `fetch` and needs no client.

## The container image

Published to GHCR for `linux/amd64` and `linux/arm64`:

| Tag | Follows |
| --- | --- |
| `0.2.0` | exactly that release |
| `0.2` | the newest release in that `major.minor` |
| `latest` | the newest stable release |
| `edge` | `main`, after the image has been started and probed in CI |

The image runs `node dist/standalone.js` (the `hackerpot` command, `serve` by default)
with the bundled `/app/hackerpot.toml`. Mount your own config over it, or point
`HACKERPOT_CONFIG` at another path; environment variables still override the file. See
[Docker](../integration/docker.md).

## The `hackerpot` command

Installing the package puts `hackerpot` on your path, so `npx hackerpot` works without a
global install:

```bash
npx hackerpot --help
npx hackerpot explain "sqlmap/1.7.2#stable" --url /.env
```

Every command is on [the command line](../testing/cli.md) page.

## The shipped config is a reference, not a default

The `hackerpot.toml` inside the package is **never loaded from `node_modules`**. The
command discovers config relative to the working directory, so copy the file to your
project root or `/etc/hackerpot/` and edit it there. An installed dependency silently
imposing its own configuration would be the wrong behaviour. See
[configuration](../reference/configuration.md#loading-and-precedence).

## Related

- [Your first integration](first-integration.md) — the library in front of an app
- [Running it standalone](standalone.md) — the service from a file
- [Upgrading](upgrading.md) — what changed recently
