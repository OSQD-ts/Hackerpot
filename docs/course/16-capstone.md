# Lesson 16 — The capstone

**Goal:** assemble everything into a Pantry you can defend, with the test that stops it
catching people.

← [Course](index.md) · Prev: [Proving it](15-proving-it.md)

---

## What you are assembling

Three files, and one of them you already have.

| File | What it is | From |
| --- | --- | --- |
| `pantry-honeypot.mjs` | Pantry's detector set, shared by the server and its tests | [lesson 15](15-proving-it.md) |
| `server.mjs` | Pantry, with the honeypot in front of it and every operator surface wired | this lesson |
| `pantry.test.mjs` | the corpus, as a test that fails if a person is caught | this lesson |

## The server

`pantry/server.mjs`:

```js
import http from "node:http";
import Redis from "ioredis";
import {
  CrawlerRanges, ManagementServer, MemoryBlocklist, MemoryStore, RedisBlocklist, RedisStore, TrafficAudit,
  createDashboardHandler, createMiddleware, generateRobotsTxt, defaultDecoyPaths, hardenHttpServer,
  renderTrapField, renderTrapLink, startCrawlerRangeRefresh, trapFormGuard,
} from "@osqd/hackerpot";
import { PANTRY, createPantryEngine } from "./pantry-honeypot.mjs";

const env = process.env;

// Shared state across replicas when Redis is configured.                  lesson 13
const redis = env.REDIS_URL ? new Redis(env.REDIS_URL) : undefined;
const store = redis ? new RedisStore({ client: redis, keyPrefix: "pantry:", scoreTtlSeconds: 3600, maxHits: 1500 }) : new MemoryStore();
const blocklist = redis ? new RedisBlocklist({ client: redis, keyPrefix: "pantry:block:" }) : new MemoryBlocklist();

// Published crawler ranges, refreshed on a timer (outbound HTTPS).        lesson 8
const ranges = new CrawlerRanges();
const stopRanges = env.PANTRY_FETCH_RANGES === "1" ? startCrawlerRangeRefresh(ranges) : () => {};

const audit = new TrafficAudit();                                          // lesson 12
let management;

const engine = createPantryEngine({                                        // lessons 5-8
  store,
  blocklist,
  ranges,
  audit,
  trustProxy: env.PANTRY_BEHIND_PROXY === "1",                             // lesson 10
  allowlist: (env.PANTRY_ALLOWLIST ?? "").split(",").filter(Boolean),
  serviceTokens: { tokens: env.MONITOR_TOKEN ? { "uptime-monitor": env.MONITOR_TOKEN } : {} },
  onHit: (hit) => management?.publish(hit),
  onError: (error, { source }) => console.error(`[honeypot] ${source}: ${error instanceof Error ? error.message : error}`),
});

// The operator surfaces, on loopback.                                     lesson 12
if (env.MANAGEMENT_KEY) {
  management = new ManagementServer({ store, host: "127.0.0.1", port: Number(env.MANAGEMENT_PORT ?? 9500), apiKeys: [env.MANAGEMENT_KEY], detectorFailures: () => engine.detectorFailures });
  await management.listen();
  audit.start(60_000, (anomaly) => management.announce(anomaly));
}
const dashboard = createDashboardHandler(engine, {
  basePath: "/_hackerpot",
  title: "pantry",
  auth: { username: "ops", password: env.DASHBOARD_PASSWORD ?? "change-me-before-deploying" },
});

const honeypot = createMiddleware(engine);                                 // lessons 4, 10
const checkTraps = trapFormGuard(engine);                                  // lesson 7
const decoys = defaultDecoyPaths.filter((d) => !PANTRY.realRoutes.includes(d.id));
const robots = generateRobotsTxt({ decoys, trapPaths: [PANTRY.trapPath], sitemap: "https://pantry.example/sitemap.xml" });

function pantry(req, res) {
  const path = req.url.split("?")[0];
  if (path === "/") return res.end(`<h1>Pantry</h1><main>…</main>${renderTrapLink(PANTRY.trapPath)}`);
  if (path === "/robots.txt") return res.writeHead(200, { "content-type": "text/plain" }).end(robots);
  if (path === "/healthz") return res.end("ok");
  if (path === "/admin") return res.end("<h1>Pantry admin: sign in</h1>");
  if (path === "/signup" && req.method === "GET") return res.end(`<form method="post">${renderTrapField(PANTRY.trapField)}<input name="email"></form>`);
  if (path === "/signup" && req.method === "POST") {
    let text = "";
    req.on("data", (chunk) => (text += chunk));
    req.on("end", () => {
      req.body = Object.fromEntries(new URLSearchParams(text));
      checkTraps(req, res, () => res.writeHead(303, { location: "/welcome" }).end());
    });
    return;
  }
  res.writeHead(404).end("Not Found");
}

const server = http.createServer((req, res) => {
  if (req.url.startsWith("/_hackerpot")) return dashboard(req, res);       // outside the honeypot
  void honeypot(req, res, () => pantry(req, res));
});
hardenHttpServer(server);
await new Promise((resolve) => server.listen(Number(env.PORT ?? 3000), env.HOST ?? "127.0.0.1", resolve));
console.log(`pantry on http://${env.HOST ?? "127.0.0.1"}:${server.address().port}`);

export async function shutdown() {
  stopRanges();
  audit.stop();
  await dashboard.close();
  await new Promise((resolve) => server.close(resolve));
  await management?.close();
  await redis?.quit();
}
process.once("SIGTERM", () => void shutdown());
export { server };
```

Everything that differs between a laptop and production comes from the environment, and each
default is the safe one: no proxy trusted, no ranges fetched, memory state, no management API.

## Smoke it

`pantry/smoke.mjs` starts the server on a free port, plays five kinds of client, and shuts it
down:

```js
process.env.PORT = "0";
const { server, shutdown } = await import("./server.mjs");
const base = `http://127.0.0.1:${server.address().port}`;
const show = async (label, path, init = {}) => {
  const res = await fetch(base + path, { redirect: "manual", ...init });
  console.log(`${label.padEnd(30)} ${res.status}`);
  await res.arrayBuffer();
};
const browser = { "user-agent": "Mozilla/5.0 (Macintosh) Chrome/126.0.0.0 Safari/537.36", accept: "text/html", "accept-language": "en-GB", "accept-encoding": "gzip" };
await show("reader: home", "/", { headers: browser });
await show("reader: robots.txt", "/robots.txt", { headers: browser });
await show("reader: real /admin", "/admin", { headers: browser });
await show("dashboard without a password", "/_hackerpot/api/stats", { headers: browser });
await show("dashboard with one", "/_hackerpot/api/stats", { headers: { ...browser, authorization: `Basic ${Buffer.from("ops:change-me-before-deploying").toString("base64")}` } });
await show("sqlmap: /.env", "/.env", { headers: { "user-agent": "sqlmap/1.7.2#stable" } });
await shutdown();
```

```bash
node smoke.mjs
REDIS_URL=redis://127.0.0.1:6379 MANAGEMENT_KEY=pantry-management-key-0123456789 MANAGEMENT_PORT=19600 node smoke.mjs
```

### Checkpoint

Both runs print the same statuses; only the port on the first line differs.

```
pantry on http://127.0.0.1:44657
reader: home                   200
reader: robots.txt             200
reader: real /admin            200
dashboard without a password   401
dashboard with one             200
sqlmap: /.env                  200
```

Run it against a Redis that still holds lesson 13's block for `127.0.0.1` and every request
through the honeypot is a `403` — only the two dashboard lines, mounted outside it, are
unchanged. That is the shared blocklist doing its job, and a reminder that every client in a
local test is the same address. Flush that Redis first.

Reading the lines against the lessons: the reader's pages and **the real `/admin`** are Pantry's
(lesson 6); the dashboard is mounted outside the honeypot and refuses a missing password
(lesson 12); `sqlmap` got a fake `.env` (lessons 1 and 6).

## The test that stops it catching people

`pantry/pantry.test.mjs`:

```js
import { test } from "node:test";
import assert from "node:assert/strict";
import { CrawlerRanges } from "@osqd/hackerpot";
import { CORPUS_CRAWLER_RANGES, CORPUS_HONEYTOKEN, CORPUS_TRAP_FIELD, CORPUS_TRAP_PATH, runCorpus } from "@osqd/hackerpot/corpus";
import { createPantryEngine } from "./pantry-honeypot.mjs";

test("Pantry's honeypot never catches a person", async () => {
  const ranges = new CrawlerRanges();
  for (const [id, prefixes] of Object.entries(CORPUS_CRAWLER_RANGES)) ranges.update(id, prefixes);
  const scorecard = await runCorpus({
    create: ({ resolver }) =>
      createPantryEngine({
        enricher: null, resolver, ranges,
        extra: { honeytokens: [CORPUS_HONEYTOKEN], trapPaths: [CORPUS_TRAP_PATH], trapFields: [CORPUS_TRAP_FIELD] },
      }),
    provides: ["honeytoken", "trap", "crawler-verification", "published-ranges"],
  });
  assert.deepEqual(scorecard.falsePositives.map((r) => r.case.id), []);
  assert.equal(scorecard.skipped.length, 0);
  assert.equal(scorecard.failed, 0);
});
```

```bash
node --test pantry.test.mjs
```

### Checkpoint

```
TAP version 13
# Subtest: Pantry's honeypot never catches a person
ok 1 - Pantry's honeypot never catches a person
  ---
  duration_ms: 76.10604
  type: 'test'
  ...
1..1
# tests 1
# suites 0
# pass 1
# fail 0
# cancelled 0
# skipped 0
# todo 0
# duration_ms 460.545029
```

The durations will differ. The test imports the **same** `createPantryEngine` the server uses,
so it cannot drift from what is deployed, and it asserts three things: no false positives,
nothing skipped, nothing failed. The second matters: without it, a refactor that dropped the
trap detector would skip the trap cases and still pass.

## Before it goes anywhere real

Configuration, in the order it bites:

1. **The client address** ([lesson 10](10-in-front-of-an-app.md)). `PANTRY_BEHIND_PROXY=1` only
   behind a proxy that overwrites `X-Forwarded-For`, with the port unreachable around it.
2. **Your own monitors** (lesson 10). A `MONITOR_TOKEN`, or their fixed addresses in
   `PANTRY_ALLOWLIST`.
3. **Real routes against decoys** (lesson 6). `PANTRY.realRoutes` against your route table.
4. **The dashboard password** (lesson 12). `DASHBOARD_PASSWORD`, and the page it is embedded in
   behind the same authentication.
5. **Shared state** (lesson 13). `REDIS_URL` with a `maxHits` your Redis can hold, the moment
   there is more than one process.
6. **Replay a week of logs** (lesson 15), then **shadow** anything you retuned.

## Final exercise

Answer these without looking anything up. They are the whole course.

1. An address walks twelve decoys with `curl` and reaches a total of 120. In front of Pantry, is it blocked?
2. `hackerpot_downgrades_total` doubled after a deploy. What happened?
3. Pantry's uptime monitor reports the site down, but readers are fine. Where do you look first?
4. You write a detector that catches Pantry's scraper perfectly. Is its evidence `certain`?
5. A `SIGHUP` after changing `[store.redis] url` produced no error. Is the new Redis in use?

<details>
<summary>Answers</summary>

1. **No — it is tarpitted.** The policy asks to block, and the guard refuses: nothing on a `curl`
   decoy walk is proof. It is blocked the moment one of its requests carries proof.
   [Lesson 4](04-the-guard.md).

2. **Scores are reaching the block line on suspicion more often.** A detector or threshold changed
   in the deploy, and the evidence is adding up on traffic that proves nothing — in front of Pantry,
   quite possibly on readers. The guard absorbed it, and the number is telling you so.
   [Lessons 4](04-the-guard.md) and [12](12-operating-it.md).

3. **The monitor's own incidents.** A bare HTTP client with a scripting User-Agent is what
   `scanner-signature` looks for; the honeypot is answering it. Give it a service token.
   [Lesson 10](10-in-front-of-an-app.md).

4. **Almost certainly not.** Ask whether you can write down why no legitimate client could produce
   the finding. Unless it rests on a planted secret, a hidden trap, a protocol violation, a
   self-declared tool or a refuted crawler claim, you cannot, and it is suspicion.
   [Lessons 2](02-proof-and-suspicion.md) and [14](14-extending.md).

5. **No.** The store needs a restart, and the service said so in a `reload-requires-restart`
   line — no error, because refusing to swap live state is the correct outcome.
   [Lesson 13](13-scaling.md).
</details>

## Where to go now

- **[The threat model](../concepts/threat-model.md).** Read it before you promise anybody
  anything. It names what this defends against, what it does not, and what each mistake costs.
- **[Design decisions](../design/decisions.md).** The trade-offs, and what each one cost.
- **[The reference](../index.md).** One page per question, now that you know the questions.

## What you learned in this course

- A detector scores, a policy chooses, an action carries it out, and `evaluate` never acts
- Proof and suspicion are different things, and only proof may block in front of real users
- The guard lives in the engine, and `hackerpot_downgrades_total` is its report card
- Decoys are bait, and a decoy that shadows a real route breaks it
- Honeytokens and traps are the proof you plant, and each rests on something only you can do
- A crawler name is a claim; DNS that says nothing proves nothing
- Volume is suspicion, time can be simulated, and a fingerprint never creates suspicion
- The client address is the setting that is silent when it is wrong
- Every operator surface shows attacker data and belongs off the attacker-facing interface
- Scores and blocks are shared across replicas; what cannot be changed live is named
- Find out who a configuration catches before it catches them

← [Back to the course](index.md)
