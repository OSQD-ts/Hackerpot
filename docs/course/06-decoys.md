# Lesson 6 — Decoys

**Goal:** know what the built-in bait covers and how it matches, find the decoy that
collides with a real Pantry route, and add a decoy of your own.

← [Course](index.md) · Prev: [The detectors](05-detectors.md) · Next: [Traps and honeytokens](07-traps-and-honeytokens.md)

---

## Bait

A **decoy** is a path only an attacker would know: a leaked `.env`, a `.git` directory, a
phpMyAdmin panel, a framework debug endpoint. No link on Pantry leads to it, so a request
for it is a probe. `decoy-path` recognises the request, and the decoy says what to serve —
often a convincing fake, so the probe appears to have worked.

```ts
interface DecoyPath {
  id: string;
  description: string;                 // becomes the detection's reason
  path: string | RegExp;               // an exact path, or a pattern
  match?: "exact" | "prefix";          // for a string path; default "exact"
  method?: string;
  score: number;
  respondWith?: string;                // a response action id
  payload?: { status?: number; contentType?: string; body?: string; location?: string };
}
```

## Do this

`pantry/lesson-06.mjs`:

```js
import { HoneypotEngine, defaultDecoyPaths } from "@osqd/hackerpot";
import { CHROME } from "./browser.mjs";

console.log(defaultDecoyPaths.length, "built-in decoys");
const engine = new HoneypotEngine();
const paths = ["/.env", "/.env.production", "/.ENV", "/.envelope", "/.git/index", "//.env", "/%2eenv", "/admin", "/recipes/42"];
for (const [i, path] of paths.entries()) {
  const r = await engine.evaluate({ method: "GET", path, query: {}, headers: CHROME, ip: `198.51.100.${i + 1}` });
  const decoy = r.detections.find((d) => d.detectorId === "decoy-path");
  console.log(`${path.padEnd(18)} ${decoy ? `${decoy.metadata.decoyId} (+${decoy.score}) -> ${r.actionId}` : "no decoy"}`);
}
```

Each path gets its own address, so no request inherits another's score.

### Checkpoint

```
40 built-in decoys
/.env              dotenv (+10) -> decoy-content
/.env.production   dotenv (+10) -> decoy-content
/.ENV              dotenv (+10) -> decoy-content
/.envelope         no decoy
/.git/index        git-dir (+9) -> not-found
//.env             dotenv (+10) -> decoy-content
/%2eenv            dotenv (+10) -> decoy-content
/admin             admin-panel (+4) -> decoy-content
/recipes/42        no decoy
```

Four things to read in that.

**Prefix matching respects boundaries.** `dotenv` is a prefix decoy, so it covers
`/.env.production` and `/.ENV` (scanners probe both spellings), but **not** `/.envelope`: a
prefix matches only at a `/` or `.` boundary.

**Spelling does not evade it.** `//.env` and `/%2eenv` are the same file to most servers,
and the engine normalises them to `/.env` before any decoy is consulted.

**Not every decoy serves a fake.** `git-dir` answers `not-found`: the probe was the signal,
and a flat 404 reveals nothing.

**And `/admin` fired.** Pantry has a real admin panel there.

## A decoy that shadows a real route breaks it

The honeypot answers first. Mounted in front of Pantry, every administrator opening
`/admin` would get a fake login page instead of the real one, and add 4 to their address's
score while doing it. Common collisions: a real `/admin`, a real Swagger or OpenAPI
document, a Spring Boot health check at `/actuator/health`.

Before deploying, read the built-in list against your own routes. Then drop what
collides, and add a decoy that belongs to Pantry specifically.

`pantry/lesson-06b.mjs`:

```js
import { HoneypotEngine, decoyPathDetector, defaultDecoyPaths, defaultDetectors, generateRobotsTxt } from "@osqd/hackerpot";
import { CHROME } from "./browser.mjs";

const PANTRY_ROUTES = ["admin-panel"]; // Pantry has a real /admin

const recipeExport = {
  id: "recipe-export",
  description: "Bulk recipe and user export probe",
  path: "/api/recipes/export",
  match: "prefix",
  score: 8,
  respondWith: "fake-data",
};

const decoys = [...defaultDecoyPaths.filter((d) => !PANTRY_ROUTES.includes(d.id)), recipeExport];

const engine = new HoneypotEngine({
  detectors: defaultDetectors().map((d) => (d.id === "decoy-path" ? decoyPathDetector(decoys) : d)),
});

for (const path of ["/admin", "/api/recipes/export", "/api/recipes/export/users.json"]) {
  const r = await engine.evaluate({ method: "GET", path, query: {}, headers: CHROME, ip: "198.51.100.21" });
  console.log(path.padEnd(32), r.detections.map((d) => `${d.detectorId} +${d.score}`).join(", ") || "nothing fired", r.actionId ? `-> ${r.actionId}` : "");
}

const robots = generateRobotsTxt({ decoys, sitemap: "https://pantry.example/sitemap.xml" });
const lines = robots.trimEnd().split("\n");
console.log(lines.slice(0, 7).join("\n"));
console.log("…");
console.log(lines.slice(-3).join("\n"));
console.log(lines.filter((l) => l.startsWith("Disallow")).length, "Disallow lines; /admin listed:", lines.includes("Disallow: /admin"));
```

### Checkpoint

```
/admin                           nothing fired 
/api/recipes/export              decoy-path +8 -> fake-data
/api/recipes/export/users.json   decoy-path +8 -> fake-data
# Generated by hackerpot. The paths below are honeypot decoys advertised as
# Disallow: a legitimate crawler skips them, so anything that fetches one
# anyway has identified itself as not respecting robots.txt.
User-agent: *
Disallow: /.aws
Disallow: /.aws/credentials
Disallow: /.docker/config.json
…
Disallow: /xmlrpc.php

Sitemap: https://pantry.example/sitemap.xml
30 Disallow lines; /admin listed: false
```

`/admin` is Pantry's again. `recipe-export` answers with `fake-data`, which synthesises a
fresh, plausible user table on every hit, so anything exfiltrated is noise.

Passing an array to `decoyPathDetector` **replaces** the built-in decoys, which is why the
defaults are spread in first.

## robots.txt as a lure

A `robots.txt` listing the decoys as `Disallow` has two effects. A legitimate crawler obeys
it and never touches them, so Pantry's incidents are not cluttered with well-behaved bots.
Anything that fetches a disallowed path anyway has shown it does not respect robots.txt.

Thirty lines, not forty: only string decoys can be listed, because a pattern has no single
path to disallow.

Advertising decoys tells a curious reader where they are. That costs little. A decoy works
on tooling that probes a wordlist regardless, and a person reading your robots.txt was
never going to be caught by one.

## The same thing in a configuration file

When Pantry runs from a TOML file ([lesson 11](11-standalone-and-protocols.md)), dropping a
built-in decoy is one line, and a typo in it is a startup error rather than a decoy
silently left on:

```toml
[detectors.decoy-path]
disabled = ["admin-panel"]
```

## Exercise

Pantry also publishes its API documentation at `/api-docs`. Find out which built-in decoy
that collides with, and prove that dropping it hands `/api-docs`, `/swagger` and
`/openapi` back to Pantry.

<details>
<summary>Checkpoint</summary>

```js
import { HoneypotEngine, decoyPathDetector, defaultDecoyPaths, defaultDetectors } from "@osqd/hackerpot";
import { CHROME } from "./browser.mjs";
const drop = new Set(["admin-panel", "swagger"]);
const engine = new HoneypotEngine({
  detectors: defaultDetectors().map((d) => (d.id === "decoy-path" ? decoyPathDetector(defaultDecoyPaths.filter((x) => !drop.has(x.id))) : d)),
});
const before = new HoneypotEngine();
for (const path of ["/api-docs", "/swagger", "/openapi"]) {
  const b = await before.evaluate({ method: "GET", path, query: {}, headers: CHROME, ip: "198.51.100.30" });
  const a = await engine.evaluate({ method: "GET", path, query: {}, headers: CHROME, ip: "198.51.100.31" });
  console.log(path.padEnd(10), "before:", b.detections.map((d) => d.detectorId).join(",") || "-", " after:", a.detections.map((d) => d.detectorId).join(",") || "-");
}
```

```
/api-docs  before: decoy-path  after: -
/swagger   before: decoy-path  after: -
/openapi   before: decoy-path  after: -
```

It is the `swagger` decoy, which covers all three paths. From here on Pantry drops both
`admin-panel` and `swagger`. You will see that exact list again in the capstone.
</details>

## What you learned

- Forty built-in decoys; prefix decoys match only at a `/` or `.` boundary
- Normalisation happens first, so spelling a path differently does not evade a decoy
- A decoy that shadows a real route breaks that route for everyone — check before deploying
- Passing a decoy list replaces the defaults; spread them in to keep them
- A generated robots.txt keeps honest crawlers out of the incident log

## Where to read more

- [Decoys](../detection/decoys.md) — the full built-in table, matching rules, TOML decoys
- [Response actions](../responses/actions.md) — what a decoy can serve
- [nginx edge capture](../integration/nginx.md) — the same decoys, diverted at the edge

Next: [Traps and honeytokens](07-traps-and-honeytokens.md).
