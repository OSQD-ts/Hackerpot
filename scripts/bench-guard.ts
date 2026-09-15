#!/usr/bin/env tsx
/**
 * The performance guard.
 *
 *   npm run bench:guard
 *
 * In middleware mode `evaluate()` runs inline on every request the host app serves, so
 * its cost is latency added to every page. Without a guard, a detector that got ten times
 * slower, or a regex that went quadratic on a large body, would ship without a failing
 * build. Adapted from bothandlerjs.
 *
 * Every budget is a ratio against a reference loop measured in the same process seconds
 * earlier, not a number of microseconds: a CI runner half as fast as a laptop runs both
 * halves at half speed, so the ratio stays put and moves only when detection does. The
 * budgets sit at roughly twice today's measured ratio, loose enough that noise does not
 * fail the build and tight enough to catch a real regression.
 */
import { HoneypotEngine } from "../src/core.js";
import { normalizePath } from "../src/http-request.js";
import type { HitStore } from "../src/types.js";
import type { RequestFacts } from "../src/detectors/types.js";

const ITERATIONS = Number(process.env["ITERATIONS"] ?? 2000);
const ROUNDS = Number(process.env["ROUNDS"] ?? 5);

interface Sample {
  name: string;
  weight: number;
  tags: string[];
}

const REFERENCE_PATTERN = /^[a-z]+-[0-9]+$/;

/**
 * The yardstick: allocation, map lookups, string building and a regex, the same kinds of
 * work detection does. Nothing in `src/` can change what this costs, so it measures the
 * machine and everything else is measured against it.
 */
function reference(): number {
  let hash = 0x811c9dc5;
  const seen = new Map<string, number>();
  const kept: Sample[] = [];
  for (let i = 0; i < 5; i++) {
    hash ^= i;
    hash = Math.imul(hash, 0x01000193);
    const name = `field-${hash >>> 24}`;
    const sample: Sample = { name, weight: (hash >>> 8) / 0xffffff, tags: [name.slice(0, 5), `t${i % 7}`] };
    seen.set(name, (seen.get(name) ?? 0) + 1);
    if (REFERENCE_PATTERN.test(name)) kept.push(sample);
  }
  let total = 0;
  for (const sample of kept) {
    total += sample.weight + sample.tags.length;
    if (sample.name.startsWith("field-1")) total += 1;
  }
  return hash + seen.size + total;
}

interface Budget {
  label: string;
  maxRatio: number;
  run: () => unknown;
}

function buildCases(): Budget[] {
  // Detection only: nothing is stored, nothing is enriched, and a 1 ms activity window
  // keeps one address from accumulating history across iterations and tripping the
  // volume detectors part-way through a measurement.
  const discard: HitStore = { record: () => undefined, list: () => [], scoreFor: () => 0 };
  const engine = new HoneypotEngine({ enricher: null, store: discard, activityWindowMs: 1 });
  const headers: Record<string, string> = {
    host: "shop.example",
    "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-language": "en-GB,en;q=0.9",
    "accept-encoding": "gzip, deflate, br",
    "sec-fetch-site": "none",
    "sec-fetch-mode": "navigate",
  };
  const rawHeaders = Object.entries(headers).flat();
  const facts = (extra: Partial<RequestFacts>): RequestFacts => ({ method: "GET", path: "/products/12", query: {}, headers, rawHeaders, ip: "203.0.113.5", ...extra });

  const clean = facts({});
  const longPath = facts({ path: `/${Array.from({ length: 60 }, (_, i) => `segment${i}`).join("/")}/42` });
  const manyKeys = facts({ query: Object.fromEntries(Array.from({ length: 200 }, (_, i) => [`key${i}`, `value${i}`])) });
  const floodKeys = facts({ query: Object.fromEntries(Array.from({ length: 4000 }, (_, i) => [`k${i}`, "v"])) });
  const largeBody = facts({ method: "POST", path: "/api/orders", body: Array.from({ length: 4000 }, (_, i) => `field${i}=value${i}`).join("&").slice(0, 64 * 1024) });
  const probe = facts({ path: "/.env" });

  return [
    // The overwhelmingly common case in middleware mode: a real browser, nothing firing.
    // Budgets are about twice the top of the range measured over repeated runs on the
    // development machine: 16–24x, 28–33x, 313–338x, 850–1010x, 226–280x, 15–19x and
    // 0.8–0.9x respectively. Twice the top, not twice one run, is what stops noise failing
    // the build.
    { label: "evaluate — clean browser", maxRatio: 50, run: () => engine.evaluate(clean) },
    // A request costs whatever its URL says, and the URL is written by the client.
    { label: "evaluate — very long path", maxRatio: 70, run: () => engine.evaluate(longPath) },
    { label: "evaluate — 200 query keys", maxRatio: 700, run: () => engine.evaluate(manyKeys) },
    // Capped at MAX_QUERY_PARAMS before any detector runs. Uncapped, this one request cost
    // 9.9 ms: about 130 times an ordinary one.
    { label: "evaluate — 4000 query keys", maxRatio: 2000, run: () => engine.evaluate(floodKeys) },
    // Every body detector scanning the largest body the front ends read: where a regex
    // that goes quadratic would show up first.
    { label: "evaluate — 64 KB body", maxRatio: 560, run: () => engine.evaluate(largeBody) },
    // A hit: the policy runs and a hit record is built.
    { label: "evaluate — decoy probe", maxRatio: 40, run: () => engine.evaluate(probe) },
    { label: "normalizePath — encoded", maxRatio: 4, run: () => normalizePath("/static//%2e%2e/%61ssets/./app.js") },
  ];
}

/** Median per-iteration cost over several rounds, each preceded by a warm-up. */
async function measure(run: () => unknown): Promise<number> {
  const isAsync = run() instanceof Promise;
  const samples: number[] = [];
  for (let round = 0; round < ROUNDS; round++) {
    for (let i = 0; i < 200; i++) {
      if (isAsync) await run();
      else run();
    }
    const started = performance.now();
    for (let i = 0; i < ITERATIONS; i++) {
      if (isAsync) await run();
      else run();
    }
    samples.push(performance.now() - started);
  }
  samples.sort((a, b) => a - b);
  return (samples[Math.floor(samples.length / 2)] as number) / ITERATIONS;
}

async function main(): Promise<number> {
  const unit = await measure(reference);
  console.log(`\n  reference loop: ${(unit * 1000).toFixed(2)} us   (this machine's yardstick)\n`);

  let failed = 0;
  for (const budget of buildCases()) {
    const cost = await measure(budget.run);
    const ratio = cost / unit;
    const ok = ratio <= budget.maxRatio;
    if (!ok) failed += 1;
    console.log(
      `  ${ok ? "ok  " : "FAIL"}  ${budget.label.padEnd(28)} ${(cost * 1000).toFixed(2).padStart(8)} us   ${ratio.toFixed(1).padStart(6)}x reference   budget ${budget.maxRatio}x`,
    );
  }

  if (failed > 0) {
    console.log(
      `\n  ${failed} case(s) over budget. Either something on the request path got materially slower,\n` +
        "  or the budget is wrong for a change worth making; then raise it in scripts/bench-guard.ts and say why.\n",
    );
    return 1;
  }
  console.log("\n  Everything within budget.\n");
  return 0;
}

process.exitCode = await main();
