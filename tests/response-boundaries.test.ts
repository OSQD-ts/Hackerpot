import { describe, expect, it } from "vitest";
import * as R from "../src/responses/index.js";
import { MemoryBlocklist } from "../src/blocklist.js";
import { parseConfig } from "../src/config/schema.js";
import type { ResponseContext } from "../src/responses/types.js";

/** A response that reports the client gone as soon as anything listens, so the holding
 *  actions take their abandon path. We are testing termination, not duration. */
function stubContext(path = "/"): ResponseContext {
  const res = {
    statusCode: 0,
    writableEnded: false,
    setHeader() {},
    end() {
      (res as { writableEnded: boolean }).writableEnded = true;
    },
    write: () => true,
    on(event: string, cb: () => void) {
      if (event === "close") setImmediate(cb);
    },
    once(event: string, cb: () => void) {
      if (event === "close") setImmediate(cb);
    },
    off() {},
  };
  return {
    res,
    ip: "203.0.113.1",
    path,
    totalScore: 50,
    detection: { detectorId: "d", reason: "r", score: 5 },
    detections: [{ detectorId: "d", reason: "r", score: 5 }],
    tracker: { recent: () => [], countIn: () => 0 },
    blocklist: new MemoryBlocklist(),
    onError: () => {},
  } as unknown as ResponseContext;
}

/** Runs an action, failing if it neither settles nor throws within the budget. */
async function runs(action: R.ResponseAction, budgetMs = 2_000): Promise<"settled"> {
  const outcome = action.execute(stubContext());
  if (outcome && typeof (outcome as Promise<void>).then === "function") {
    const result = await Promise.race([
      (outcome as Promise<void>).then(() => "settled" as const),
      new Promise<"hung">((resolve) => setTimeout(() => resolve("hung"), budgetMs)),
    ]);
    expect(result).toBe("settled");
  }
  return "settled";
}

describe("large-payload cannot be configured into an infinite loop", () => {
  // The stream advances by `chunkBytes`: `size = min(chunkBytes, remaining)`, then
  // `sent += size`. At 0 that adds nothing, so `sent < totalBytes` stays true forever —
  // and there is no await on that path either, because an empty write() returns true
  // (no drain) and throttleMs defaults to 0 (no sleep). The result was a tight
  // synchronous spin pinning the event loop: the HTTP honeypot, the management API and
  // every protocol emulator stop, permanently, from the first request routed here.
  it("terminates with a zero or negative chunk size", async () => {
    for (const chunkBytes of [0, -1, -1024]) {
      const action = R.largePayloadAction({ totalBytes: 4096, chunkBytes, maxConcurrent: 4 });
      await expect(runs(action), `chunkBytes=${chunkBytes}`).resolves.toBe("settled");
    }
  }, 15_000);

  it("still streams normally at a sane chunk size", async () => {
    await expect(runs(R.largePayloadAction({ totalBytes: 4096, chunkBytes: 512 }))).resolves.toBe("settled");
  });

  it("the config layer rejects it before it can run", () => {
    expect(() => parseConfig({ responses: { "large-payload": { chunk_bytes: 0 } } }, "<test>")).toThrow(/chunk_bytes/);
    expect(() => parseConfig({ responses: { "large-payload": { chunk_bytes: 0 } } }, "<test>")).toThrow(/never finishes/);
    // A valid value is untouched.
    expect(parseConfig({ responses: { "large-payload": { chunk_bytes: 8192 } } }, "<test>").responses["large-payload"].options.chunkBytes).toBe(8192);
  });
});

describe("no response action throws or hangs at an option boundary", () => {
  // Exhaustive over (option x boundary) for every built-in action. This is the class
  // that produced both the chaos `randomInt` throw and the large-payload spin: an option
  // the config accepts, or a library caller passes, that only misbehaves once a request
  // is actually routed to the action — long after `config:check` said the setup was fine.
  const boundaries = [0, -1, 1, 63, 64, 65];
  const cases: Array<[string, (v: number) => R.ResponseAction]> = [
    ["tarpit.delayMs", (v) => R.tarpitAction({ delayMs: v, maxConcurrent: 4 })],
    ["tarpit.maxConcurrent", (v) => R.tarpitAction({ maxConcurrent: v, delayMs: 0 })],
    ["chaos.maxGarbageBytes", (v) => R.chaosAction({ maxGarbageBytes: v, garbageChance: 1 })],
    ["fakeData.rows", (v) => R.fakeDataAction({ rows: v })],
    ["largePayload.totalBytes", (v) => R.largePayloadAction({ totalBytes: v, chunkBytes: 16, maxConcurrent: 4 })],
    ["largePayload.chunkBytes", (v) => R.largePayloadAction({ totalBytes: 64, chunkBytes: v, maxConcurrent: 4 })],
    ["dripFeed.chunkBytes", (v) => R.dripFeedAction({ chunkBytes: v, intervalMs: 0, maxDurationMs: 5 })],
    ["dripFeed.maxDurationMs", (v) => R.dripFeedAction({ chunkBytes: 1, intervalMs: 0, maxDurationMs: v })],
    ["gzipBomb.decompressedBytes", (v) => R.gzipBombAction({ decompressedBytes: v })],
    ["block.durationMs", (v) => R.blockAction({ durationMs: v })],
    ["rateLimit.retryAfterSeconds", (v) => R.rateLimitAction({ retryAfterSeconds: v })],
  ];

  for (const [label, make] of cases) {
    it(`${label} survives every boundary`, async () => {
      for (const value of boundaries) {
        const action = make(value);
        await expect(runs(action), `${label}=${value}`).resolves.toBe("settled");
      }
    }, 20_000);
  }
});
