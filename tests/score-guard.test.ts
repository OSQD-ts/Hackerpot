import { describe, expect, it } from "vitest";
import type { Redis } from "ioredis";
import { usableScore } from "../src/stores/scores.js";
import { RedisStore } from "../src/stores/redis.js";
import { ElasticStore } from "../src/stores/elastic.js";
import { defaultResponsePolicy } from "../src/responses/index.js";
import type { PolicyContext } from "../src/responses/types.js";

/** A Redis double whose score key holds `value` — standing in for a foreign writer. */
function redisReturning(value: unknown): RedisStore {
  const client = { get: async () => value } as unknown as Redis;
  return new RedisStore({ client });
}

function elasticReturning(value: unknown): ElasticStore {
  const fetchStub = (async () =>
    new Response(JSON.stringify({ aggregations: { total: { value } } }), {
      status: 200,
      headers: { "content-type": "application/json" },
    })) as unknown as typeof fetch;
  return new ElasticStore({ node: "http://es.invalid", fetch: fetchStub, onError: () => {} });
}

describe("an unusable stored score cannot switch blocking off", () => {
  // A score is only ever compared against a threshold, and every comparison against NaN
  // is false. So one unusable value does not *degrade* blocking for that IP — it
  // silently disables it: totalScore becomes NaN, both threshold tests fail, and the
  // attacker is served the benign default response no matter how much they accrue.
  // Nothing logs, because nothing threw. `ScoreLedger.seed` has always guarded the
  // checkpoint file against this; the remote stores read their equivalent unguarded.

  it("coerces every unusable shape to zero", () => {
    for (const value of ["corrupted", "", null, undefined, "NaN", Number.NaN, Infinity, -Infinity, -50, "-50", {}, []]) {
      expect(usableScore(value), String(value)).toBe(0);
    }
  });

  it("keeps a genuine score intact", () => {
    expect(usableScore("42")).toBe(42);
    expect(usableScore(42)).toBe(42);
    expect(usableScore(0.5)).toBe(0.5);
  });

  it("RedisStore returns a usable number for a corrupted key", async () => {
    expect(await redisReturning("corrupted").scoreFor("203.0.113.9")).toBe(0);
    expect(await redisReturning("-999999").scoreFor("203.0.113.9")).toBe(0);
    // A real value still reads back unchanged.
    expect(await redisReturning("77").scoreFor("203.0.113.9")).toBe(77);
  });

  it("ElasticStore applies the same rail", async () => {
    expect(await elasticReturning("corrupted").scoreFor("203.0.113.9")).toBe(0);
    expect(await elasticReturning(null).scoreFor("203.0.113.9")).toBe(0);
    expect(await elasticReturning(64).scoreFor("203.0.113.9")).toBe(64);
  });

  it("the policy still escalates once the score is usable", () => {
    const policy = defaultResponsePolicy(40, 15);
    const ctx = (totalScore: number): PolicyContext =>
      ({ detection: { detectorId: "d", reason: "r", score: 25 }, detections: [], ip: "203.0.113.9", path: "/", totalScore, tracker: {} }) as unknown as PolicyContext;

    // The value a corrupted read used to produce — every threshold comparison false.
    expect(policy(ctx(Number.NaN))).toBe("not-found");
    // What the same attacker now gets, with the read guarded.
    expect(policy(ctx(0 + 25))).toBe("tarpit");
    expect(policy(ctx(0 + 55))).toBe("block");
  });
});
