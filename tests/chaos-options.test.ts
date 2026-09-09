import { describe, expect, it } from "vitest";
import { chaosAction } from "../src/responses/chaos.js";
import { parseConfig } from "../src/config/schema.js";
import type { ResponseContext } from "../src/responses/types.js";

/** A response double that records what the action wrote. */
function fakeContext(): ResponseContext & { body: unknown } {
  const ctx = {
    statusCode: 0,
    body: undefined as unknown,
    res: {
      statusCode: 0,
      setHeader() {},
      end(payload?: unknown) {
        ctx.body = payload;
      },
      writableEnded: false,
    },
  } as unknown as ResponseContext & { body: unknown };
  return ctx;
}

describe("the chaos action cannot be configured into throwing", () => {
  // `randomInt` throws ERR_OUT_OF_RANGE on an empty range rather than returning
  // anything, so an out-of-range option was not a degraded response — it was an
  // exception thrown from inside the response action, which escapes `execute()` and
  // becomes a 500. That is a honeypot tell, and with garbage_chance defaulting to 0.5
  // it appeared intermittently, long after the config that caused it was accepted.
  const pathological = [
    { label: "ceiling below the usual floor", options: { maxGarbageBytes: 32, garbageChance: 1 } },
    { label: "zero ceiling", options: { maxGarbageBytes: 0, garbageChance: 1 } },
    { label: "negative ceiling", options: { maxGarbageBytes: -100, garbageChance: 1 } },
    { label: "empty status list", options: { statuses: [], garbageChance: 0 } },
  ];

  for (const { label, options } of pathological) {
    it(`survives ${label}`, () => {
      const action = chaosAction(options);
      for (let i = 0; i < 50; i += 1) {
        expect(() => action.execute(fakeContext())).not.toThrow();
      }
    });
  }

  it("still emits a payload within the configured ceiling", () => {
    const action = chaosAction({ maxGarbageBytes: 32, garbageChance: 1 });
    for (let i = 0; i < 50; i += 1) {
      const ctx = fakeContext();
      action.execute(ctx);
      expect(Buffer.isBuffer(ctx.body)).toBe(true);
      expect((ctx.body as Buffer).length).toBeLessThanOrEqual(32);
    }
  });

  it("falls back to the default statuses rather than failing on an empty list", () => {
    const action = chaosAction({ statuses: [], garbageChance: 0 });
    const ctx = fakeContext();
    action.execute(ctx);
    expect(String(ctx.body)).toMatch(/^(500|502|503|504) /);
  });
});

describe("the config layer rejects chaos options that would throw at runtime", () => {
  // `garbage_chance` was already range-checked right beside these; these two were not,
  // so `config:check` reported a config that could only fail once traffic arrived.
  it("rejects a garbage ceiling below the floor", () => {
    expect(() => parseConfig({ responses: { chaos: { max_garbage_bytes: 32 } } }, "<test>")).toThrow(/max_garbage_bytes/);
    expect(() => parseConfig({ responses: { chaos: { max_garbage_bytes: 0 } } }, "<test>")).toThrow(/max_garbage_bytes/);
  });

  it("rejects an empty status list, pointing at the way to switch the action off", () => {
    expect(() => parseConfig({ responses: { chaos: { statuses: [] } } }, "<test>")).toThrow(/enabled = false/);
  });

  it("accepts a valid configuration unchanged", () => {
    const config = parseConfig({ responses: { chaos: { max_garbage_bytes: 8192, statuses: [500, 503] } } }, "<test>");
    expect(config.responses.chaos.options.maxGarbageBytes).toBe(8192);
    expect(config.responses.chaos.options.statuses).toEqual([500, 503]);
  });
});
