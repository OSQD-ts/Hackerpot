import { randomBytes, randomInt } from "node:crypto";
import type { ResponseAction, ResponseContext } from "./types.js";

export interface ChaosOptions {
  /** Server-error statuses to pick from. Default [500, 502, 503, 504]. */
  statuses?: number[];
  /** Probability (0–1) of returning random garbage bytes instead of an error. Default 0.5. */
  garbageChance?: number;
  /** Max garbage payload size. Default 4096 bytes. */
  maxGarbageBytes?: number;
}

/**
 * Answers unpredictably — sometimes a random 5xx, sometimes a blob of random
 * bytes — to break the assumptions of automated tooling. A scanner expecting
 * consistent, parseable responses gets neither, wasting its retries and confusing
 * its fingerprinting.
 */
const DEFAULT_STATUSES = [500, 502, 503, 504];
/** Smallest garbage payload we would normally emit; also the low end of the size range. */
const MIN_GARBAGE_BYTES = 64;

export function chaosAction(options: ChaosOptions = {}): ResponseAction {
  // Both of these feed `randomInt`, which THROWS `ERR_OUT_OF_RANGE` on an empty range
  // rather than returning anything — so an out-of-range option is not a degraded
  // response, it is an exception thrown from inside the response action. That escapes
  // `execute()` and becomes a 500, which is a honeypot tell: every other response here
  // is a plausible one, and `garbage_chance` defaults to 0.5, so the tell is
  // intermittent and correspondingly hard to trace. The config layer now rejects both
  // values, but this action is also public API that a library caller constructs
  // directly, so it holds its own floor rather than trusting the caller.
  const statuses = options.statuses?.length ? options.statuses : DEFAULT_STATUSES;
  const garbageChance = options.garbageChance ?? 0.5;
  const maxGarbage = Math.max(0, options.maxGarbageBytes ?? 4096);
  // A ceiling below the usual floor means the operator wants small payloads, not an
  // inverted range: shrink the low end to match instead of throwing.
  const minGarbage = Math.min(MIN_GARBAGE_BYTES, maxGarbage);

  return {
    id: "chaos",
    description: "Return a random 5xx or random garbage bytes to confuse automated tooling",
    execute(ctx: ResponseContext): void {
      if (Math.random() < garbageChance) {
        const size = randomInt(minGarbage, maxGarbage + 1);
        ctx.res.statusCode = 200;
        ctx.res.setHeader("Content-Type", "application/octet-stream");
        ctx.res.end(randomBytes(size));
        return;
      }
      const status = statuses[randomInt(0, statuses.length)]!;
      ctx.res.statusCode = status;
      ctx.res.setHeader("Content-Type", "text/plain; charset=utf-8");
      ctx.res.end(`${status} Internal Server Error`);
    },
  };
}
