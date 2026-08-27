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
export function chaosAction(options: ChaosOptions = {}): ResponseAction {
  const statuses = options.statuses ?? [500, 502, 503, 504];
  const garbageChance = options.garbageChance ?? 0.5;
  const maxGarbage = options.maxGarbageBytes ?? 4096;

  return {
    id: "chaos",
    description: "Return a random 5xx or random garbage bytes to confuse automated tooling",
    execute(ctx: ResponseContext): void {
      if (Math.random() < garbageChance) {
        const size = randomInt(64, maxGarbage + 1);
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
