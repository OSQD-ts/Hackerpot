import type { Detection, DetectionContext, Detector } from "./types.js";

export interface RateSpikeOptions {
  /** Window to count requests over. Default 10s. */
  windowMs?: number;
  /** Requests from one IP within the window before it counts as a flood. Default 60. */
  requestThreshold?: number;
  score?: number;
  respondWith?: string;
}

/**
 * Raw request-rate flood from a single IP — aggressive scraping, or the
 * volume side of an automated attack. Deliberately a high threshold: this is
 * the noisiest signal, so it scores low on its own and mainly matters when it
 * stacks with a more specific detection.
 */
export function rateSpikeDetector(options: RateSpikeOptions = {}): Detector {
  const windowMs = options.windowMs ?? 10_000;
  const threshold = options.requestThreshold ?? 60;
  const score = options.score ?? 4;

  return {
    id: "rate-spike",
    description: "Abnormally high request rate from a single IP",
    inspect(ctx: DetectionContext): Detection | undefined {
      // A crawler DNS has confirmed crawls fast by design. See `crawler-verification`.
      if (ctx.verifiedCrawler !== undefined) return undefined;
      const count = ctx.tracker.countIn(windowMs, ctx.timestamp.getTime());
      if (count < threshold) return undefined;
      const detection: Detection = {
        detectorId: "rate-spike",
        reason: `${count} requests in ${Math.round(windowMs / 1000)}s`,
        score,
        metadata: { requestCount: count, windowMs },
      };
      if (options.respondWith) detection.respondWith = options.respondWith;
      return detection;
    },
  };
}
