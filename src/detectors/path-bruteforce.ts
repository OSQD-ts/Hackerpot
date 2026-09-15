import type { Detection, DetectionContext, Detector } from "./types.js";

export interface PathBruteforceOptions {
  /** Window to count distinct paths over. Default 30s. */
  windowMs?: number;
  /** Distinct paths from one IP within the window before it counts as enumeration. Default 15. */
  uniquePathThreshold?: number;
  score?: number;
  respondWith?: string;
}

/**
 * Directory/path enumeration: one IP walking a wordlist hits many distinct
 * paths in a short window, whereas a real user or crawler revisits a small,
 * mostly repeating set. Counts distinct paths rather than raw request volume
 * so a busy legitimate client polling one endpoint never trips it.
 */
export function pathBruteforceDetector(options: PathBruteforceOptions = {}): Detector {
  const windowMs = options.windowMs ?? 30_000;
  const threshold = options.uniquePathThreshold ?? 15;
  const score = options.score ?? 8;

  return {
    id: "path-bruteforce",
    description: "One IP requesting many distinct paths in a short window (directory enumeration)",
    inspect(ctx: DetectionContext): Detection | undefined {
      // A crawler DNS has confirmed visits many distinct paths by design. See `crawler-verification`.
      if (ctx.verifiedCrawler !== undefined) return undefined;
      const unique = ctx.tracker.uniquePathsIn(windowMs, ctx.timestamp.getTime());
      if (unique < threshold) return undefined;
      const detection: Detection = {
        detectorId: "path-bruteforce",
        reason: `${unique} distinct paths requested in ${Math.round(windowMs / 1000)}s`,
        score,
        metadata: { uniquePaths: unique, windowMs },
      };
      if (options.respondWith) detection.respondWith = options.respondWith;
      return detection;
    },
  };
}
