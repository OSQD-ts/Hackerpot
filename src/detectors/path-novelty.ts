import type { Detection, DetectionContext, Detector } from "./types.js";

export interface PathNoveltyOptions {
  score?: number;
  /** Sliding window for counting this address's requests for unserved paths. Default 60000. */
  windowMs?: number;
  /** Distinct never-served paths one address must ask for to fire. Default 5. */
  unseenPathThreshold?: number;
  /** Distinct addresses probing one never-served path before that alone fires. Default 4. */
  walkerThreshold?: number;
  /** Outcomes the baseline must hold before this detector reads it at all. Default 500. */
  minObservations?: number;
  /** Real paths the baseline must know before it is believed. Default 20. */
  minServedPaths?: number;
  respondWith?: string;
}

/**
 * Probing measured against what this site actually serves.
 *
 * `path-bruteforce` counts distinct paths in a window, which is a guess about the site
 * dressed as a threshold: fifteen paths in thirty seconds is a scanner on a marketing page
 * and one page load on an asset-heavy application. This detector asks a different question —
 * are these paths *real here*? — and answers it from the application's own status codes,
 * collected by {@link SiteBaseline} through `engine.reportOutcome()`.
 *
 * Two shapes fire it:
 *
 * - **Walking**: one address asking for several paths the application has never served.
 * - **A distributed walk**: one never-served path being asked for by many addresses, which is
 *   the shape of a scan spread thin enough that no single address trips a volume threshold.
 *
 * It is deliberately conservative, because a wrong answer here lands on a real visitor:
 *
 * - It reads nothing until the baseline is warm, so a fresh process flags nobody.
 * - A path the application has served is never novel, however odd it looks.
 * - A crawler DNS has confirmed is skipped, as in the volume detectors.
 * - It shares the `path-probing` family with `path-bruteforce`, so one walk seen by both
 *   counts once rather than twice.
 * - It is off by default and only works in middleware mode, where outcomes exist.
 *
 * Adapted from bothandlerjs.
 */
export function pathNoveltyDetector(options: PathNoveltyOptions = {}): Detector {
  const score = options.score ?? 6;
  const windowMs = options.windowMs ?? 60_000;
  const unseenPathThreshold = options.unseenPathThreshold ?? 5;
  const walkerThreshold = options.walkerThreshold ?? 4;
  const minObservations = options.minObservations ?? 500;
  const minServedPaths = options.minServedPaths ?? 20;

  return {
    id: "path-novelty",
    description: "Requests for paths this site has never served, measured against its own traffic",
    inspect(ctx: DetectionContext): Detection | undefined {
      // `baseline` is the field's old name, still set by the engine and read here for a context
      // somebody builds by hand.
      const baseline = ctx.site ?? ctx.baseline;
      // No baseline (standalone mode, or disabled), or one that has not seen enough of this
      // site's traffic to have an opinion. "I have never seen this path" is true of every
      // page on the site until it is warm.
      if (baseline === undefined || !baseline.isWarm(minObservations, minServedPaths)) return undefined;
      if (ctx.verifiedCrawler !== undefined) return undefined;
      // The application serves this path. Whatever else is true of the request, it is not a
      // probe for something that does not exist.
      if (baseline.isServed(ctx.path)) return undefined;

      const now = ctx.timestamp.getTime();
      const cutoff = now - windowMs;
      const unseen = new Set<string>();
      for (const event of ctx.tracker.recent(now)) {
        // `passed` requests are included on purpose: the baseline, not the tracker, decides
        // whether the path turned out to be real, and it knows the answer for those too.
        if (event.at >= cutoff && !baseline.isServed(event.path)) unseen.add(event.path);
      }
      const walkers = baseline.walkers(ctx.path);
      const walking = unseen.size >= unseenPathThreshold;
      const distributed = walkers >= walkerThreshold;
      if (!walking && !distributed) return undefined;

      const reasons: string[] = [];
      if (walking) reasons.push(`${unseen.size} paths this site has never served in ${Math.round(windowMs / 1000)}s`);
      if (distributed) reasons.push(`${walkers} distinct addresses probing ${ctx.path}, which this site has never served`);

      const detection: Detection = {
        detector: "path-novelty",
        summary: `Probing against the site's own baseline: ${reasons.join("; ")}`,
        // Both shapes at once is one address walking a space that others are walking too —
        // a coordinated scan rather than a curious client.
        score: walking && distributed ? Math.round(score * 1.5) : score,
        family: "path-probing",
        metadata: { unseenPaths: unseen.size, walkers, baseline: baseline.snapshot() },
      };
      if (options.respondWith) detection.respondWith = options.respondWith;
      return detection;
    },
  };
}
