/**
 * A cumulative histogram, in the shape Prometheus defines one.
 *
 * One implementation for every distribution this library exposes, so a score and a duration are
 * bucketed by the same rule and rendered the same way.
 */

/**
 * Upper bounds for the cumulative-score histogram.
 *
 * The same name bothandlerjs uses, deliberately different values. Its scores are capped at 100
 * and spread evenly, so ten equal buckets fit. A cumulative score here is unbounded and the
 * decisions sit at specific points — the shipped ladder tarpits at 15 and blocks at 40 — so the
 * bounds cluster around those lines, which is where "how close does traffic run to a block?"
 * is actually answered. Totals past the last bound are counted in `+Inf`.
 */
export const SCORE_BUCKETS: readonly number[] = [5, 10, 15, 20, 30, 40, 60, 100];

/**
 * Upper bounds, in milliseconds, for the time spent evaluating a request.
 *
 * The same values bothandlerjs uses, and on purpose: unlike a score, a millisecond means the same
 * thing in both libraries, so a dashboard built against one reads the other without edits.
 * Detection is usually well under a millisecond, which is why the bounds start at 50µs.
 */
export const DURATION_BUCKETS_MS: readonly number[] = [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100];

export interface HistogramSnapshot {
  count: number;
  total: number;
  max: number;
  /** Cumulative counts, one per bound and then everything past the last bound (`+Inf`). */
  buckets: number[];
}

export class Histogram {
  private readonly bounds: readonly number[];
  private readonly perBucket: Float64Array;
  private count = 0;
  private total = 0;
  private max = 0;

  constructor(bounds: readonly number[]) {
    this.bounds = bounds;
    // One slot per bound, plus the overflow past the last.
    this.perBucket = new Float64Array(bounds.length + 1);
  }

  observe(value: number): void {
    const v = Number.isFinite(value) ? value : 0;
    this.count += 1;
    this.total += v;
    if (v > this.max) this.max = v;
    // A linear scan: at a dozen bounds it beats a binary search, and it runs on the hit path.
    let bucket = this.bounds.length;
    for (let i = 0; i < this.bounds.length; i += 1) {
      if (v <= (this.bounds[i] as number)) {
        bucket = i;
        break;
      }
    }
    this.perBucket[bucket] = (this.perBucket[bucket] ?? 0) + 1;
  }

  /** Per-bucket counts made cumulative, which is how Prometheus defines a histogram. */
  snapshot(): HistogramSnapshot {
    const buckets: number[] = [];
    let running = 0;
    for (let i = 0; i < this.perBucket.length; i += 1) {
      running += this.perBucket[i] as number;
      buckets.push(running);
    }
    return { count: this.count, total: this.total, max: this.max, buckets };
  }
}
