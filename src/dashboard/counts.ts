// Kept identical in hackerpot and bothandlerjs. Change both, or neither.

import { systemClock, type Clock } from "../internal/clock.js";

/**
 * How many entries happened in a stretch of time, kept apart from the entries themselves.
 *
 * The page's count was the length of the list it was holding. That list is bounded — by the
 * store's retention, by the `limit` the page asked for, by the rows the live feed drops as
 * newer ones arrive — because every entry in it carries an address, a User-Agent, a header set
 * and a detection list belonging to somebody. Those are the right bounds for *entries*. They
 * are the wrong bound for *counting*, and they were the same number: a busy honeypot showed
 * "100" on the Incidents tab for as long as it ran, because 100 was the page size.
 *
 * So the count is kept separately, in minute buckets. A bucket is an integer and a timestamp —
 * no addresses, no headers, nothing anybody could object to retaining — which is what lets it
 * speak for a window far longer than the entries do, at a cost that does not depend on traffic.
 * A day of history is 1,440 numbers.
 *
 */

const MINUTE = 60_000;

/**
 * Most minutes kept, whatever the retention says.
 *
 * A second bound, because the first one is optional: retention may be zero, meaning "keep
 * them until the capacity bound evicts them" — and that bound is a count of *entries*, which
 * says nothing about these. The entries stay bounded while the counts behind them grow by one
 * object per minute of traffic for as long as the process lives. Slowly, and without end,
 * which is the shape of leak found in production a year later rather than in a test.
 */
const MAX_BUCKETS = 7 * 24 * 60;

/** A minute that saw traffic. Absent minutes are zero and cost nothing. */
interface Bucket {
  /** Start of the minute, as epoch milliseconds. */
  at: number;
  total: number;
}

export interface FeedCountsOptions {
  /** How long counts are kept, in ms. 0 keeps them until the ceiling evicts them. */
  retainMs?: number;
  clock?: Clock;
}

/** What the page needs to say something true about a window. */
export interface CountsSnapshot {
  /** Incidents counted in the requested window. */
  total: number;
  /** The earliest instant these counts can speak for, or undefined when nothing is held. */
  oldest: number | undefined;
  /** One entry per minute that saw traffic, oldest first. */
  series: ReadonlyArray<{ at: number; total: number }>;
}

export class FeedCounts {
  /** Oldest first, one per minute that saw at least one incident. */
  private buckets: Bucket[] = [];
  private retainMs: number;
  private readonly clock: Clock;

  constructor(options: FeedCountsOptions = {}) {
    this.clock = options.clock ?? systemClock;
    this.retainMs = Math.max(0, Math.floor(options.retainMs ?? 24 * 60 * MINUTE));
  }

  /**
   * How long counts are kept.
   *
   * Follows the entries' own retention, so "we keep nothing older than an hour" stays one promise
   * rather than becoming two with different answers.
   */
  get retention(): number {
    return this.retainMs;
  }

  setRetention(ms: number, now: number = this.clock.now()): void {
    this.retainMs = Math.max(0, Math.floor(ms));
    this.prune(now);
  }

  /** Counts one incident, at the time it happened. */
  record(at: number = this.clock.now()): void {
    const minute = Math.floor(at / MINUTE) * MINUTE;
    const last = this.buckets[this.buckets.length - 1];
    // Almost always the newest minute, because incidents arrive in time order. The scan below
    // is for the exception — a replayed or back-dated timestamp — rather than the rule, so
    // this stays O(1) on the path it is actually on.
    if (last !== undefined && last.at === minute) {
      last.total += 1;
      return;
    }
    if (last === undefined || minute > last.at) {
      this.buckets.push({ at: minute, total: 1 });
      // The ceiling is applied here and only here, because this is the only way a bucket is
      // ever added — so the array cannot exceed it.
      if (this.buckets.length > MAX_BUCKETS) this.buckets.splice(0, this.buckets.length - MAX_BUCKETS);
      return;
    }
    for (let i = this.buckets.length - 1; i >= 0; i -= 1) {
      const bucket = this.buckets[i]!;
      if (bucket.at === minute) {
        bucket.total += 1;
        return;
      }
      if (bucket.at < minute) {
        this.buckets.splice(i + 1, 0, { at: minute, total: 1 });
        return;
      }
    }
    this.buckets.unshift({ at: minute, total: 1 });
  }

  /** Drops buckets older than the retention. Returns how many went. */
  prune(now: number = this.clock.now()): number {
    if (this.retainMs <= 0) return 0;
    const cutoff = now - this.retainMs;
    let expired = 0;
    while (expired < this.buckets.length && this.buckets[expired]!.at + MINUTE <= cutoff) expired += 1;
    if (expired > 0) this.buckets.splice(0, expired);
    return expired;
  }

  /**
   * How many incidents fell in a window, either end open.
   *
   * Counted at minute resolution, which is the honest precision: a bucket counts when any part
   * of it overlaps the window. For the windows this answers — an hour, a shift, "everything so
   * far" — a minute is far finer than the question.
   */
  count(from?: number, to?: number): number {
    let total = 0;
    for (const bucket of this.buckets) {
      if (from !== undefined && bucket.at + MINUTE <= from) continue;
      if (to !== undefined && bucket.at > to) continue;
      total += bucket.total;
    }
    return total;
  }

  /** The earliest instant these counts can speak for, or undefined when empty. */
  get oldest(): number | undefined {
    return this.buckets[0]?.at;
  }

  get total(): number {
    let sum = 0;
    for (const bucket of this.buckets) sum += bucket.total;
    return sum;
  }

  /** Everything a page needs for a window, pruned first so it never answers for a forgotten stretch. */
  snapshot(windowMs?: number, now: number = this.clock.now()): CountsSnapshot {
    this.prune(now);
    const from = windowMs === undefined || windowMs <= 0 ? undefined : now - windowMs;
    return {
      total: this.count(from, now),
      oldest: this.oldest,
      series: this.buckets.filter((bucket) => from === undefined || bucket.at + MINUTE > from).map((bucket) => ({ at: bucket.at, total: bucket.total })),
    };
  }

  /** For a chart, and anything else that wants the shape rather than the sum. */
  series(): ReadonlyArray<{ at: number; total: number }> {
    return this.buckets.map((bucket) => ({ at: bucket.at, total: bucket.total }));
  }

  clear(): void {
    this.buckets = [];
  }
}
