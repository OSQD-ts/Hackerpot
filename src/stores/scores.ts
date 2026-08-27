/**
 * Per-IP cumulative suspicion scores, bounded.
 *
 * Every store kept this as a plain `Map<string, number>` that only ever grew: one
 * permanent entry for each distinct source address ever seen, never expired, never
 * capped. A honeypot is internet-facing by design, so the entry count is "how many
 * hosts have touched us since boot" — unbounded on its own, and driven far faster by a
 * botnet, a spoofed-source flood, or (with `trustProxy` on) a single host minting
 * `X-Forwarded-For` values. Small per entry, but no ceiling is still no ceiling.
 *
 * Eviction is least-recently-*updated*, which is the policy that costs nothing where
 * it matters: `add()` refreshes an IP's recency on every hit, so an IP actively
 * attacking is never the one dropped. What ages out is a source that scored once and
 * left — and if it comes back it simply starts accruing again, then blocks on its own
 * merits. Durable stores keep the underlying records regardless (the file store's
 * archive, Redis, Elasticsearch), so an evicted score is a dropped cache entry, not
 * lost evidence.
 */
export class ScoreLedger {
  private readonly scores = new Map<string, number>();
  private readonly maxEntries: number;

  constructor(maxEntries = 100_000) {
    this.maxEntries = Math.max(1, maxEntries);
  }

  /** Adds `points` to `ip`'s running total and returns the new total. */
  add(ip: string, points: number): number {
    const total = (this.scores.get(ip) ?? 0) + points;
    // Delete before set so the entry moves to the end: Map iterates in insertion order,
    // which makes "first key" the least-recently-updated one.
    this.scores.delete(ip);
    if (this.scores.size >= this.maxEntries) this.evict();
    this.scores.set(ip, total);
    return total;
  }

  get(ip: string): number {
    return this.scores.get(ip) ?? 0;
  }

  get size(): number {
    return this.scores.size;
  }

  /** Current totals, for persisting across a restart. Bounded by `maxEntries`. */
  entries(): Record<string, number> {
    return Object.fromEntries(this.scores);
  }

  /** Adds persisted totals back in. Used to restore state the live log no longer holds. */
  seed(totals: Record<string, number>): void {
    for (const [ip, score] of Object.entries(totals)) {
      if (typeof score === "number" && Number.isFinite(score)) this.add(ip, score);
    }
  }

  private evict(): void {
    const target = Math.max(0, this.maxEntries - 1);
    for (const ip of this.scores.keys()) {
      if (this.scores.size <= target) break;
      this.scores.delete(ip);
    }
  }
}
