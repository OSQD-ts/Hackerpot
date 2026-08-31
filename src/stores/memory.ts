import { ScoreLedger } from "./scores.js";
import { matchesQuery } from "./query.js";
import type { HitQuery, HitStore, HoneypotHit } from "../types.js";

export interface MemoryStoreOptions {
  /**
   * Cap on retained hits — the store keeps only the most recent `maxHits` (a ring
   * buffer). Without a bound, an attacker flooding distinct requests grows the array
   * without limit until the process OOMs. Default 10000. Per-IP scores are retained
   * separately (they're small) and still drive blocking.
   */
  maxHits?: number;
  /**
   * Cap on per-IP scores retained. Least-recently-updated are dropped past this, so an
   * IP under active attack is never the one evicted. Default 100000.
   */
  maxScoreEntries?: number;
}

/** Simple in-process hit store. Good for a single instance / development; use FileStore or RedisStore to persist across restarts or share across instances. */
export class MemoryStore implements HitStore {
  private hits: HoneypotHit[] = [];
  private readonly scores: ScoreLedger;
  private readonly maxHits: number;

  constructor(options: MemoryStoreOptions = {}) {
    this.maxHits = Math.max(1, options.maxHits ?? 10_000);
    this.scores = new ScoreLedger(options.maxScoreEntries ?? 100_000);
  }

  record(hit: HoneypotHit): void {
    this.hits.push(hit);
    // Bounded ring buffer: drop the oldest hit(s) once we exceed the cap, so a flood of
    // distinct requests can't grow memory without limit.
    if (this.hits.length > this.maxHits) this.hits.splice(0, this.hits.length - this.maxHits);
    this.scores.add(hit.ip, hit.score);
  }

  list(): HoneypotHit[] {
    return [...this.hits];
  }

  /**
   * Walks backwards from the newest hit and stops as soon as `limit` matches are
   * found, so a `?limit=10` read touches ten records rather than copying the whole
   * ring buffer (up to `maxHits`, 10 000 by default) and discarding almost all of it.
   */
  query(query: HitQuery): HoneypotHit[] {
    const limit = query.limit !== undefined && query.limit >= 0 ? query.limit : Infinity;
    const found: HoneypotHit[] = [];
    for (let i = this.hits.length - 1; i >= 0 && found.length < limit; i -= 1) {
      const hit = this.hits[i]!;
      if (matchesQuery(hit, query)) found.push(hit);
    }
    // Collected newest-first; `list()`'s contract is oldest-first.
    return found.reverse();
  }

  scoreFor(ip: string): number {
    return this.scores.get(ip);
  }
}
