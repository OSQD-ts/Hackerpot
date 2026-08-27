import { ScoreLedger } from "./scores.js";
import type { HitStore, HoneypotHit } from "../types.js";

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

  scoreFor(ip: string): number {
    return this.scores.get(ip);
  }
}
