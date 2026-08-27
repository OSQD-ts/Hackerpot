import type { HitStore, HoneypotHit } from "../types.js";

/**
 * Fans every hit out to several stores at once, reading back from the first
 * (the primary). Typical use: keep a fast in-memory/Redis store as the primary
 * for scoring while also durably logging every hit to a FileStore.
 */
export class CompositeStore implements HitStore {
  private readonly stores: HitStore[];

  constructor(primary: HitStore, ...others: HitStore[]) {
    this.stores = [primary, ...others];
  }

  private get primary(): HitStore {
    return this.stores[0]!;
  }

  async record(hit: HoneypotHit): Promise<void> {
    await Promise.all(this.stores.map((store) => store.record(hit)));
  }

  list(): HoneypotHit[] | Promise<HoneypotHit[]> {
    return this.primary.list();
  }

  scoreFor(ip: string): number | Promise<number> {
    return this.primary.scoreFor(ip);
  }
}
