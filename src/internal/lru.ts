// Kept identical in hackerpot and bothandlerjs. Change both, or neither.

import { systemClock, type Clock } from "./clock.js";

interface Entry<V> {
  value: V;
  expiresAt: number;
}

/**
 * A map with a ceiling, a per-entry lifetime, and least-recently-used eviction.
 *
 * The ceiling is a security property rather than a nicety. Everything this library
 * remembers is keyed by something the client chooses — an address, a fingerprint, a path,
 * a header value — so a map without a bound is a remote out-of-memory waiting to be found.
 *
 * Capacity is enforced on every insert. Expiry is checked when an entry is read, plus a
 * bounded sweep on insert, so a process that goes quiet keeps no timer alive.
 */
export class TtlLru<V> {
  private readonly entries = new Map<string, Entry<V>>();

  constructor(
    readonly capacity: number,
    readonly ttlMs: number,
    private readonly clock: Clock = systemClock,
  ) {
    if (capacity < 1) throw new RangeError("a TtlLru needs a capacity of at least 1");
    // Zero is allowed and means remember nothing: a window a caller configured to 0.
    if (!(ttlMs >= 0)) throw new RangeError("a TtlLru needs a time to live of zero or more");
  }

  get size(): number {
    return this.entries.size;
  }

  get(key: string): V | undefined {
    const entry = this.entries.get(key);
    if (entry === undefined) return undefined;
    if (entry.expiresAt <= this.clock.now()) {
      this.entries.delete(key);
      return undefined;
    }
    // Re-inserted to move it to the end: Map keeps insertion order, so the first key is
    // always the least recently used.
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.value;
  }

  /** The value without counting as a use, for a caller that is only looking. */
  peek(key: string): V | undefined {
    const entry = this.entries.get(key);
    return entry !== undefined && entry.expiresAt > this.clock.now() ? entry.value : undefined;
  }

  set(key: string, value: V): void {
    const now = this.clock.now();
    this.entries.delete(key);
    this.entries.set(key, { value, expiresAt: now + this.ttlMs });
    if (this.entries.size > this.capacity) this.evict(now);
  }

  /** Reads, or creates with `factory` and stores. The read-modify-write every caller was writing by hand. */
  getOrCreate(key: string, factory: () => V): V {
    const existing = this.get(key);
    if (existing !== undefined) return existing;
    const created = factory();
    this.set(key, created);
    return created;
  }

  /** Refreshes an entry's lifetime without replacing its value; false when it is not there. */
  touch(key: string): boolean {
    const entry = this.entries.get(key);
    if (entry === undefined || entry.expiresAt <= this.clock.now()) return false;
    entry.expiresAt = this.clock.now() + this.ttlMs;
    this.entries.delete(key);
    this.entries.set(key, entry);
    return true;
  }

  delete(key: string): boolean {
    return this.entries.delete(key);
  }

  clear(): void {
    this.entries.clear();
  }

  /** Every live value, least recently used first. Expired entries are skipped, not deleted: a read must not evict. */
  values(): V[] {
    const now = this.clock.now();
    const live: V[] = [];
    for (const entry of this.entries.values()) if (entry.expiresAt > now) live.push(entry.value);
    return live;
  }

  /** Every live key and value, least recently used first. */
  entriesLive(): Array<[string, V]> {
    const now = this.clock.now();
    const live: Array<[string, V]> = [];
    for (const [key, entry] of this.entries) if (entry.expiresAt > now) live.push([key, entry.value]);
    return live;
  }

  /** Drops everything past its lifetime. Worth calling from a caller's own timer; never required. */
  prune(): number {
    const now = this.clock.now();
    let removed = 0;
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) {
        this.entries.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  private evict(now: number): void {
    // Reclaiming dead space beats evicting a live entry, but a full scan on every insert
    // would make inserts linear, so the sweep is bounded and the ceiling below is what holds.
    let scanned = 0;
    for (const [key, entry] of this.entries) {
      if (scanned++ >= 32) break;
      if (entry.expiresAt <= now) this.entries.delete(key);
    }
    while (this.entries.size > this.capacity) {
      const oldest = this.entries.keys().next();
      if (oldest.done === true) break;
      this.entries.delete(oldest.value);
    }
  }
}
