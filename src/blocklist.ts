import type { Redis } from "ioredis";

/**
 * Where "this IP is blocked until T" lives. The default is in-memory and
 * per-instance; swap in `RedisBlocklist` (opt-in) to make blocks survive a
 * restart and be shared across every replica pointing at the same Redis.
 */
export interface Blocklist {
  /** Block `ip` until the given epoch-ms timestamp (extends an existing block, never shortens it). */
  block(ip: string, untilEpochMs: number): void | Promise<void>;
  /** Whether `ip` is currently blocked. */
  isBlocked(ip: string, now?: number): boolean | Promise<boolean>;
  /** Count of currently-active blocks, if cheaply known (may be `undefined` when unknown, e.g. Redis) — used for the metrics gauge. */
  size?(): number | Promise<number> | undefined;
}

export interface MemoryBlocklistOptions {
  /**
   * Hard ceiling on tracked blocks. Expired entries are swept first; if that is not
   * enough, the soonest-to-expire live blocks are shed until we fit. Default 100000.
   */
  maxEntries?: number;
}

/** In-memory, per-instance blocklist. The default: simple, fast, lost on restart. */
export class MemoryBlocklist implements Blocklist {
  private readonly until = new Map<string, number>();
  private readonly maxEntries: number;

  constructor(options: MemoryBlocklistOptions = {}) {
    this.maxEntries = Math.max(1, options.maxEntries ?? 100_000);
  }

  block(ip: string, untilEpochMs: number): void {
    if (!this.until.has(ip) && this.until.size >= this.maxEntries) this.evict(Date.now());
    this.until.set(ip, Math.max(this.until.get(ip) ?? 0, untilEpochMs));
  }

  /**
   * Keeps the map bounded. This was the last unbounded per-IP map in the engine — the
   * activity registry, the fingerprint registry and the port-scan sentinel are all
   * capped, and each of them documents that "block state lives in the Blocklist", which
   * is precisely why this one had to hold it forever.
   *
   * An entry is only ever removed by `isBlocked()` re-checking that same IP after it
   * expired, so an attacker who is blocked once and never returns leaves a permanent
   * entry. Every distinct source that crosses the block threshold adds one, and blocking
   * is driven entirely by inbound traffic: a botnet, a spoofed-source flood, or (with
   * `trustProxy` on) one host minting `X-Forwarded-For` values grows this without limit
   * until the process dies. The honeypot is internet-facing by design, so this rises on
   * its own even without an attacker aiming at it.
   *
   * Sweep the expired first — they are free and worth nothing. If that still leaves us
   * at the ceiling, every remaining block is live, so shed the ones expiring soonest:
   * they protect us for the shortest remaining time, and losing a block is a graceful
   * degradation (the IP is re-detected and re-blocked on its next request) where an OOM
   * is not.
   */
  private evict(now: number): void {
    for (const [ip, until] of this.until) if (until <= now) this.until.delete(ip);
    if (this.until.size < this.maxEntries) return;
    const target = Math.max(0, this.maxEntries - 1);
    const soonestFirst = [...this.until.entries()].sort((a, b) => a[1] - b[1]);
    for (const [ip] of soonestFirst) {
      if (this.until.size <= target) break;
      this.until.delete(ip);
    }
  }

  isBlocked(ip: string, now = Date.now()): boolean {
    const until = this.until.get(ip);
    if (until === undefined) return false;
    if (until <= now) {
      this.until.delete(ip);
      return false;
    }
    return true;
  }

  /** Currently-*active* blocks. The map itself is capped separately (see `evict`). */
  size(now = Date.now()): number {
    let n = 0;
    for (const until of this.until.values()) if (until > now) n += 1;
    return n;
  }
}

/**
 * Reads across several blocklists, writes to one. `isBlocked` is true if ANY child
 * blocks the IP; `block()` writes only to the **primary** (first) child.
 *
 * This is the mechanism that keeps block *provenance* honest for threat-feed ingest.
 * Wire the engine with `new CompositeBlocklist(localEnforcing, feed)`: locally-observed
 * blocks flow through `block()` to the enforcing primary and reach the firewall (they're
 * first-hand evidence), while an IOC-ingest poller writes ingested IPs **directly into
 * the `feed` child** — so the honeypot short-circuits them, but they never trigger the
 * external enforcer. Hearsay from a feed can waste an attacker's time here; it must not
 * be able to add `iptables` rules on your host (a poisoned feed would become a
 * fleet-wide firewall amplifier). Escalation still works: once that IP actually attacks
 * you, a detector's `block()` hits the enforcing primary on its own merits.
 */
export class CompositeBlocklist implements Blocklist {
  private readonly children: Blocklist[];

  constructor(primary: Blocklist, ...rest: Blocklist[]) {
    this.children = [primary, ...rest];
  }

  async block(ip: string, untilEpochMs: number): Promise<void> {
    await this.children[0]!.block(ip, untilEpochMs);
  }

  async isBlocked(ip: string, now = Date.now()): Promise<boolean> {
    for (const child of this.children) {
      if (await child.isBlocked(ip, now)) return true;
    }
    return false;
  }

  size(): number | undefined {
    let total = 0;
    let anyKnown = false;
    for (const child of this.children) {
      const s = child.size?.();
      if (typeof s === "number") {
        total += s;
        anyKnown = true;
      }
    }
    return anyKnown ? total : undefined;
  }
}

export interface RedisBlocklistOptions {
  client: Redis;
  /** Key namespace. Default "hackerpot:block:". */
  keyPrefix?: string;
}

/**
 * Redis-backed blocklist (opt-in). Blocks are plain keys with a native TTL, so
 * expiry is handled by Redis and a block set on one instance is instantly
 * visible to all the others — the shared/persistent blocklist for multi-replica
 * or restart-prone deployments.
 */
export class RedisBlocklist implements Blocklist {
  private readonly redis: Redis;
  private readonly prefix: string;

  constructor(options: RedisBlocklistOptions) {
    this.redis = options.client;
    this.prefix = options.keyPrefix ?? "hackerpot:block:";
  }

  async block(ip: string, untilEpochMs: number): Promise<void> {
    const ms = untilEpochMs - Date.now();
    if (ms <= 0) return;
    // PX sets a millisecond TTL; a later, longer block extends it (NX would not).
    await this.redis.set(`${this.prefix}${ip}`, "1", "PX", ms);
  }

  async isBlocked(ip: string): Promise<boolean> {
    return (await this.redis.exists(`${this.prefix}${ip}`)) === 1;
  }
}
