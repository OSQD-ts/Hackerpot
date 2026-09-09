import { Redis, type RedisOptions } from "ioredis";
import { applyQuery } from "./query.js";
import { usableScore } from "./scores.js";
import type { HitQuery, HitStore, HoneypotHit } from "../types.js";

export interface RedisStoreOptions {
  /** An existing ioredis client to reuse. If omitted, one is created from `redisOptions`. */
  client?: Redis;
  /** Connection options used to create a client when `client` is not given. */
  redisOptions?: RedisOptions;
  /** Namespace prefix for all keys. Default "hackerpot:". */
  keyPrefix?: string;
  /**
   * TTL (seconds) applied to each IP's score key, refreshed on every hit. This
   * makes suspicion decay for IPs that go quiet, and bounds key growth. Omit
   * for scores that never expire.
   */
  scoreTtlSeconds?: number;
  /** Cap the retained hit log to this many most-recent entries. Default 10000. */
  maxHits?: number;
}

/**
 * Redis-backed store for scores and the hit log, so suspicion is shared across
 * every honeypot instance pointing at the same Redis — essential when the
 * honeypot runs behind a load balancer or as several replicas, since an
 * attacker's requests may land on different instances.
 */
export class RedisStore implements HitStore {
  private readonly redis: Redis;
  private readonly ownsClient: boolean;
  private readonly prefix: string;
  private readonly scoreTtl: number | undefined;
  private readonly maxHits: number;

  constructor(options: RedisStoreOptions = {}) {
    // ioredis exposes many constructor overloads; narrow to the two shapes we use.
    const RedisCtor = Redis as unknown as { new (options: RedisOptions): Redis; new (): Redis };
    this.redis = options.client ?? (options.redisOptions ? new RedisCtor(options.redisOptions) : new RedisCtor());
    this.ownsClient = !options.client;
    this.prefix = options.keyPrefix ?? "hackerpot:";
    this.scoreTtl = options.scoreTtlSeconds;
    this.maxHits = options.maxHits ?? 10_000;
  }

  private scoreKey(ip: string): string {
    return `${this.prefix}score:${ip}`;
  }

  private get hitsKey(): string {
    return `${this.prefix}hits`;
  }

  async record(hit: HoneypotHit): Promise<void> {
    const scoreKey = this.scoreKey(hit.ip);
    const pipeline = this.redis.multi();
    pipeline.incrby(scoreKey, hit.score);
    if (this.scoreTtl !== undefined) pipeline.expire(scoreKey, this.scoreTtl);
    pipeline.rpush(this.hitsKey, JSON.stringify(hit));
    pipeline.ltrim(this.hitsKey, -this.maxHits, -1);
    await pipeline.exec();
  }

  /**
   * The retained hit log, skipping any entry that will not parse.
   *
   * This is the read path the whole management API sits on, and an unguarded
   * `JSON.parse` turned one damaged entry — a truncated write, a foreign writer to the
   * same key, a half-migrated prefix — into a permanent 500 on `/incidents`, `/stats`,
   * `/metrics`, `/ioc`, `/sessions` and `/actors`. The operator loses visibility into
   * an ongoing attack at exactly the moment they need it. The file store was already
   * hardened against precisely this; Redis was not.
   */
  async list(): Promise<HoneypotHit[]> {
    return this.parse(await this.redis.lrange(this.hitsKey, 0, -1));
  }

  /**
   * Redis holds the hit log as an opaque list of JSON strings, so it cannot filter
   * server-side — but it CAN slice. A plain `?limit=N` read therefore asks for only
   * the last N entries instead of transferring the whole retained log (up to
   * `maxHits`, 10 000 by default) to return a screenful.
   *
   * When a filter is present the candidates still have to be fetched and matched
   * here; the slice is skipped in that case, because trimming before filtering would
   * silently answer from the newest N *records* rather than the newest N *matches*.
   */
  async query(query: HitQuery): Promise<HoneypotHit[]> {
    const filtered = query.ip !== undefined || query.detector !== undefined || query.fingerprint !== undefined || query.sinceMs !== undefined;
    const raw =
      !filtered && query.limit !== undefined && query.limit >= 0
        ? await this.redis.lrange(this.hitsKey, -query.limit, -1)
        : await this.redis.lrange(this.hitsKey, 0, -1);
    return applyQuery(this.parse(raw), query);
  }

  /** Parse a batch of stored records, skipping any that will not parse. See `list()`. */
  private parse(raw: string[]): HoneypotHit[] {
    const hits: HoneypotHit[] = [];
    for (const line of raw) {
      try {
        hits.push(JSON.parse(line) as HoneypotHit);
      } catch {
        // A damaged record is not a reason to stop serving the intact ones.
      }
    }
    return hits;
  }

  async scoreFor(ip: string): Promise<number> {
    // Guarded: an unusable value here silently disables blocking for this IP rather
    // than degrading it — see `usableScore`.
    return usableScore(await this.redis.get(this.scoreKey(ip)));
  }

  /** Close the connection — only if this store created it. */
  async close(): Promise<void> {
    if (this.ownsClient) await this.redis.quit();
  }
}
