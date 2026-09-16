import { systemClock, type Clock } from "./internal/clock.js";
import { TtlLru } from "./internal/lru.js";

export interface RequestEvent {
  at: number;
  method: string;
  path: string;
  /**
   * `passed` marks a request middleware handed to the downstream app before anyone knew
   * whether the path exists. It counts toward request volume but not toward distinct
   * paths until `confirmPath()` promotes it. See `MiddlewareOptions.countOnlyMissedPaths`.
   */
  status: "flagged" | "seen" | "passed";
}

/**
 * Longest request path kept on an event. The path is attacker-chosen and attacker-sized
 * (up to the ~16 KB header limit), and it is the only unbounded field on the event, so
 * retaining it whole multiplied every stored event by three orders of magnitude. Only
 * `uniquePathsIn`/`countPathIn` read it, both by equality, so a prefix is enough: two
 * paths that agree for 512 characters are the same probe for detection purposes.
 */
export const MAX_PATH_CHARS = 512;

/**
 * Addresses remembered per fingerprint. `repeat-actor` asks "how many distinct addresses",
 * and its thresholds are single digits, so a saturated count changes no decision.
 */
export const MAX_IPS_PER_FINGERPRINT = 256;

/**
 * Default ceiling on events retained per IP. See `IpTracker.record`.
 *
 * Public, like the two caps above it, and for one reason: a detector threshold set higher
 * than the cap it counts against can never be reached, so the detector is switched off while
 * looking configured. That is the failure this refuses to ship — a control that looks set and
 * is not — so the config rejects such a threshold, and rejecting it means naming the number.
 */
export const DEFAULT_MAX_EVENTS = 4096;

/** Sliding-window activity history for a single IP, used by the stateful detectors. */
export class IpTracker {
  readonly ip: string;
  private events: RequestEvent[] = [];
  private readonly windowMs: number;
  private readonly maxEvents: number;
  private readonly clock: Clock;

  constructor(ip: string, windowMs: number, maxEvents = DEFAULT_MAX_EVENTS, clock: Clock = systemClock) {
    this.ip = ip;
    this.windowMs = windowMs;
    this.maxEvents = Math.max(1, maxEvents);
    this.clock = clock;
  }

  /**
   * Appends one request to this IP's window, bounded in both count and size.
   *
   * Neither bound existed. Every request appended an event holding the full
   * attacker-controlled path, and `prune()` only drops events that have aged out of the
   * window — so inside the window the array grew with the request rate, with no ceiling
   * at all. At a few thousand requests per second against a 60s window that is millions
   * of retained events, each carrying up to 16 KB of attacker-chosen path: gigabytes,
   * from one source, with no exploit. In practice `rate-spike` blocked such a flood
   * first, but that is a coincidence of the default detector set, not a defense — turn
   * `rate-spike` off, or raise its threshold, and nothing bounds this.
   *
   * The count cap is safe for detection because every consumer asks `count >= threshold`
   * and the cap sits far above any sane threshold (defaults top out at 60). Once an IP
   * is over `maxEvents` in the window it is already past every threshold it could trip,
   * so saturating the count changes no decision — it only stops us buying more evidence
   * for a verdict already reached.
   */
  record(event: Omit<RequestEvent, "at">, now = this.clock.now()): void {
    const path = event.path.length > MAX_PATH_CHARS ? event.path.slice(0, MAX_PATH_CHARS) : event.path;
    this.events.push({ ...event, path, at: now });
    this.prune(now);
    // Oldest-first: the newest activity is what every detector actually reasons about.
    if (this.events.length > this.maxEvents) this.events.splice(0, this.events.length - this.maxEvents);
  }

  private prune(now: number): void {
    const cutoff = now - this.windowMs;
    if (this.events.length > 0 && this.events[0]!.at >= cutoff) return;
    this.events = this.events.filter((event) => event.at >= cutoff);
  }

  recent(now = this.clock.now()): RequestEvent[] {
    this.prune(now);
    return this.events;
  }

  /**
   * The three window queries below are the engine's hottest read path: `rate-spike`,
   * `path-bruteforce` and `credential-bruteforce` each call one on **every** request,
   * against a window holding up to `maxEvents` (4096) events.
   *
   * Each used to `filter()` — and `uniquePathsIn` additionally `map()`ped — building one
   * or two throwaway arrays of up to 4096 entries per detector per request before
   * reading a single number off the result. Under exactly the flood these detectors
   * exist to catch, that is the allocation rate at its worst precisely when the process
   * can least afford it. Counting in place is the same logic with nothing retained.
   */
  countIn(ms: number, now = this.clock.now()): number {
    const cutoff = now - ms;
    const events = this.recent(now);
    let count = 0;
    for (const event of events) if (event.at >= cutoff) count += 1;
    return count;
  }

  /** Distinct paths in the window, not counting `passed` requests the app may have served. */
  uniquePathsIn(ms: number, now = this.clock.now()): number {
    const cutoff = now - ms;
    const paths = new Set<string>();
    for (const event of this.recent(now)) if (event.at >= cutoff && event.status !== "passed") paths.add(event.path);
    return paths.size;
  }

  /**
   * Promotes the newest `passed` request for `path` to a counted one, once it turned out
   * to be a probe: the app answered 404, or the honeypot answered it itself.
   */
  confirmPath(path: string): void {
    const key = path.length > MAX_PATH_CHARS ? path.slice(0, MAX_PATH_CHARS) : path;
    for (let i = this.events.length - 1; i >= 0; i -= 1) {
      const event = this.events[i]!;
      if (event.status === "passed" && event.path === key) {
        event.status = "seen";
        return;
      }
    }
  }

  countPathIn(path: string, ms: number, now = this.clock.now()): number {
    const cutoff = now - ms;
    let count = 0;
    for (const event of this.recent(now)) if (event.at >= cutoff && event.path === path) count += 1;
    return count;
  }
}

/** Registry of per-IP trackers. Evicts IPs that have gone quiet so memory stays bounded. */
export class ActivityRegistry {
  /**
   * Trackers, bounded and expiring together.
   *
   * A tracker whose window has aged out holds nothing any detector can read, so the
   * lifetime is the window itself and eviction is least-recently-used: under the flood this
   * cap exists for, every tracker is active and something has to go, and the one nobody has
   * touched longest is the cheapest to lose. Block state lives in the blocklist, never here,
   * so dropping a tracker never releases a block.
   */
  private readonly trackers: TtlLru<IpTracker>;
  private readonly windowMs: number;
  private readonly maxEventsPerIp: number;
  private readonly clock: Clock;

  constructor(windowMs = 60_000, maxTrackedIps = 10_000, maxEventsPerIp = 4096, clock: Clock = systemClock) {
    this.windowMs = windowMs;
    this.maxEventsPerIp = maxEventsPerIp;
    this.clock = clock;
    this.trackers = new TtlLru<IpTracker>(Math.max(1, maxTrackedIps), Math.max(1, windowMs), clock);
  }

  for(ip: string): IpTracker {
    return this.trackers.getOrCreate(ip, () => new IpTracker(ip, this.windowMs, this.maxEventsPerIp, this.clock));
  }

  get size(): number {
    return this.trackers.size;
  }
}

/**
 * Tracks which source IPs each **actor fingerprint** (see `computeFingerprint`) has
 * been seen from. Only *suspicious* requests are recorded (the engine writes here
 * when a hit fires), so a fingerprint accumulating many distinct IPs means one client
 * — same tool, same header order — attacking from a rotating set of addresses, which
 * a per-IP view can never see. Entries expire on a sliding window and the map is
 * capped, so memory stays bounded under a flood of unique fingerprints.
 */
export class FingerprintRegistry {
  /** One entry per fingerprint, holding when each address was last seen using it. */
  private readonly map: TtlLru<Map<string, number>>;
  private readonly windowMs: number;
  private readonly clock: Clock;

  constructor(windowMs = 3_600_000, maxTracked = 10_000, clock: Clock = systemClock) {
    this.windowMs = windowMs;
    this.clock = clock;
    this.map = new TtlLru<Map<string, number>>(Math.max(1, maxTracked), Math.max(1, windowMs), clock);
  }

  /** Record that `fp` was just seen from `ip` (call only for scored/suspicious requests). */
  record(fp: string, ip: string, now = this.clock.now()): void {
    const ips = this.map.getOrCreate(fp, () => new Map<string, number>());
    // Bounded per fingerprint too: the addresses are attacker-chosen, and a count that has
    // passed every threshold buys nothing by growing.
    if (!ips.has(ip) && ips.size >= MAX_IPS_PER_FINGERPRINT) {
      const oldest = ips.keys().next();
      if (!oldest.done) ips.delete(oldest.value);
    }
    ips.set(ip, now);
    // Re-inserted so the fingerprint's own lifetime restarts while it is still being used.
    this.map.set(fp, ips);
  }

  private freshIps(fp: string, ms: number, now: number): string[] {
    const ips = this.map.get(fp);
    if (!ips) return [];
    const cutoff = now - Math.min(ms, this.windowMs);
    const live: string[] = [];
    for (const [ip, at] of ips) {
      if (at >= cutoff) live.push(ip);
      else ips.delete(ip);
    }
    if (ips.size === 0) this.map.delete(fp);
    return live;
  }

  /** Distinct IPs this fingerprint has been seen from within the last `ms`. */
  distinctIpsWithin(fp: string, ms: number, now = this.clock.now()): number {
    return this.freshIps(fp, ms, now).length;
  }

  /** The distinct IPs this fingerprint has been seen from within the last `ms`. */
  ipsWithin(fp: string, ms: number, now = this.clock.now()): string[] {
    return this.freshIps(fp, ms, now);
  }

  get size(): number {
    return this.map.size;
  }
}
