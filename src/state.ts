export interface RequestEvent {
  at: number;
  method: string;
  path: string;
  status: "flagged" | "seen";
}

/**
 * Longest request path kept on an event. The path is attacker-chosen and attacker-sized
 * (up to the ~16 KB header limit), and it is the only unbounded field on the event, so
 * retaining it whole multiplied every stored event by three orders of magnitude. Only
 * `uniquePathsIn`/`countPathIn` read it, both by equality, so a prefix is enough: two
 * paths that agree for 512 characters are the same probe for detection purposes.
 */
const MAX_PATH_CHARS = 512;

/** Default ceiling on events retained per IP. See `IpTracker.record`. */
const DEFAULT_MAX_EVENTS = 4096;

/** Sliding-window activity history for a single IP, used by the stateful detectors. */
export class IpTracker {
  readonly ip: string;
  private events: RequestEvent[] = [];
  private readonly windowMs: number;
  private readonly maxEvents: number;

  constructor(ip: string, windowMs: number, maxEvents = DEFAULT_MAX_EVENTS) {
    this.ip = ip;
    this.windowMs = windowMs;
    this.maxEvents = Math.max(1, maxEvents);
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
  record(event: Omit<RequestEvent, "at">, now = Date.now()): void {
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

  recent(now = Date.now()): RequestEvent[] {
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
  countIn(ms: number, now = Date.now()): number {
    const cutoff = now - ms;
    const events = this.recent(now);
    let count = 0;
    for (const event of events) if (event.at >= cutoff) count += 1;
    return count;
  }

  uniquePathsIn(ms: number, now = Date.now()): number {
    const cutoff = now - ms;
    const paths = new Set<string>();
    for (const event of this.recent(now)) if (event.at >= cutoff) paths.add(event.path);
    return paths.size;
  }

  countPathIn(path: string, ms: number, now = Date.now()): number {
    const cutoff = now - ms;
    let count = 0;
    for (const event of this.recent(now)) if (event.at >= cutoff && event.path === path) count += 1;
    return count;
  }
}

/** Registry of per-IP trackers. Evicts IPs that have gone quiet so memory stays bounded. */
export class ActivityRegistry {
  private trackers = new Map<string, IpTracker>();
  private readonly windowMs: number;
  private readonly maxTrackedIps: number;
  private readonly maxEventsPerIp: number;

  constructor(windowMs = 60_000, maxTrackedIps = 10_000, maxEventsPerIp = 4096) {
    this.windowMs = windowMs;
    this.maxTrackedIps = maxTrackedIps;
    this.maxEventsPerIp = maxEventsPerIp;
  }

  for(ip: string): IpTracker {
    let tracker = this.trackers.get(ip);
    if (!tracker) {
      if (this.trackers.size >= this.maxTrackedIps) this.evict();
      tracker = new IpTracker(ip, this.windowMs, this.maxEventsPerIp);
      this.trackers.set(ip, tracker);
    }
    return tracker;
  }

  /**
   * Enforces `maxTrackedIps` as a HARD ceiling.
   *
   * Dropping only idle trackers was not a cap at all: under the very condition the cap
   * exists for — a flood of distinct source IPs inside the activity window — every
   * tracker is active, nothing is idle, so nothing was evicted and the map grew without
   * bound until the process died. One attacker can drive that directly whenever
   * `trustProxy` is on (each forged X-Forwarded-For mints a fresh tracker), and a
   * botnet or spoofed sources can drive it regardless.
   *
   * So: evict the idle first (free, and they are worth nothing), then, if that did not
   * get us under the ceiling, evict the least-recently-active until it does. Map
   * iteration is insertion-ordered, which for an "evict something" fallback is a fine
   * approximation of oldest-first. Block state lives in the Blocklist, not here, so
   * dropping a tracker never releases a block — only the sliding activity window it
   * accumulated, which is the cheapest thing to lose under memory pressure.
   */
  private evict(now = Date.now()): void {
    for (const [ip, tracker] of this.trackers) {
      if (tracker.recent(now).length === 0) this.trackers.delete(ip);
    }
    if (this.trackers.size < this.maxTrackedIps) return;
    // Still over the ceiling: every tracker is active. Shed the oldest until we fit,
    // leaving room for the caller's incoming IP.
    const target = Math.max(0, this.maxTrackedIps - 1);
    for (const ip of this.trackers.keys()) {
      if (this.trackers.size <= target) break;
      this.trackers.delete(ip);
    }
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
  private map = new Map<string, Map<string, number>>();
  private readonly windowMs: number;
  private readonly maxTracked: number;

  constructor(windowMs = 3_600_000, maxTracked = 10_000) {
    this.windowMs = windowMs;
    this.maxTracked = maxTracked;
  }

  /** Record that `fp` was just seen from `ip` (call only for scored/suspicious requests). */
  record(fp: string, ip: string, now = Date.now()): void {
    let ips = this.map.get(fp);
    if (!ips) {
      if (this.map.size >= this.maxTracked) this.evictIdle(now);
      ips = new Map<string, number>();
      this.map.set(fp, ips);
    }
    ips.set(ip, now);
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
  distinctIpsWithin(fp: string, ms: number, now = Date.now()): number {
    return this.freshIps(fp, ms, now).length;
  }

  /** The distinct IPs this fingerprint has been seen from within the last `ms`. */
  ipsWithin(fp: string, ms: number, now = Date.now()): string[] {
    return this.freshIps(fp, ms, now);
  }

  /**
   * Enforces `maxTracked` as a HARD ceiling — same reasoning as `ActivityRegistry.evict`.
   * Expiring only entries older than the (1 hour, by default) window is not a cap: a
   * flood of distinct fingerprints inside that window expires nothing, and since a
   * fingerprint is just a hash of header order + UA family, an attacker mints a fresh
   * one per request simply by varying header order. So expire first, then shed
   * oldest-first until we are actually under the ceiling.
   */
  private evictIdle(now: number): void {
    const cutoff = now - this.windowMs;
    for (const [fp, ips] of this.map) {
      for (const [ip, at] of ips) if (at < cutoff) ips.delete(ip);
      if (ips.size === 0) this.map.delete(fp);
    }
    if (this.map.size < this.maxTracked) return;
    const target = Math.max(0, this.maxTracked - 1);
    for (const fp of this.map.keys()) {
      if (this.map.size <= target) break;
      this.map.delete(fp);
    }
  }

  get size(): number {
    return this.map.size;
  }
}
