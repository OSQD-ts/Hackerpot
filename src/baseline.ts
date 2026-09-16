import { systemClock, type Clock } from "./internal/clock.js";
import { TtlLru } from "./internal/lru.js";

/**
 * What this site actually serves, learned from what the application answered.
 *
 * Every other detector reasons from the request alone: this path looks like a WordPress
 * login, that header order is wrong, this address asked for fifteen things in ten seconds.
 * None of them know what *this* site is. So `/graphql` is a probe on a marketing page and an
 * ordinary request on an API, and a threshold that is right for one is wrong for the other —
 * which is why the volume detectors are the ones operators spend their first week tuning.
 *
 * The baseline closes that loop. The application already answers every request that is not a
 * probe, and its status code is the ground truth nobody was collecting: a 200 says this path
 * is real, a 404 says it is not. Fed back through `engine.reportOutcome()`, that turns
 * "unusual" from a guess into a measurement against the site's own path space.
 *
 * Three rules keep it honest:
 *
 * - **It learns only from outcomes, never from requests.** A path is known because the
 *   application served it, not because somebody asked for it. An attacker cannot teach the
 *   baseline that `/.env` is a real page by requesting it a thousand times.
 * - **It is inert until it knows something.** With no outcomes reported — standalone mode,
 *   or a fresh process — it answers "I have not seen enough" and every consumer stands down.
 *   A cold baseline must never be read as "nothing here is real, so everything is a probe".
 * - **It is bounded.** Paths are attacker-chosen, so they live in a capped, expiring cache
 *   and the addresses remembered per path are capped too.
 *
 * Adapted from bothandlerjs, where the same feedback loop is what lets a site-specific
 * baseline replace hand-tuned thresholds.
 */

/** One request the application (or the honeypot) has finished answering. */
export interface RequestOutcome {
  ip: string;
  path: string;
  /** The status the request was answered with. Below 400 is what makes a path *real*. */
  status: number;
  /**
   * True when the honeypot answered instead of the application. Such a request is counted as
   * a miss — the honeypot answers probes — but it can never mark a path as served, because
   * the honeypot's own decoy content says nothing about what the site has.
   */
  fromHoneypot?: boolean;
  at?: number;
}

export interface SiteBaselineOptions {
  /** Distinct paths remembered. Default 20000. */
  maxPaths?: number;
  /** How long a path is remembered after its last request. Default 24h. */
  ttlMs?: number;
  /** Addresses remembered per unserved path, for the distributed-walk signal. Default 64. */
  maxWalkersPerPath?: number;
  clock?: Clock;
}

/** What the baseline knows about one path. */
export interface PathStat {
  /** Times the application answered this path successfully. Above zero means it is real. */
  served: number;
  /** Times it was answered with 404/410, or by the honeypot. */
  missed: number;
  lastAt: number;
  /** Distinct addresses that have asked for it while it was never served. Capped. */
  walkers: Set<string>;
}

export interface BaselineSnapshot {
  /** Distinct paths remembered. */
  paths: number;
  /** Of those, how many the application has served. */
  servedPaths: number;
  /** Outcomes recorded since this baseline started. */
  observations: number;
  /** Share of outcomes that were misses — the site's own 404 rate. */
  missShare: number;
}

/** A path is attacker-sized; only equality is ever asked of it, so a prefix is enough. */
const MAX_PATH_CHARS = 512;

/**
 * How much the baseline must have seen before anything may read it.
 *
 * A baseline that has recorded four outcomes knows nothing, and "this path is not one of the
 * three I have seen" is true of every page on the site. These are the defaults a consumer
 * gets when it does not ask for stricter ones.
 */
export const DEFAULT_MIN_OBSERVATIONS = 500;
export const DEFAULT_MIN_SERVED_PATHS = 20;

export class SiteBaseline {
  private readonly paths: TtlLru<PathStat>;
  private readonly maxWalkersPerPath: number;
  private readonly clock: Clock;
  private observations = 0;
  private misses = 0;
  private servedPaths = 0;

  constructor(options: SiteBaselineOptions = {}) {
    this.clock = options.clock ?? systemClock;
    this.paths = new TtlLru<PathStat>(options.maxPaths ?? 20_000, options.ttlMs ?? 86_400_000, this.clock);
    this.maxWalkersPerPath = options.maxWalkersPerPath ?? 64;
  }

  /** Records what a request was answered with. The only way anything enters the baseline. */
  record(outcome: RequestOutcome): void {
    const at = outcome.at ?? this.clock.now();
    const path = outcome.path.length > MAX_PATH_CHARS ? outcome.path.slice(0, MAX_PATH_CHARS) : outcome.path;
    const served = outcome.fromHoneypot !== true && outcome.status < 400;
    const missed = outcome.status === 404 || outcome.status === 410 || outcome.fromHoneypot === true;
    // A redirect, a 500, a 401 — the application answered, but not in a way that says whether
    // the path exists. Those count toward nothing except the fact that traffic is flowing.
    this.observations += 1;
    if (missed) this.misses += 1;

    const stat = this.paths.getOrCreate(path, () => ({ served: 0, missed: 0, lastAt: at, walkers: new Set<string>() }));
    stat.lastAt = at;
    if (served) {
      if (stat.served === 0) this.servedPaths += 1;
      stat.served += 1;
      // It is a real page, so the addresses that asked for it are visitors, not walkers.
      if (stat.walkers.size > 0) stat.walkers.clear();
      return;
    }
    if (missed) {
      stat.missed += 1;
      // Only tracked while the path has never been served: this set answers "how many
      // different addresses are walking the same space that does not exist".
      if (stat.served === 0 && stat.walkers.size < this.maxWalkersPerPath) stat.walkers.add(outcome.ip);
    }
  }

  /** True when the application has answered this path successfully at least once. */
  isServed(path: string): boolean {
    const stat = this.paths.peek(this.key(path));
    return stat !== undefined && stat.served > 0;
  }

  /** What the baseline knows about a path: whether it is real, a known probe target, or new. */
  noveltyOf(path: string): "served" | "missed" | "unseen" {
    const stat = this.paths.peek(this.key(path));
    if (stat === undefined) return "unseen";
    return stat.served > 0 ? "served" : "missed";
  }

  /** Distinct addresses seen probing this never-served path. Capped; 0 for a real page. */
  walkers(path: string): number {
    const stat = this.paths.peek(this.key(path));
    return stat === undefined || stat.served > 0 ? 0 : stat.walkers.size;
  }

  /**
   * Whether the baseline has seen enough to be believed.
   *
   * Every consumer must ask this first. A cold baseline says "unseen" about the site's own
   * home page, and acting on that would flag real visitors on a freshly restarted process —
   * exactly the failure the volume detectors have been shaped over and over to avoid.
   */
  isWarm(minObservations = DEFAULT_MIN_OBSERVATIONS, minServedPaths = DEFAULT_MIN_SERVED_PATHS): boolean {
    return this.observations >= minObservations && this.servedPaths >= minServedPaths;
  }

  snapshot(): BaselineSnapshot {
    return {
      paths: this.paths.size,
      servedPaths: this.servedPaths,
      observations: this.observations,
      missShare: this.observations > 0 ? this.misses / this.observations : 0,
    };
  }

  /** Drops expired entries. Called by consumers that want the size to be current. */
  prune(): void {
    this.paths.prune();
    // `servedPaths` is a running count, so an expired real page would leave it too high
    // forever. Recount from what is actually left, which is cheap next to an eviction sweep.
    let served = 0;
    for (const stat of this.paths.values()) if (stat.served > 0) served += 1;
    this.servedPaths = served;
  }

  private key(path: string): string {
    return path.length > MAX_PATH_CHARS ? path.slice(0, MAX_PATH_CHARS) : path;
  }
}
