import { randomUUID } from "node:crypto";
import net from "node:net";
import type { IncomingHttpHeaders } from "node:http";
import { IpAllowlist } from "./allowlist.js";
import { MemoryBlocklist, type Blocklist } from "./blocklist.js";
import { defaultDetectors } from "./detectors/index.js";
import type { Detection, DetectionContext, Detector, RequestFacts } from "./detectors/types.js";
import { upgradeDetection } from "./detectors/legacy.js";
import type { LegacyDetection } from "./detectors/legacy.js";
import { SiteProfile } from "./site/index.js";
import type { ActorLabels } from "./labels.js";
import type { MarkerCookie } from "./marker.js";
import type { RequestOutcome } from "./site/index.js";
import { defaultResponseActions } from "./actions/index.js";
import { ladderPolicy } from "./policy/index.js";
import type { ResponseAction } from "./actions/types.js";
import type { PolicyContext, ResponseDecision, ResponsePolicy } from "./policy/types.js";
import { computeFingerprint } from "./fingerprint.js";
import { confidenceOf } from "./evidence.js";
import { DURATION_BUCKETS_MS, Histogram } from "./internal/histogram.js";
import type { HistogramSnapshot } from "./internal/histogram.js";
import { MAX_RAW_PATH_CHARS, boundedQuery, normalizePath } from "./internal/http.js";
import { normalizeAddress, stripPort } from "./internal/ip.js";
import { pathMatches, statelessPattern } from "./internal/pattern.js";
import { withDeadline } from "./internal/async.js";
import { systemClock, type Clock } from "./internal/clock.js";
import { Emitter } from "./internal/emitter.js";
import { defaultIpEnricher, type IpEnricher } from "./enrichment.js";
import { ActivityRegistry, FingerprintRegistry, IpTracker } from "./state.js";
import { MemoryStore } from "./stores/index.js";
import { ServiceTokens, type ServiceTokenOptions } from "./service-tokens.js";
import type { TrafficAudit } from "./audit.js";
import type { HitStore, HoneypotConfig, HoneypotHit, ProxyConfig, ShadowEvent } from "./types.js";

/**
 * Which of `evaluate()`'s once-per-request side effects to perform.
 *
 * Evaluation is not pure: it appends the request to the IP's sliding activity
 * window, and — when something fires — writes a hit to the store, announces it to
 * `onHit`, and remembers the actor fingerprint. Every one of those must happen
 * **exactly once per request**, which stops being automatic the moment a caller
 * evaluates the same request twice.
 *
 * The middleware does exactly that: it evaluates on headers alone, and only if
 * something fires does it read the body and evaluate again. With both passes
 * committing, one probe against a decoy path became two stored incidents, two
 * `onHit` alerts, two entries in the activity window (inflating `rate-spike` and
 * `path-bruteforce` counts), and **double the score** — so an attacker crossed the
 * block threshold at half the evidence, and the incident log double-counted them.
 *
 * So the two side-effect groups are separable: the first pass counts the activity
 * and defers the hit; the second pass commits the hit and does not re-count.
 */
export interface EvaluateOptions {
  /** Append this request to the IP's sliding activity window. Default true. */
  trackActivity?: boolean;
  /** Record the hit in the store, enrich it, and announce it via `onHit`. Default true. */
  recordHit?: boolean;
  /**
   * How the tracked request is marked. Default `seen`, which counts toward every
   * volume detector. Middleware passes `passed` so a path the app serves normally
   * does not count as enumeration. See `MiddlewareOptions.countOnlyMissedPaths`.
   */
  activityStatus?: "seen" | "passed";
  /**
   * Refuse to let the policy choose `block` unless a detection is proof (`certain`). The
   * request gets `unprovenBlockFallback` instead and the hit records `downgradedFrom`.
   * Default false; middleware turns it on. See `MiddlewareOptions.blockRequiresProof`.
   */
  blockRequiresProof?: boolean;
  /** Action id run instead of an unproven block. Default "tarpit". */
  unprovenBlockFallback?: string;
  /**
   * When the request happened. Default: now. A log replay passes each line's own time, so
   * the sliding windows see traffic spread the way it arrived rather than all at once.
   */
  now?: Date;
  /**
   * Count this request in the configured `TrafficAudit`. Default true. A front end that
   * evaluates a request a second time outside the usual two passes (`trapFormGuard`)
   * passes false, so the audit counts it once.
   */
  audit?: boolean;
}

export interface EvaluationResult {
  detections: Detection[];
  score: number;
  totalScore: number;
  tracker: IpTracker;
  actionId: string;
  action: ResponseAction | undefined;
  /** The request's actor fingerprint (header order + UA family). See `computeFingerprint`. */
  fingerprint: string;
  /**
   * The normalised path detection matched against. Front ends use this instead of
   * normalising again: decoding twice would turn `%252e` into `.`.
   */
  path: string;
  /** Set to `"block"` when the policy chose a block that `blockRequiresProof` refused. */
  downgradedFrom?: string;
  /** Id of the policy rule that chose the response. `"default"` for the shipped ladder. */
  rule?: string;
  /** One sentence saying why this response was chosen, safe to log and to show an operator. */
  reason?: string;
  /** The verified marker this client presented, when markers are configured. */
  marker?: string;
  /**
   * How strongly this request's evidence supports acting, in [0, 1] — see `confidenceOf`.
   * Suspicion alone is capped below 1; only proof reaches it. Scores are unaffected.
   */
  confidence: number;
  /** Findings from shadowed detectors: reported, never acted on. See `HoneypotConfig.shadowDetectors`. */
  shadowDetections: Detection[];
  /** The name of the service token that exempted this request, if one did. */
  serviceToken?: string;
}

/** True for a promise, or any other thenable a detector hands back. */
function isThenable<T>(value: T | PromiseLike<T>): value is PromiseLike<T> {
  return typeof (value as { then?: unknown } | null | undefined)?.then === "function";
}

/**
 * Sum of detection scores, counting each family once at its highest score.
 *
 * One act often shows through several detectors (an encoded traversal is both a
 * traversal payload and an evasively spelled target), and adding those up scored one
 * request as independent reasons. A detection with no family counts on its own.
 */
function combinedScore(detections: Detection[]): number {
  let total = 0;
  const best = new Map<string, number>();
  for (const detection of detections) {
    if (detection.family === undefined) total += detection.score;
    else best.set(detection.family, Math.max(best.get(detection.family) ?? 0, detection.score));
  }
  for (const score of best.values()) total += score;
  return total;
}

/** Why a request was exempted from detection. */
export type BypassReason = "allowlist" | "service-token" | "ignored-path";

/** Who made a runtime change, carried into the event and the notice it raises. */
export interface ChangeContext {
  /** A person or a process: an operator's name, "SIGHUP", "dashboard". */
  by?: string;
}

/** One part of the engine replaced at runtime. */
export interface ChangeEvent {
  /** What was replaced: "detectors", "responses", "policy", "allowlist", "shadow-detectors", "service-tokens". */
  part: string;
  /** A sentence an operator can read, e.g. "24 detectors installed". */
  summary: string;
  by?: string | undefined;
}

/** Something an operator should know that is not an error: a change, a risky setting, a degraded component. */
export interface Notice {
  timestamp: string;
  message: string;
  /** Present when the notice came from a runtime change. */
  change?: ChangeEvent | undefined;
}

/**
 * What the engine announces.
 *
 * `onHit`, `onError` and `onShadow` stay what they are: the one handler a deployment
 * configures when it builds the engine. These are for everything attached afterwards — a
 * dashboard, a SIEM sink, an operator's own logging — where several consumers want the same
 * facts and none of them should be able to take a request down by throwing.
 */
export interface HoneypotEngineEvents extends Record<string, unknown> {
  hit: HoneypotHit;
  shadow: ShadowEvent;
  error: { error: unknown; source: string };
  warning: Notice;
  change: ChangeEvent;
  outcome: RequestOutcome;
}

/** Notices kept for the dashboard and `notices()`. Small: this is a recent-history panel, not a log. */
const MAX_NOTICES = 200;

function toServiceTokens(value: ServiceTokenOptions | ServiceTokens | undefined): ServiceTokens | undefined {
  if (value === undefined) return undefined;
  const tokens = value instanceof ServiceTokens ? value : new ServiceTokens(value);
  return tokens.size > 0 ? tokens : undefined;
}

export class HoneypotEngine {
  // Swappable at runtime via reconfigure() — read live on every request (never cached
  // by callers), so a hot-reload takes effect on the next request with no restart.
  detectors: Detector[];
  actions: Map<string, ResponseAction>;
  policy: ResponsePolicy;
  /** Ids of detectors whose findings are reported but never acted on. See `HoneypotConfig.shadowDetectors`. */
  shadowed: Set<string>;
  // Live state — deliberately NOT reconfigurable: rebuilding these would drop the
  // suspicion scores, block list, and activity windows an attacker has accrued.
  readonly store: HitStore;
  readonly registry: ActivityRegistry;
  readonly fingerprints: FingerprintRegistry;
  allowlist: IpAllowlist;
  readonly blocklist: Blocklist;
  private readonly enricher: IpEnricher | undefined;
  private readonly onHit: ((hit: HoneypotHit) => void | Promise<void>) | undefined;
  private readonly onError: ((error: unknown, context: { source: string }) => void) | undefined;
  /** The proxy settings, resolved and validated once. See `ProxyConfig` and `resolveIp`. */
  private readonly proxy: ResolvedProxy;
  /** `ignorePaths` strings without a trailing slash: exact paths, looked up in one step. */
  private readonly ignoreExact: Set<string>;
  /** `ignorePaths` prefixes (strings ending in `/`) and regexes, tested in order. */
  private readonly ignorePatterns: readonly (string | RegExp)[];
  private readonly detectorTimeoutMs: number;
  private readonly onShadow: ((event: ShadowEvent) => void) | undefined;
  /** Accepted service tokens. Replaced by `reconfigure`. See `HoneypotConfig.serviceTokens`. */
  serviceTokens: ServiceTokens | undefined;
  readonly audit: TrafficAudit | undefined;
  /**
   * What this site actually serves, learned from `reportOutcome()`. Always present unless
   * disabled with `site: null`, and empty — so every consumer stands down — until
   * outcomes are reported, which happens in middleware mode.
   */
  readonly site: SiteProfile | undefined;

  /** @deprecated Renamed `site`. */
  get baseline(): SiteProfile | undefined {
    return this.site;
  }
  /**
   * Names for sources you already know. Labels never exempt anybody — a labelled actor is
   * detected, scored and answered exactly as it would be otherwise. See `ActorLabels`.
   */
  labels: ActorLabels | undefined;
  /**
   * The marker handed to whoever probes, for correlating one client across addresses. Only
   * ever issued on the honeypot's own responses; see `MarkerCookie`.
   */
  readonly markers: MarkerCookie | undefined;
  /**
   * Failures and timeouts per detector id since the engine started, for `/metrics`. Bounded
   * by the number of detectors, since only detector ids are counted.
   */
  readonly detectorFailures = new Map<string, number>();
  /**
   * Requests exempted from detection, by reason. Both reasons start at zero, so a scrape has a
   * series for each from the first request rather than only after the first exemption.
   */
  readonly bypassed = new Map<string, number>([["allowlist", 0], ["service-token", 0], ["ignored-path", 0]]);
  /**
   * Time spent evaluating a request. Measured with a monotonic high-resolution timer rather than
   * `clock`: that clock models wall time for the activity windows at millisecond resolution,
   * and detection is usually well under a millisecond, so it would put every sample at zero.
   */
  private readonly evaluationDuration = new Histogram(DURATION_BUCKETS_MS);
  /**
   * Where every window in this engine reads "now": the activity window, the fingerprint
   * registry, the default blocklist's expiry, and the timestamp on a recorded hit. Injecting
   * it is what lets a test assert "forgotten after an hour" without waiting an hour.
   */
  readonly clock: Clock;
  /**
   * Everything the engine announces. Listeners are isolated: one that throws is reported on
   * the error channel and the rest still hear the event.
   */
  private readonly events = new Emitter<HoneypotEngineEvents>((error, event) => this.onError?.(error, { source: `listener:${event}` }));
  /** Recent notices, newest last. Bounded, because this is a panel rather than a log. */
  private readonly recentNotices: Notice[] = [];

  constructor(config: HoneypotConfig = {}) {
    this.clock = config.clock ?? systemClock;
    this.detectors = config.detectors ?? [...defaultDetectors(), ...(config.extraDetectors ?? [])];
    const actions = config.responseActions ?? [...defaultResponseActions(), ...(config.extraResponseActions ?? [])];
    this.actions = new Map(actions.map((action) => [action.id, action]));
    this.policy = config.policy ?? ladderPolicy();
    this.store = config.store ?? new MemoryStore();
    this.registry = new ActivityRegistry(config.activityWindowMs ?? 60_000, undefined, undefined, this.clock);
    this.fingerprints = new FingerprintRegistry(config.fingerprintWindowMs ?? 3_600_000, undefined, this.clock);
    this.allowlist = new IpAllowlist(config.allowlist ?? []);
    this.blocklist = config.blocklist ?? new MemoryBlocklist({ clock: this.clock });
    // null disables; undefined gets the dependency-free default classifier.
    this.enricher = config.enricher === null ? undefined : config.enricher ?? defaultIpEnricher();
    this.onHit = config.onHit;
    this.onError = config.onError;
    this.proxy = resolveProxy(config.proxy ?? (config.trustProxy !== undefined ? { trustProxy: config.trustProxy } : {}));
    const ignorePaths = (config.ignorePaths ?? []).map(statelessPattern);
    for (const entry of ignorePaths) {
      if (typeof entry === "string" && !entry.startsWith("/")) {
        throw new Error(`ignorePaths entry "${entry}" does not start with "/", so it can never match a path and would exempt nothing`);
      }
    }
    this.ignoreExact = new Set(ignorePaths.filter((entry): entry is string => typeof entry === "string" && !entry.endsWith("/")));
    this.ignorePatterns = ignorePaths.filter((entry) => typeof entry !== "string" || entry.endsWith("/"));
    this.detectorTimeoutMs = config.detectorTimeoutMs ?? 2000;
    this.shadowed = new Set(config.shadowDetectors ?? []);
    this.onShadow = config.onShadow;
    this.serviceTokens = toServiceTokens(config.serviceTokens);
    this.audit = config.audit;
    const site = config.site !== undefined ? config.site : config.baseline;
    this.site = site === null ? undefined : (site ?? new SiteProfile({ clock: this.clock }));
    this.labels = config.labels;
    this.markers = config.markers;
  }

  /**
   * Reports what a request was finally answered with.
   *
   * This is the honeypot's one piece of ground truth about the site it is protecting: the
   * application knows which paths are real, and its status codes say so. The middleware calls
   * this on every request it lets through; call it yourself if you dispatch some other way.
   * Cheap, synchronous, and safe to call for traffic nothing flagged.
   */
  reportOutcome(outcome: RequestOutcome): void {
    try {
      this.site?.record(outcome);
    } catch (err) {
      // The baseline is bookkeeping. A failure here must never reach the request that was
      // merely reporting its own status.
      this.reportError(err, { source: "baseline" });
    }
    this.events.emit("outcome", outcome);
  }

  /**
   * Hot-swaps the parts of the engine that are safe to change without dropping live
   * state — detectors, response actions, the policy, and the allowlist — in place, so
   * a config reload takes effect on the next request without a restart and without
   * losing accrued scores, blocks, or activity windows. Only the fields you pass are
   * replaced. What is deliberately NOT here — the store, blocklist, and listeners —
   * can't be rebound without dropping state or connections; a reload must refuse those
   * rather than silently ignore them.
   */
  reconfigure(
    patch: {
      detectors?: Detector[];
      responseActions?: ResponseAction[];
      policy?: ResponsePolicy;
      allowlist?: string[];
      shadowDetectors?: string[];
      serviceTokens?: ServiceTokenOptions | ServiceTokens;
    },
    context: ChangeContext = {},
  ): ChangeEvent[] {
    const changes: ChangeEvent[] = [];
    const changed = (part: string, summary: string): void => {
      const event: ChangeEvent = { part, summary, by: context.by };
      changes.push(event);
      // The notice and the event carry the same sentence: an audit trail that can say a rule
      // set was replaced but not by whom is half of one.
      this.warn(`${summary}${context.by === undefined ? "" : ` (by ${context.by})`}`, event);
      this.events.emit("change", event);
    };

    if (patch.detectors) {
      this.detectors = patch.detectors;
      changed("detectors", `${patch.detectors.length} detector(s) installed`);
    }
    if (patch.responseActions) {
      this.actions = new Map(patch.responseActions.map((a) => [a.id, a]));
      changed("responses", `${this.actions.size} response action(s) registered`);
    }
    if (patch.policy) {
      this.policy = patch.policy;
      changed("policy", "the response policy was replaced");
    }
    if (patch.allowlist) {
      this.allowlist = new IpAllowlist(patch.allowlist);
      changed("allowlist", `allowlist replaced: ${this.allowlist.size} entr${this.allowlist.size === 1 ? "y" : "ies"}`);
      // An entry that cannot be matched exempts nobody, and the symptom is silence.
      if (this.allowlist.invalid.length > 0) this.warn(`allowlist entries that match nothing: ${this.allowlist.invalid.join(", ")}`);
    }
    if (patch.shadowDetectors) {
      this.shadowed = new Set(patch.shadowDetectors);
      changed("shadow-detectors", this.shadowed.size === 0 ? "no detectors are shadowed" : `shadowed: ${[...this.shadowed].join(", ")}`);
    }
    if (patch.serviceTokens) {
      this.serviceTokens = toServiceTokens(patch.serviceTokens);
      const weak = this.serviceTokens?.weak ?? [];
      changed("service-tokens", `${this.serviceTokens?.size ?? 0} service token(s) accepted`);
      if (weak.length > 0) this.warn(`service tokens short enough to guess: ${weak.join(", ")}`);
    }
    return changes;
  }

  /**
   * Whether this request is exempt from detection, and why — counted.
   *
   * For the front end that decides it: the middleware and the standalone server call this once
   * per request, before evaluating anything. `isAllowlisted` and `serviceTokenFor` stay pure,
   * because they are also asked on a second pass over the same request (`trapFormGuard`) and
   * repeatedly within one protocol session, where counting would report one exemption many times.
   */
  exempt(ip: string, headers: Readonly<Record<string, string | string[] | undefined>>): BypassReason | undefined {
    const reason: BypassReason | undefined = this.allowlist.allows(ip) ? "allowlist" : this.serviceTokens?.identify(headers) !== undefined ? "service-token" : undefined;
    if (reason !== undefined) this.countBypass(reason);
    return reason;
  }

  /** What the engine counts that no incident carries, for `/metrics`. */
  counters(): { detectorFailures: Map<string, number>; bypassed: Map<string, number>; evaluationDuration: HistogramSnapshot } {
    return { detectorFailures: this.detectorFailures, bypassed: this.bypassed, evaluationDuration: this.evaluationDuration.snapshot() };
  }

  private countBypass(reason: BypassReason): void {
    this.bypassed.set(reason, (this.bypassed.get(reason) ?? 0) + 1);
  }

  /** The name of the valid service token these headers present, or undefined. */
  serviceTokenFor(headers: Readonly<Record<string, string | string[] | undefined>>): string | undefined {
    return this.serviceTokens?.identify(headers);
  }

  /** True when this IP is exempt from all detection (an allowlisted known-good source). */
  isAllowlisted(ip: string): boolean {
    return this.allowlist.allows(ip);
  }

  /** Whether this IP is currently blocked (checks the configured blocklist). */
  isBlocked(ip: string): boolean | Promise<boolean> {
    return this.blocklist.isBlocked(ip);
  }

  /**
   * Reports a failure on the engine's error channel. Exposed so the response layer can
   * surface a side effect that failed (see `blockAction`) on the same channel the
   * engine already uses for the store, the enricher and `onHit`.
   */
  reportError(error: unknown, context: { source: string }): void {
    this.onError?.(error, context);
    this.events.emit("error", { error, source: context.source });
  }

  /** True if this detector set has any detector that inspects the request body. */
  get needsBodyPhase(): boolean {
    return this.detectors.some((detector) => detector.needsBody);
  }

  /**
   * Resolves the client IP. Adapted from bothandlerjs (`resolveClientIp`); see `ProxyConfig`.
   *
   * With `trustProxy` off (the default) this is the socket address and the forwarded header
   * is never read. With it on, the header is believed only on behalf of a peer that put it
   * there: with `trustedProxies`, the connecting peer must itself be one of them and the
   * chain is walked from the right past them; without, the `hops`-th address from the right
   * is taken, and a chain shorter than that falls back to the socket address.
   *
   * Every entry is validated as a real IP before it can be chosen. That string is what the
   * allowlist, the blocklist, the per-IP registry, the store and the firewall enforcer all
   * key on, so a non-address would let an attacker mint unbounded distinct "IPs" or collide
   * every source into one bucket. An earlier version took the LEFTMOST entry, which the
   * client writes; the rightmost entries are the ones your own proxies append.
   */
  resolveIp(remoteAddress: string | undefined, headers: IncomingHttpHeaders): string {
    const direct = remoteAddress === undefined ? "unknown" : canonicalAddress(remoteAddress) ?? remoteAddress;
    const proxy = this.proxy;
    if (!proxy.trustProxy) return direct;

    const raw = headers[proxy.header];
    const header = Array.isArray(raw) ? raw.join(",") : raw;
    if (header === undefined) return direct;

    // Bounded: the chain is client-supplied and would otherwise be an unbounded split.
    const chain: string[] = [];
    for (const entry of header.slice(0, 2048).split(",")) {
      const address = canonicalAddress(entry);
      if (address !== undefined) chain.push(address);
    }
    if (chain.length === 0) return direct;

    if (proxy.trustedProxies) {
      // The peer we are actually talking to is the first hop, and it is checked like any
      // other. Without this a request that reached this server WITHOUT passing through the
      // configured proxies — a leaked origin address, a port reachable inside the network —
      // is believed when it claims to come from somewhere else.
      if (remoteAddress !== undefined && !proxy.trustedProxies.allows(direct)) return direct;
      // Walk right to left past our own infrastructure. The first address that is not ours
      // is the closest one we did not put there — the furthest we can trust.
      for (let i = chain.length - 1; i >= 0; i--) {
        const candidate = chain[i]!;
        if (!proxy.trustedProxies.allows(candidate)) return candidate;
      }
      // Everything in the chain is our own proxies; the socket address is the truth.
      return direct;
    }

    // A chain shorter than the number of proxies we expect did not traverse the topology
    // this server was configured for, and every entry in it is client-controlled.
    const index = chain.length - proxy.hops;
    if (index < 0) return direct;
    return chain[index] ?? direct;
  }

  /**
   * Whether a path is one of `ignorePaths` — counted, like `exempt`. The front ends ask this
   * first, before the allowlist and the block check: an ignored path costs nothing, which is
   * the point of ignoring a health check. Matched on the normalised path.
   */
  ignores(path: string): boolean {
    const ignored = this.isIgnoredPath(path);
    if (ignored) this.countBypass("ignored-path");
    return ignored;
  }

  /** Whether a path is one of `ignorePaths`, uncounted — for a second look at the same request. */
  isIgnoredPath(path: string): boolean {
    if (this.ignoreExact.size === 0 && this.ignorePatterns.length === 0) return false;
    const normalised = normalizePath(path);
    return this.ignoreExact.has(normalised) || pathMatches(this.ignorePatterns, normalised);
  }

  trackerFor(ip: string): IpTracker {
    return this.registry.for(ip);
  }

  /**
   * Runs every detector over the request and, if any fired, records a hit and
   * resolves which response action should run. `body` is only inspected when
   * provided (the body phase) — callers omit it on the first pass so a
   * downstream app never has its request stream consumed unnecessarily.
   */
  async evaluate(input: RequestFacts, options: EvaluateOptions = {}): Promise<EvaluationResult> {
    // Normalised exactly once, here, for every front end. See `normalizePath`.
    const path = normalizePath(input.path);
    const rawPath = input.rawPath ?? (path !== input.path ? input.path.slice(0, MAX_RAW_PATH_CHARS) : undefined);
    // Bounded here too, so no front end can hand every detector an unbounded query. See `boundedQuery`.
    const { query, dropped } = boundedQuery(input.query);
    const facts: RequestFacts = {
      ...input,
      path,
      query,
      ...(rawPath !== undefined ? { rawPath } : {}),
      ...(dropped > 0 ? { queryParamsDropped: dropped } : {}),
    };

    const trackActivity = options.trackActivity ?? true;
    const recordHit = options.recordHit ?? true;
    const tracker = this.registry.for(facts.ip);
    const fingerprint = computeFingerprint(facts);
    // A marker we did not sign reads as no marker at all — a forgery must not become an actor.
    const marker = this.markers?.read(facts.headers);

    // Allowlisted sources are fully exempt: no detection, no scoring, no footprint.
    if (this.allowlist.allows(facts.ip)) {
      // Counted on a real pass only: a caller evaluating directly reaches this branch, while the
      // middleware and the standalone server have already counted it through `exempt()`.
      if (options.audit !== false) this.countBypass("allowlist");
      return { detections: [], score: 0, totalScore: 0, tracker, actionId: "", action: undefined, fingerprint, path, shadowDetections: [], confidence: 0 };
    }
    // So is a request presenting one of your service tokens, whatever its address.
    const serviceToken = this.serviceTokens?.identify(facts.headers);
    if (serviceToken !== undefined) {
      if (options.audit !== false) this.countBypass("service-token");
      return { detections: [], score: 0, totalScore: 0, tracker, actionId: "", action: undefined, fingerprint, path, shadowDetections: [], confidence: 0, serviceToken };
    }

    // Timed from here: an exempt request ran no detection, so it has no detection time to report.
    // `audit: false` marks an evaluation that is not traffic — the dashboard's dry run, or a second
    // pass over a request already counted — and those are not timed either.
    const started = performance.now();
    const measured = options.audit !== false;
    const now = options.now ?? new Date(this.clock.now());
    if (trackActivity) tracker.record({ method: facts.method, path: facts.path, status: options.activityStatus ?? "seen" }, now.getTime());

    const ctx: DetectionContext = { ...facts, tracker, timestamp: now, fingerprint, fingerprintRegistry: this.fingerprints, ...(this.site !== undefined ? { site: this.site, baseline: this.site } : {}), ...(marker !== undefined ? { marker } : {}) };
    const detections: Detection[] = [];
    const shadowDetections: Detection[] = [];
    const failed: string[] = [];
    for (const detector of this.detectors) {
      let detection: Detection | LegacyDetection | undefined;
      try {
        // Typed as the current shape; a detector written against the old names returns the old
        // one at run time, which `upgradeDetection` below turns into this.
        const pending = detector.inspect(ctx) as Detection | LegacyDetection | undefined | Promise<Detection | LegacyDetection | undefined>;
        // Only an asynchronous result gets a deadline; synchronous detectors pay nothing.
        detection =
          isThenable(pending) && this.detectorTimeoutMs > 0
            ? await withDeadline(pending, this.detectorTimeoutMs, `detector "${detector.id}"`)
            : await pending;
      } catch (err) {
        // A detector must never throw; if one does (crafted input, a latent bug), isolate
        // it — skip only this detector — so an attacker can't crash evaluation or bypass
        // every other detector by feeding one a poison input. The rest still run.
        this.reportError(err, { source: detector.id });
        failed.push(detector.id);
        continue;
      }
      if (detection) (this.shadowed.has(detector.id) ? shadowDetections : detections).push(upgradeDetection(detection));
    }

    // Reported once per request, by the pass that commits (a deferred pass writes nothing).
    if (shadowDetections.length > 0 && recordHit) this.reportShadow(facts, shadowDetections, detections.length > 0, now);

    // Counted by the pass that decides this request: the committing one, or a first pass
    // nothing flagged (no second pass follows it). A deferred pass that flagged something
    // is evaluated again, and that pass counts.
    const settle = (actionId: string, downgraded: boolean): void => {
      for (const id of failed) this.detectorFailures.set(id, (this.detectorFailures.get(id) ?? 0) + 1);
      if (options.audit === false || this.audit === undefined) return;
      this.audit.record({ at: now.getTime(), ip: facts.ip, path: facts.path, flagged: detections.length > 0, blocked: actionId === "block", downgraded, failures: failed.length });
    };

    if (detections.length === 0) {
      settle("", false);
      if (measured) this.evaluationDuration.observe(performance.now() - started);
      return { detections, score: 0, totalScore: await this.safeScore(facts.ip), tracker, actionId: "", action: undefined, fingerprint, path, shadowDetections, confidence: 0 };
    }

    // Record this fingerprint→IP only now that the request has scored — the registry
    // holds attackers only, so repeat-actor can't correlate benign traffic (see its docs).
    if (recordHit) this.fingerprints.record(fingerprint, facts.ip, now.getTime());
    // Markers share that registry — it is keyed by a string, and written only for requests
    // that already scored, which is the gate a marker needs too. The prefix keeps the two
    // key spaces apart.
    if (recordHit && marker !== undefined) this.fingerprints.record(`marker:${marker}`, facts.ip, now.getTime());

    detections.sort((a, b) => b.score - a.score);
    const score = combinedScore(detections);
    // The second reading of the same detections: how strong they are, rather than how much
    // they add up to. Both are recorded; the policy may use either.
    const confidence = confidenceOf(detections);
    const priorScore = await this.safeScore(facts.ip);
    const totalScore = priorScore + score;

    const policyCtx: PolicyContext = {
      detection: detections[0]!,
      detections,
      ip: facts.ip,
      path: facts.path,
      method: facts.method,
      score,
      totalScore,
      confidence,
      tracker,
    };
    // A policy may answer with a bare action id (the closure form) or with a decision that
    // names the rule and says why. Both are normalised here, so an incident always records
    // the reasoning when there was any.
    const decided = this.policy(policyCtx);
    const decision: ResponseDecision = typeof decided === "string" ? { actionId: decided, rule: "default", reason: "" } : decided;
    let actionId = decision.actionId;
    // Blocking writes the address to the blocklist (and the firewall enforcer), refusing
    // every later request from it, the host app's own pages included. Summed guesses
    // reached that for real visitors more than once, so a front end in front of real
    // users can require proof: without a `certain` detection the block becomes a
    // response to this one request and nothing is blocklisted.
    let downgradedFrom: string | undefined;
    let reason = decision.reason;
    if (actionId === "block" && options.blockRequiresProof === true && !detections.some((detection) => detection.certain === true)) {
      downgradedFrom = actionId;
      actionId = options.unprovenBlockFallback ?? "tarpit";
      // The substitution is recorded rather than silent: a policy quietly doing less than it
      // says is worse than one that refuses out loud.
      reason = `${reason === "" ? `Rule "${decision.rule}" asked to block.` : reason} No detection was proof, so the block was refused and ${actionId} served instead.`;
    }
    const outcome = { rule: decision.rule, ...(reason === "" ? {} : { reason }) };

    // A deferred pass reports what it found but writes nothing: the caller is going to
    // evaluate this same request again, and that pass is the one that commits.
    if (!recordHit) {
      if (measured) this.evaluationDuration.observe(performance.now() - started);
      return { detections, score, totalScore, tracker, actionId, action: this.actions.get(actionId), fingerprint, path, shadowDetections, confidence, ...outcome, ...(marker !== undefined ? { marker } : {}), ...(downgradedFrom !== undefined ? { downgradedFrom } : {}) };
    }

    settle(actionId, downgradedFrom !== undefined);

    let enrichment: HoneypotHit["enrichment"];
    try {
      enrichment = this.enricher ? await this.enricher.enrich(facts.ip) : undefined;
    } catch (err) {
      this.reportError(err, { source: "enricher" });
    }

    // Named after enrichment, because a label may be written against an ASN or an
    // organisation the enricher supplies. Synchronous, and never able to fail the request.
    let actor: HoneypotHit["actor"];
    try {
      actor = this.labels?.labelFor({ ip: facts.ip, enrichment, headers: facts.headers });
    } catch (err) {
      this.reportError(err, { source: "labels" });
    }

    const hit: HoneypotHit = {
      id: randomUUID(),
      timestamp: now.toISOString(),
      ip: facts.ip,
      method: facts.method,
      path: facts.path,
      ...(facts.rawPath !== undefined ? { rawPath: facts.rawPath } : {}),
      headers: facts.headers,
      body: facts.body,
      fingerprint,
      ...(enrichment ? { enrichment } : {}),
      ...(actor ? { actor } : {}),
      ...(marker !== undefined ? { marker } : {}),
      confidence,
      detections,
      ...(shadowDetections.length > 0 ? { shadowDetections } : {}),
      score,
      totalScore,
      respondedWith: actionId,
      ...outcome,
      ...(downgradedFrom !== undefined ? { downgradedFrom } : {}),
    };
    // Recording is best-effort: a flaky store or a throwing onHit must not fail the
    // evaluation (and, in middleware mode, must not reject into the host app) — the
    // detection result is still valid and the caller must be able to serve a response.
    try {
      await this.store.record(hit);
    } catch (err) {
      this.reportError(err, { source: "store" });
    }
    try {
      await this.onHit?.(hit);
    } catch (err) {
      this.reportError(err, { source: "onHit" });
    }
    this.publish(hit);

    if (measured) this.evaluationDuration.observe(performance.now() - started);
    return { detections, score, totalScore, tracker, actionId, action: this.actions.get(actionId), fingerprint, path, shadowDetections, confidence, ...outcome, ...(marker !== undefined ? { marker } : {}), ...(downgradedFrom !== undefined ? { downgradedFrom } : {}) };
  }

  /**
   * Hands shadowed findings to `onShadow`. A throwing callback is reported, never raised.
   *
   * Public for front ends that defer a pass: a deferred first pass reports nothing, and
   * when only shadowed detectors fired no committing pass follows, so the front end
   * reports them itself.
   */
  reportShadow(facts: Pick<RequestFacts, "ip" | "method" | "path">, detections: Detection[], alsoHit: boolean, at: Date = new Date(this.clock.now())): void {
    try {
      const event: ShadowEvent = { timestamp: at.toISOString(), ip: facts.ip, method: facts.method, path: facts.path, detections, alsoHit };
      this.onShadow?.(event);
      this.events.emit("shadow", event);
    } catch (err) {
      this.reportError(err, { source: "onShadow" });
    }
  }

  /**
   * Calls `listener` with every hit this engine records, after `onHit`, and returns the way
   * to stop. For consumers attached after construction, such as a dashboard; `onHit` stays the
   * place for the one handler a deployment configures. A throwing listener is reported and
   * never reaches the request.
   */
  subscribe(listener: (hit: HoneypotHit) => void): () => void {
    return this.events.on("hit", listener);
  }

  /**
   * Tells subscribers about a hit recorded somewhere else, such as an SSH or SMTP honeypot
   * sharing this engine's store, so they see the whole deployment rather than only HTTP.
   * Records nothing itself.
   */
  publish(hit: HoneypotHit): void {
    this.events.emit("hit", hit);
  }

  /**
   * Listens to what the engine announces, and returns the way to stop.
   *
   * `on("hit")` is what `subscribe` does; the others are `shadow` (a shadowed detector
   * fired), `error` (something the engine isolated), `warning` (an operator-facing notice)
   * and `change` (a part replaced at runtime).
   */
  on<K extends keyof HoneypotEngineEvents & string>(event: K, listener: (payload: HoneypotEngineEvents[K]) => void): () => void {
    return this.events.on(event, listener);
  }

  /**
   * Raises an operator-facing notice: a risky setting, a component running degraded, a
   * change somebody made. Kept in a short history as well as emitted, so a dashboard opened
   * after the fact can still show what happened.
   */
  warn(message: string, change?: ChangeEvent): void {
    const notice: Notice = { timestamp: new Date(this.clock.now()).toISOString(), message, ...(change !== undefined ? { change } : {}) };
    this.recentNotices.push(notice);
    if (this.recentNotices.length > MAX_NOTICES) this.recentNotices.splice(0, this.recentNotices.length - MAX_NOTICES);
    this.events.emit("warning", notice);
  }

  /** The recent notices, oldest first. */
  notices(): readonly Notice[] {
    return [...this.recentNotices];
  }

  /** Read an IP's prior score without letting a flaky store crash evaluation — degrades to 0. */
  private async safeScore(ip: string): Promise<number> {
    try {
      return await this.store.scoreFor(ip);
    } catch (err) {
      this.reportError(err, { source: "store" });
      return 0;
    }
  }

  async scoreFor(ip: string): Promise<number> {
    return this.store.scoreFor(ip);
  }
}

/** `ProxyConfig` with its defaults applied and its ranges compiled. */
interface ResolvedProxy {
  trustProxy: boolean;
  trustedProxies: IpAllowlist | undefined;
  hops: number;
  header: string;
}

/**
 * Applies defaults and validates. Adapted from bothandlerjs. Throws where bothandlerjs throws
 * (an entry that is not an address or CIDR) and also on a hop count that is not a positive
 * integer and an empty header name: each would leave the forwarded header read wrongly or not
 * at all while the configuration looked right.
 */
function resolveProxy(config: ProxyConfig): ResolvedProxy {
  let trustedProxies: IpAllowlist | undefined;
  if (config.trustedProxies !== undefined) {
    trustedProxies = new IpAllowlist([...config.trustedProxies]);
    if (trustedProxies.invalid.length > 0) {
      throw new Error(`proxy.trustedProxies contains entries that are not valid addresses or CIDRs: ${trustedProxies.invalid.join(", ")}`);
    }
    if (trustedProxies.size === 0) {
      throw new Error("proxy.trustedProxies is empty, so no peer could ever be trusted and the forwarded header would never be read; leave it unset or list your proxies");
    }
  }
  const hops = config.hops ?? 1;
  if (!Number.isInteger(hops) || hops < 1) throw new Error(`proxy.hops must be a positive integer, got ${String(config.hops)}`);
  const header = (config.header ?? "x-forwarded-for").trim().toLowerCase();
  if (header === "") throw new Error("proxy.header is empty, so the forwarded header could never be found");
  return { trustProxy: config.trustProxy === true, trustedProxies, hops, header };
}

/** One canonical spelling of an address (port, brackets, IPv4-mapped prefix removed), or undefined. */
function canonicalAddress(value: string): string | undefined {
  const address = normalizeAddress(stripPort(value));
  return net.isIP(address) !== 0 ? address : undefined;
}
