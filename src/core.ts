import { randomUUID } from "node:crypto";
import net from "node:net";
import type { IncomingHttpHeaders } from "node:http";
import { IpAllowlist } from "./allowlist.js";
import { MemoryBlocklist, type Blocklist } from "./blocklist.js";
import { defaultDetectors } from "./detectors/index.js";
import type { Detection, DetectionContext, Detector, RequestFacts } from "./detectors/types.js";
import { defaultResponseActions, defaultResponsePolicy } from "./responses/index.js";
import type { PolicyContext, ResponseAction, ResponsePolicy } from "./responses/types.js";
import { computeFingerprint } from "./fingerprint.js";
import { MAX_RAW_PATH_CHARS, boundedQuery, normalizePath } from "./http-request.js";
import { withDeadline } from "./internal/async.js";
import { defaultIpEnricher, type IpEnricher } from "./enrichment.js";
import { ActivityRegistry, FingerprintRegistry, IpTracker } from "./state.js";
import { MemoryStore } from "./stores/index.js";
import { ServiceTokens, type ServiceTokenOptions } from "./service-tokens.js";
import type { TrafficAudit } from "./audit.js";
import type { HitStore, HoneypotConfig, HoneypotHit, ShadowEvent } from "./types.js";

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
  private readonly trustProxy: boolean;
  private readonly detectorTimeoutMs: number;
  private readonly onShadow: ((event: ShadowEvent) => void) | undefined;
  /** Accepted service tokens. Replaced by `reconfigure`. See `HoneypotConfig.serviceTokens`. */
  serviceTokens: ServiceTokens | undefined;
  readonly audit: TrafficAudit | undefined;
  /**
   * Failures and timeouts per detector id since the engine started, for `/metrics`. Bounded
   * by the number of detectors, since only detector ids are counted.
   */
  readonly detectorFailures = new Map<string, number>();
  /** Listeners told about every recorded hit. See `subscribe`. */
  private readonly listeners = new Set<(hit: HoneypotHit) => void>();

  constructor(config: HoneypotConfig = {}) {
    this.detectors = config.detectors ?? [...defaultDetectors(), ...(config.extraDetectors ?? [])];
    const actions = config.responseActions ?? [...defaultResponseActions(), ...(config.extraResponseActions ?? [])];
    this.actions = new Map(actions.map((action) => [action.id, action]));
    this.policy = config.policy ?? defaultResponsePolicy();
    this.store = config.store ?? new MemoryStore();
    this.registry = new ActivityRegistry(config.activityWindowMs ?? 60_000);
    this.fingerprints = new FingerprintRegistry(config.fingerprintWindowMs ?? 3_600_000);
    this.allowlist = new IpAllowlist(config.allowlist ?? []);
    this.blocklist = config.blocklist ?? new MemoryBlocklist();
    // null disables; undefined gets the dependency-free default classifier.
    this.enricher = config.enricher === null ? undefined : config.enricher ?? defaultIpEnricher();
    this.onHit = config.onHit;
    this.onError = config.onError;
    this.trustProxy = config.trustProxy ?? false;
    this.detectorTimeoutMs = config.detectorTimeoutMs ?? 2000;
    this.shadowed = new Set(config.shadowDetectors ?? []);
    this.onShadow = config.onShadow;
    this.serviceTokens = toServiceTokens(config.serviceTokens);
    this.audit = config.audit;
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
  reconfigure(patch: {
    detectors?: Detector[];
    responseActions?: ResponseAction[];
    policy?: ResponsePolicy;
    allowlist?: string[];
    shadowDetectors?: string[];
    serviceTokens?: ServiceTokenOptions | ServiceTokens;
  }): void {
    if (patch.detectors) this.detectors = patch.detectors;
    if (patch.responseActions) this.actions = new Map(patch.responseActions.map((a) => [a.id, a]));
    if (patch.policy) this.policy = patch.policy;
    if (patch.allowlist) this.allowlist = new IpAllowlist(patch.allowlist);
    if (patch.shadowDetectors) this.shadowed = new Set(patch.shadowDetectors);
    if (patch.serviceTokens) this.serviceTokens = toServiceTokens(patch.serviceTokens);
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
  }

  /** True if this detector set has any detector that inspects the request body. */
  get needsBodyPhase(): boolean {
    return this.detectors.some((detector) => detector.needsBody);
  }

  /**
   * Resolves the client IP, honoring `X-Forwarded-For` only when `trustProxy` is on.
   *
   * The forwarded value is **validated as a real IP** before it is trusted. Without
   * that check any header value at all became this request's "IP", and that string is
   * what the allowlist, the blocklist, the per-IP registry, the store, and the firewall
   * enforcer all key on — so an attacker could mint unbounded distinct "IPs" (memory
   * growth in every keyed map) or hand us a non-address like `unknown` that collides
   * every source into one bucket. `net.isIP` is the same rail the firewall enforcer
   * already applies; applying it here means no downstream consumer ever sees a non-IP.
   *
   * ⚠️ This still takes the LEFTMOST entry, which is client-supplied: a proxy that
   * *appends* rather than replaces leaves it attacker-controlled. Enable `trustProxy`
   * only behind a proxy that overwrites the header.
   */
  resolveIp(remoteAddress: string | undefined, headers: IncomingHttpHeaders): string {
    if (this.trustProxy) {
      const forwarded = headers["x-forwarded-for"];
      const value = Array.isArray(forwarded) ? forwarded[0] : forwarded;
      const first = value?.split(",")[0]?.trim();
      // A bracketed IPv6 literal ("[::1]") is still an address; strip before validating.
      const candidate = first && first.startsWith("[") && first.endsWith("]") ? first.slice(1, -1) : first;
      if (candidate && net.isIP(candidate) !== 0) return candidate;
    }
    return remoteAddress ?? "unknown";
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

    // Allowlisted sources are fully exempt: no detection, no scoring, no footprint.
    if (this.allowlist.allows(facts.ip)) {
      return { detections: [], score: 0, totalScore: 0, tracker, actionId: "", action: undefined, fingerprint, path, shadowDetections: [] };
    }
    // So is a request presenting one of your service tokens, whatever its address.
    const serviceToken = this.serviceTokens?.identify(facts.headers);
    if (serviceToken !== undefined) {
      return { detections: [], score: 0, totalScore: 0, tracker, actionId: "", action: undefined, fingerprint, path, shadowDetections: [], serviceToken };
    }

    const now = options.now ?? new Date();
    if (trackActivity) tracker.record({ method: facts.method, path: facts.path, status: options.activityStatus ?? "seen" }, now.getTime());

    const ctx: DetectionContext = { ...facts, tracker, timestamp: now, fingerprint, fingerprintRegistry: this.fingerprints };
    const detections: Detection[] = [];
    const shadowDetections: Detection[] = [];
    const failed: string[] = [];
    for (const detector of this.detectors) {
      let detection: Detection | undefined;
      try {
        const pending = detector.inspect(ctx);
        // Only an asynchronous result gets a deadline; synchronous detectors pay nothing.
        detection =
          isThenable(pending) && this.detectorTimeoutMs > 0
            ? await withDeadline(pending, this.detectorTimeoutMs, `detector "${detector.id}"`)
            : await pending;
      } catch (err) {
        // A detector must never throw; if one does (crafted input, a latent bug), isolate
        // it — skip only this detector — so an attacker can't crash evaluation or bypass
        // every other detector by feeding one a poison input. The rest still run.
        this.onError?.(err, { source: detector.id });
        failed.push(detector.id);
        continue;
      }
      if (detection) (this.shadowed.has(detector.id) ? shadowDetections : detections).push(detection);
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
      return { detections, score: 0, totalScore: await this.safeScore(facts.ip), tracker, actionId: "", action: undefined, fingerprint, path, shadowDetections };
    }

    // Record this fingerprint→IP only now that the request has scored — the registry
    // holds attackers only, so repeat-actor can't correlate benign traffic (see its docs).
    if (recordHit) this.fingerprints.record(fingerprint, facts.ip, now.getTime());

    detections.sort((a, b) => b.score - a.score);
    const score = combinedScore(detections);
    const priorScore = await this.safeScore(facts.ip);
    const totalScore = priorScore + score;

    const policyCtx: PolicyContext = {
      detection: detections[0]!,
      detections,
      ip: facts.ip,
      path: facts.path,
      totalScore,
      tracker,
    };
    let actionId = this.policy(policyCtx);
    // Blocking writes the address to the blocklist (and the firewall enforcer), refusing
    // every later request from it, the host app's own pages included. Summed guesses
    // reached that for real visitors more than once, so a front end in front of real
    // users can require proof: without a `certain` detection the block becomes a
    // response to this one request and nothing is blocklisted.
    let downgradedFrom: string | undefined;
    if (actionId === "block" && options.blockRequiresProof === true && !detections.some((detection) => detection.certain === true)) {
      downgradedFrom = actionId;
      actionId = options.unprovenBlockFallback ?? "tarpit";
    }

    // A deferred pass reports what it found but writes nothing: the caller is going to
    // evaluate this same request again, and that pass is the one that commits.
    if (!recordHit) {
      return { detections, score, totalScore, tracker, actionId, action: this.actions.get(actionId), fingerprint, path, shadowDetections, ...(downgradedFrom !== undefined ? { downgradedFrom } : {}) };
    }

    settle(actionId, downgradedFrom !== undefined);

    let enrichment: HoneypotHit["enrichment"];
    try {
      enrichment = this.enricher ? await this.enricher.enrich(facts.ip) : undefined;
    } catch (err) {
      this.onError?.(err, { source: "enricher" });
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
      detections,
      ...(shadowDetections.length > 0 ? { shadowDetections } : {}),
      score,
      totalScore,
      respondedWith: actionId,
      ...(downgradedFrom !== undefined ? { downgradedFrom } : {}),
    };
    // Recording is best-effort: a flaky store or a throwing onHit must not fail the
    // evaluation (and, in middleware mode, must not reject into the host app) — the
    // detection result is still valid and the caller must be able to serve a response.
    try {
      await this.store.record(hit);
    } catch (err) {
      this.onError?.(err, { source: "store" });
    }
    try {
      await this.onHit?.(hit);
    } catch (err) {
      this.onError?.(err, { source: "onHit" });
    }
    this.publish(hit);

    return { detections, score, totalScore, tracker, actionId, action: this.actions.get(actionId), fingerprint, path, shadowDetections, ...(downgradedFrom !== undefined ? { downgradedFrom } : {}) };
  }

  /**
   * Hands shadowed findings to `onShadow`. A throwing callback is reported, never raised.
   *
   * Public for front ends that defer a pass: a deferred first pass reports nothing, and
   * when only shadowed detectors fired no committing pass follows, so the front end
   * reports them itself.
   */
  reportShadow(facts: Pick<RequestFacts, "ip" | "method" | "path">, detections: Detection[], alsoHit: boolean, at: Date = new Date()): void {
    if (!this.onShadow) return;
    try {
      this.onShadow({ timestamp: at.toISOString(), ip: facts.ip, method: facts.method, path: facts.path, detections, alsoHit });
    } catch (err) {
      this.onError?.(err, { source: "onShadow" });
    }
  }

  /**
   * Calls `listener` with every hit this engine records, after `onHit`, and returns the way
   * to stop. For consumers attached after construction, such as a dashboard; `onHit` stays the
   * place for the one handler a deployment configures. A throwing listener is reported and
   * never reaches the request.
   */
  subscribe(listener: (hit: HoneypotHit) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /**
   * Tells subscribers about a hit recorded somewhere else, such as an SSH or SMTP honeypot
   * sharing this engine's store, so they see the whole deployment rather than only HTTP.
   * Records nothing itself.
   */
  publish(hit: HoneypotHit): void {
    for (const listener of this.listeners) {
      try {
        listener(hit);
      } catch (err) {
        this.onError?.(err, { source: "subscriber" });
      }
    }
  }

  /** Read an IP's prior score without letting a flaky store crash evaluation — degrades to 0. */
  private async safeScore(ip: string): Promise<number> {
    try {
      return await this.store.scoreFor(ip);
    } catch (err) {
      this.onError?.(err, { source: "store" });
      return 0;
    }
  }

  async scoreFor(ip: string): Promise<number> {
    return this.store.scoreFor(ip);
  }
}
