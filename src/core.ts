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
import { defaultIpEnricher, type IpEnricher } from "./enrichment.js";
import { ActivityRegistry, FingerprintRegistry, IpTracker } from "./state.js";
import { MemoryStore } from "./stores/index.js";
import type { HitStore, HoneypotConfig, HoneypotHit } from "./types.js";

export interface EvaluationResult {
  detections: Detection[];
  score: number;
  totalScore: number;
  tracker: IpTracker;
  actionId: string;
  action: ResponseAction | undefined;
  /** The request's actor fingerprint (header order + UA family). See `computeFingerprint`. */
  fingerprint: string;
}

export class HoneypotEngine {
  // Swappable at runtime via reconfigure() — read live on every request (never cached
  // by callers), so a hot-reload takes effect on the next request with no restart.
  detectors: Detector[];
  actions: Map<string, ResponseAction>;
  policy: ResponsePolicy;
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
  }): void {
    if (patch.detectors) this.detectors = patch.detectors;
    if (patch.responseActions) this.actions = new Map(patch.responseActions.map((a) => [a.id, a]));
    if (patch.policy) this.policy = patch.policy;
    if (patch.allowlist) this.allowlist = new IpAllowlist(patch.allowlist);
  }

  /** True when this IP is exempt from all detection (an allowlisted known-good source). */
  isAllowlisted(ip: string): boolean {
    return this.allowlist.allows(ip);
  }

  /** Whether this IP is currently blocked (checks the configured blocklist). */
  isBlocked(ip: string): boolean | Promise<boolean> {
    return this.blocklist.isBlocked(ip);
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
  async evaluate(facts: RequestFacts): Promise<EvaluationResult> {
    const tracker = this.registry.for(facts.ip);
    const fingerprint = computeFingerprint(facts);

    // Allowlisted sources are fully exempt: no detection, no scoring, no footprint.
    if (this.allowlist.allows(facts.ip)) {
      return { detections: [], score: 0, totalScore: 0, tracker, actionId: "", action: undefined, fingerprint };
    }

    const now = new Date();
    tracker.record({ method: facts.method, path: facts.path, status: "seen" }, now.getTime());

    const ctx: DetectionContext = { ...facts, tracker, timestamp: now, fingerprint, fingerprintRegistry: this.fingerprints };
    const detections: Detection[] = [];
    for (const detector of this.detectors) {
      let detection: Detection | undefined;
      try {
        detection = await detector.inspect(ctx);
      } catch (err) {
        // A detector must never throw; if one does (crafted input, a latent bug), isolate
        // it — skip only this detector — so an attacker can't crash evaluation or bypass
        // every other detector by feeding one a poison input. The rest still run.
        this.onError?.(err, { source: detector.id });
        continue;
      }
      if (detection) detections.push(detection);
    }

    if (detections.length === 0) {
      return { detections, score: 0, totalScore: await this.safeScore(facts.ip), tracker, actionId: "", action: undefined, fingerprint };
    }

    // Record this fingerprint→IP only now that the request has scored — the registry
    // holds attackers only, so repeat-actor can't correlate benign traffic (see its docs).
    this.fingerprints.record(fingerprint, facts.ip, now.getTime());

    detections.sort((a, b) => b.score - a.score);
    const score = detections.reduce((sum, detection) => sum + detection.score, 0);
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
    const actionId = this.policy(policyCtx);

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
      headers: facts.headers,
      body: facts.body,
      fingerprint,
      ...(enrichment ? { enrichment } : {}),
      detections,
      score,
      totalScore,
      respondedWith: actionId,
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

    return { detections, score, totalScore, tracker, actionId, action: this.actions.get(actionId), fingerprint };
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
