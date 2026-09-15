/**
 * Watching the shape of traffic change. Adapted from bothandlerjs.
 *
 * Counters say what is happening; they do not say it is unusual. An attack is an event,
 * not a level: a scanner sweeps, a flood starts, a wave of probes for yesterday's CVE
 * arrives. So this keeps a short recent window and the longer stretch before it, compares
 * them on a schedule, and raises an anomaly when the comparison clears a bar.
 *
 * Three properties make it safe to leave on:
 *
 * - **A few increments per request.** Counters live in a fixed ring of time buckets.
 * - **No verdicts from a small sample.** Every check needs `minSamples` requests in the
 *   window, because four requests at 3am produce ratios like "800% more probes".
 * - **A cooldown per check.** A spike lasting an hour is one event, not sixty.
 */

/** How urgent an anomaly is. */
export type AnomalySeverity = "info" | "warning" | "critical";

export interface TrafficAnomaly {
  /** Stable id of the check that fired, e.g. `"flagged-share-spike"`. */
  id: string;
  severity: AnomalySeverity;
  /** One sentence, our own words except for a quoted path, safe to log. */
  summary: string;
  /** The measure that moved. */
  metric: string;
  value: number;
  baseline: number;
  /** `value / baseline`, or undefined when the baseline was zero. */
  ratio?: number | undefined;
  timestamp: string;
  /** Extra facts about the anomaly, such as the path a campaign targets. */
  details?: Record<string, unknown>;
}

/** Counters over one stretch of time. */
export interface AuditWindow {
  spanMs: number;
  requests: number;
  /** Requests at least one detector flagged. */
  flagged: number;
  /** Requests answered with `block`. */
  blocks: number;
  /** Blocks refused for lack of proof. */
  downgrades: number;
  /** Detector failures and timeouts. */
  failures: number;
  /** Requests per minute. */
  rate: number;
  /** Flagged requests as a fraction of all requests, 0–1. */
  flaggedShare: number;
}

export interface AuditContext {
  window: AuditWindow;
  baseline: AuditWindow;
  now: number;
  minSamples: number;
}

export interface AuditCheck {
  id: string;
  description: string;
  /** Returns the anomaly, or undefined when nothing is worth saying. Must not throw; one that does is skipped. */
  evaluate(context: AuditContext): Omit<TrafficAnomaly, "timestamp"> | undefined;
}

/** What one request contributes. */
export interface AuditRecord {
  at: number;
  ip: string;
  path: string;
  flagged: boolean;
  blocked: boolean;
  downgraded: boolean;
  failures: number;
}

export interface TrafficAuditOptions {
  /** The recent stretch being judged. Default 300000 (5 minutes). */
  windowMs?: number;
  /**
   * The stretch before it, which the window is compared with. Default 3600000 (1 hour).
   * It ends where the window begins: a baseline containing the window would be partly made
   * of the spike, and a large enough spike would raise its own bar.
   */
  baselineMs?: number;
  /** Requests needed in the window before any check speaks. Default 50. */
  minSamples?: number;
  /** Silence per check (per path, for campaigns) after it fires. Default 900000 (15 minutes). */
  cooldownMs?: number;
  /** Distinct source IPs a newly probed path needs inside the window to count as a campaign. Default 10. 0 disables the check. */
  campaignMinIps?: number;
  /** Replaces the built-in rate checks. */
  checks?: readonly AuditCheck[];
  /** Appended to the built-in rate checks. */
  extraChecks?: readonly AuditCheck[];
}

/** Buckets held in the ring, however the spans work out. Keeps memory flat. */
const MAX_BUCKETS = 512;
/** Probed paths tracked for the campaign check. Least recently probed are forgotten first. */
const MAX_CAMPAIGN_PATHS = 2_000;
/** Distinct IPs remembered per path; past the threshold, more add nothing. */
const MAX_IPS_PER_PATH = 256;
/** Longest path kept; probes worth reporting are short. */
const MAX_PATH_CHARS = 256;

interface Bucket {
  at: number;
  requests: number;
  flagged: number;
  blocks: number;
  downgrades: number;
  failures: number;
}

interface CampaignPath {
  firstSeen: number;
  lastSeen: number;
  ips: Map<string, number>;
}

function ratioOf(value: number, baseline: number): number | undefined {
  return baseline > 0 ? value / baseline : undefined;
}

function percent(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

/** The checks that ship. Each describes a different thing going wrong. */
export const DEFAULT_AUDIT_CHECKS: readonly AuditCheck[] = Object.freeze([
  {
    id: "flagged-share-spike",
    description: "The share of requests detectors flag has risen sharply against the baseline",
    evaluate({ window, baseline }) {
      // A share that doubles from 1% to 2% is not news, so an absolute floor sits beside the
      // ratio. A zero baseline has no ratio and is the loudest case, not a reason for silence.
      if (window.flaggedShare < 0.25) return undefined;
      const ratio = ratioOf(window.flaggedShare, baseline.flaggedShare);
      if (ratio !== undefined && ratio < 2) return undefined;
      return {
        id: "flagged-share-spike",
        severity: window.flaggedShare >= 0.6 ? "critical" : "warning",
        metric: "flagged share",
        value: window.flaggedShare,
        baseline: baseline.flaggedShare,
        ratio,
        summary: `Detectors flagged ${percent(window.flaggedShare)} of requests, against ${percent(baseline.flaggedShare)} in the baseline${ratio !== undefined ? ` (${ratio.toFixed(1)}x)` : ", where there was none"}.`,
      };
    },
  },
  {
    id: "traffic-spike",
    description: "Request volume is far above the baseline rate",
    evaluate({ window, baseline }) {
      const ratio = ratioOf(window.rate, baseline.rate);
      if (ratio === undefined || ratio < 3 || window.rate < 10) return undefined;
      return {
        id: "traffic-spike",
        severity: ratio >= 10 ? "critical" : "warning",
        metric: "requests per minute",
        value: window.rate,
        baseline: baseline.rate,
        ratio,
        summary: `Traffic is ${window.rate.toFixed(0)} requests a minute, against a baseline of ${baseline.rate.toFixed(1)} (${ratio.toFixed(1)}x).`,
      };
    },
  },
  {
    id: "block-spike",
    description: "A much larger share of requests is being blocked than usual",
    evaluate({ window, baseline }) {
      const share = window.requests > 0 ? window.blocks / window.requests : 0;
      const baseShare = baseline.requests > 0 ? baseline.blocks / baseline.requests : 0;
      if (window.blocks < 10 || share < 0.05) return undefined;
      const ratio = ratioOf(share, baseShare);
      if (ratio !== undefined && ratio < 3) return undefined;
      return {
        id: "block-spike",
        severity: "warning",
        metric: "block rate",
        value: share,
        baseline: baseShare,
        ratio,
        summary: `${window.blocks} request(s) blocked, ${percent(share)} of traffic, against ${percent(baseShare)} in the baseline. Check that they are all attackers.`,
      };
    },
  },
  {
    id: "downgrade-spike",
    description: "The proof guard is refusing far more blocks than usual",
    evaluate({ window, baseline }) {
      const share = window.requests > 0 ? window.downgrades / window.requests : 0;
      const baseShare = baseline.requests > 0 ? baseline.downgrades / baseline.requests : 0;
      if (window.downgrades < 10 || share < 0.05) return undefined;
      const ratio = ratioOf(share, baseShare);
      if (ratio !== undefined && ratio < 3) return undefined;
      return {
        id: "downgrade-spike",
        severity: "warning",
        metric: "downgraded blocks",
        value: share,
        baseline: baseShare,
        ratio,
        // About the policy rather than the traffic: scores are reaching the block threshold
        // on evidence that proves nothing, which is how real visitors end up blocked.
        summary: `The proof guard refused ${window.downgrades} block(s), ${percent(share)} of traffic. Scores are reaching the block threshold without proof; check which detectors are adding up.`,
      };
    },
  },
  {
    id: "detector-failures",
    description: "Detectors are erroring or timing out on a meaningful share of requests",
    evaluate({ window }) {
      const share = window.requests > 0 ? window.failures / window.requests : 0;
      if (share < 0.01 || window.failures < 5) return undefined;
      return {
        id: "detector-failures",
        severity: share >= 0.1 ? "critical" : "warning",
        metric: "detector failure rate",
        value: share,
        baseline: 0,
        summary: `Detectors failed on ${percent(share)} of requests (${window.failures} failure(s)). Detection is degraded; the cause is usually a resolver or a custom detector, not the traffic.`,
      };
    },
  },
]);

/** Emits its anomalies from `evaluate()`; call `start()` to run it on a timer. */
export class TrafficAudit {
  readonly checks: readonly AuditCheck[];
  private readonly windowMs: number;
  private readonly baselineMs: number;
  private readonly bucketMs: number;
  private readonly buckets: Bucket[];
  private readonly minSamples: number;
  private readonly cooldownMs: number;
  private readonly campaignMinIps: number;
  private readonly lastFired = new Map<string, number>();
  private readonly campaigns = new Map<string, CampaignPath>();
  private timer: ReturnType<typeof setInterval> | undefined;

  constructor(options: TrafficAuditOptions = {}) {
    const windowMs = Math.max(1000, options.windowMs ?? 300_000);
    const baselineMs = Math.max(windowMs, options.baselineMs ?? 3_600_000);
    this.minSamples = Math.max(1, options.minSamples ?? 50);
    this.cooldownMs = Math.max(0, options.cooldownMs ?? 900_000);
    this.campaignMinIps = Math.max(0, options.campaignMinIps ?? 10);
    this.checks = options.checks ?? [...DEFAULT_AUDIT_CHECKS, ...(options.extraChecks ?? [])];

    // Ten buckets to a window, coarsened if that needs more than the ring holds. Both spans
    // are rounded up to whole buckets so no edge half-counts a bucket.
    let bucketMs = Math.max(1000, Math.round(windowMs / 10));
    if (Math.ceil((windowMs + baselineMs) / bucketMs) + 1 > MAX_BUCKETS) bucketMs = Math.ceil((windowMs + baselineMs) / (MAX_BUCKETS - 1));
    this.bucketMs = bucketMs;
    this.windowMs = Math.ceil(windowMs / bucketMs) * bucketMs;
    this.baselineMs = Math.ceil(baselineMs / bucketMs) * bucketMs;
    const count = (this.windowMs + this.baselineMs) / bucketMs + 1;
    this.buckets = Array.from({ length: count }, () => ({ at: -1, requests: 0, flagged: 0, blocks: 0, downgrades: 0, failures: 0 }));
  }

  /** Counts one evaluated request. */
  record(entry: AuditRecord): void {
    const bucket = this.bucketFor(entry.at);
    bucket.requests += 1;
    if (entry.flagged) bucket.flagged += 1;
    if (entry.blocked) bucket.blocks += 1;
    if (entry.downgraded) bucket.downgrades += 1;
    bucket.failures += entry.failures;
    if (entry.flagged && this.campaignMinIps > 0) this.recordProbe(entry);
  }

  /** The window and baseline as they stand. */
  summary(now = Date.now()): { window: AuditWindow; baseline: AuditWindow } {
    // The current bucket is still filling, so the window ends at its far edge.
    const end = (Math.floor(now / this.bucketMs) + 1) * this.bucketMs;
    const windowStart = end - this.windowMs;
    return { window: this.aggregate(windowStart, end, this.windowMs), baseline: this.aggregate(windowStart - this.baselineMs, windowStart, this.baselineMs) };
  }

  /** Runs every check that is out of its cooldown. Safe to call as often as you like. */
  evaluate(now = Date.now()): TrafficAnomaly[] {
    const { window, baseline } = this.summary(now);
    const anomalies: TrafficAnomaly[] = [];
    const timestamp = new Date(now).toISOString();

    if (window.requests >= this.minSamples) {
      const context: AuditContext = { window, baseline, now, minSamples: this.minSamples };
      for (const check of this.checks) {
        if (this.cooling(check.id, now)) continue;
        let result: ReturnType<AuditCheck["evaluate"]>;
        try {
          result = check.evaluate(context);
        } catch {
          // Caller-supplied code on a timer: a throwing check is skipped, never fatal.
          continue;
        }
        if (result === undefined) continue;
        this.lastFired.set(check.id, now);
        anomalies.push({ ...result, timestamp });
      }
    }

    anomalies.push(...this.campaignAnomalies(now, timestamp));
    this.pruneCooldowns(now);
    return anomalies;
  }

  /** Runs `evaluate` every `intervalMs` and hands each anomaly over. The timer never keeps the process alive. */
  start(intervalMs: number, onAnomaly: (anomaly: TrafficAnomaly) => void): void {
    if (this.timer !== undefined) return;
    this.timer = setInterval(() => {
      for (const anomaly of this.evaluate()) {
        try {
          onAnomaly(anomaly);
        } catch {
          // A failing sink must not stop the audit.
        }
      }
    }, Math.max(1000, intervalMs));
    this.timer.unref();
  }

  stop(): void {
    if (this.timer !== undefined) clearInterval(this.timer);
    this.timer = undefined;
  }

  /**
   * A path many unrelated sources start probing at once is what a freshly published
   * vulnerability looks like from inside a honeypot: everybody is running the same new
   * list. One source running one probe looks like nothing on its own; the union is the
   * signal. Only flagged requests count, so a page launch that many people visit is not a
   * campaign. The idea is bothandlerjs's `path-campaign` detector, reported here as an
   * anomaly because it describes many clients rather than the one in front of us.
   */
  private recordProbe(entry: AuditRecord): void {
    const path = entry.path.length > MAX_PATH_CHARS ? entry.path.slice(0, MAX_PATH_CHARS) : entry.path;
    let tracked = this.campaigns.get(path);
    if (tracked === undefined) {
      if (this.campaigns.size >= MAX_CAMPAIGN_PATHS) {
        const oldest = this.campaigns.keys().next();
        if (!oldest.done) this.campaigns.delete(oldest.value);
      }
      tracked = { firstSeen: entry.at, lastSeen: entry.at, ips: new Map() };
    } else {
      // Re-inserted so iteration order stays least recently probed first.
      this.campaigns.delete(path);
    }
    tracked.lastSeen = Math.max(tracked.lastSeen, entry.at);
    if (tracked.ips.has(entry.ip) || tracked.ips.size < MAX_IPS_PER_PATH) tracked.ips.set(entry.ip, entry.at);
    this.campaigns.set(path, tracked);
  }

  private campaignAnomalies(now: number, timestamp: string): TrafficAnomaly[] {
    if (this.campaignMinIps === 0) return [];
    const windowStart = now - this.windowMs;
    const anomalies: TrafficAnomaly[] = [];
    for (const [path, tracked] of this.campaigns) {
      // Forget paths nobody has probed for a whole window plus baseline.
      if (tracked.lastSeen < windowStart - this.baselineMs) {
        this.campaigns.delete(path);
        continue;
      }
      // New means first probed inside the window; a path probed all day is background noise.
      if (tracked.firstSeen < windowStart) continue;
      let recent = 0;
      for (const at of tracked.ips.values()) if (at >= windowStart) recent += 1;
      if (recent < this.campaignMinIps) continue;
      const key = `probe-campaign:${path}`;
      if (this.cooling(key, now)) continue;
      this.lastFired.set(key, now);
      const minutes = Math.max(1, Math.round((now - tracked.firstSeen) / 60_000));
      anomalies.push({
        id: "probe-campaign",
        severity: recent >= this.campaignMinIps * 3 ? "critical" : "warning",
        metric: "distinct sources probing a new path",
        value: recent,
        baseline: 0,
        summary: `${recent} different addresses started probing ${JSON.stringify(path.slice(0, 120))} in the last ${minutes} minute(s), a path nothing probed before. This is what a newly published exploit looks like.`,
        timestamp,
        details: { path },
      });
    }
    return anomalies;
  }

  private cooling(key: string, now: number): boolean {
    const last = this.lastFired.get(key);
    return last !== undefined && now - last < this.cooldownMs;
  }

  /** Campaign cooldowns are keyed by path, so they are pruned rather than left to grow. */
  private pruneCooldowns(now: number): void {
    if (this.lastFired.size <= MAX_CAMPAIGN_PATHS) return;
    for (const [key, at] of this.lastFired) if (now - at >= this.cooldownMs) this.lastFired.delete(key);
  }

  private bucketFor(timestamp: number): Bucket {
    const index = Math.floor(timestamp / this.bucketMs);
    const slot = this.buckets[((index % this.buckets.length) + this.buckets.length) % this.buckets.length]!;
    const at = index * this.bucketMs;
    if (slot.at !== at) {
      // The ring has come round: this slot belongs to an older stretch and is reset.
      slot.at = at;
      slot.requests = 0;
      slot.flagged = 0;
      slot.blocks = 0;
      slot.downgrades = 0;
      slot.failures = 0;
    }
    return slot;
  }

  private aggregate(from: number, to: number, spanMs: number): AuditWindow {
    const totals = { requests: 0, flagged: 0, blocks: 0, downgrades: 0, failures: 0 };
    for (const bucket of this.buckets) {
      if (bucket.at < from || bucket.at >= to) continue;
      totals.requests += bucket.requests;
      totals.flagged += bucket.flagged;
      totals.blocks += bucket.blocks;
      totals.downgrades += bucket.downgrades;
      totals.failures += bucket.failures;
    }
    return { ...totals, spanMs, rate: totals.requests / (spanMs / 60_000), flaggedShare: totals.requests > 0 ? totals.flagged / totals.requests : 0 };
  }
}
