import type { Blocklist } from "./blocklist.js";
import type { Detection, Detector } from "./detectors/types.js";
import type { IpEnricher, IpEnrichment } from "./enrichment.js";
import type { ResponseAction, ResponsePolicy } from "./responses/types.js";

export interface HoneypotHit {
  id: string;
  timestamp: string;
  ip: string;
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body?: string | undefined;
  /** Actor fingerprint (header order + UA family) — correlates one actor across rotating IPs. See `computeFingerprint`. */
  fingerprint?: string | undefined;
  /** Source-IP annotation (special-use category, and geo/ASN if a data-backed enricher is configured). */
  enrichment?: IpEnrichment | undefined;
  /** Every detector that fired on this request. */
  detections: Detection[];
  /** Points added to this IP by this request. */
  score: number;
  /** This IP's cumulative score after this request. */
  totalScore: number;
  /** Id of the response action that ran. */
  respondedWith: string;
}

export interface HitStore {
  record(hit: HoneypotHit): void | Promise<void>;
  list(): HoneypotHit[] | Promise<HoneypotHit[]>;
  scoreFor(ip: string): number | Promise<number>;
}

export interface HoneypotConfig {
  /** Detectors to run, in order. Defaults to the full built-in set. */
  detectors?: Detector[];
  /** Extra detectors appended to the defaults (ignored if `detectors` is set). */
  extraDetectors?: Detector[];
  /** Response actions available to run, keyed by their id. Defaults to the full built-in set. */
  responseActions?: ResponseAction[];
  /** Extra response actions appended to the defaults (ignored if `responseActions` is set). */
  extraResponseActions?: ResponseAction[];
  /** Chooses which action id runs for a request. Defaults to the built-in escalation policy. */
  policy?: ResponsePolicy;
  /** Where hits are recorded. Defaults to an in-memory store. */
  store?: HitStore;
  /** Called every time one or more detectors fire — wire up your own logging/alerting. */
  onHit?: (hit: HoneypotHit) => void | Promise<void>;
  /**
   * Called if any internal step throws/rejects — a detector's `inspect()`, or the
   * store/`onHit` when recording a hit. The engine isolates each so a crafted input or
   * a flaky store backend can't crash evaluation, bypass other detectors, or take down a
   * host app in middleware mode. `context.source` is the detector id, `"store"`, or
   * `"onHit"`. Wire this to your logs to see a misbehaving detector or a failing store.
   */
  onError?: (error: unknown, context: { source: string }) => void;
  /** Sliding-window length for the stateful detectors, in ms. Default 60000. */
  activityWindowMs?: number;
  /**
   * How long an actor fingerprint remembers the IPs it was seen attacking from, in ms
   * (bounds `repeat-actor` correlation and the registry's memory). Default 3600000 (1h).
   */
  fingerprintWindowMs?: number;
  /**
   * Annotates each recorded hit's source IP with an `enrichment`. Defaults to the
   * dependency-free `defaultIpEnricher()` (special-use classification only). Pass your
   * own `IpEnricher` — e.g. one backed by a GeoLite2 database — to add ASN/geo. Set to
   * `null` to disable enrichment entirely.
   */
  enricher?: IpEnricher | null;
  /** Resolve client IP from X-Forwarded-For when behind a proxy/load balancer. Default false. */
  trustProxy?: boolean;
  /**
   * IPs and CIDR ranges (IPv4/IPv6) that are exempt from all detection — known-good
   * sources like uptime monitors, health checkers, and office/VPC ranges. They never
   * score, never get blocked, and leave no incident. E.g. ["127.0.0.1", "10.0.0.0/8", "2001:db8::/32"].
   */
  allowlist?: string[];
  /**
   * Where "this IP is blocked" state lives. Defaults to an in-memory, per-instance
   * blocklist. Provide a `RedisBlocklist` to make blocks survive restarts and be
   * shared across replicas (opt-in — the default keeps everything self-contained).
   */
  blocklist?: Blocklist;
}
