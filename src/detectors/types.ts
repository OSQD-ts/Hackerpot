import type { FingerprintRegistry, IpTracker } from "../state.js";

export interface RequestFacts {
  method: string;
  path: string;
  query: Record<string, string>;
  headers: Record<string, string | string[] | undefined>;
  ip: string;
  /**
   * The client's headers as Node's `[name, value, name, value, …]` array, order and
   * casing preserved. Feeds the actor fingerprint (header ordering is a stable
   * cross-IP signal). Optional — omitted callers fall back to parsed-header key order.
   */
  rawHeaders?: string[] | undefined;
  /**
   * The request target exactly as sent, present only when it differs from `path`. The
   * engine normalises `path` once (see `normalizePath`); this keeps the spelling for
   * detectors that care how a target was written, such as an encoded traversal.
   */
  rawPath?: string | undefined;
  /** HTTP version from the request line (`"1.1"`, `"2.0"`), when the front end knows it. */
  httpVersion?: string | undefined;
  /** Query parameters past `MAX_QUERY_PARAMS` that no detector inspected. Set by the engine. */
  queryParamsDropped?: number | undefined;
  /**
   * True when the header set is incomplete by construction: facts rebuilt from an access log
   * carry a User-Agent and a Referer at most. Detectors that reason from a missing header
   * (no Host, no User-Agent, no Accept headers) skip such requests, because an absent header
   * there is an absent log field, not something the client left out.
   */
  partialHeaders?: boolean | undefined;
  /** Only populated during the body phase — see `Detector.needsBody`. */
  body?: string | undefined;
  /**
   * Form fields the host application has already parsed, for detectors that read submitted
   * values (the `trap` detector's hidden fields). Set by `trapFormGuard`; the engine never
   * parses a body into this itself.
   */
  formFields?: Record<string, unknown> | undefined;
}

export interface DetectionContext extends RequestFacts {
  /** Sliding-window history of what this IP has done recently. */
  tracker: IpTracker;
  timestamp: Date;
  /** This request's actor fingerprint (header order + UA family). See `computeFingerprint`. */
  fingerprint: string;
  /** Which IPs each fingerprint has recently been *suspicious* from — for cross-IP actor correlation. */
  fingerprintRegistry: FingerprintRegistry;
  /**
   * Set by `crawler-verification` when DNS confirms the crawler the User-Agent claims, for
   * the detectors that run after it: the volume detectors skip a verified crawler.
   */
  verifiedCrawler?: string;
}

export interface Detection {
  detectorId: string;
  /** Human-readable explanation of what tripped the detector, for logs and alerts. */
  reason: string;
  /** Suspicion points added to this IP's running total. */
  score: number;
  /** Id of the response action to run. Falls back to the engine's default policy when omitted. */
  respondWith?: string;
  /**
   * True when this detection is proof rather than suspicion: no legitimate client can
   * produce it (a replayed honeytoken, a protocol violation no client stack emits). A
   * policy guard can require proof before blocking.
   */
  certain?: boolean;
  /**
   * Root cause shared with other detections, so one act seen by several detectors counts
   * once: within a family only the highest score is added. Detections without a family
   * each count on their own.
   */
  family?: string;
  metadata?: Record<string, unknown>;
}

export interface Detector {
  id: string;
  description?: string;
  /**
   * Detectors that need the request body run in a second phase, after a
   * first-phase detector has already flagged the request. In middleware mode
   * the body is never consumed unless the request is being handled by the
   * honeypot, so real downstream routes always receive an intact stream.
   */
  needsBody?: boolean;
  inspect(ctx: DetectionContext): Detection | undefined | Promise<Detection | undefined>;
}
