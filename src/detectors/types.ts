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
  /** Only populated during the body phase — see `Detector.needsBody`. */
  body?: string | undefined;
}

export interface DetectionContext extends RequestFacts {
  /** Sliding-window history of what this IP has done recently. */
  tracker: IpTracker;
  timestamp: Date;
  /** This request's actor fingerprint (header order + UA family). See `computeFingerprint`. */
  fingerprint: string;
  /** Which IPs each fingerprint has recently been *suspicious* from — for cross-IP actor correlation. */
  fingerprintRegistry: FingerprintRegistry;
}

export interface Detection {
  detectorId: string;
  /** Human-readable explanation of what tripped the detector, for logs and alerts. */
  reason: string;
  /** Suspicion points added to this IP's running total. */
  score: number;
  /** Id of the response action to run. Falls back to the engine's default policy when omitted. */
  respondWith?: string;
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
