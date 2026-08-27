import type { Detection, DetectionContext, Detector } from "./types.js";

export interface SuspiciousMethodOptions {
  /** Methods to treat as suspicious. Defaults to WebDAV/debug verbs that a normal web client never sends. */
  methods?: string[];
  score?: number;
  respondWith?: string;
}

/** HTTP verbs no browser or normal API client sends. Exported so edge configs (e.g. the nginx generator) can reuse the list. */
export const defaultSuspiciousMethods = ["TRACE", "TRACK", "DEBUG", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH"];

/**
 * Flags HTTP verbs a browser or normal API client never sends: WebDAV methods
 * (server misconfiguration probing), and TRACE/TRACK/DEBUG (cross-site tracing
 * and debug-interface hunting).
 */
export function suspiciousMethodDetector(options: SuspiciousMethodOptions = {}): Detector {
  const methods = new Set((options.methods ?? defaultSuspiciousMethods).map((method) => method.toUpperCase()));
  const score = options.score ?? 6;

  return {
    id: "suspicious-method",
    description: "Request used an HTTP method no legitimate client sends",
    inspect(ctx: DetectionContext): Detection | undefined {
      const method = ctx.method.toUpperCase();
      if (!methods.has(method)) return undefined;
      const detection: Detection = {
        detectorId: "suspicious-method",
        reason: `Request used the ${method} method`,
        score,
        metadata: { method },
      };
      if (options.respondWith) detection.respondWith = options.respondWith;
      return detection;
    },
  };
}
