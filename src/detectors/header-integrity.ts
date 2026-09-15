import type { Detection, DetectionContext, Detector } from "./types.js";

export interface HeaderIntegrityOptions {
  /** Score for a protocol violation: a repeated Host or Content-Length, or a connection-specific header over HTTP/2 or HTTP/3. Default 9. */
  score?: number;
  /** Score for repeating a header no browser sends twice (User-Agent, Accept, …) over HTTP/1.x. Default 3; 0 disables it. */
  duplicateScore?: number;
  respondWith?: string;
}

/** Headers HTTP/2 and HTTP/3 forbid outright (RFC 9113 §8.2.2). */
const CONNECTION_SPECIFIC = ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"];

/** A second copy makes the target or the body length ambiguous, which is what request smuggling is built on (RFC 9112 §3.2, §6.3). */
const MALFORMED_IF_REPEATED = ["host", "content-length"];

/** Duplicating these is bad practice rather than a violation: typically a script appending a header its library already set. */
const SINGLETON_HEADERS = ["user-agent", "accept", "accept-encoding", "accept-language", "referer", "content-type", "authorization", "range"];

function repeatedHeaders(rawHeaders: readonly string[]): Set<string> {
  const seen = new Set<string>();
  const repeated = new Set<string>();
  for (let i = 0; i < rawHeaders.length; i += 2) {
    const name = rawHeaders[i]!.toLowerCase();
    if (seen.has(name)) repeated.add(name);
    else seen.add(name);
  }
  return repeated;
}

/**
 * Protocol violations in the header set, read only from what the request contains.
 *
 * A repeated `Host` or `Content-Length`, or a connection-specific header on HTTP/2, is a
 * rule the specification requires a recipient to enforce, so no browser or maintained
 * HTTP library emits one. Those are marked `certain`. Nothing here reasons from a
 * missing header: an absent header is indistinguishable from a front end that dropped
 * it. Both-Content-Length-and-Transfer-Encoding stays in `header-anomaly`, which already
 * reports it. Adapted from bothandlerjs.
 */
export function headerIntegrityDetector(options: HeaderIntegrityOptions = {}): Detector {
  const score = options.score ?? 9;
  const duplicateScore = options.duplicateScore ?? 3;

  return {
    id: "header-integrity",
    description: "Header set violates HTTP framing rules no client stack breaks",
    inspect(ctx: DetectionContext): Detection | undefined {
      const build = (reason: string, points: number, certain: boolean, metadata: Record<string, unknown>): Detection => {
        const detection: Detection = { detectorId: "header-integrity", reason, score: points, metadata };
        if (certain) detection.certain = true;
        if (options.respondWith) detection.respondWith = options.respondWith;
        return detection;
      };

      const version = ctx.httpVersion;
      if (version !== undefined && (version.startsWith("2") || version.startsWith("3"))) {
        const offending = CONNECTION_SPECIFIC.filter((name) => ctx.headers[name] !== undefined);
        if (offending.length > 0) {
          return build(`HTTP/${version} request carries connection-specific header(s): ${offending.join(", ")}`, score, true, { kind: "h2-connection-header", headers: offending });
        }
      }

      if (!ctx.rawHeaders || ctx.rawHeaders.length < 4) return undefined;
      const repeated = repeatedHeaders(ctx.rawHeaders);
      if (repeated.size === 0) return undefined;

      const malformed = MALFORMED_IF_REPEATED.filter((name) => repeated.has(name));
      if (malformed.length > 0) {
        return build(`Request repeats the ${malformed.join(" and ")} header, which may appear only once`, score, true, { kind: "repeated-framing-header", headers: malformed });
      }

      // HTTP/2 lets a client split some fields across frames, so only judge HTTP/1.x.
      if (duplicateScore > 0 && (version === undefined || version.startsWith("1"))) {
        const singletons = SINGLETON_HEADERS.filter((name) => repeated.has(name));
        if (singletons.length > 0) {
          return build(`Request sends ${singletons.join(", ")} more than once, which no browser does`, duplicateScore, false, { kind: "duplicate-header", headers: singletons });
        }
      }
      return undefined;
    },
  };
}
