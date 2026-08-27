import type { Detection, DetectionContext, Detector } from "./types.js";

export interface HeaderAnomalyOptions {
  score?: number;
  /** Flag HTTP/1.1 requests that omit the Host header. Default true. */
  flagMissingHost?: boolean;
  respondWith?: string;
}

function headerValue(ctx: DetectionContext, name: string): string | undefined {
  const raw = ctx.headers[name];
  return Array.isArray(raw) ? raw[0] : raw;
}

/**
 * Flags protocol-level abnormalities in the request line and headers that a
 * normal browser or API client never produces:
 *   - absolute-form request target (`GET http://host/…`) — open-proxy probing
 *   - Shellshock payload (`() {`) in any header (CVE-2014-6271)
 *   - request smuggling: both Content-Length and Transfer-Encoding present
 *   - missing Host header on an HTTP/1.1-style request
 * These are cheap, header-only checks with very low false-positive rates.
 */
export function headerAnomalyDetector(options: HeaderAnomalyOptions = {}): Detector {
  const score = options.score ?? 7;
  const flagMissingHost = options.flagMissingHost ?? true;

  return {
    id: "header-anomaly",
    description: "Request line or headers show a protocol-level abnormality",
    inspect(ctx: DetectionContext): Detection | undefined {
      const build = (reason: string, kind: string, hiScore?: number): Detection => {
        const detection: Detection = {
          detectorId: "header-anomaly",
          reason,
          score: hiScore ?? score,
          metadata: { kind },
        };
        if (options.respondWith) detection.respondWith = options.respondWith;
        return detection;
      };

      // Absolute-form request target: the path itself is a full URL (proxy abuse).
      if (/^https?:\/\//i.test(ctx.path)) {
        return build(`Absolute-form request target (open-proxy probe): ${ctx.path.slice(0, 120)}`, "absolute-uri", 8);
      }

      // Shellshock in any header value.
      for (const [name, raw] of Object.entries(ctx.headers)) {
        const value = Array.isArray(raw) ? raw.join(" ") : raw;
        if (value && /\(\)\s*\{/.test(value)) {
          return build(`Shellshock payload in header "${name}"`, "shellshock", 10);
        }
      }

      // Request smuggling: conflicting length framing.
      const hasContentLength = ctx.headers["content-length"] !== undefined;
      const hasTransferEncoding = ctx.headers["transfer-encoding"] !== undefined;
      if (hasContentLength && hasTransferEncoding) {
        return build("Both Content-Length and Transfer-Encoding present (request-smuggling indicator)", "smuggling", 9);
      }

      // Missing Host on a non-OPTIONS request. HTTP/2 uses :authority instead,
      // so accept either to avoid false positives on h2 traffic.
      const hasAuthority = Boolean(headerValue(ctx, "host") || headerValue(ctx, ":authority"));
      if (flagMissingHost && ctx.method.toUpperCase() !== "OPTIONS" && !hasAuthority) {
        return build("Request omitted the Host header", "missing-host");
      }

      return undefined;
    },
  };
}
