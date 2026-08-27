import type { Detection, DetectionContext, Detector } from "./types.js";

export interface ClientAnomalyOptions {
  score?: number;
  /** Headers a real browser always sends; a browser-claiming UA missing all of them is spoofing. Lowercase. */
  requiredBrowserHeaders?: string[];
  respondWith?: string;
}

// User agents that claim to be a mainstream browser.
const BROWSER_UA = /mozilla\/5\.0.*(chrome|firefox|safari|edg|opr|trident|gecko)/i;
const DEFAULT_REQUIRED = ["accept", "accept-language", "accept-encoding"];

function has(ctx: DetectionContext, name: string): boolean {
  const raw = ctx.headers[name];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return Boolean(value && value.trim());
}

/**
 * Client fingerprint anomaly: a request whose User-Agent claims a mainstream
 * browser but is missing the request headers every real browser sends on every
 * request (`Accept`, `Accept-Language`, `Accept-Encoding`). Real browsers set these
 * unconditionally, so a "Chrome" that omits them is a script wearing a browser's
 * name — cheap UA spoofing. A weak, corroborating signal (easily evaded by a
 * careful attacker), so it scores low. Full TLS/JA3 fingerprinting would need the
 * transport layer and is out of scope for an HTTP detector.
 */
export function clientAnomalyDetector(options: ClientAnomalyOptions = {}): Detector {
  const score = options.score ?? 4;
  const required = options.requiredBrowserHeaders ?? DEFAULT_REQUIRED;

  return {
    id: "client-anomaly",
    description: "A browser-claiming User-Agent is missing headers real browsers always send",
    inspect(ctx: DetectionContext): Detection | undefined {
      const raw = ctx.headers["user-agent"];
      const ua = Array.isArray(raw) ? raw[0] : raw;
      if (!ua || !BROWSER_UA.test(ua)) return undefined;

      const missing = required.filter((name) => !has(ctx, name));
      // Only flag when ALL of the required headers are absent — one missing header can
      // happen legitimately (a stripped proxy), but a browser sending none of them does not.
      if (missing.length < required.length) return undefined;

      const detection: Detection = {
        detectorId: "client-anomaly",
        reason: `User-Agent claims a browser but sent none of: ${required.join(", ")}`,
        score,
        metadata: { userAgent: ua.slice(0, 120), missing },
      };
      if (options.respondWith) detection.respondWith = options.respondWith;
      return detection;
    },
  };
}
