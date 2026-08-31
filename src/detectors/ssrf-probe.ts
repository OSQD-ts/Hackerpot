import type { Detection, DetectionContext, Detector } from "./types.js";

export interface SsrfProbeOptions {
  score?: number;
  /** Also scan the request body. Default true. */
  inspectBody?: boolean;
  /** Header names to scan (some SSRF vectors arrive via headers). Lowercase. */
  inspectHeaders?: string[];
  respondWith?: string;
}

// Note: the X-Forwarded-* / Forwarded family is deliberately NOT scanned — those
// headers legitimately carry internal/private IPs (a load balancer appends its own
// hop), so scanning them would false-positive on every proxied request. SSRF via a
// header shows up in these request-target-ish headers instead.
const DEFAULT_HEADERS = ["referer", "destination", "x-original-url", "x-rewrite-url"];

// Cloud metadata endpoints, loopback, and RFC1918/link-local ranges — the classic SSRF targets.
const INTERNAL_HOST = /(^|\/{2}|@)(169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200|127\.0\.0\.1|0\.0\.0\.0|localhost|\[?::1\]?|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})/i;

// Non-HTTP URL schemes an attacker uses to reach internal services or read files.
const DANGEROUS_SCHEME = /\b(file|gopher|dict|ftp|ldap|tftp|jar|netdoc|php|expect):\/\//i;

const MAX_SCAN = 16384;

function classify(raw: string): string | undefined {
  const value = raw.length > MAX_SCAN ? raw.slice(0, MAX_SCAN) : raw;
  let decoded = value;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    /* keep raw */
  }
  for (const candidate of [value, decoded]) {
    // `exec` rather than `test` + `RegExp.lastMatch`: that legacy global is deprecated,
    // is clobbered by any regex run anywhere in the process, and made the reason string
    // depend on nothing having matched in between — a fact this function cannot check.
    const scheme = DANGEROUS_SCHEME.exec(candidate);
    if (scheme) return `dangerous URL scheme (${scheme[0]})`;
    if (INTERNAL_HOST.test(candidate)) return "URL targeting an internal/metadata host";
  }
  return undefined;
}

/**
 * Server-Side Request Forgery probing: a parameter, header, or body value that
 * points the server at an internal address (cloud metadata `169.254.169.254`,
 * loopback, RFC1918) or a non-HTTP scheme (`file://`, `gopher://`, …) — i.e. an
 * attempt to make the app fetch something it shouldn't.
 */
export function ssrfProbeDetector(options: SsrfProbeOptions = {}): Detector {
  const score = options.score ?? 9;
  const inspectBody = options.inspectBody ?? true;
  const inspectHeaders = options.inspectHeaders ?? DEFAULT_HEADERS;

  return {
    id: "ssrf-probe",
    description: "Request tries to make the server fetch an internal address or non-HTTP scheme",
    needsBody: inspectBody,
    inspect(ctx: DetectionContext): Detection | undefined {
      const targets: Array<{ location: string; value: string }> = [];
      for (const [key, value] of Object.entries(ctx.query)) targets.push({ location: `query.${key}`, value });
      for (const name of inspectHeaders) {
        const raw = ctx.headers[name];
        const value = Array.isArray(raw) ? raw.join(" ") : raw;
        if (value) targets.push({ location: `header.${name}`, value });
      }
      if (inspectBody && ctx.body) targets.push({ location: "body", value: ctx.body });

      for (const target of targets) {
        const kind = classify(target.value);
        if (!kind) continue;
        const detection: Detection = {
          detectorId: "ssrf-probe",
          reason: `SSRF probe — ${kind} in ${target.location}`,
          score,
          metadata: { location: target.location, sample: target.value.slice(0, 200) },
        };
        if (options.respondWith) detection.respondWith = options.respondWith;
        return detection;
      }
      return undefined;
    },
  };
}
