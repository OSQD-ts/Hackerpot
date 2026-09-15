import type { Detection, DetectionContext, Detector } from "./types.js";

export interface CrlfInjectionOptions {
  score?: number;
  /** Header names to scan for injected CRLF sequences. Lowercase. */
  inspectHeaders?: string[];
  respondWith?: string;
}

const DEFAULT_HEADERS = ["referer", "x-forwarded-for", "user-agent"];

// Encoded and raw carriage-return / line-feed variants used to inject headers.
const CRLF = /%0d%0a|%0d|%0a|%23%0a|\r\n|\r|\n|%e5%98%8a|%e5%98%8d/i;
// A CRLF immediately followed by something that looks like a smuggled header or body.
const HEADER_SMUGGLE = /(%0d%0a|%0a|\r\n|\n)\s*(set-cookie|location|content-length|content-type|refresh|link|x-[a-z-]+)\s*[:=]/i;

const MAX_SCAN = 16384;

function scan(raw: string): string | undefined {
  const value = raw.length > MAX_SCAN ? raw.slice(0, MAX_SCAN) : raw;
  let decoded = value;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    /* keep raw */
  }
  for (const candidate of [value, decoded]) {
    if (HEADER_SMUGGLE.test(candidate)) return "CRLF followed by a smuggled header";
    if (CRLF.test(candidate)) return "CRLF sequence";
  }
  return undefined;
}

/**
 * CRLF injection / HTTP response splitting: a carriage-return + line-feed
 * smuggled into the path, a query value, or a header, used to inject response
 * headers (`Set-Cookie`, `Location`), poison caches, or split the response.
 */
export function crlfInjectionDetector(options: CrlfInjectionOptions = {}): Detector {
  const score = options.score ?? 8;
  const inspectHeaders = options.inspectHeaders ?? DEFAULT_HEADERS;

  return {
    id: "crlf-injection",
    description: "A CRLF sequence was smuggled into the path, query, or a header",
    inspect(ctx: DetectionContext): Detection | undefined {
      const targets: Array<{ location: string; value: string }> = [{ location: "path", value: ctx.path }];
      // The target as sent keeps its `%0d%0a` escapes, which normalisation decodes away.
      if (ctx.rawPath !== undefined) targets.push({ location: "path (as sent)", value: ctx.rawPath });
      for (const [key, value] of Object.entries(ctx.query)) targets.push({ location: `query.${key}`, value });
      for (const name of inspectHeaders) {
        const raw = ctx.headers[name];
        const value = Array.isArray(raw) ? raw.join(" ") : raw;
        if (value) targets.push({ location: `header.${name}`, value });
      }

      for (const target of targets) {
        const kind = scan(target.value);
        if (!kind) continue;
        const detection: Detection = {
          detectorId: "crlf-injection",
          reason: `CRLF injection — ${kind} in ${target.location}`,
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
