import type { Detection, DetectionContext, Detector } from "./types.js";

export interface PayloadInjectionOptions {
  score?: number;
  /** Inspect the request body as well as the path and query. Default true. */
  inspectBody?: boolean;
  /** Header names to scan for payloads (Log4Shell and friends arrive via headers). Lowercase. */
  inspectHeaders?: string[];
  respondWith?: string;
}

const DEFAULT_INSPECTED_HEADERS = ["user-agent", "referer", "x-forwarded-for", "x-api-version", "cookie"];

export interface InjectionSignature {
  kind: string;
  pattern: RegExp;
}

/** Exploitation-payload signatures. Exported so edge configs (e.g. the nginx generator) can reuse the same patterns. */
export const injectionSignatures: InjectionSignature[] = [
  { kind: "path-traversal", pattern: /(\.\.[/\\]){2,}|\.\.%2f|%2e%2e%2f|\/etc\/passwd|\/proc\/self\/environ|boot\.ini/i },
  { kind: "sql-injection", pattern: /(\bunion\b[\s/*]+\bselect\b)|(\bor\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+)|(\bsleep\s*\(\s*\d+\s*\))|(\bwaitfor\s+delay\b)|(information_schema)|(\bdrop\s+table\b)/i },
  { kind: "xss", pattern: /<script[\s>]|javascript:|onerror\s*=|onload\s*=|<iframe[\s>]|document\.cookie/i },
  { kind: "command-injection", pattern: /(;|\||`|\$\()\s*(cat|curl|wget|nc|bash|sh|python|perl|whoami|id|uname)\b|\/bin\/(ba)?sh/i },
  // The inner spans are `[^{}]`, NOT `.*?`, and bounded. With `.*?` this signature was a
  // CPU amplifier: on input like `{{` repeated to fill the 16 KB scan window, the lazy
  // span re-scanned to end-of-string from every one of the thousands of `{{` start
  // positions — measured at ~100 ms per value, ~200 ms per request end to end, so ~5
  // requests/second pinned the event loop. In middleware mode that stalls the *host*
  // application, and the payload is a plain 16 KB query string or body: no auth, no
  // detection needed, and the honeypot is the component that opened the hole.
  // A negated class can't cross a brace, so every non-matching start position fails on
  // its first character and the match is linear.
  //
  // Tradeoff: an interpolation that nests braces *inside* itself ahead of the keyword
  // (`{{ {'k':config} }}`) no longer matches this signature. That form is rare in the
  // wild, the keyword-adjacent forms attackers actually send are all still covered, and
  // it is a fair trade for removing a remote, unauthenticated event-loop stall.
  { kind: "template-injection", pattern: /\{\{[^{}]{0,400}(?:constructor|__class__|self|config|process|global)[^{}]{0,400}\}\}|\$\{[^{}]{0,400}(?:java|runtime|process)[^{}]{0,400}\}/i },
  { kind: "log4shell", pattern: /\$\{jndi:(ldap|rmi|dns|iiop)/i },
  { kind: "php-code-injection", pattern: /<\?php|php:\/\/(input|filter)|base64_decode\s*\(|eval\s*\(|system\s*\(/i },
  { kind: "xxe", pattern: /<!ENTITY\s+\S+\s+SYSTEM|<!DOCTYPE[^>]+SYSTEM/i },
];

// Cap the length any single value is matched against. The signatures are all
// polynomial, but bounding the input is cheap insurance against a future pattern
// (or a huge crafted value) turning into a CPU sink — the payload that matters is
// always near the front anyway.
const MAX_SCAN = 16384;

function scan(raw: string): InjectionSignature | undefined {
  const value = raw.length > MAX_SCAN ? raw.slice(0, MAX_SCAN) : raw;
  let decoded = value;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    // Malformed percent-encoding is itself suspicious; fall back to the raw value.
  }
  return injectionSignatures.find((signature) => signature.pattern.test(value) || signature.pattern.test(decoded));
}

/**
 * Looks for exploitation payloads — traversal, SQLi, XSS, command/template
 * injection, Log4Shell, XXE — in the path, query values, and body. A hit means
 * someone is actively trying to exploit, not merely mapping the surface, so
 * this scores high.
 */
export function payloadInjectionDetector(options: PayloadInjectionOptions = {}): Detector {
  const score = options.score ?? 10;
  const inspectBody = options.inspectBody ?? true;
  const inspectHeaders = options.inspectHeaders ?? DEFAULT_INSPECTED_HEADERS;

  return {
    id: "payload-injection",
    description: "Request contains a recognizable exploitation payload",
    needsBody: inspectBody,
    inspect(ctx: DetectionContext): Detection | undefined {
      const targets: Array<{ location: string; value: string }> = [{ location: "path", value: ctx.path }];
      for (const [key, value] of Object.entries(ctx.query)) targets.push({ location: `query.${key}`, value });
      for (const name of inspectHeaders) {
        const raw = ctx.headers[name];
        const value = Array.isArray(raw) ? raw.join(" ") : raw;
        if (value) targets.push({ location: `header.${name}`, value });
      }
      if (inspectBody && ctx.body) targets.push({ location: "body", value: ctx.body });

      for (const target of targets) {
        const signature = scan(target.value);
        if (!signature) continue;
        const detection: Detection = {
          detectorId: "payload-injection",
          reason: `${signature.kind} payload detected in ${target.location}`,
          score,
          metadata: { kind: signature.kind, location: target.location, sample: target.value.slice(0, 200) },
        };
        if (options.respondWith) detection.respondWith = options.respondWith;
        return detection;
      }
      return undefined;
    },
  };
}
