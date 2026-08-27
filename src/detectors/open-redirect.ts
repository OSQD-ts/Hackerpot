import type { Detection, DetectionContext, Detector } from "./types.js";

export interface OpenRedirectOptions {
  /** Query parameter names treated as redirect targets. Lowercase. */
  params?: string[];
  /**
   * Hosts to treat as your own (a redirect to one is a legitimate self-redirect,
   * not flagged). When set, this pinned allowlist is authoritative; when omitted,
   * the detector falls back to the request's own `Host` header — convenient, but
   * an attacker who controls Host could spoof it, so pin `trustedHosts` if this
   * ever feeds anything stronger than scoring.
   */
  trustedHosts?: string[];
  score?: number;
  respondWith?: string;
}

const DEFAULT_PARAMS = ["redirect", "redirect_uri", "redirect_url", "url", "next", "return", "returnurl", "return_url", "goto", "dest", "destination", "continue", "target", "link", "out", "forward", "callback", "r", "u"];

/**
 * An off-site absolute URL, a protocol-relative `//host`, or a backslash trick.
 *
 * Every alternative is anchored. A bare `|@` used to ride along here to catch the
 * userinfo trick, but unanchored it matched an `@` ANYWHERE in the value, so ordinary
 * same-site targets were reported as "malformed off-site target": `?next=/dashboard?
 * email=foo@bar.com`, `?u=alice@example.com`, `?r=/u/@alice` (an @handle path, which
 * half the web serves). It bought nothing either — the userinfo forms that actually
 * redirect off-site (`https://trusted.com@evil.com`, `//trusted.com@evil.com`) already
 * match the anchored scheme/authority alternatives, and `classify()` then resolves the
 * real host through `new URL()`, which is what decides same-site. A value that merely
 * contains `@` with no scheme and no leading `//` is a relative path to a browser, so
 * it is not an open redirect at all.
 */
const OFFSITE = /^(https?:)?\/\/|^\/\\|^\\\/|^https?:[/\\]/i;

function requestHost(ctx: DetectionContext): string | undefined {
  const raw = ctx.headers["host"] ?? ctx.headers[":authority"];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return value?.split(":")[0]?.toLowerCase();
}

/**
 * Classify a redirect target: `undefined` (same-site or not a redirect at all),
 * or a reason string when it points off-site. An absolute/protocol-relative URL
 * whose host is considered same-site (`isSameSite`) is a legitimate self-redirect
 * (OAuth `redirect_uri` to your own domain, an absolute canonical link), not an
 * open redirect.
 */
function classify(value: string, isSameSite: (host: string) => boolean): string | undefined {
  let v = value;
  try {
    v = decodeURIComponent(value);
  } catch {
    /* keep raw */
  }
  v = v.trim();
  if (!OFFSITE.test(v)) return undefined;

  // Backslash tricks (\/, /\, \\) never appear in a legitimate URL — always off-site.
  if (/^[/\\]?\\|^\/\\/.test(v)) return "backslash-obfuscated off-site target";

  try {
    const url = new URL(v.startsWith("//") ? `https:${v}` : v);
    if (isSameSite(url.host.split(":")[0]!.toLowerCase())) return undefined; // same-site self-redirect
    return `off-site target (${url.host})`;
  } catch {
    return "malformed off-site target";
  }
}

/**
 * Open-redirect probing: a `?redirect=`/`?next=`/`?url=`-style parameter carrying
 * an *off-site* target — a protocol-relative `//evil.com`, an absolute
 * `https://evil.com`, or an `@`/backslash trick. Attackers use these to bounce
 * victims off a trusted domain in phishing, and to smuggle OAuth `redirect_uri`s.
 * A same-site absolute redirect (to the request's own Host) is not flagged.
 */
export function openRedirectDetector(options: OpenRedirectOptions = {}): Detector {
  const params = new Set(options.params ?? DEFAULT_PARAMS);
  const trustedHosts = options.trustedHosts?.length ? new Set(options.trustedHosts.map((h) => h.toLowerCase())) : undefined;
  const score = options.score ?? 5;

  return {
    id: "open-redirect",
    description: "A redirect-style parameter points off-site (open-redirect / phishing bounce)",
    inspect(ctx: DetectionContext): Detection | undefined {
      // A pinned allowlist is authoritative; otherwise fall back to the request Host.
      const ownHost = requestHost(ctx);
      const isSameSite = trustedHosts ? (host: string) => trustedHosts.has(host) : (host: string) => ownHost !== undefined && host === ownHost;
      for (const [key, value] of Object.entries(ctx.query)) {
        if (!params.has(key.toLowerCase())) continue;
        const kind = classify(value, isSameSite);
        if (!kind) continue;
        const detection: Detection = {
          detectorId: "open-redirect",
          reason: `Open-redirect probe — ${kind} in query.${key}`,
          score,
          metadata: { param: key, target: value.slice(0, 200) },
        };
        if (options.respondWith) detection.respondWith = options.respondWith;
        return detection;
      }
      return undefined;
    },
  };
}
