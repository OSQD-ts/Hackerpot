import type { Detection, DetectionContext, Detector } from "./types.js";

export interface JwtWeaknessOptions {
  score?: number;
  /** Header names to scan for a JWT. Lowercase. Default authorization + cookie. */
  inspectHeaders?: string[];
  respondWith?: string;
}

const DEFAULT_HEADERS = ["authorization", "cookie", "x-access-token"];
// A JWT: three base64url segments. The signature (3rd) may be empty (that's the tell for alg:none).
const JWT = /eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.([A-Za-z0-9_-]*)/g;

function decodeAlg(header: string): { alg?: string } | undefined {
  try {
    return JSON.parse(Buffer.from(header, "base64url").toString("utf8")) as { alg?: string };
  } catch {
    return undefined;
  }
}

/**
 * JWT forgery probing: a JSON Web Token whose header declares `alg: "none"` (an
 * unsigned token an attacker crafts to impersonate anyone), or a token presented
 * with an empty signature. A legitimate token is always signed (HS256/RS256/…), so
 * this is a very low-false-positive, high-confidence attack signal.
 */
export function jwtWeaknessDetector(options: JwtWeaknessOptions = {}): Detector {
  const score = options.score ?? 9;
  const inspectHeaders = options.inspectHeaders ?? DEFAULT_HEADERS;

  return {
    id: "jwt-weakness",
    description: "A JWT with alg:none or an empty signature — token-forgery attempt",
    needsBody: false,
    inspect(ctx: DetectionContext): Detection | undefined {
      const values: Array<{ location: string; value: string }> = [];
      for (const name of inspectHeaders) {
        const raw = ctx.headers[name];
        const value = Array.isArray(raw) ? raw.join(" ") : raw;
        if (value) values.push({ location: `header.${name}`, value });
      }
      for (const [key, value] of Object.entries(ctx.query)) values.push({ location: `query.${key}`, value });

      for (const { location, value } of values) {
        for (const match of value.matchAll(JWT)) {
          const headerB64 = match[0].split(".")[0]!;
          const signature = match[1] ?? "";
          const parsed = decodeAlg(headerB64);
          const alg = parsed?.alg?.toLowerCase();
          if (alg === "none" || (parsed !== undefined && signature === "")) {
            const detection: Detection = {
              detectorId: "jwt-weakness",
              reason: `JWT ${alg === "none" ? 'alg:"none"' : "with an empty signature"} in ${location}`,
              score,
              metadata: { location, alg: parsed?.alg ?? null },
            };
            if (options.respondWith) detection.respondWith = options.respondWith;
            return detection;
          }
        }
      }
      return undefined;
    },
  };
}
