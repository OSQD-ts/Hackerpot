import type { Detection, DetectionContext, Detector } from "./types.js";

export interface Honeytoken {
  /** The exact secret value seeded as bait (a fake API key, password, session id, account number, …). */
  value: string;
  /** Human-readable name for where you planted it, shown in logs. */
  label?: string;
}

export interface HoneytokenOptions {
  /** The seeded bait values to watch for. */
  tokens: Array<Honeytoken | string>;
  score?: number;
  respondWith?: string;
}

interface Normalized {
  value: string;
  label: string;
}

/** The headers whose value is, by definition, `Basic base64(user:password)`. */
const CREDENTIAL_HEADERS = new Set(["authorization", "proxy-authorization"]);

/**
 * The `user:password` inside an HTTP Basic credential, or undefined for anything else.
 *
 * A token replayed as a Basic password never appears in the raw header, only its base64
 * form, so a plain `includes()` missed the most natural place to try a harvested
 * credential. Only these two headers are decoded: their value is base64 by definition,
 * so decoding them adds no false-positive surface. Guessing at base64 inside arbitrary
 * values would.
 */
function decodeBasic(value: string): string | undefined {
  const match = /^\s*basic\s+([A-Za-z0-9+/_-]+=*)\s*$/i.exec(value);
  if (!match) return undefined;
  const decoded = Buffer.from(match[1]!, "base64").toString("utf8");
  return decoded === "" ? undefined : decoded;
}

/**
 * Detects use of a honeytoken — a fake credential/key/id you deliberately
 * seeded somewhere an attacker might harvest it (a decoy `.env`, a fake admin
 * page, a planted config). Because no legitimate client ever possesses these
 * values, seeing one replayed in a request is one of the highest-confidence,
 * lowest-false-positive signals of an actual breach, so it scores very high.
 */
export function honeytokenDetector(options: HoneytokenOptions): Detector {
  const score = options.score ?? 15;
  const tokens: Normalized[] = options.tokens
    .map((token) => (typeof token === "string" ? { value: token, label: "honeytoken" } : { value: token.value, label: token.label ?? "honeytoken" }))
    .filter((token) => token.value.length > 0);

  return {
    id: "honeytoken",
    description: "A seeded honeytoken (fake credential/key/id) was replayed in a request",
    needsBody: true,
    inspect(ctx: DetectionContext): Detection | undefined {
      if (tokens.length === 0) return undefined;

      const haystacks: Array<{ location: string; value: string }> = [
        { location: "path", value: ctx.path },
        ...Object.entries(ctx.query).map(([key, value]) => ({ location: `query.${key}`, value })),
      ];
      for (const [name, raw] of Object.entries(ctx.headers)) {
        const value = Array.isArray(raw) ? raw.join(" ") : raw;
        if (value) haystacks.push({ location: `header.${name}`, value });
        if (!CREDENTIAL_HEADERS.has(name)) continue;
        for (const one of Array.isArray(raw) ? raw : [raw]) {
          const decoded = one ? decodeBasic(one) : undefined;
          if (decoded) haystacks.push({ location: `header.${name} (basic, decoded)`, value: decoded });
        }
      }
      if (ctx.body) haystacks.push({ location: "body", value: ctx.body });

      for (const token of tokens) {
        const found = haystacks.find((h) => h.value.includes(token.value));
        if (!found) continue;
        const detection: Detection = {
          detectorId: "honeytoken",
          reason: `Honeytoken "${token.label}" replayed in ${found.location}`,
          score,
          metadata: { label: token.label, location: found.location },
        };
        if (options.respondWith) detection.respondWith = options.respondWith;
        return detection;
      }
      return undefined;
    },
  };
}
