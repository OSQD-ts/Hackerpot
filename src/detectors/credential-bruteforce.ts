import type { Detection, DetectionContext, Detector } from "./types.js";

export interface CredentialBruteforceOptions {
  /** Paths treated as authentication endpoints. Default matches common login/auth routes. */
  authPaths?: RegExp;
  /** Window to count attempts over. Default 60s. */
  windowMs?: number;
  /** Attempts against one auth path within the window before it counts as brute force. Default 8. */
  attemptThreshold?: number;
  score?: number;
  respondWith?: string;
}

const DEFAULT_AUTH_PATHS = /(login|signin|sign-in|auth|token|oauth|session|password|wp-login\.php)/i;

/**
 * Credential stuffing / password spraying: repeated submissions to the same
 * authentication endpoint from one IP. Scoped to auth-ish paths and to POST-like
 * methods so ordinary navigation to a login page never trips it.
 */
export function credentialBruteforceDetector(options: CredentialBruteforceOptions = {}): Detector {
  const authPaths = options.authPaths ?? DEFAULT_AUTH_PATHS;
  const windowMs = options.windowMs ?? 60_000;
  const threshold = options.attemptThreshold ?? 8;
  const score = options.score ?? 9;

  return {
    id: "credential-bruteforce",
    description: "Repeated authentication attempts against one endpoint from a single IP",
    inspect(ctx: DetectionContext): Detection | undefined {
      const method = ctx.method.toUpperCase();
      if (method !== "POST" && method !== "PUT" && method !== "PATCH") return undefined;
      if (!authPaths.test(ctx.path)) return undefined;

      const attempts = ctx.tracker.countPathIn(ctx.path, windowMs, ctx.timestamp.getTime());
      if (attempts < threshold) return undefined;

      const detection: Detection = {
        detectorId: "credential-bruteforce",
        reason: `${attempts} auth attempts against ${ctx.path} in ${Math.round(windowMs / 1000)}s`,
        score,
        metadata: { attempts, path: ctx.path, windowMs },
      };
      if (options.respondWith) detection.respondWith = options.respondWith;
      return detection;
    },
  };
}
