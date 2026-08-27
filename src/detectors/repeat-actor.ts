import type { Detection, DetectionContext, Detector } from "./types.js";

export interface RepeatActorOptions {
  score?: number;
  /** Distinct IPs one fingerprint must be seen attacking from to fire. Default 3. */
  distinctIpThreshold?: number;
  /** Sliding window for counting those IPs, in ms. Default 600000 (10 min). */
  windowMs?: number;
  respondWith?: string;
}

/**
 * Cross-IP actor correlation: fires when one **actor fingerprint** (header ordering +
 * UA family — see `computeFingerprint`) has been seen attacking from several distinct
 * source IPs in a short window, i.e. one actor rotating addresses to dodge per-IP
 * blocking.
 *
 * Critically, it reads the `FingerprintRegistry`, which the engine populates **only
 * from requests that already scored a detection**. So the IPs it counts are always
 * fellow *attackers* sharing this fingerprint — never benign traffic. That gating is
 * what keeps it safe in middleware mode mounted in front of a real app: three ordinary
 * users on the same browser build never reach the registry (they trip nothing), so
 * they can't be correlated into a phantom "rotating actor". This detector confirms
 * that two suspicious IPs are one actor; it never manufactures suspicion on its own.
 */
export function repeatActorDetector(options: RepeatActorOptions = {}): Detector {
  const score = options.score ?? 7;
  const threshold = options.distinctIpThreshold ?? 3;
  const windowMs = options.windowMs ?? 600_000;

  return {
    id: "repeat-actor",
    description: "One actor fingerprint seen attacking from several distinct IPs (IP rotation)",
    inspect(ctx: DetectionContext): Detection | undefined {
      // IPs (other than this one) that this fingerprint has attacked from recently.
      // The current IP isn't in the registry yet — the engine records it after a hit —
      // so we add 1 for it when comparing to the threshold.
      const others = ctx.fingerprintRegistry
        .ipsWithin(ctx.fingerprint, windowMs, ctx.timestamp.getTime())
        .filter((ip) => ip !== ctx.ip);
      const distinct = others.length + 1;
      if (distinct < threshold) return undefined;

      const detection: Detection = {
        detectorId: "repeat-actor",
        reason: `Actor fingerprint ${ctx.fingerprint} seen attacking from ${distinct} IPs in ${Math.round(windowMs / 60_000)}m (rotation): ${others.slice(0, 5).join(", ")}${others.length > 5 ? ", …" : ""}`,
        score,
        metadata: { fingerprint: ctx.fingerprint, distinctIps: distinct, otherIps: others.slice(0, 20) },
      };
      if (options.respondWith) detection.respondWith = options.respondWith;
      return detection;
    },
  };
}
