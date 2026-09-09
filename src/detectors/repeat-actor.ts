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
      // Every IP the registry has confirmed suspicious under this fingerprint. The
      // registry only ever holds IPs whose requests already scored, so this is a list
      // of attackers — never of benign traffic.
      const seen = ctx.fingerprintRegistry.ipsWithin(ctx.fingerprint, windowMs, ctx.timestamp.getTime());

      // This IP must be one of them. That is the whole difference between *confirming*
      // that two suspicious IPs are one actor and *manufacturing* suspicion for
      // whoever happens to share a fingerprint — and a fingerprint is header order plus
      // UA family, which every user of one browser build on one site shares.
      //
      // The count used to be `others.length + 1`, adding the current IP on the grounds
      // that the engine records it only after a hit. That is true, but it assumed this
      // request was already suspicious, which this detector cannot know: detectors run
      // independently and their results are collected afterwards. So with the threshold
      // at 3, two real attackers were enough to make every later request carrying that
      // fingerprint fire — and because firing is itself a hit, each such request wrote
      // its own IP into the registry, raising the count and guaranteeing the next one
      // fired too. Measured: after two attackers probed a decoy, six of six ordinary
      // browser requests to an ordinary page were flagged, and a single visitor reached
      // a cumulative 49 — past the default block threshold of 40 — in seven page views.
      // Mounted as middleware in front of a real application, that blocks customers.
      //
      // Requiring membership makes this purely an escalation signal, which is what the
      // documentation above has always promised. A rotating attacker is unaffected in
      // substance: each of their IPs enters the registry on its own first scoring
      // request, so the correlation still fires — from that IP's next request onward.
      if (!seen.includes(ctx.ip)) return undefined;

      const others = seen.filter((ip) => ip !== ctx.ip);
      const distinct = seen.length;
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
