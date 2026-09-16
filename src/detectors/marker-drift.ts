import type { Detection, DetectionContext, Detector } from "./types.js";

export interface MarkerDriftOptions {
  score?: number;
  /** Distinct addresses one marker must be presented from to fire. Default 3. */
  distinctIpThreshold?: number;
  /** Sliding window for counting them, in ms. Default 600000 (10 min). */
  windowMs?: number;
  respondWith?: string;
}

/**
 * One marked client, arriving from several addresses.
 *
 * `repeat-actor` correlates a rotating attacker by their [fingerprint](../fingerprint.ts) —
 * header order plus client family — which works while the tooling stays identical and stops
 * working the moment it does not: a browser-driven attack, or one tool swapped for another
 * mid-session, looks like several actors. A [marker](../marker.ts) survives that, because it
 * is the same value coming back regardless of how the next request is made.
 *
 * What it is safe to conclude is narrow, and the narrowness is the point:
 *
 * - The marker is only ever issued to somebody the honeypot **already answered as a probe**,
 *   so every marked client was an incident before this detector saw it. This is escalation,
 *   not a new accusation.
 * - It is signed, so a marker that was edited or minted is not a marker at all.
 * - It is still only correlation. A cookie can be copied, including out of somebody else's
 *   traffic, so this is never proof and adds a modest score — enough to say "the same client
 *   as those earlier incidents", never enough to convict on its own.
 *
 * Adapted from bothandlerjs.
 */
export function markerDriftDetector(options: MarkerDriftOptions = {}): Detector {
  const score = options.score ?? 7;
  const threshold = options.distinctIpThreshold ?? 3;
  const windowMs = options.windowMs ?? 600_000;

  return {
    id: "marker-drift",
    description: "One marked client presenting the same marker from several addresses (rotation)",
    inspect(ctx: DetectionContext): Detection | undefined {
      const marker = ctx.marker;
      // No marker, or one we did not issue: nothing to correlate. A rejected marker is
      // deliberately indistinguishable from none — see `MarkerCookie.read`.
      if (marker === undefined) return undefined;

      // Markers share the registry the fingerprints use: it is keyed by a string and written
      // only for requests that already scored, which is exactly the gate this needs. The
      // prefix keeps the two key spaces from ever colliding.
      const earlier = ctx.fingerprintRegistry.ipsWithin(`marker:${marker}`, windowMs, ctx.timestamp.getTime());
      // The registry is written after the detectors run, so it holds the addresses this
      // marker arrived from *before* this request. This one counts too: a verified marker
      // says it is the same client, and "now at a third address" is the signal itself.
      const seen = earlier.includes(ctx.ip) ? earlier : [...earlier, ctx.ip];
      if (seen.length < threshold) return undefined;

      const others = seen.filter((ip) => ip !== ctx.ip);
      const detection: Detection = {
        detectorId: "marker-drift",
        reason: `One marked client seen from ${seen.length} addresses in ${Math.round(windowMs / 60_000)}m (rotation): ${others.slice(0, 5).join(", ")}${others.length > 5 ? ", …" : ""}`,
        score,
        // The same act `repeat-actor` may also see: one actor, several addresses. Counted once.
        family: "actor-rotation",
        metadata: { distinctIps: seen.length, otherIps: others.slice(0, 20) },
      };
      if (options.respondWith) detection.respondWith = options.respondWith;
      return detection;
    },
  };
}
