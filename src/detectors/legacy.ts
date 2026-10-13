import type { HoneypotHit } from "../types.js";
import type { Detection } from "./types.js";

/**
 * A detection as this library shaped it before its field names matched bothandlerjs's:
 * `detectorId` where there is now `detector`, `reason` where there is now `summary`.
 *
 * The rename is only worth making if nothing already written breaks on it, so the old shape is
 * still accepted everywhere one can arrive from outside this release: returned by a detector
 * somebody wrote against the old names, read back from a file, Redis or Elasticsearch store
 * that recorded it, or served by an older honeypot's management API to a newer dashboard. Each
 * of those upgrades it on the way in, and everything past that point sees one shape.
 *
 * @deprecated Return a {@link Detection}. Still accepted from a detector, and still read from
 * storage, for a release.
 */
export type LegacyDetection = Omit<Detection, "detector" | "summary"> & { detectorId: string; reason: string };

/** A detection in the current shape, whichever shape it arrived in. */
export function upgradeDetection(value: Detection | LegacyDetection): Detection {
  if (typeof (value as Partial<Detection>).detector === "string") return value as Detection;
  const { detectorId, reason, ...rest } = value as LegacyDetection;
  return { ...rest, detector: detectorId, summary: reason };
}

/** A recorded hit with every detection in the current shape. Returns the same object when nothing needed upgrading. */
export function upgradeHit<T extends HoneypotHit>(hit: T): T {
  const stale = (list: readonly unknown[] | undefined): boolean => list !== undefined && list.some((d) => typeof (d as Partial<Detection>).detector !== "string");
  if (!Array.isArray(hit.detections) || (!stale(hit.detections) && !stale(hit.shadowDetections))) return hit;
  return {
    ...hit,
    detections: hit.detections.map(upgradeDetection),
    ...(hit.shadowDetections !== undefined ? { shadowDetections: hit.shadowDetections.map(upgradeDetection) } : {}),
  };
}
