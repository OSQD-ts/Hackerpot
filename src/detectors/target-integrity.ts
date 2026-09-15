import type { Detection, DetectionContext, Detector } from "./types.js";

export interface TargetIntegrityOptions {
  /** Score for a target spelled to evade: double-encoded, an encoded control character, or an encoded traversal. Default 7. */
  score?: number;
  /** Score for the ambiguous cases a broken client also produces: a plain `..`, or an encoded slash inside a segment. Default 3. */
  weakScore?: number;
  respondWith?: string;
}

const ENCODED_SEPARATOR = /%2e|%2f|%5c/i;
const ENCODED_SLASH = /%2f|%5c/i;
/** A percent sign that was itself percent-encoded, followed by more hex. */
const DOUBLE_ENCODED = /%25[0-9a-f]{2}/i;
/** The whole C0 range and DEL, including `%0a`/`%0d`: nothing legitimate puts one in a path. */
const ENCODED_CONTROL = /%0[0-9a-f]|%1[0-9a-f]|%7f/i;
/** Dots written out or spelled: `..`, `%2e%2e`, `%2e.`, `.%2e`. */
const TRAVERSAL = /\.\.|%2e%2e|%2e\.|\.%2e/i;
const ABSOLUTE_FORM = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * Request targets spelled to get past a filter rather than to fetch something.
 *
 * Every other detector reads the normalised `path`, where `/%2e%2e%2f%2e%2e%2fapp.yml`
 * has become `/app.yml`: the one fact that made it interesting is gone. This reads
 * `rawPath`, which is only present when normalisation changed something, so ordinary
 * traffic costs one property read. An absolute-form target is left to `header-anomaly`.
 *
 * An encoded traversal is usually also a traversal payload, so traversal findings share
 * the `path-traversal` family with `payload-injection` and are counted once. Adapted
 * from bothandlerjs.
 */
export function targetIntegrityDetector(options: TargetIntegrityOptions = {}): Detector {
  const score = options.score ?? 7;
  const weakScore = options.weakScore ?? 3;

  return {
    id: "target-integrity",
    description: "Request target is spelled to evade path filters",
    inspect(ctx: DetectionContext): Detection | undefined {
      const raw = ctx.rawPath;
      if (raw === undefined || ABSOLUTE_FORM.test(raw)) return undefined;

      const strong: string[] = [];
      const weak: string[] = [];
      if (DOUBLE_ENCODED.test(raw)) strong.push("double-encoded");
      if (ENCODED_CONTROL.test(raw)) strong.push("encoded control character");
      const traversal = TRAVERSAL.test(raw);
      if (traversal) {
        if (ENCODED_SEPARATOR.test(raw)) strong.push("encoded directory traversal");
        else weak.push("directory traversal");
      } else if (ENCODED_SLASH.test(raw)) {
        weak.push("encoded path separator");
      }
      if (strong.length === 0 && weak.length === 0) return undefined;

      const findings = [...strong, ...weak];
      const detection: Detection = {
        detectorId: "target-integrity",
        reason: `Request target is ${findings.join(", ")}`,
        score: strong.length > 0 ? score : weakScore,
        family: traversal ? "path-traversal" : "evasive-target",
        metadata: { findings, target: raw.length > 200 ? `${raw.slice(0, 200)}…` : raw },
      };
      if (options.respondWith) detection.respondWith = options.respondWith;
      return detection;
    },
  };
}
