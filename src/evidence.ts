import type { Detection } from "./detectors/types.js";

/**
 * How strong the evidence is, as opposed to how much of it there is.
 *
 * Scores answer "how much": small integers, added up, compared against a threshold. That
 * works, and it has one failure mode this project has already been bitten by — many weak
 * findings sum to a number that looks like proof. The comment in `repeat-actor` records the
 * measurement: an ordinary visitor reached a cumulative 49, past the default block threshold
 * of 40, in seven page views, because a shared browser fingerprint and a page load's worth of
 * asset paths each contributed a few points. Addition cannot tell "one damning finding" from
 * "fifteen forgivable ones", and in front of real users the difference is a customer.
 *
 * Tiers answer "how strong", and combine by **noisy-OR** rather than by addition:
 *
 *     confidence = 1 - Π (1 - weight(tier))
 *
 * Independent evidence raises confidence, with each addition worth less than the last, and —
 * the point — suspicion alone is capped below certainty. Only {@link CERTAIN} evidence, the
 * kind no legitimate client can produce, reaches 1.
 *
 * Nothing here replaces scores. Scores still drive the ladder, the thresholds and the stored
 * per-address total; confidence is the second view, for a policy that would rather say "act on
 * strong evidence" than "act on the number 40". Adapted from bothandlerjs.
 */
export type EvidenceTier = "weak" | "moderate" | "strong" | "certain";

/**
 * What one finding at each tier is worth.
 *
 * Read as "how much of the way to acting on it does this alone get you": a weak finding a
 * quarter, a clear probe half, an exploit payload most of it, proof all of it.
 */
export const TIER_WEIGHT: Record<EvidenceTier, number> = {
  weak: 0.25,
  moderate: 0.5,
  strong: 0.8,
  certain: 1,
};

/**
 * The ceiling on confidence built from suspicion alone.
 *
 * Without it, noisy-OR walks to 1 given enough weak findings — the same failure as addition,
 * reached more slowly. Ten weak findings are not proof of anything; they are ten weak
 * findings. So only a `certain` detection reaches 1, and everything else asymptotes here.
 */
export const SUSPICION_CEILING = 0.95;

/** Score at or above which a finding is treated as strong, when it names no tier. */
const STRONG_SCORE = 9;
/** Score at or above which a finding is treated as moderate. */
const MODERATE_SCORE = 6;

/**
 * The tier of one detection.
 *
 * An explicit `tier` wins. Otherwise it is derived from what the detector already says: proof
 * is `certain`, and the score bands are the ones the detectors were written against — 3-5 for
 * a finding with ordinary innocent explanations, 6-8 for a clear probe, 9+ for an exploit or a
 * credential attack. So every existing detector gets a sensible tier without being touched.
 */
export function tierOf(detection: Detection): EvidenceTier {
  if (detection.tier !== undefined) return detection.tier;
  if (detection.certain === true) return "certain";
  if (detection.score >= STRONG_SCORE) return "strong";
  if (detection.score >= MODERATE_SCORE) return "moderate";
  return "weak";
}

/**
 * Confidence that this request is what its detections say it is, in [0, 1].
 *
 * One root cause counts once, exactly as it does for scores: within a family only the
 * strongest tier contributes, because an encoded traversal seen by two detectors is one act,
 * not two independent reasons to believe.
 */
export function confidenceOf(detections: readonly Detection[]): number {
  if (detections.length === 0) return 0;

  const strongestByFamily = new Map<string, number>();
  const independent: number[] = [];
  for (const detection of detections) {
    const weight = TIER_WEIGHT[tierOf(detection)];
    if (detection.family === undefined) independent.push(weight);
    else strongestByFamily.set(detection.family, Math.max(strongestByFamily.get(detection.family) ?? 0, weight));
  }

  let doubt = 1;
  let proven = false;
  for (const weight of [...independent, ...strongestByFamily.values()]) {
    if (weight >= 1) proven = true;
    doubt *= 1 - weight;
  }
  // Proof is proof: it does not get diluted by the company it keeps, and nothing short of it
  // is allowed to look like it.
  return proven ? 1 : Math.min(1 - doubt, SUSPICION_CEILING);
}

/** The tier a confidence corresponds to, for reporting it in words rather than a decimal. */
export function tierOfConfidence(confidence: number): EvidenceTier {
  if (confidence >= 1) return "certain";
  if (confidence >= TIER_WEIGHT.strong) return "strong";
  if (confidence >= TIER_WEIGHT.moderate) return "moderate";
  return "weak";
}
