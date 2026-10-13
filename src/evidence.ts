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
 * Certainty answers "how strong", and combines by **noisy-OR** rather than by addition:
 *
 *     confidence = 1 - Π (1 - weight(certainty))
 *
 * Independent evidence raises confidence, with each addition worth less than the last, and —
 * the point — suspicion alone is capped below certainty. Only {@link CERTAIN} evidence, the
 * kind no legitimate client can produce, reaches 1.
 *
 * Nothing here replaces scores. Scores still drive the ladder, the thresholds and the stored
 * per-address total; confidence is the second view, for a policy that would rather say "act on
 * strong evidence" than "act on the number 40". Adapted from bothandlerjs.
 */
export type Certainty = "weak" | "moderate" | "strong" | "certain";

/** @deprecated Renamed {@link Certainty}, bothandlerjs's name for the same four values. */
export type EvidenceTier = Certainty;

/**
 * What one finding at each level of certainty is worth.
 *
 * Read as "how much of the way to acting on it does this alone get you": a weak finding a
 * quarter, a clear probe half, an exploit payload most of it, proof all of it.
 *
 * The name and the keys are bothandlerjs's; the values are this library's own. There the weights
 * feed a 0–1 bot score and are deliberately lower, because a bot score gates a challenge on every
 * page; here they feed a confidence that sits beside an additive score, over traffic that has
 * already reached a honeypot. The same word, calibrated for a different question.
 */
export const CERTAINTY_WEIGHT: Record<Certainty, number> = {
  weak: 0.25,
  moderate: 0.5,
  strong: 0.8,
  certain: 1,
};

/** @deprecated Renamed {@link CERTAINTY_WEIGHT}. */
export const TIER_WEIGHT = CERTAINTY_WEIGHT;

/**
 * The ceiling on confidence built from suspicion alone.
 *
 * Without it, noisy-OR walks to 1 given enough weak findings — the same failure as addition,
 * reached more slowly. Ten weak findings are not proof of anything; they are ten weak
 * findings. So only a `certain` detection reaches 1, and everything else asymptotes here.
 */
export const SUSPICION_CEILING = 0.95;

/** Score at or above which a finding is treated as strong, when it names no certainty. */
const STRONG_SCORE = 9;
/** Score at or above which a finding is treated as moderate. */
const MODERATE_SCORE = 6;

/**
 * The certainty of one detection.
 *
 * An explicit `certainty` wins — or `tier`, its name before it matched bothandlerjs's. Otherwise it is derived from what the detector already says: proof
 * is `certain`, and the score bands are the ones the detectors were written against — 3-5 for
 * a finding with ordinary innocent explanations, 6-8 for a clear probe, 9+ for an exploit or a
 * credential attack. So every existing detector gets a sensible certainty without being touched.
 */
export function certaintyOf(detection: Detection): Certainty {
  const explicit = detection.certainty ?? detection.tier;
  if (explicit !== undefined) return explicit;
  if (detection.certain === true) return "certain";
  if (detection.score >= STRONG_SCORE) return "strong";
  if (detection.score >= MODERATE_SCORE) return "moderate";
  return "weak";
}

/**
 * Confidence that this request is what its detections say it is, in [0, 1].
 *
 * One root cause counts once, exactly as it does for scores: within a family only the
 * strongest certainty contributes, because an encoded traversal seen by two detectors is one act,
 * not two independent reasons to believe.
 */
export function confidenceOf(detections: readonly Detection[]): number {
  if (detections.length === 0) return 0;

  const strongestByFamily = new Map<string, number>();
  const independent: number[] = [];
  for (const detection of detections) {
    const weight = CERTAINTY_WEIGHT[certaintyOf(detection)];
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

/** The certainty a confidence corresponds to, for reporting it in words rather than a decimal. */
export function certaintyOfConfidence(confidence: number): Certainty {
  if (confidence >= 1) return "certain";
  if (confidence >= CERTAINTY_WEIGHT.strong) return "strong";
  if (confidence >= CERTAINTY_WEIGHT.moderate) return "moderate";
  return "weak";
}

/** @deprecated Renamed {@link certaintyOf}. */
export const tierOf = certaintyOf;

/** @deprecated Renamed {@link certaintyOfConfidence}. */
export const tierOfConfidence = certaintyOfConfidence;
