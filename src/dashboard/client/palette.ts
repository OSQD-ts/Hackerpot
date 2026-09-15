/**
 * Which colour a mark wears, as a class name rather than a colour.
 *
 * The colours themselves are tokens in `page.ts`, one set per scheme: the categorical
 * slots are the same eight hues stepped separately for the light and the dark surface,
 * validated against each (lightness band, chroma floor, colour-vision separation of
 * adjacent slots). A mark therefore carries `fill-s3`, and the theme decides what that
 * is. Switching schemes restyles every chart without redrawing one, and nothing in the
 * client ever writes a hex value into the page.
 *
 * Slots are assigned in fixed order and never cycled: a ninth series folds into "other".
 */

export const CATEGORICAL_SLOTS = 8;

/** `s1` to `s8`, or `so` (other) past the last slot or for a negative one. */
export function slot(index: number): string {
  return index >= 0 && index < CATEGORICAL_SLOTS ? `s${index + 1}` : "so";
}

/** Steps in the sequential ramp, not counting the empty cell. */
export const SEQUENTIAL_STEPS = 12;

/**
 * The sequential step for a heat cell: `0` is "nothing here" and has its own neutral,
 * `1` to `12` run from near-zero to the maximum. One hue throughout, so darker (or, on
 * the dark surface, brighter) always means more.
 */
export function sequentialStep(value: number, max: number): number {
  if (!(value > 0) || !(max > 0)) return 0;
  return Math.max(1, Math.min(SEQUENTIAL_STEPS, Math.floor((value / max) * (SEQUENTIAL_STEPS - 1) + 1.0001)));
}

/** Five ordered steps for the escalation funnel, lightest-to-strongest by stage. */
export function ordinalStep(stage: number): string {
  return `o${Math.max(1, Math.min(5, stage + 1))}`;
}
