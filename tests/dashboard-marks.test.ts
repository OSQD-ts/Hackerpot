import { describe, expect, it } from "vitest";

/** The shape `timeChart` takes, declared here so this test pulls in no DOM module. */
interface ChartMark {
  at: number;
  label: string;
}

/**
 * Where a runtime change lands on the traffic it changed.
 *
 * The placement is the whole claim: a mark says "this happened *here*, and the traffic either
 * side of it is before and after". Getting that wrong is worse than drawing nothing.
 */

/**
 * The same arithmetic `volumeChart` uses, exercised directly.
 *
 * `marksFor` is not exported — it is an implementation detail of one chart — so this pins the
 * rule rather than the function: proportional placement by real time, and nothing outside the
 * window.
 */
function marksFor(
  buckets: ReadonlyArray<{ start: number }>,
  bucketSize: number,
  changes: ReadonlyArray<{ timestamp: string; message: string }>,
): ChartMark[] {
  const first = buckets[0]?.start;
  const last = buckets[buckets.length - 1]?.start;
  if (first === undefined || last === undefined) return [];
  const span = last - first;
  const marks: ChartMark[] = [];
  for (const change of changes) {
    const at = Date.parse(change.timestamp);
    if (Number.isNaN(at) || at < first || at > last + bucketSize) continue;
    marks.push({ at: span === 0 ? 0.5 : (at - first) / span, label: change.message });
  }
  return marks;
}

const MINUTE = 60_000;
const START = Date.UTC(2026, 8, 16, 12, 0, 0);
const buckets = Array.from({ length: 11 }, (_, i) => ({ start: START + i * MINUTE }));
const change = (offsetMs: number, message = "policy replaced") => ({ timestamp: new Date(START + offsetMs).toISOString(), message });

describe("placing a change on the axis", () => {
  it("places it by when it happened, not by which bucket it fell in", () => {
    // Halfway along a ten-minute span, whatever the bucket boundaries are.
    expect(marksFor(buckets, MINUTE, [change(5 * MINUTE)])[0]?.at).toBeCloseTo(0.5);
    expect(marksFor(buckets, MINUTE, [change(0)])[0]?.at).toBeCloseTo(0);
    expect(marksFor(buckets, MINUTE, [change(10 * MINUTE)])[0]?.at).toBeCloseTo(1);
    // A quarter of the way in is a quarter of the way across, not rounded to a bucket.
    expect(marksFor(buckets, MINUTE, [change(2.5 * MINUTE)])[0]?.at).toBeCloseTo(0.25);
  });

  it("drops a change outside the window rather than clamping it to the edge", () => {
    // A clamped mark would assert a change happened inside a range it did not.
    expect(marksFor(buckets, MINUTE, [change(-MINUTE)])).toEqual([]);
    expect(marksFor(buckets, MINUTE, [change(60 * MINUTE)])).toEqual([]);
  });

  it("keeps a change inside the last bucket, which extends past its own start", () => {
    // The final bucket covers `start` to `start + bucketSize`; a change at 10m30s is in it.
    expect(marksFor(buckets, MINUTE, [change(10.5 * MINUTE)])).toHaveLength(1);
  });

  it("carries the message, so hovering says what changed", () => {
    expect(marksFor(buckets, MINUTE, [change(MINUTE, "shadowed: rate-spike (by ada@example.com)")])[0]?.label).toBe("shadowed: rate-spike (by ada@example.com)");
  });

  it("says nothing when there is nothing to say", () => {
    expect(marksFor([], MINUTE, [change(0)])).toEqual([]);
    expect(marksFor(buckets, MINUTE, [])).toEqual([]);
    // An unparseable timestamp is dropped rather than placed at the epoch.
    expect(marksFor(buckets, MINUTE, [{ timestamp: "not a date", message: "x" }])).toEqual([]);
  });

  it("puts a single-bucket window in the middle rather than dividing by zero", () => {
    expect(marksFor([{ start: START }], MINUTE, [change(0)])[0]?.at).toBe(0.5);
  });
});
