import { describe, expect, it } from "vitest";
import { FeedCounts } from "../src/dashboard/counts.js";
import { ManualClock } from "../src/internal/clock.js";

/**
 * The count the page shows has to mean "how many happened", not "how many survived eviction".
 * These are the two things that made the old number a lie: a bounded list, and a window the
 * list could not speak for.
 */

const MINUTE = 60_000;
const START = Date.UTC(2026, 8, 16, 12, 0, 0);

describe("counting apart from holding", () => {
  it("counts far more than anything is holding, at constant cost", () => {
    const clock = new ManualClock(START);
    const counts = new FeedCounts({ clock });
    // Ten thousand incidents across a day. A page holding a hundred rows can say so.
    for (let i = 0; i < 10_000; i += 1) counts.record(START + (i % 1_440) * MINUTE);
    expect(counts.total).toBe(10_000);
    expect(counts.snapshot().series.length).toBeLessThanOrEqual(1_440);
  });

  it("answers for a window, either end open", () => {
    const clock = new ManualClock(START + 120 * MINUTE);
    const counts = new FeedCounts({ clock });
    for (let i = 0; i < 120; i += 1) counts.record(START + i * MINUTE);

    // The last hour, from a clock two hours after the first record.
    expect(counts.count(START + 60 * MINUTE)).toBe(60);
    expect(counts.count(undefined, START + 9 * MINUTE)).toBe(10);
    expect(counts.snapshot(60 * MINUTE).total).toBe(60);
    expect(counts.snapshot().total).toBe(120);
  });

  it("says how far back it can speak for", () => {
    const clock = new ManualClock(START);
    const counts = new FeedCounts({ clock });
    expect(counts.snapshot().oldest).toBeUndefined();
    counts.record(START);
    expect(counts.snapshot().oldest).toBe(START);
  });

  it("forgets what it no longer speaks for", () => {
    const clock = new ManualClock(START);
    const counts = new FeedCounts({ retainMs: 60 * MINUTE, clock });
    for (let i = 0; i < 120; i += 1) counts.record(START + i * MINUTE);

    clock.set(START + 200 * MINUTE);
    counts.prune();
    // Everything is older than the hour retained, so it says nothing rather than answering
    // for a stretch it has forgotten.
    expect(counts.total).toBe(0);
    expect(counts.snapshot().oldest).toBeUndefined();
  });

  it("stays bounded even when retention is switched off", () => {
    const clock = new ManualClock(START);
    const counts = new FeedCounts({ retainMs: 0, clock });
    // Eight days of minutes, one incident each: the ceiling, not the retention, is what holds.
    for (let i = 0; i < 8 * 24 * 60; i += 1) counts.record(START + i * MINUTE);
    expect(counts.snapshot().series.length).toBe(7 * 24 * 60);
  });

  it("takes an out-of-order timestamp without losing it", () => {
    const clock = new ManualClock(START);
    const counts = new FeedCounts({ clock });
    counts.record(START + 5 * MINUTE);
    counts.record(START);
    counts.record(START + 2 * MINUTE);
    counts.record(START + 2 * MINUTE);

    expect(counts.total).toBe(4);
    expect(counts.snapshot().series.map((bucket) => bucket.at)).toEqual([START, START + 2 * MINUTE, START + 5 * MINUTE]);
  });

  it("reads the clock when nobody says when", () => {
    const clock = new ManualClock(START);
    const counts = new FeedCounts({ clock });
    counts.record();
    expect(counts.snapshot().oldest).toBe(START);
  });
});
