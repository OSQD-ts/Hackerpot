import { describe, expect, it } from "vitest";
import { baselineOf, compareToBaseline, isServed, parseBaseline } from "../src/corpus/compare.js";
import type { CaseResult, Scorecard } from "../src/corpus/runner.js";
import type { TrafficCase } from "../src/corpus/schema.js";

/**
 * The question a corpus run cannot answer on its own: did anything that used to be served
 * stop being served? A case can meet its expectations before and after a change and still
 * have moved from "answered normally" to "tarpitted".
 */

const caseOf = (id: string, audience: TrafficCase["audience"] = "human"): TrafficCase =>
  ({ id, audience, title: id, category: "browsing", provenance: "test", requests: [], expect: {} }) as unknown as TrafficCase;

const result = (id: string, actionId: string, over: Partial<CaseResult> = {}): CaseResult => ({
  case: caseOf(id),
  requests: [{ detections: [], actionId }],
  fired: actionId === "" ? [] : ["decoy-path"],
  failures: [],
  falsePositive: false,
  knownCost: false,
  durationMs: 1,
  ...over,
});

const scorecardOf = (results: CaseResult[]): Scorecard =>
  ({ results, total: results.length, passed: results.length, failed: 0, skipped: [], falsePositives: [], knownCosts: [], byAudience: {}, byCategory: {}, detectorCoverage: {}, unexercisedDetectors: [], durationMs: 1 }) as unknown as Scorecard;

describe("recording a run", () => {
  it("keeps which side of the line each case came down on", () => {
    const baseline = baselineOf(scorecardOf([result("served-case", ""), result("tarpitted-case", "tarpit")]));
    expect(baseline.version).toBe(1);
    expect(baseline.cases).toEqual([
      { id: "served-case", audience: "human", served: true, actionId: "", fired: [], passed: true },
      { id: "tarpitted-case", audience: "human", served: false, actionId: "tarpit", fired: ["decoy-path"], passed: true },
    ]);
  });

  it("leaves out a case that did not run, which has no behaviour to record", () => {
    const baseline = baselineOf(scorecardOf([result("ran", ""), result("skipped", "", { skipped: "needs DNS" })]));
    expect(baseline.cases.map((record) => record.id)).toEqual(["ran"]);
  });

  it("calls a case served when the honeypot answered nothing", () => {
    expect(isServed(result("a", ""))).toBe(true);
    expect(isServed(result("a", "not-found"))).toBe(false);
  });
});

describe("comparing against a recorded run", () => {
  const before = baselineOf(scorecardOf([result("visitor", ""), result("scanner", "block"), result("gone", "")]));

  it("reports traffic that lost service", () => {
    const comparison = compareToBaseline(before, scorecardOf([result("visitor", "tarpit"), result("scanner", "block"), result("gone", "")]));
    expect(comparison.regressions).toEqual([{ id: "visitor", audience: "human", was: "served", now: "tarpit" }]);
    expect(comparison.improvements).toEqual([]);
  });

  it("reports traffic that gained it, without failing on it", () => {
    const comparison = compareToBaseline(before, scorecardOf([result("visitor", ""), result("scanner", ""), result("gone", "")]));
    expect(comparison.regressions).toEqual([]);
    expect(comparison.improvements).toEqual([{ id: "scanner", audience: "human", was: "block", now: "served" }]);
  });

  it("counts a case that stopped meeting its expectations as a regression", () => {
    const now = scorecardOf([result("visitor", "", { failures: ["expected decoy-path"] }), result("scanner", "block"), result("gone", "")]);
    expect(compareToBaseline(before, now).regressions).toEqual([{ id: "visitor", audience: "human", was: "served", now: "served (expectations unmet)" }]);
  });

  it("says what the two runs did not have in common", () => {
    const comparison = compareToBaseline(before, scorecardOf([result("visitor", ""), result("scanner", "block"), result("new-case", "")]));
    expect(comparison.missing).toEqual(["gone"]);
    expect(comparison.added).toEqual(["new-case"]);
    // Neither is a regression: a corpus that grew or a filtered run is not lost service.
    expect(comparison.regressions).toEqual([]);
  });
});

describe("reading a baseline file", () => {
  it("refuses anything it would have to guess about", () => {
    expect(() => parseBaseline(null)).toThrow(/not a corpus baseline/);
    expect(() => parseBaseline({ cases: "nope" })).toThrow(/not a corpus baseline/);
    expect(() => parseBaseline({ version: 2, cases: [] })).toThrow(/not one this build can read/);
    expect(parseBaseline({ version: 1, total: 0, cases: [] }).cases).toEqual([]);
  });
});
