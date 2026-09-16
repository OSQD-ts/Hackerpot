import { describe, expect, it } from "vitest";
import { SUSPICION_CEILING, confidenceOf, tierOf, tierOfConfidence } from "../src/evidence.js";
import type { Detection } from "../src/detectors/types.js";

/**
 * The question tiers exist to answer: can a pile of forgivable findings ever look like proof?
 */

const finding = (over: Partial<Detection> = {}): Detection => ({ detectorId: "test", reason: "test", score: 4, ...over });

describe("what tier a finding is", () => {
  it("reads the bands the detectors were already written against", () => {
    // 3-5: a finding with ordinary innocent explanations.
    expect(tierOf(finding({ score: 4 }))).toBe("weak");
    // 6-8: a clear probe.
    expect(tierOf(finding({ score: 7 }))).toBe("moderate");
    // 9-10: an exploit payload or a credential attack.
    expect(tierOf(finding({ score: 10 }))).toBe("strong");
    // Proof is proof whatever it scored.
    expect(tierOf(finding({ score: 1, certain: true }))).toBe("certain");
  });

  it("lets a detector say so itself", () => {
    // A high score that is still only suspicion, and a low one that is not.
    expect(tierOf(finding({ score: 12, tier: "weak" }))).toBe("weak");
    expect(tierOf(finding({ score: 2, tier: "strong" }))).toBe("strong");
  });
});

describe("combining evidence", () => {
  it("is worth less each time rather than adding up", () => {
    const one = confidenceOf([finding()]);
    const two = confidenceOf([finding(), finding({ detectorId: "other" })]);
    const three = confidenceOf([finding(), finding({ detectorId: "other" }), finding({ detectorId: "third" })]);

    expect(one).toBeCloseTo(0.25);
    expect(two).toBeCloseTo(0.4375);
    // Rising, but by less each time: the third finding adds less than the second.
    expect(three - two).toBeLessThan(two - one);
  });

  it("never lets suspicion alone look like proof", () => {
    // Fifteen forgivable findings — the shape that summed to 49 for a real visitor.
    const many = Array.from({ length: 15 }, (_, i) => finding({ detectorId: `d${i}` }));
    const confidence = confidenceOf(many);

    expect(confidence).toBeLessThanOrEqual(SUSPICION_CEILING);
    expect(confidence).toBeLessThan(1);
    expect(tierOfConfidence(confidence)).not.toBe("certain");
  });

  it("reaches certainty only on proof", () => {
    expect(confidenceOf([finding({ score: 15, certain: true })])).toBe(1);
    // And proof is not diluted by the forgivable findings around it.
    expect(confidenceOf([finding(), finding({ score: 15, certain: true }), finding({ detectorId: "other" })])).toBe(1);
  });

  it("counts one root cause once", () => {
    const traversal = [
      finding({ detectorId: "payload-injection", score: 10, family: "path-traversal" }),
      finding({ detectorId: "target-integrity", score: 7, family: "path-traversal" }),
    ];
    // The strongest of the family, and nothing added for seeing it twice.
    expect(confidenceOf(traversal)).toBeCloseTo(0.8);
    expect(confidenceOf(traversal)).toBe(confidenceOf([traversal[0]!]));
  });

  it("is zero when nothing fired", () => {
    expect(confidenceOf([])).toBe(0);
  });

  it("says in words what a confidence amounts to", () => {
    expect(tierOfConfidence(0.1)).toBe("weak");
    expect(tierOfConfidence(0.5)).toBe("moderate");
    expect(tierOfConfidence(0.8)).toBe("strong");
    expect(tierOfConfidence(1)).toBe("certain");
  });
});
