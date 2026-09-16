import { describe, expect, it } from "vitest";
import { candidatePolicy, parseRules, previewPolicy } from "../src/dashboard/preview.js";
import type { Incident } from "../src/management/types.js";

/**
 * Previewing a rule set is only honest because a policy is pure. These tests pin the two
 * halves of that honesty: the answer matches what the engine would decide, and the preview
 * does not claim to know things a recorded incident cannot tell it.
 */

const incident = (over: Partial<Incident> = {}): Incident =>
  ({
    id: "a",
    timestamp: "2026-09-16T12:00:00.000Z",
    ip: "203.0.113.40",
    method: "GET",
    path: "/wp-login.php",
    headers: {},
    detections: [{ detectorId: "decoy-path", reason: "probe", score: 10 }],
    score: 10,
    totalScore: 10,
    respondedWith: "not-found",
    ...over,
  }) as Incident;

describe("replaying a candidate policy", () => {
  it("reports only what would be answered differently", () => {
    const rules = parseRules([{ id: "dotfiles", respondWith: "tarpit", match: { path: ["/wp-"] } }]);
    const result = previewPolicy([incident(), incident({ id: "b", path: "/pricing", respondedWith: "not-found" })], candidatePolicy(rules));

    expect(result.total).toBe(2);
    expect(result.unchanged).toBe(1);
    expect(result.changed).toEqual([
      { id: "a", ip: "203.0.113.40", path: "/wp-login.php", was: "not-found", now: "tarpit", rule: "dotfiles", reason: 'Matched rule "dotfiles".' },
    ]);
  });

  it("skips incidents the policy was never consulted for", () => {
    const result = previewPolicy([incident({ detections: [] })], candidatePolicy([]));
    expect(result).toMatchObject({ total: 0, skipped: 1, changed: [] });
  });

  it("shows the proof guard refusing a block the rules asked for", () => {
    const rules = parseRules([{ id: "strict", respondWith: "block", match: {}, reason: "Anything probing this host is hostile." }]);
    const result = previewPolicy([incident()], candidatePolicy(rules));

    // Nothing here is proof, so middleware mode would not have blocked — and the preview says
    // so rather than showing a block that would never have happened.
    expect(result.changed[0]).toMatchObject({ now: "tarpit", downgradedFrom: "block", rule: "strict" });
  });

  it("shows the block itself when the evidence is proof", () => {
    const rules = parseRules([{ id: "strict", respondWith: "block", match: {} }]);
    const proven = incident({ detections: [{ detectorId: "honeytoken", reason: "replayed", score: 15, certain: true }] });
    expect(previewPolicy([proven], candidatePolicy(rules)).changed[0]).toMatchObject({ now: "block", rule: "strict" });
  });

  it("can be read for standalone mode, where nothing is downgraded", () => {
    const rules = parseRules([{ id: "strict", respondWith: "block", match: {} }]);
    const result = previewPolicy([incident()], candidatePolicy(rules), { blockRequiresProof: false });
    expect(result.changed[0]).toMatchObject({ now: "block" });
    expect(result.changed[0]?.downgradedFrom).toBeUndefined();
  });

  it("treats a rule that throws as one that did not match", () => {
    const policy = (): never => {
      throw new Error("somebody's predicate is wrong");
    };
    expect(() => previewPolicy([incident()], policy)).not.toThrow();
    expect(previewPolicy([incident()], policy)).toMatchObject({ unchanged: 1, changed: [] });
  });
});

describe("reading a posted draft", () => {
  it("accepts the fields a rule is made of", () => {
    const rules = parseRules([
      {
        id: "admin-bruteforce",
        respondWith: "rate-limit",
        reason: "Password guessing against the admin login.",
        match: { detector: "credential-bruteforce", path: ["/admin"], pathPattern: ["/wp-.*\\.php$"], method: ["POST"], minScore: 5, minConfidence: 0.5, ip: ["10.0.0.0/8"], certain: false },
      },
    ]);
    expect(rules[0]?.id).toBe("admin-bruteforce");
    const match = rules[0]?.match as { path: Array<string | RegExp>; detector: string[] };
    expect(match.detector).toEqual(["credential-bruteforce"]);
    // Prefixes and patterns are separate keys, so neither is guessed at. JSON has no RegExp.
    expect(match.path[0]).toBe("/admin");
    expect(match.path[1]).toBeInstanceOf(RegExp);
  });

  it("refuses a draft it would have to guess about", () => {
    expect(() => parseRules("nope")).toThrow(/must be an array/);
    expect(() => parseRules([{ respondWith: "block" }])).toThrow(/id must be a non-empty string/);
    expect(() => parseRules([{ id: "x" }])).toThrow(/respondWith must be a non-empty string/);
    expect(() => parseRules([{ id: "same", respondWith: "block" }, { id: "same", respondWith: "tarpit" }])).toThrow(/used twice/);
    expect(() => parseRules([{ id: "x", respondWith: "block", match: [] }])).toThrow(/match must be an object/);
    expect(() => parseRules([{ id: "x", respondWith: "block", match: { minScore: "high" } }])).toThrow(/must be a number/);
    expect(() => parseRules([{ id: "x", respondWith: "block", match: { pathPattern: ["/([unclosed/"] } }])).toThrow(/not a valid regular expression/);
    expect(() => parseRules(Array.from({ length: 101 }, (_, i) => ({ id: `r${i}`, respondWith: "block" })))).toThrow(/at most 100/);
  });

  it("strips a stateful flag from a pattern, as the rest of the library does", () => {
    const rules = parseRules([{ id: "x", respondWith: "block", match: { pathPattern: ["/wp-/g"] } }]);
    const pattern = (rules[0]?.match as { path: RegExp[] }).path[0] as RegExp;
    // A `g` flag would make `.test()` match every other request.
    expect(pattern.flags).not.toContain("g");
  });
});
