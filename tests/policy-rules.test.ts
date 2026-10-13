import { describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import type { Detection } from "../src/detectors/types.js";
import type { RequestFacts } from "../src/detectors/types.js";
import { PRESETS, compileMatch, ladderPolicy, observe, protectApp, rulePolicy, standalone } from "../src/policy/index.js";
import type { PolicyContext } from "../src/policy/index.js";
import { buildPolicy } from "../src/config/build.js";
import { parseConfig } from "../src/config/schema.js";

/**
 * The policy as data: which rule decided, and whether the decision it recorded is the one an
 * operator would read back off the incident.
 */

const detection = (detector: string, over: Partial<Detection> = {}): Detection => ({ detector, summary: `${detector} fired`, score: 10, ...over });

const context = (over: Partial<PolicyContext> = {}): PolicyContext => ({
  detection: detection("decoy-path"),
  detections: [detection("decoy-path")],
  ip: "203.0.113.7",
  path: "/.env",
  method: "GET",
  score: 10,
  totalScore: 10,
  tracker: undefined as never,
  ...over,
});

const probe = (over: Partial<RequestFacts> = {}): RequestFacts => ({
  method: "GET",
  path: "/.env",
  query: {},
  headers: { host: "shop.example", "user-agent": "curl/8.4.0" },
  ip: "203.0.113.40",
  ...over,
});

describe("match specs", () => {
  it("matches on everything present and ignores everything absent", () => {
    expect(compileMatch({})(context())).toBe(true);
    expect(compileMatch({ detector: "decoy-path" })(context())).toBe(true);
    expect(compileMatch({ detector: ["nikto", "decoy-path"] })(context())).toBe(true);
    expect(compileMatch({ detector: "web-shell" })(context())).toBe(false);
  });

  it("reads a path as a prefix when it is a string and as a pattern when it is one", () => {
    expect(compileMatch({ path: "/." })(context())).toBe(true);
    expect(compileMatch({ path: "/wp-" })(context())).toBe(false);
    expect(compileMatch({ path: /\.env$/ })(context())).toBe(true);
    // A `g` flag would make the pattern stateful, matching every other request.
    const sticky = /\.env$/g;
    const matches = compileMatch({ path: sticky });
    expect([matches(context()), matches(context()), matches(context())]).toEqual([true, true, true]);
  });

  it("compares methods case-insensitively and addresses by range", () => {
    expect(compileMatch({ method: "post" })(context({ method: "POST" }))).toBe(true);
    expect(compileMatch({ method: ["POST", "PUT"] })(context())).toBe(false);
    expect(compileMatch({ ip: ["203.0.113.0/24"] })(context())).toBe(true);
    expect(compileMatch({ ip: ["10.0.0.0/8"] })(context())).toBe(false);
  });

  it("separates this request's score from the address's running total", () => {
    const ctx = context({ score: 5, totalScore: 60 });
    expect(compileMatch({ minScore: 10 })(ctx)).toBe(false);
    expect(compileMatch({ minTotalScore: 10 })(ctx)).toBe(true);
    expect(compileMatch({ maxTotalScore: 50 })(ctx)).toBe(false);
  });

  it("matches on proof in either direction", () => {
    const proven = context({ detections: [detection("honeytoken", { certain: true })] });
    expect(compileMatch({ certain: true })(proven)).toBe(true);
    expect(compileMatch({ certain: true })(context())).toBe(false);
    expect(compileMatch({ certain: false })(context())).toBe(true);
  });
});

describe("rule policies", () => {
  it("takes the first rule that matches and records which one it was", () => {
    const policy = rulePolicy([
      { id: "never", match: { path: "/admin" }, respondWith: "block" },
      { id: "env-probe", match: { path: "/." }, respondWith: "tarpit", reason: "A probe for a dotfile." },
      { id: "catch-all", match: {}, respondWith: "not-found" },
    ]);
    expect(policy(context())).toEqual({ actionId: "tarpit", rule: "env-probe", reason: "A probe for a dotfile." });
  });

  it("lets a rule defer to the detector's own choice of response", () => {
    const policy = rulePolicy([{ id: "bait", match: {}, respondWith: "@detector", fallbackAction: "decoy-content" }]);
    expect(policy(context({ detection: detection("decoy-path", { respondWith: "fake-data" }) }))).toMatchObject({ actionId: "fake-data" });
    // The detector asked for nothing, so the rule's own fallback stands.
    expect(policy(context())).toMatchObject({ actionId: "decoy-content", rule: "bait" });
  });

  it("falls back to the shipped ladder for anything no rule covers", () => {
    const policy = rulePolicy([{ id: "admin-only", match: { path: "/admin" }, respondWith: "block" }]);
    expect(policy(context({ totalScore: 80 }))).toMatchObject({ actionId: "block", rule: "default-block" });
    expect(policy(context({ totalScore: 1 }))).toMatchObject({ actionId: "not-found", rule: "default" });
  });

  it("honours a fallback the caller named instead", () => {
    const policy = rulePolicy([], { fallback: "chaos", fallbackReason: "Everything unmatched is answered badly on purpose." });
    expect(policy(context({ totalScore: 900 }))).toEqual({ actionId: "chaos", rule: "fallback", reason: "Everything unmatched is answered badly on purpose." });
  });

  it("refuses a rule list an incident could not report honestly", () => {
    expect(() => rulePolicy([{ id: "  ", match: {}, respondWith: "block" }])).toThrow(/needs an id/);
    expect(() => rulePolicy([
      { id: "same", match: {}, respondWith: "block" },
      { id: "same", match: { path: "/x" }, respondWith: "tarpit" },
    ])).toThrow(/share the id/);
  });

  it("treats a predicate that throws as a rule that did not match", () => {
    const policy = rulePolicy([
      {
        id: "broken",
        match: () => {
          throw new Error("operator's predicate is wrong");
        },
        respondWith: "block",
      },
      { id: "sound", match: {}, respondWith: "not-found" },
    ]);
    expect(policy(context())).toMatchObject({ actionId: "not-found", rule: "sound" });
  });

  it("keeps the ladder's thresholds configurable", () => {
    const policy = ladderPolicy(10, 5);
    expect(policy(context({ totalScore: 12 }))).toMatchObject({ actionId: "block" });
    expect(policy(context({ totalScore: 6, detection: detection("rate-spike") }))).toMatchObject({ actionId: "tarpit", rule: "default-tarpit" });
  });
});

describe("presets", () => {
  it("observes without doing anything a visitor could notice", () => {
    const policy = rulePolicy(observe());
    for (const totalScore of [0, 35, 400]) {
      expect(policy(context({ totalScore }))).toMatchObject({ actionId: "not-found" });
    }
  });

  it("protects an application without ever refusing on a score alone", () => {
    const policy = rulePolicy(protectApp());
    // Proof is dealt with firmly…
    expect(policy(context({ detections: [detection("honeytoken", { certain: true })] }))).toMatchObject({ actionId: "block", rule: "proof-block" });
    // …and a high score on its own is not proof, so it costs time instead of service.
    expect(policy(context({ totalScore: 90, detection: detection("rate-spike"), detections: [detection("rate-spike")] }))).toMatchObject({ actionId: "tarpit" });
  });

  it("is free to be expensive when it stands on its own", () => {
    const policy = rulePolicy(standalone());
    expect(policy(context({ totalScore: 50 }))).toMatchObject({ actionId: "block", rule: "confirmed-block" });
    expect(policy(context({ detection: detection("decoy-path", { respondWith: "gzip-bomb" }) }))).toMatchObject({ actionId: "gzip-bomb", rule: "detector-choice" });
  });

  it("names every preset it ships", () => {
    expect(Object.keys(PRESETS).sort()).toEqual(["observe", "protect-app", "standalone"]);
    for (const build of Object.values(PRESETS)) {
      const rules = build();
      expect(rules.length).toBeGreaterThan(0);
      // Every shipped rule can explain itself, because every incident it decides quotes it.
      expect(rules.every((rule) => (rule.reason ?? "").length > 0)).toBe(true);
    }
  });
});

describe("rules in a config file", () => {
  const build = (policy: Record<string, unknown>, rest: Record<string, unknown> = {}) => buildPolicy(parseConfig({ policy, ...rest }, "<test>"));

  it("consults the operator's rules before the preset and the thresholds", () => {
    const policy = build({
      preset: "observe",
      rules: [{ id: "partner", ip: ["198.51.100.0/24"], respond_with: "tarpit", reason: "A partner range, held while we look at it." }],
    });
    expect(policy(context({ ip: "198.51.100.9" }))).toMatchObject({ actionId: "tarpit", rule: "partner" });
    // Everything else is the preset's, not the ladder's.
    expect(policy(context({ ip: "203.0.113.7", totalScore: 900 }))).toMatchObject({ actionId: "not-found", rule: "observe-everything" });
  });

  it("lets a rule replace the preset's rule of the same name", () => {
    const policy = build({ preset: "protect-app", rules: [{ id: "proof-block", certain: true, respond_with: "chaos", reason: "We would rather waste their time." }] });
    expect(policy(context({ detections: [detection("honeytoken", { certain: true })] }))).toMatchObject({ actionId: "chaos", rule: "proof-block" });
  });

  it("matches on paths as prefixes or as patterns, never guessing which was meant", () => {
    const policy = build({ rules: [{ id: "prefixed", path_prefix: ["/admin"], respond_with: "tarpit" }, { id: "patterned", path_pattern: ["/wp-.*\\.php$"], respond_with: "not-found" }] });
    expect(policy(context({ path: "/admin/config" }))).toMatchObject({ rule: "prefixed" });
    expect(policy(context({ path: "/wp-login.php" }))).toMatchObject({ rule: "patterned" });
    expect(policy(context({ path: "/admin" }))).toMatchObject({ rule: "prefixed" });
  });

  it("refuses a rule that would quietly serve something else", () => {
    // Unknown, so the request would have fallen through to a plain 404 at runtime.
    expect(() => build({ rules: [{ id: "x", respond_with: "tarpid" }] })).toThrow(/not a response action/);
    // Known, but switched off — the same silent 404, and just as much a misconfiguration.
    expect(() => build({ rules: [{ id: "x", respond_with: "chaos" }] }, { responses: { chaos: { enabled: false } } })).toThrow(/is disabled/);
  });

  it("refuses a rule list that could not be reported honestly", () => {
    expect(() => build({ rules: [{ id: "same", respond_with: "tarpit" }, { id: "same", respond_with: "block" }] })).toThrow(/two rules with the id/);
    expect(() => build({ rules: [{ respond_with: "tarpit", reasin: "typo" }] })).toThrow(/unknown key: reasin/);
    expect(() => build({ rules: [{ id: "x" }] })).toThrow(/respond_with.*is required/s);
    expect(() => build({ preset: "protect_app" })).toThrow(/must be one of/);
    expect(() => build({ rules: [{ id: "x", respond_with: "tarpit", path_pattern: ["([unclosed"] }] })).toThrow(/not a valid regular expression/);
    expect(() => build({ rules: [{ id: "x", respond_with: "tarpit", ip: ["10.0.0.0/64"] }] })).toThrow(/invalid \/prefix/);
  });

  it("is the ladder alone when nothing is configured", () => {
    const policy = build({ block_threshold: 5, tarpit_threshold: 2 });
    expect(policy(context({ totalScore: 6 }))).toMatchObject({ actionId: "block", rule: "default-block" });
  });
});

describe("what the engine records", () => {
  it("puts the deciding rule and its reason on the result and on the hit", async () => {
    const engine = new HoneypotEngine({
      enricher: null,
      policy: rulePolicy([{ id: "dotfile-probe", match: { path: "/." }, respondWith: "tarpit", reason: "A probe for a dotfile that does not exist." }]),
    });
    const rules: Array<string | undefined> = [];
    engine.on("hit", (hit) => rules.push(hit.rule));

    const result = await engine.evaluate(probe());
    expect(result).toMatchObject({ actionId: "tarpit", rule: "dotfile-probe", reason: "A probe for a dotfile that does not exist." });
    expect(rules).toEqual(["dotfile-probe"]);
  });

  it("records the shipped ladder as the decider when the policy is a plain closure", async () => {
    const engine = new HoneypotEngine({ enricher: null, policy: () => "chaos" });
    const result = await engine.evaluate(probe({ ip: "203.0.113.41" }));
    expect(result).toMatchObject({ actionId: "chaos", rule: "default" });
    expect(result.reason).toBeUndefined();
  });

  it("says out loud when the proof guard refused the block a rule asked for", async () => {
    const engine = new HoneypotEngine({
      enricher: null,
      policy: rulePolicy([{ id: "strict", match: {}, respondWith: "block", reason: "Anything probing this host is hostile." }]),
    });
    const result = await engine.evaluate(probe({ ip: "203.0.113.42" }), { blockRequiresProof: true });

    expect(result.actionId).toBe("tarpit");
    expect(result.downgradedFrom).toBe("block");
    expect(result.rule).toBe("strict");
    // The rule's own sentence is kept, and the substitution is appended rather than hidden.
    expect(result.reason).toContain("Anything probing this host is hostile.");
    expect(result.reason).toContain("No detection was proof");
    expect(result.reason).toContain("tarpit served instead");
  });
});
