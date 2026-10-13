import { IpAllowlist } from "../allowlist.js";
import { statelessPattern } from "../internal/pattern.js";
import type { PolicyContext, ResponseDecision, ResponsePolicy } from "./types.js";

/**
 * The policy as data.
 *
 * A policy used to be a closure returning an action id, which works and tells nobody
 * anything: an incident recorded *what* was served and never *why*, the dashboard could not
 * show the policy, and a change to it was a code change. Rules are ordinary first-match-wins
 * configuration — there is nothing clever about them — and what they buy is that every
 * decision can name the rule that made it and carry a sentence an operator can read.
 *
 * Two things are deliberately kept out of the rules. The **proof guard** runs after a rule
 * has been chosen (see `EvaluateOptions.blockRequiresProof`), so it cannot be forgotten by
 * whoever writes one, and a rule asking to block an unproven request is refused rather than
 * obeyed. And **`certain` is a property of the evidence**, not of the rule: a rule may match
 * on it, never assert it. Adapted from bothandlerjs.
 */

/**
 * What a rule matches on. Every field present must match; absent fields are ignored, so `{}`
 * matches everything and is how a last-resort rule is written.
 */
export interface MatchSpec {
  /** Any of these detectors fired on the request. */
  detector?: string | readonly string[];
  /** Whether at least one detection is proof. `false` matches a request with none. */
  certain?: boolean;
  /** Bounds on what this request scored on its own. */
  minScore?: number;
  maxScore?: number;
  /**
   * Bounds on how strong the evidence is, in [0, 1]. A rule written on confidence rather than
   * on a score cannot be reached by piling up forgivable findings: suspicion alone is capped
   * below 1, and only proof reaches it. See `confidenceOf`.
   */
  minConfidence?: number;
  maxConfidence?: number;
  /** Bounds on the address's running total, which is what escalation is built on. */
  minTotalScore?: number;
  maxTotalScore?: number;
  /** Path prefixes (a plain string) or patterns. A `g`/`y` flag is stripped: see `statelessPattern`. */
  path?: string | RegExp | ReadonlyArray<string | RegExp>;
  /** Request methods, compared case-insensitively. */
  method?: string | readonly string[];
  /** Source addresses or CIDR ranges. */
  ip?: readonly string[];
}

/** One rule. The first whose `match` holds decides the response. */
export interface Rule {
  /** Stable id, shown on the incident this rule decided. */
  id: string;
  /** A spec, or your own predicate when a spec cannot express it. */
  match: MatchSpec | ((context: PolicyContext) => boolean);
  /**
   * The response action to run. `"@detector"` means the action the detector asked for
   * (`Detection.respondWith`), which is how decoys keep serving their own bait, falling back
   * to `fallbackAction` when the detector asked for nothing.
   */
  respondWith: string;
  /** Used when `respondWith` is `"@detector"` and the detector named no action. Default `"not-found"`. */
  fallbackAction?: string;
  /** One sentence, recorded on the incident and safe to show an operator. */
  reason?: string;
}

export interface RulePolicyOptions {
  /**
   * What decides when no rule matches. An action id, or another policy — by default the
   * shipped score ladder, so a short rule list added to a working deployment only overrides
   * what it names.
   */
  fallback?: string | ResponsePolicy;
  /** Reason recorded when the fallback decided. */
  fallbackReason?: string;
}

/** The action `"@detector"` falls back to when a rule names none and the detector asked for nothing. */
const DEFAULT_DETECTOR_FALLBACK = "not-found";

function toSet(value: string | readonly string[] | undefined): Set<string> | undefined {
  if (value === undefined) return undefined;
  return new Set(Array.isArray(value) ? (value as readonly string[]) : [value as string]);
}

/**
 * Compiles a spec into a predicate.
 *
 * Compiled once when the policy is built rather than interpreted per request: this runs on
 * every request the honeypot answers, and a rule list is consulted in order.
 */
export function compileMatch(spec: MatchSpec): (context: PolicyContext) => boolean {
  const detectors = toSet(spec.detector);
  const methods = spec.method === undefined ? undefined : new Set((Array.isArray(spec.method) ? spec.method : [spec.method]).map((method) => method.toUpperCase()));
  const paths =
    spec.path === undefined ? undefined : ((Array.isArray(spec.path) ? spec.path : [spec.path]) as ReadonlyArray<string | RegExp>).map((pattern) => statelessPattern(pattern));
  // The allowlist is the library's address matcher: it compares by value, so every spelling
  // of an address matches the range an operator wrote.
  const addresses = spec.ip === undefined || spec.ip.length === 0 ? undefined : new IpAllowlist([...spec.ip]);

  return (context: PolicyContext): boolean => {
    if (spec.minTotalScore !== undefined && context.totalScore < spec.minTotalScore) return false;
    if (spec.maxTotalScore !== undefined && context.totalScore > spec.maxTotalScore) return false;
    if (spec.minScore !== undefined && (context.score ?? context.totalScore) < spec.minScore) return false;
    if (spec.maxScore !== undefined && (context.score ?? context.totalScore) > spec.maxScore) return false;
    if (spec.minConfidence !== undefined && (context.confidence ?? 0) < spec.minConfidence) return false;
    if (spec.maxConfidence !== undefined && (context.confidence ?? 0) > spec.maxConfidence) return false;
    if (spec.certain !== undefined && context.detections.some((detection) => detection.certain === true) !== spec.certain) return false;
    if (methods !== undefined && !methods.has((context.method ?? "GET").toUpperCase())) return false;
    if (addresses !== undefined && !addresses.allows(context.ip)) return false;
    if (detectors !== undefined && !context.detections.some((detection) => detectors.has(detection.detector))) return false;
    if (paths !== undefined && !paths.some((pattern) => (typeof pattern === "string" ? context.path.startsWith(pattern) : pattern.test(context.path)))) return false;
    return true;
  };
}

interface CompiledRule {
  rule: Rule;
  matches: (context: PolicyContext) => boolean;
}

/**
 * Turns a rule list into a policy.
 *
 * The result is a `ResponsePolicy`, so it goes anywhere the closure form does; it returns a
 * decision rather than a bare action id, and the engine records the rule and the reason on
 * the incident.
 */
export function rulePolicy(rules: readonly Rule[], options: RulePolicyOptions = {}): ResponsePolicy {
  const seen = new Set<string>();
  for (const rule of rules) {
    if (rule.id.trim() === "") throw new Error("every response rule needs an id: it is what an incident names when the rule decides");
    if (seen.has(rule.id)) throw new Error(`two response rules share the id "${rule.id}"; an incident could not say which one decided`);
    seen.add(rule.id);
  }
  const compiled: CompiledRule[] = rules.map((rule) => ({ rule, matches: typeof rule.match === "function" ? rule.match : compileMatch(rule.match) }));
  const fallback = options.fallback ?? ladderPolicy();
  const fallbackReason = options.fallbackReason ?? "No rule matched.";

  return (context: PolicyContext): ResponseDecision => {
    for (const { rule, matches } of compiled) {
      let hit: boolean;
      try {
        hit = matches(context);
      } catch {
        // A predicate is caller-supplied code on the request path. One that throws is a rule
        // that does not match, not a request that fails.
        continue;
      }
      if (!hit) continue;
      const actionId = rule.respondWith === "@detector" ? (context.detection.respondWith ?? rule.fallbackAction ?? DEFAULT_DETECTOR_FALLBACK) : rule.respondWith;
      return { actionId, rule: rule.id, reason: rule.reason ?? `Matched rule "${rule.id}".` };
    }
    if (typeof fallback === "string") return { actionId: fallback, rule: "fallback", reason: fallbackReason };
    const decided = fallback(context);
    return typeof decided === "string" ? { actionId: decided, rule: "fallback", reason: fallbackReason } : decided;
  };
}

/**
 * The shipped score ladder, as a decision that says which rung it landed on.
 *
 * This is the one definition: `defaultResponsePolicy` is this function, and it is also what
 * a rule list falls back to when no rule matched, so a deployment that adds a handful of
 * rules keeps the shipped behaviour everywhere it did not override.
 */
export function ladderPolicy(blockThreshold = 40, tarpitThreshold = 15): ResponsePolicy {
  return (context: PolicyContext): ResponseDecision => {
    if (context.totalScore >= blockThreshold) return { actionId: "block", rule: "default-block", reason: `This address has reached ${context.totalScore} on its running score, past the block threshold of ${blockThreshold}.` };
    if (context.detection.respondWith) return { actionId: context.detection.respondWith, rule: "default-detector", reason: `The ${context.detection.detector} detector asked for this response.` };
    if (context.totalScore >= tarpitThreshold) return { actionId: "tarpit", rule: "default-tarpit", reason: `Past the tarpit threshold of ${tarpitThreshold}: enough suspicion to be worth slowing down.` };
    return { actionId: "not-found", rule: "default", reason: "A first probe: answered as though nothing is here." };
  };
}
