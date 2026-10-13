import type { Incident } from "../management/types.js";
import { ladderPolicy, rulePolicy } from "../policy/index.js";
import type { MatchSpec, PolicyContext, ResponseDecision, ResponsePolicy, Rule } from "../policy/index.js";
import { IpTracker } from "../state.js";

/**
 * What a rule set would have done to the traffic you just watched.
 *
 * Rules are tuned by guessing and then waiting to see, which means every adjustment is tried
 * on real visitors. This answers the question first, against the incidents already on the
 * screen, and it is possible only because a policy is **pure**: it reads a request's
 * detections and returns a decision, touching no state, no store and no network. Replaying one
 * over recorded incidents is therefore exactly what it would have done to them.
 *
 * Say plainly what that is faithful about and what it is not:
 *
 * - **Faithful**: which rule matches, what it decides, and whether the proof guard would have
 *   refused a block it asked for. These are the decision, and the decision is what is being
 *   tuned.
 * - **Not faithful**: what the action would have *done*. A tarpit's delay, a decoy's bait, a
 *   block's entry in the blocklist — none of that is replayed, and none of it happens here.
 * - **Not available**: anything a rule reads off the live activity window. A recorded incident
 *   carries its scores but not the tracker they came from, so a rule matching on tracker state
 *   sees an empty one. Such a rule is reported rather than silently previewed as "no match".
 *
 * Nothing here writes: no score moves, no incident is recorded, and the running policy is
 * untouched until somebody applies it. Adapted from bothandlerjs.
 */

/** One incident the candidate rules would answer differently. */
export interface PreviewChange {
  id: string;
  ip: string;
  path: string;
  /** The action this incident actually received. */
  was: string;
  /** What the candidate rules would serve instead. */
  now: string;
  /** The rule that decided, and the sentence it gives. */
  rule: string;
  reason: string;
  /** Set when the proof guard would refuse the block these rules asked for. */
  downgradedFrom?: string;
}

export interface PreviewResult {
  /** Incidents the policy was consulted for. */
  total: number;
  changed: PreviewChange[];
  unchanged: number;
  /**
   * Incidents skipped: nothing fired on them, so the policy was never consulted and there is
   * no decision to compare.
   */
  skipped: number;
}

export interface PreviewOptions {
  /**
   * Refuse a block the evidence does not prove, as middleware mode does. Default true, which
   * is the mode a preview is nearly always being read for.
   */
  blockRequiresProof?: boolean;
  /** What an unproven block becomes. Default `"tarpit"`. */
  unprovenBlockFallback?: string;
}

/** The policy a candidate rule list describes, falling through to the shipped ladder. */
export function candidatePolicy(rules: readonly Rule[]): ResponsePolicy {
  return rulePolicy(rules, { fallback: ladderPolicy() });
}

/**
 * Replays recorded incidents against a candidate policy.
 *
 * The tracker handed to the policy is empty and belongs to nobody: a recorded incident does
 * not carry the activity window its scores came from. That is a limit of replay, not a
 * pretence — see the note above.
 */
export function previewPolicy(incidents: readonly Incident[], policy: ResponsePolicy, options: PreviewOptions = {}): PreviewResult {
  const requireProof = options.blockRequiresProof !== false;
  const fallback = options.unprovenBlockFallback ?? "tarpit";
  const result: PreviewResult = { total: 0, changed: [], unchanged: 0, skipped: 0 };

  for (const incident of incidents) {
    const detections = incident.detections;
    if (detections.length === 0 || detections[0] === undefined) {
      result.skipped += 1;
      continue;
    }
    result.total += 1;

    const context: PolicyContext = {
      detection: detections[0],
      detections,
      ip: incident.ip,
      path: incident.path,
      method: incident.method,
      score: incident.score,
      totalScore: incident.totalScore,
      ...(incident.confidence !== undefined ? { confidence: incident.confidence } : {}),
      // Empty, and only ever read: a preview must not manufacture history that did not happen.
      tracker: new IpTracker(incident.ip, 60_000),
    };

    let decision: ResponseDecision;
    try {
      const decided = policy(context);
      decision = typeof decided === "string" ? { actionId: decided, rule: "default", reason: "" } : decided;
    } catch {
      // A predicate of somebody's own that throws is a rule that did not match, here as well
      // as on the request path.
      result.unchanged += 1;
      continue;
    }

    let actionId = decision.actionId;
    let downgradedFrom: string | undefined;
    if (actionId === "block" && requireProof && !detections.some((detection) => detection.certain === true)) {
      downgradedFrom = actionId;
      actionId = fallback;
    }

    if (actionId === incident.respondedWith) {
      result.unchanged += 1;
      continue;
    }
    result.changed.push({
      id: incident.id,
      ip: incident.ip,
      path: incident.path,
      was: incident.respondedWith,
      now: actionId,
      rule: decision.rule,
      reason: decision.reason,
      ...(downgradedFrom !== undefined ? { downgradedFrom } : {}),
    });
  }
  return result;
}

/** Most rules a posted draft may carry. A list longer than this is a paste, not a policy. */
const MAX_RULES = 100;
/** Longest id, pattern or reason accepted from a draft. */
const MAX_TEXT = 512;

function text(value: unknown, field: string, max = MAX_TEXT): string {
  if (typeof value !== "string" || value.trim() === "") throw new Error(`${field} must be a non-empty string`);
  if (value.length > max) throw new Error(`${field} is longer than ${max} characters`);
  return value;
}

function stringList(value: unknown, field: string): string[] {
  const list = Array.isArray(value) ? value : [value];
  return list.map((entry, index) => text(entry, `${field}[${index}]`));
}

function number(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new Error(`${field} must be a number`);
  return value;
}

/**
 * A pattern from a draft. JSON cannot carry a RegExp, so one arrives as text.
 *
 * Prefixes and patterns are separate keys — `path` and `pathPattern` — rather than one value
 * guessed at, for the reason the configuration file gives: `/admin/` is a perfectly good
 * prefix and a perfectly good regular expression, and a draft that silently read it as the
 * wrong one would be previewed as matching traffic it does not match, and then applied.
 */
function patternOf(value: string, field: string): RegExp {
  const literal = /^\/(.*)\/([a-z]*)$/s.exec(value);
  try {
    // `g` and `y` make `.test()` stateful, which would match every other request.
    return literal === null ? new RegExp(value, "i") : new RegExp(literal[1] as string, (literal[2] as string).replace(/[gy]/g, ""));
  } catch (error) {
    throw new Error(`${field} is not a valid regular expression: ${(error as Error).message}`);
  }
}

/**
 * Reads a rule list posted by the page.
 *
 * Everything unreadable is refused with a sentence rather than guessed at: a draft that
 * silently loses a condition would be previewed as something other than what it says, and then
 * applied. Predicates are not accepted at all — JSON cannot carry a function, and a rule that
 * looked like one would match nothing.
 */
export function parseRules(value: unknown): Rule[] {
  if (!Array.isArray(value)) throw new Error("rules must be an array");
  if (value.length > MAX_RULES) throw new Error(`rules has ${value.length} entries; at most ${MAX_RULES} are accepted`);

  const seen = new Set<string>();
  return value.map((entry, index) => {
    if (typeof entry !== "object" || entry === null) throw new Error(`rules[${index}] must be an object`);
    const raw = entry as Record<string, unknown>;
    const id = text(raw["id"], `rules[${index}].id`, 64);
    if (seen.has(id)) throw new Error(`rules[${index}].id "${id}" is used twice; an incident could not say which rule decided`);
    seen.add(id);

    const respondWith = text(raw["respondWith"] ?? raw["respond_with"], `rules[${index}].respondWith`, 64);
    const matchRaw = raw["match"] ?? {};
    if (typeof matchRaw !== "object" || matchRaw === null || Array.isArray(matchRaw)) throw new Error(`rules[${index}].match must be an object`);
    const m = matchRaw as Record<string, unknown>;

    const prefixes = m["path"] === undefined ? [] : stringList(m["path"], `rules[${index}].match.path`);
    const patterns = m["pathPattern"] === undefined ? [] : stringList(m["pathPattern"], `rules[${index}].match.pathPattern`).map((entry) => patternOf(entry, `rules[${index}].match.pathPattern`));
    const paths: Array<string | RegExp> = [...prefixes, ...patterns];
    const match: MatchSpec = {
      ...(m["detector"] !== undefined ? { detector: stringList(m["detector"], `rules[${index}].match.detector`) } : {}),
      ...(m["certain"] !== undefined ? { certain: m["certain"] === true } : {}),
      ...(m["minScore"] !== undefined ? { minScore: number(m["minScore"], `rules[${index}].match.minScore`) } : {}),
      ...(m["maxScore"] !== undefined ? { maxScore: number(m["maxScore"], `rules[${index}].match.maxScore`) } : {}),
      ...(m["minTotalScore"] !== undefined ? { minTotalScore: number(m["minTotalScore"], `rules[${index}].match.minTotalScore`) } : {}),
      ...(m["maxTotalScore"] !== undefined ? { maxTotalScore: number(m["maxTotalScore"], `rules[${index}].match.maxTotalScore`) } : {}),
      ...(m["minConfidence"] !== undefined ? { minConfidence: number(m["minConfidence"], `rules[${index}].match.minConfidence`) } : {}),
      ...(m["maxConfidence"] !== undefined ? { maxConfidence: number(m["maxConfidence"], `rules[${index}].match.maxConfidence`) } : {}),
      ...(paths.length > 0 ? { path: paths } : {}),
      ...(m["method"] !== undefined ? { method: stringList(m["method"], `rules[${index}].match.method`) } : {}),
      ...(m["ip"] !== undefined ? { ip: stringList(m["ip"], `rules[${index}].match.ip`) } : {}),
    };

    return {
      id,
      respondWith,
      match,
      ...(raw["fallbackAction"] !== undefined ? { fallbackAction: text(raw["fallbackAction"], `rules[${index}].fallbackAction`, 64) } : {}),
      ...(raw["reason"] !== undefined ? { reason: text(raw["reason"], `rules[${index}].reason`) } : {}),
    };
  });
}
