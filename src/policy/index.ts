import { ladderPolicy } from "./rules.js";
import type { PolicyContext, ResponseDecision, ResponsePolicy } from "./types.js";

// The policy as data: rules, the ladder they fall back to, and the presets to start from. The
// actions a policy chooses between live in `actions/`, the split bothandlerjs's source makes.
export type { PolicyContext, ResponseDecision, ResponsePolicy } from "./types.js";
export { compileMatch, ladderPolicy, rulePolicy } from "./rules.js";
export type { MatchSpec, Rule, RulePolicyOptions } from "./rules.js";
export { PRESET_NAMES, PRESETS, observe, protectApp, standalone } from "./presets.js";
export type { PresetName } from "./presets.js";

/**
 * Default escalation policy. A confirmed persistent attacker (cumulative score
 * past the block threshold) is blocked regardless of what any single detector
 * requested. Below that, a detector's explicit `respondWith` is honored (so
 * decoys keep serving convincing bait); otherwise middling scores are
 * tarpitted and first-touch probes get a plain 404.
 *
 * This returns a bare action id, and keeps doing so: wrapping it and comparing the result to
 * an id (`if (ladder(ctx) === "block")`) is the documented way to write a policy on top of
 * the default, and that must keep working. {@link ladderPolicy} is the same ladder returning
 * a {@link ResponseDecision} instead, which is what the engine and `rulePolicy` use so that an
 * incident can say which rung decided it.
 */
export function defaultResponsePolicy(blockThreshold = 40, tarpitThreshold = 15): ResponsePolicy {
  const ladder = ladderPolicy(blockThreshold, tarpitThreshold);
  return (ctx: PolicyContext): string => (ladder(ctx) as ResponseDecision).actionId;
}
