import { blockAction } from "./block.js";
import { tarpitAction } from "./tarpit.js";
import { dripFeedAction } from "./drip-feed.js";
import { largePayloadAction } from "./large-payload.js";
import { decoyContentAction, notFoundAction, redirectAction } from "./decoy-content.js";
import { fakeSuccessAction } from "./fake-success.js";
import { fakeDataAction } from "./fake-data.js";
import { gzipBombAction } from "./gzip-bomb.js";
import { chaosAction } from "./chaos.js";
import { rateLimitAction } from "./rate-limit.js";
import { ladderPolicy } from "./rules.js";
import type { PolicyContext, ResponseAction, ResponseDecision, ResponsePolicy } from "./types.js";

export type { PolicyContext, ResponseAction, ResponseContext, ResponseDecision, ResponsePolicy } from "./types.js";
// The policy as data: rules, the ladder they fall back to, and the presets to start from.
export { compileMatch, ladderPolicy, rulePolicy } from "./rules.js";
export type { MatchSpec, Rule, RulePolicyOptions } from "./rules.js";
export { PRESET_NAMES, PRESETS, observe, protectApp, standalone } from "./presets.js";
export type { PresetName } from "./presets.js";
export { blockAction } from "./block.js";
export type { BlockOptions } from "./block.js";
export { tarpitAction } from "./tarpit.js";
export type { TarpitOptions } from "./tarpit.js";
export { dripFeedAction } from "./drip-feed.js";
export type { DripFeedOptions } from "./drip-feed.js";
export { largePayloadAction } from "./large-payload.js";
export type { LargePayloadOptions } from "./large-payload.js";
export { decoyContentAction, notFoundAction, redirectAction } from "./decoy-content.js";
export { fakeSuccessAction } from "./fake-success.js";
export type { FakeSuccessOptions } from "./fake-success.js";
export { fakeDataAction } from "./fake-data.js";
export type { FakeDataOptions } from "./fake-data.js";
export { gzipBombAction } from "./gzip-bomb.js";
export type { GzipBombOptions } from "./gzip-bomb.js";
export { chaosAction } from "./chaos.js";
export type { ChaosOptions } from "./chaos.js";
export { rateLimitAction } from "./rate-limit.js";
export type { RateLimitOptions } from "./rate-limit.js";
export { checkResponseActions } from "./check.js";
export type { CheckResponseActionsOptions, ResponseCheckResult } from "./check.js";

/** The response actions registered when none are configured explicitly. */
export function defaultResponseActions(): ResponseAction[] {
  return [
    decoyContentAction(),
    notFoundAction(),
    redirectAction(),
    blockAction(),
    tarpitAction(),
    dripFeedAction(),
    largePayloadAction(),
    fakeSuccessAction(),
    fakeDataAction(),
    gzipBombAction(),
    chaosAction(),
    rateLimitAction(),
  ];
}

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
