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
import type { PolicyContext, ResponseAction, ResponsePolicy } from "./types.js";

export type { PolicyContext, ResponseAction, ResponseContext, ResponsePolicy } from "./types.js";
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
 */
export function defaultResponsePolicy(blockThreshold = 40, tarpitThreshold = 15): ResponsePolicy {
  return (ctx: PolicyContext): string => {
    if (ctx.totalScore >= blockThreshold) return "block";
    if (ctx.detection.respondWith) return ctx.detection.respondWith;
    if (ctx.totalScore >= tarpitThreshold) return "tarpit";
    return "not-found";
  };
}
