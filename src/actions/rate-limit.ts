import type { ResponseAction, ResponseContext } from "./types.js";

export interface RateLimitOptions {
  /** Value for the Retry-After header, in seconds. Default 60. */
  retryAfterSeconds?: number;
  status?: number;
  body?: string;
}

/**
 * Answers with a standard `429 Too Many Requests` and a `Retry-After` header.
 * A polite, low-cost throttle for a high-volume IP — it looks like ordinary rate
 * limiting to the attacker (revealing nothing about the honeypot) while telling
 * well-behaved clients to back off.
 */
export function rateLimitAction(options: RateLimitOptions = {}): ResponseAction {
  const retryAfter = options.retryAfterSeconds ?? 60;
  const status = options.status ?? 429;
  const body = options.body ?? "Too Many Requests";

  return {
    id: "rate-limit",
    description: "Answer 429 Too Many Requests with a Retry-After header",
    execute(ctx: ResponseContext): void {
      ctx.res.statusCode = status;
      ctx.res.setHeader("Retry-After", String(retryAfter));
      ctx.res.setHeader("Content-Type", "text/plain; charset=utf-8");
      ctx.res.end(body);
    },
  };
}
