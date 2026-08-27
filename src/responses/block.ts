import type { ResponseAction, ResponseContext } from "./types.js";

export interface BlockOptions {
  /** How long the IP stays blocked. Default 15 minutes. */
  durationMs?: number;
  status?: number;
  body?: string;
  /** Send Retry-After so well-behaved clients back off. Default true. */
  sendRetryAfter?: boolean;
}

/**
 * Marks the IP blocked for a duration and answers with 403. Subsequent
 * requests from a blocked IP are short-circuited by the engine before any
 * detector runs, so a blocked attacker costs almost nothing to serve.
 */
export function blockAction(options: BlockOptions = {}): ResponseAction {
  const durationMs = options.durationMs ?? 15 * 60_000;
  const status = options.status ?? 403;
  const body = options.body ?? "Forbidden";
  const sendRetryAfter = options.sendRetryAfter ?? true;

  return {
    id: "block",
    description: "Block the source IP for a period and answer 403",
    async execute(ctx: ResponseContext): Promise<void> {
      await ctx.blocklist.block(ctx.ip, Date.now() + durationMs);
      ctx.res.statusCode = status;
      if (sendRetryAfter) ctx.res.setHeader("Retry-After", String(Math.round(durationMs / 1000)));
      ctx.res.setHeader("Content-Type", "text/plain; charset=utf-8");
      ctx.res.end(body);
    },
  };
}
