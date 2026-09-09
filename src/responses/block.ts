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
      // Blocking is best-effort, exactly as recording a hit is — the same rail the
      // engine already applies to the store, the enricher and `onHit`, and for the same
      // reason: the caller must still be able to serve a response.
      //
      // This call reaches a live backend whenever the blocklist is Redis-backed or
      // wraps an external enforcer, so it can fail for reasons that have nothing to do
      // with the request. It used to propagate, and the two consequences were both bad.
      // The visible one: the request became a **500**, and a 500 is a honeypot tell —
      // every other response here is a plausible one, so a backend outage turned every
      // flagged request into a distinctive "you broke something" signal, and in
      // middleware mode handed the error to the host app's error page. The quiet one:
      // the failure was reported nowhere at all, so blocking could stop working
      // entirely — the security-critical side effect — with no signal to the operator.
      //
      // So: report it, and answer 403 regardless. The block will not persist, but the
      // attacker sees exactly what they would have seen anyway, and the operator sees
      // why in the log.
      try {
        await ctx.blocklist.block(ctx.ip, Date.now() + durationMs);
      } catch (err) {
        ctx.onError?.(err, { source: "blocklist" });
      }
      ctx.res.statusCode = status;
      if (sendRetryAfter) ctx.res.setHeader("Retry-After", String(Math.round(durationMs / 1000)));
      ctx.res.setHeader("Content-Type", "text/plain; charset=utf-8");
      ctx.res.end(body);
    },
  };
}
