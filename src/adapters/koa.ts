import type { IncomingMessage, ServerResponse } from "node:http";
import type { HoneypotEngine } from "../core.js";
import { createMiddleware, type MiddlewareOptions } from "../middleware.js";

/** The parts of a Koa context this adapter touches, described structurally so there is no dependency on Koa. */
export interface KoaLikeContext {
  req: IncomingMessage;
  res: ServerResponse;
  /** Set to false when the honeypot has answered on the raw response, so Koa does not write over it. */
  respond?: boolean;
}

export type KoaHoneypotMiddleware = (ctx: KoaLikeContext, next: () => Promise<unknown>) => Promise<void>;

/**
 * Koa middleware around `createMiddleware`: the same two-phase evaluation, 404 gating,
 * proof guard and failure handling, on Koa's raw request and response.
 *
 * ```ts
 * app.use(koaHoneypot(engine));
 * ```
 *
 * Mount it first. When the honeypot answers a request it sets `ctx.respond = false` and
 * does not call `next()`, so nothing downstream runs. The 404 gating reads the final
 * status from the raw response when it finishes, which Koa writes after the whole chain.
 */
export function koaHoneypot(engine: HoneypotEngine, options: MiddlewareOptions = {}): KoaHoneypotMiddleware {
  const middleware = createMiddleware(engine, options);
  return async function honeypotKoaMiddleware(ctx, next) {
    let passed = false;
    let passedError: unknown;
    await middleware(ctx.req, ctx.res, (err) => {
      passed = true;
      passedError = err;
    });
    if (!passed) {
      ctx.respond = false;
      return;
    }
    // Only reachable with `failOpen: false`: hand the honeypot's own failure to Koa.
    if (passedError !== undefined) throw passedError;
    await next();
  };
}
