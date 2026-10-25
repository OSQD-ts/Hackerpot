import type { ResponseAction, ResponseContext } from "./types.js";

/** The id a rule names to let a request through. Adapted from bothandlerjs's `allow`. */
export const PASS_ACTION = "pass";

/**
 * Let the request through to your application, untouched: the incident is still recorded,
 * scored and alerted on, and nobody can tell from the response that anything was watching.
 *
 * In middleware mode (Express/Connect, Koa, Fastify, Fetch) the front end never runs this
 * action — it calls `next()` instead, and your route answers. A passed request is never
 * body-read, never given the probe marker, and teaches the site baseline from what your
 * application actually answered, exactly like a request nothing flagged.
 *
 * Where nothing sits behind the honeypot — the standalone server — there is no application
 * to pass to, so this runs and answers the way an empty path is answered there: a plain 404.
 */
export function passAction(): ResponseAction {
  return {
    id: PASS_ACTION,
    description: "Let the request through to the application (a plain 404 where there is none)",
    execute(ctx: ResponseContext): void {
      ctx.res.statusCode = 404;
      ctx.res.end("Not Found");
    },
  };
}
