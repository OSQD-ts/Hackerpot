import type { ResponseAction, ResponseContext } from "./types.js";

interface DecoyPayload {
  status?: number;
  contentType?: string;
  body?: string;
  location?: string;
}

function payloadFrom(ctx: ResponseContext): DecoyPayload {
  const raw = ctx.detection.metadata?.["payload"];
  return (raw as DecoyPayload | undefined) ?? {};
}

/**
 * Serves the convincing fake content attached to a decoy-path detection (a
 * fake .env, a fake admin login page, etc.), so probing appears to succeed
 * and the attacker keeps engaging with the decoy instead of moving on.
 */
export function decoyContentAction(): ResponseAction {
  return {
    id: "decoy-content",
    description: "Return the fake content attached to the detection payload",
    execute(ctx: ResponseContext): void {
      const payload = payloadFrom(ctx);
      ctx.res.statusCode = payload.status ?? 200;
      ctx.res.setHeader("Content-Type", payload.contentType ?? "text/plain; charset=utf-8");
      ctx.res.end(payload.body ?? "");
    },
  };
}

/** Answers a flat 404 — used for decoys where the mere probe is the signal and no fake content is warranted. */
export function notFoundAction(): ResponseAction {
  return {
    id: "not-found",
    description: "Answer 404 without revealing anything",
    execute(ctx: ResponseContext): void {
      ctx.res.statusCode = payloadFrom(ctx).status ?? 404;
      ctx.res.end();
    },
  };
}

/** Issues a redirect, e.g. bouncing a /wp-admin probe to the fake login decoy. */
export function redirectAction(): ResponseAction {
  return {
    id: "redirect",
    description: "Redirect the attacker, typically toward another decoy",
    execute(ctx: ResponseContext): void {
      const payload = payloadFrom(ctx);
      ctx.res.statusCode = payload.status ?? 302;
      if (payload.location) ctx.res.setHeader("Location", payload.location);
      ctx.res.end();
    },
  };
}
