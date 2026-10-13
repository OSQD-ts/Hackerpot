import { randomBytes } from "node:crypto";
import type { ResponseAction, ResponseContext } from "./types.js";

export interface FakeSuccessOptions {
  status?: number;
  /** Static body, or a function per-request. Defaults to a fake auth-success JSON with a random token. */
  body?: string | ((ctx: ResponseContext) => string);
  contentType?: string;
  /** Set a fake session cookie so the attacker "keeps" a session. Default true. */
  setSessionCookie?: boolean;
}

/**
 * Pretends the attacker's exploit or login attempt worked — returns a plausible
 * success with a fake session token — instead of an error. A sticky decoy: the
 * attacker believes they're in and keeps going, and every follow-up request is
 * more captured intent. Nothing real is ever granted; the token is noise.
 */
export function fakeSuccessAction(options: FakeSuccessOptions = {}): ResponseAction {
  const status = options.status ?? 200;
  const contentType = options.contentType ?? "application/json";
  const setSessionCookie = options.setSessionCookie ?? true;

  return {
    id: "fake-success",
    description: "Return a fake success + session token so the attacker keeps engaging",
    execute(ctx: ResponseContext): void {
      const token = randomBytes(24).toString("hex");
      const body =
        typeof options.body === "function"
          ? options.body(ctx)
          : options.body ?? JSON.stringify({ status: "ok", authenticated: true, token, expiresIn: 3600 });

      ctx.res.statusCode = status;
      ctx.res.setHeader("Content-Type", contentType);
      if (setSessionCookie) ctx.res.setHeader("Set-Cookie", `session=${randomBytes(16).toString("hex")}; Path=/; HttpOnly; SameSite=Lax`);
      ctx.res.end(body);
    },
  };
}
