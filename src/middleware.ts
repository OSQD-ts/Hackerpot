import type { IncomingMessage, ServerResponse } from "node:http";
import type { HoneypotEngine } from "./core.js";
import type { RequestFacts } from "./detectors/types.js";
import { mayHaveBody, parseQuery, pathOf, readBody } from "./http-request.js";
import type { ResponseContext } from "./responses/types.js";

export type NextFn = (err?: unknown) => void;
export type HoneypotMiddleware = (req: IncomingMessage, res: ServerResponse, next: NextFn) => Promise<void>;

/**
 * Builds Express/Connect-compatible middleware. Mount it ahead of your real
 * routes (`app.use(createMiddleware(engine))`). Requests nothing flags fall
 * through to `next()` untouched — including their unread body — so legitimate
 * traffic is never disturbed. Only once a first-phase detector flags a request
 * that also has body-inspecting detectors is the body read.
 */
export function createMiddleware(engine: HoneypotEngine): HoneypotMiddleware {
  return async function honeypotMiddleware(req, res, next) {
    // Nothing below may reject into the host application. This middleware sits in
    // front of someone else's routes, and an async middleware that rejects is not
    // caught by Express 4 — the request simply hangs until it times out. The engine
    // already isolates a throwing detector and a failing store, but the blocklist
    // check is a live backend call (Redis) and a response action writes to a socket
    // that can die mid-write, so both can still throw here. A honeypot that can take
    // the host app down with it is worse than no honeypot.
    try {
      await handle(engine, req, res, next);
    } catch (err) {
      // Once we have started answering, the host app cannot render an error page over
      // the top of it — close the response ourselves rather than hand Express a
      // half-written stream.
      if (res.headersSent || res.writableEnded) {
        if (!res.writableEnded) res.end();
        return;
      }
      next(err);
    }
  };
}

async function handle(engine: HoneypotEngine, req: IncomingMessage, res: ServerResponse, next: NextFn): Promise<void> {
  const method = req.method ?? "GET";
  const url = req.url ?? "/";
  const path = pathOf(url);
  const ip = engine.resolveIp(req.socket.remoteAddress, req.headers);

  // Allowlisted known-good sources bypass everything, including the block check.
  if (engine.isAllowlisted(ip)) {
    next();
    return;
  }

  if (await engine.isBlocked(ip)) {
    res.statusCode = 403;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end("Forbidden");
    return;
  }

  const baseFacts: RequestFacts = { method, path, query: parseQuery(url), headers: req.headers, rawHeaders: req.rawHeaders, ip };

  // A second, body-inspecting pass is only possible when some detector wants the body
  // AND this method can carry one. When it is, the first pass DEFERS recording: it is
  // the same request, and committing both passes counts it twice (see `EvaluateOptions`).
  const bodyPhase = engine.needsBodyPhase && mayHaveBody(method);
  let result = await engine.evaluate(baseFacts, bodyPhase ? { recordHit: false } : {});

  if (bodyPhase && result.detections.length > 0) {
    // Something fired, so this request is ours to handle — reading the body can no
    // longer disturb a downstream route. Re-evaluate with it, and commit exactly once:
    // the activity window already counted this request on the first pass.
    //
    // The second pass sees a superset of the first's inputs (same facts, same tracker
    // contents, plus the body), so it re-derives everything the first pass found and may
    // add more. The one way it can find less is a sliding window ageing out an event in
    // the microseconds between the two passes — a borderline request then falls through
    // unrecorded, which is the same outcome it would have had a moment later anyway.
    const body = await readBody(req);
    const facts = body !== undefined ? { ...baseFacts, body } : baseFacts;
    result = await engine.evaluate(facts, { trackActivity: false });
  }

  if (result.detections.length === 0) {
    next();
    return;
  }

  await dispatch(engine, res, result, ip, path);
}

export async function dispatch(
  engine: HoneypotEngine,
  res: ServerResponse,
  result: Awaited<ReturnType<HoneypotEngine["evaluate"]>>,
  ip: string,
  path: string,
): Promise<void> {
  const action = result.action ?? engine.actions.get("not-found");
  if (!action) {
    res.statusCode = 404;
    res.end();
    return;
  }
  const ctx: ResponseContext = {
    res,
    detection: result.detections[0]!,
    detections: result.detections,
    ip,
    path,
    totalScore: result.totalScore,
    tracker: result.tracker,
    blocklist: engine.blocklist,
  };
  await action.execute(ctx);
  if (!res.writableEnded) res.end();
}
