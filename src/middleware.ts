import type { IncomingMessage, ServerResponse } from "node:http";
import type { EvaluateOptions, HoneypotEngine } from "./core.js";
import type { RequestFacts } from "./detectors/types.js";
import { mayHaveBody, parseQuery, pathOf, readBody } from "./http-request.js";
import type { ResponseContext } from "./responses/types.js";

export type NextFn = (err?: unknown) => void;
export type HoneypotMiddleware = (req: IncomingMessage, res: ServerResponse, next: NextFn) => Promise<void>;

export interface MiddlewareOptions {
  /**
   * Count a path toward `path-bruteforce` only once it is known to be a probe. Default true.
   *
   * In middleware mode the engine sees every request the app serves. One ordinary page
   * load of a modern SPA is 20+ distinct asset paths, which past the standalone-sized
   * default (15 in 30s) blocked a real visitor for loading a page. Path *bruteforce*
   * means guessing paths that do not exist, so a path handed to the app now counts only
   * if the app answers 404. A path the honeypot answers itself always counts.
   *
   * An app that answers unknown paths with 200 (an SPA history fallback, a catch-all
   * route) never produces a miss, so there this detector sees only the paths the
   * honeypot answers. For such an app, set this false and raise the threshold instead.
   *
   * `rate-spike` and `credential-bruteforce` still see every request: raw volume and
   * repeated attempts on one path are what they measure. Because a 404 is known only
   * once the app has answered, `path-bruteforce` fires from the request after the
   * threshold is reached rather than on it. Set false to count every path, as
   * standalone mode does.
   */
  countOnlyMissedPaths?: boolean;
  /**
   * What happens when the honeypot's own machinery fails before it has started answering,
   * for example when a Redis blocklist check throws. Default true: the error is reported
   * through the engine's `onError` (source `"middleware"`) and the request continues to
   * your routes with `next()`, so an outage in the honeypot never becomes an error page
   * for a real visitor. Set false to pass the error to `next(err)` instead.
   */
  failOpen?: boolean;
  /**
   * Let `block` run only when a detection is proof (`certain`). Default true.
   *
   * A block writes the address to the blocklist and the firewall enforcer, so every later
   * request from it is refused, your app's own pages included. In front of real users,
   * summed guesses reached that more than once (a shared browser fingerprint, one page
   * load's worth of asset paths). Without proof the request is answered with
   * `unprovenBlockFallback` instead, nothing is blocklisted, and the hit records
   * `downgradedFrom: "block"`. Proof today is a replayed honeytoken, a hidden trap, a
   * protocol violation `header-integrity` reports, a self-declared attack tool (sqlmap,
   * nikto, …), or a crawler claim `crawler-verification` refutes. Set false to block on
   * score alone, as standalone mode does.
   */
  blockRequiresProof?: boolean;
  /** Action run instead of an unproven block. Default "tarpit". Must not be "block". */
  unprovenBlockFallback?: string;
}

type GuardOptions = Pick<EvaluateOptions, "blockRequiresProof" | "unprovenBlockFallback">;

/**
 * Builds Express/Connect-compatible middleware. Mount it ahead of your real
 * routes (`app.use(createMiddleware(engine))`). Requests nothing flags fall
 * through to `next()` untouched — including their unread body — so legitimate
 * traffic is never disturbed. Only once a first-phase detector flags a request
 * that also has body-inspecting detectors is the body read.
 */
export function createMiddleware(engine: HoneypotEngine, options: MiddlewareOptions = {}): HoneypotMiddleware {
  const countOnlyMissedPaths = options.countOnlyMissedPaths ?? true;
  const failOpen = options.failOpen ?? true;
  const guard: GuardOptions = {
    blockRequiresProof: options.blockRequiresProof ?? true,
    unprovenBlockFallback: options.unprovenBlockFallback ?? "tarpit",
  };
  // The fallback is what an unproven block becomes; a block there would make the guard
  // report success while doing nothing.
  if (guard.unprovenBlockFallback === "block") {
    throw new Error('unprovenBlockFallback cannot be "block": it is the action an unproven block is replaced with');
  }
  return async function honeypotMiddleware(req, res, next) {
    // `next` runs at most once: if the host's next() throws synchronously, the catch below
    // must not continue the same request a second time.
    let continued = false;
    const proceed: NextFn = (err) => {
      continued = true;
      next(err);
    };
    // Nothing below may reject into the host application. This middleware sits in
    // front of someone else's routes, and an async middleware that rejects is not
    // caught by Express 4 — the request simply hangs until it times out. The engine
    // already isolates a throwing detector and a failing store, but the blocklist
    // check is a live backend call (Redis) and a response action writes to a socket
    // that can die mid-write, so both can still throw here. A honeypot that can take
    // the host app down with it is worse than no honeypot.
    try {
      await handle(engine, req, res, proceed, countOnlyMissedPaths, guard);
    } catch (err) {
      if (continued) {
        engine.reportError(err, { source: "middleware" });
        return;
      }
      // Once we have started answering, the host app cannot render an error page over
      // the top of it — close the response ourselves rather than hand Express a
      // half-written stream.
      if (res.headersSent || res.writableEnded) {
        if (!res.writableEnded) res.end();
        return;
      }
      if (failOpen) {
        // The honeypot failed, not the request. Report it and let the app serve it.
        engine.reportError(err, { source: "middleware" });
        proceed();
        return;
      }
      proceed(err);
    }
  };
}

async function handle(
  engine: HoneypotEngine,
  req: IncomingMessage,
  res: ServerResponse,
  next: NextFn,
  countOnlyMissedPaths: boolean,
  guard: GuardOptions,
): Promise<void> {
  const method = req.method ?? "GET";
  const url = req.url ?? "/";
  const path = pathOf(url);
  const ip = engine.resolveIp(req.socket.remoteAddress, req.headers);

  // Allowlisted known-good sources bypass everything, including the block check. So does a
  // request presenting one of your service tokens, whose address is not known in advance.
  if (engine.isAllowlisted(ip) || engine.serviceTokenFor(req.headers) !== undefined) {
    next();
    return;
  }

  if (await engine.isBlocked(ip)) {
    res.statusCode = 403;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end("Forbidden");
    return;
  }

  const baseFacts: RequestFacts = { method, path, query: parseQuery(url), headers: req.headers, rawHeaders: req.rawHeaders, ip, httpVersion: req.httpVersion };

  // A second, body-inspecting pass is only possible when some detector wants the body
  // AND this method can carry one. When it is, the first pass DEFERS recording: it is
  // the same request, and committing both passes counts it twice (see `EvaluateOptions`).
  const bodyPhase = engine.needsBodyPhase && mayHaveBody(method);
  const activityStatus = countOnlyMissedPaths ? "passed" : "seen";
  let result = await engine.evaluate(baseFacts, bodyPhase ? { recordHit: false, activityStatus, ...guard } : { activityStatus, ...guard });

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
    result = await engine.evaluate(facts, { trackActivity: false, ...guard });
  }

  if (result.detections.length === 0) {
    // A deferred first pass reports nothing, and with no live detection no second pass
    // follows to report shadowed findings, so they are reported here.
    if (bodyPhase && result.shadowDetections.length > 0) engine.reportShadow({ ip, method, path: result.path }, result.shadowDetections, false);
    if (countOnlyMissedPaths) {
      // Registered before next(), because the app may answer synchronously.
      const { tracker, path: tracked } = result;
      res.once("finish", () => {
        if (res.statusCode === 404) tracker.confirmPath(tracked);
      });
    }
    next();
    return;
  }

  // The honeypot answers this request itself, so it was a probe, not an app page.
  if (countOnlyMissedPaths) result.tracker.confirmPath(result.path);
  await dispatch(engine, res, result, ip, result.path);
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
    onError: (error, context) => engine.reportError(error, context),
  };
  await action.execute(ctx);
  if (!res.writableEnded) res.end();
}

/** A request whose body your framework has already parsed into `req.body`. */
type ParsedBodyRequest = IncomingMessage & { body?: unknown };

/**
 * Checks a form's hidden trap fields after your body parser has run.
 *
 * The honeypot middleware sits in front of your routes and reads a body only for a request
 * something already flagged, so a hidden field in a POST form, the kind trap fields are put
 * on, is never seen there. Mount this on the form's route after your body parser:
 *
 * ```ts
 * app.post("/signup", express.urlencoded({ extended: false }), trapFormGuard(engine), signupHandler);
 * ```
 *
 * It runs the engine over the parsed fields (`RequestFacts.formFields`) without counting the
 * request a second time. If anything fires, the honeypot answers the request, as the
 * middleware would have; otherwise the request continues to your handler. Configure the
 * field names on the engine's `trapDetector({ formFields })`. Fails open, like the middleware.
 */
export function trapFormGuard(engine: HoneypotEngine, options: Pick<MiddlewareOptions, "blockRequiresProof" | "unprovenBlockFallback"> = {}): HoneypotMiddleware {
  const guard: GuardOptions = {
    blockRequiresProof: options.blockRequiresProof ?? true,
    unprovenBlockFallback: options.unprovenBlockFallback ?? "tarpit",
  };
  return async function honeypotTrapFormGuard(req: ParsedBodyRequest, res, next) {
    let continued = false;
    try {
      const fields = req.body;
      if (fields === null || typeof fields !== "object" || Array.isArray(fields)) {
        continued = true;
        next();
        return;
      }
      const url = req.url ?? "/";
      const ip = engine.resolveIp(req.socket.remoteAddress, req.headers);
      if (engine.isAllowlisted(ip) || engine.serviceTokenFor(req.headers) !== undefined) {
        continued = true;
        next();
        return;
      }
      const facts: RequestFacts = {
        method: req.method ?? "POST",
        path: pathOf(url),
        query: parseQuery(url),
        headers: req.headers,
        rawHeaders: req.rawHeaders,
        ip,
        httpVersion: req.httpVersion,
        formFields: fields as Record<string, unknown>,
      };
      // The middleware in front already counted this request and judged it on its headers.
      // Only a trap field can add anything here, so only the trap decides.
      const result = await engine.evaluate(facts, { trackActivity: false, recordHit: false, audit: false, ...guard });
      if (!result.detections.some((detection) => detection.detectorId === "trap")) {
        continued = true;
        next();
        return;
      }
      const committed = await engine.evaluate(facts, { trackActivity: false, audit: false, ...guard });
      await dispatch(engine, res, committed, ip, committed.path);
    } catch (err) {
      engine.reportError(err, { source: "trap-form-guard" });
      if (continued) return;
      if (res.headersSent || res.writableEnded) {
        if (!res.writableEnded) res.end();
        return;
      }
      next();
    }
  };
}
