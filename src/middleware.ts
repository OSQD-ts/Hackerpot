import type { IncomingMessage, ServerResponse } from "node:http";
import type { HoneypotEngine } from "./core.js";
import type { RequestFacts } from "./detectors/types.js";
import type { ResponseContext } from "./responses/types.js";

export type NextFn = (err?: unknown) => void;
export type HoneypotMiddleware = (req: IncomingMessage, res: ServerResponse, next: NextFn) => Promise<void>;

const MAX_BODY_BYTES = 64 * 1024;

function readBody(req: IncomingMessage): Promise<string | undefined> {
  const method = (req.method ?? "GET").toUpperCase();
  if (method === "GET" || method === "HEAD") return Promise.resolve(undefined);

  return new Promise((resolve) => {
    let data = "";
    let bytes = 0;
    let truncated = false;
    req.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > MAX_BODY_BYTES) {
        truncated = true;
        return;
      }
      data += chunk.toString("utf8");
    });
    req.on("end", () => resolve(truncated ? `${data}…[truncated]` : data));
    req.on("error", () => resolve(undefined));
  });
}

function parseQuery(url: string): Record<string, string> {
  // Null-prototype bag: a literal `?__proto__=…` param becomes an ordinary own key
  // (a plain object silently discards it via the __proto__ setter), so detectors can
  // actually see a prototype-pollution probe — and the honeypot itself can never be
  // prototype-polluted through query parsing.
  const query: Record<string, string> = Object.create(null);
  const queryStart = url.indexOf("?");
  if (queryStart === -1) return query;
  for (const [key, value] of new URLSearchParams(url.slice(queryStart)).entries()) query[key] = value;
  return query;
}

/**
 * Builds Express/Connect-compatible middleware. Mount it ahead of your real
 * routes (`app.use(createMiddleware(engine))`). Requests nothing flags fall
 * through to `next()` untouched — including their unread body — so legitimate
 * traffic is never disturbed. Only once a first-phase detector flags a request
 * that also has body-inspecting detectors is the body read.
 */
export function createMiddleware(engine: HoneypotEngine): HoneypotMiddleware {
  return async function honeypotMiddleware(req, res, next) {
    const method = req.method ?? "GET";
    const url = req.url ?? "/";
    const path = url.split("?")[0] ?? "/";
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

    let result = await engine.evaluate(baseFacts);

    // Second phase: something fired and a body-inspecting detector exists — read
    // the body and re-evaluate so injection payloads in the body are caught too.
    if (result.detections.length > 0 && engine.needsBodyPhase && baseFacts.body === undefined) {
      const body = await readBody(req);
      if (body !== undefined) result = await engine.evaluate({ ...baseFacts, body });
    }

    if (result.detections.length === 0) {
      next();
      return;
    }

    await dispatch(engine, res, result, ip, path);
  };
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
