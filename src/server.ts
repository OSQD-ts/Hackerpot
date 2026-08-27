import http from "node:http";
import { HoneypotEngine } from "./core.js";
import { hardenHttpServer } from "./http-hardening.js";
import { dispatch } from "./middleware.js";
import type { RequestFacts } from "./detectors/types.js";
import type { HoneypotConfig } from "./types.js";

const MAX_BODY_BYTES = 64 * 1024;

function readBody(req: http.IncomingMessage): Promise<string | undefined> {
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
  // Null-prototype bag so a literal `?__proto__=…` param becomes a real own key that
  // detectors can inspect (a plain object silently drops it), and the honeypot itself
  // can never be prototype-polluted through query parsing.
  const query: Record<string, string> = Object.create(null);
  const queryStart = url.indexOf("?");
  if (queryStart === -1) return query;
  for (const [key, value] of new URLSearchParams(url.slice(queryStart)).entries()) query[key] = value;
  return query;
}

/**
 * Runs the honeypot as its own standalone HTTP service — no host app. Because
 * nothing sits downstream, it reads the request body up front so body-based
 * detectors always run, and anything no detector flags simply gets a 404.
 */
export class HoneypotServer {
  readonly engine: HoneypotEngine;
  private server?: http.Server;

  constructor(config: HoneypotConfig = {}) {
    this.engine = new HoneypotEngine(config);
  }

  listen(port: number, host?: string): Promise<void> {
    this.server = http.createServer((req, res) => {
      void this.handle(req, res).catch(() => {
        if (!res.writableEnded) {
          res.statusCode = 500;
          res.end();
        }
      });
    });
    hardenHttpServer(this.server);
    return new Promise((resolve) => this.server?.listen(port, host, resolve));
  }

  private async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const method = req.method ?? "GET";
    const url = req.url ?? "/";
    const path = url.split("?")[0] ?? "/";
    const ip = this.engine.resolveIp(req.socket.remoteAddress, req.headers);

    // Allowlisted known-good sources bypass everything, including the block check.
    if (this.engine.isAllowlisted(ip)) {
      res.statusCode = 404;
      res.end("Not Found");
      return;
    }

    if (await this.engine.isBlocked(ip)) {
      res.statusCode = 403;
      res.end("Forbidden");
      return;
    }

    const body = await readBody(req);
    const facts: RequestFacts = { method, path, query: parseQuery(url), headers: req.headers, rawHeaders: req.rawHeaders, ip, body };
    const result = await this.engine.evaluate(facts);

    if (result.detections.length === 0) {
      res.statusCode = 404;
      res.end("Not Found");
      return;
    }
    await dispatch(this.engine, res, result, ip, path);
  }

  address(): ReturnType<http.Server["address"]> {
    return this.server?.address() ?? null;
  }

  close(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server?.close((err) => (err ? reject(err) : resolve()));
    });
  }
}
