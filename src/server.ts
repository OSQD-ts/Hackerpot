import http from "node:http";
import { HoneypotEngine } from "./core.js";
import { hardenHttpServer } from "./http-hardening.js";
import { parseQuery, pathOf, readBody } from "./http-request.js";
import { dispatch } from "./middleware.js";
import type { RequestFacts } from "./detectors/types.js";
import type { HoneypotConfig } from "./types.js";

/**
 * Runs the honeypot as its own standalone HTTP service — no host app. Because
 * nothing sits downstream, it reads the request body up front so body-based
 * detectors always run, and anything no detector flags simply gets a 404.
 */
export class HoneypotServer {
  readonly engine: HoneypotEngine;
  private server: http.Server | undefined;

  constructor(config: HoneypotConfig = {}) {
    this.engine = new HoneypotEngine(config);
  }

  /**
   * Binds the listener. **Rejects** if the bind fails.
   *
   * It used to only ever resolve: `listen()`'s callback fires on success, and a failure
   * (EADDRINUSE, EACCES on a privileged port — the two most common ways a honeypot
   * deployment goes wrong) arrives as an `error` event on the server instead. With no
   * listener for it, Node rethrows it as an uncaughtException from inside the bind,
   * bypassing the caller's `await`. The standalone entrypoint's careful `ConfigError`
   * handling and its "port already in use" message never got a chance to run; the
   * operator got a raw stack trace. Every other listener in this project (the SSH
   * honeypot, the port-scan sentinel) already binds this way.
   */
  listen(port: number, host?: string): Promise<void> {
    if (this.server) return Promise.reject(new Error("HoneypotServer is already listening"));
    const server = http.createServer((req, res) => {
      void this.handle(req, res).catch(() => {
        if (!res.writableEnded) {
          if (!res.headersSent) res.statusCode = 500;
          res.end();
        }
      });
    });
    hardenHttpServer(server);
    this.server = server;

    return new Promise((resolve, reject) => {
      const onError = (err: Error): void => {
        this.server = undefined;
        reject(err);
      };
      server.once("error", onError);
      server.listen(port, host, () => {
        server.removeListener("error", onError);
        resolve();
      });
    });
  }

  private async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const method = req.method ?? "GET";
    const url = req.url ?? "/";
    const path = pathOf(url);
    const ip = this.engine.resolveIp(req.socket.remoteAddress, req.headers);

    // Allowlisted known-good sources bypass everything, including the block check, and so
    // does a request presenting a service token.
    if (this.engine.isAllowlisted(ip) || this.engine.serviceTokenFor(req.headers) !== undefined) {
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
    const facts: RequestFacts = { method, path, query: parseQuery(url), headers: req.headers, rawHeaders: req.rawHeaders, ip, body, httpVersion: req.httpVersion };
    const result = await this.engine.evaluate(facts);

    if (result.detections.length === 0) {
      res.statusCode = 404;
      res.end("Not Found");
      return;
    }
    await dispatch(this.engine, res, result, ip, result.path);
  }

  address(): ReturnType<http.Server["address"]> {
    return this.server?.address() ?? null;
  }

  /**
   * Stops the listener. Resolves immediately (rather than hanging) if it never started.
   *
   * `server.close()` alone stops accepting but then *waits for every live connection to
   * end*, and on an internet-facing honeypot who holds a connection open is the
   * attacker's choice: a half-sent request header keeps its socket in-flight until
   * `headersTimeout`/`requestTimeout` fires, so a shutdown stalls for up to 30 seconds
   * per such client — a deploy, a restart, or a test teardown hanging on traffic aimed
   * at us. Node closes *idle* keep-alive sockets on its own; these are the ones mid-
   * request, which it does not. `closeAllConnections()` ends them: we are shutting down,
   * so an in-flight probe has no answer coming either way.
   */
  close(): Promise<void> {
    const server = this.server;
    if (!server) return Promise.resolve();
    this.server = undefined;
    return new Promise((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
      server.closeAllConnections();
    });
  }
}
