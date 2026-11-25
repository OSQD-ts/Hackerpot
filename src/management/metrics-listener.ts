import http from "node:http";
import type { AddressInfo } from "node:net";
import { IpAllowlist } from "../allowlist.js";
import type { IncidentBroker } from "./broker.js";
import { type EngineCounters, IncidentCounters } from "./metrics.js";

export interface MetricsListenerOptions {
  /** Default 127.0.0.1. */
  host?: string;
  /** Default 9502. */
  port?: number;
  /** The one path served. Default `/metrics`. */
  path?: string;
  /** Addresses or ranges allowed to scrape. Empty or absent allows any peer that reaches the bind. */
  allowedClients?: readonly string[];
  /** The fan-out every incident is published on. The counters subscribe at construction. */
  broker: IncidentBroker;
  /** Live gauges the incidents cannot supply: active blocks, tracked addresses. */
  gauges?: () => Record<string, number> | Promise<Record<string, number>>;
  /** What the engine counts that no incident carries. Pass `() => engine.counters()`. */
  engineCounters?: () => EngineCounters;
  onError?: (error: Error) => void;
}

/**
 * Serves `/metrics` and nothing else.
 *
 * Scraping used to mean enabling `[management]`: a REST API over every captured request, a
 * WebSocket feed and an API key the scraper had to hold. A Prometheus server needs none of
 * that, and a listener that can only ever answer with counters has nothing to leak, so it can
 * sit on a network the management API never should. Counted from published incidents, as the
 * management server's own `/metrics` is, so it never reads the store.
 */
export class MetricsListener {
  private readonly counters = new IncidentCounters();
  private readonly host: string;
  private readonly port: number;
  private readonly path: string;
  private readonly allowed: IpAllowlist | undefined;
  private server: http.Server | undefined;

  constructor(private readonly options: MetricsListenerOptions) {
    this.host = options.host ?? "127.0.0.1";
    this.port = options.port ?? 9502;
    this.path = options.path ?? "/metrics";
    this.allowed = options.allowedClients && options.allowedClients.length > 0 ? new IpAllowlist([...options.allowedClients]) : undefined;
    options.broker.subscribe((incident) => this.counters.record(incident));
  }

  /** The exposition text this listener serves. */
  async text(): Promise<string> {
    const gauges = this.options.gauges ? await this.options.gauges() : undefined;
    const engine = this.options.engineCounters?.();
    return this.counters.render(gauges, undefined, engine?.detectorFailures, engine);
  }

  async listen(): Promise<void> {
    const server = http.createServer((request, response) => {
      void this.handle(request, response).catch((error: unknown) => {
        this.options.onError?.(error instanceof Error ? error : new Error(String(error)));
        if (!response.headersSent) response.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
        response.end("Internal Server Error");
      });
    });
    // A scrape is one small request; nothing legitimate holds a connection open for long.
    server.requestTimeout = 10_000;
    server.headersTimeout = 10_000;
    server.keepAliveTimeout = 5_000;
    this.server = server;
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(this.port, this.host, () => {
        server.off("error", reject);
        resolve();
      });
    });
  }

  private async handle(request: http.IncomingMessage, response: http.ServerResponse): Promise<void> {
    const peer = request.socket.remoteAddress ?? "";
    if (this.allowed !== undefined && !this.allowed.allows(peer)) {
      // Closed without an answer: a refused peer learns nothing about what is listening here.
      request.socket.destroy();
      return;
    }
    const path = (request.url ?? "/").split("?")[0];
    if (path !== this.path) {
      response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("Not Found");
      return;
    }
    if (request.method !== "GET" && request.method !== "HEAD") {
      response.writeHead(405, { Allow: "GET, HEAD", "Content-Type": "text/plain; charset=utf-8" });
      response.end("Method Not Allowed");
      return;
    }
    const body = await this.text();
    response.writeHead(200, { "Content-Type": "text/plain; version=0.0.4; charset=utf-8", "Cache-Control": "no-store" });
    response.end(request.method === "HEAD" ? undefined : body);
  }

  address(): AddressInfo | string | null {
    return this.server?.address() ?? null;
  }

  async close(): Promise<void> {
    const server = this.server;
    if (!server) return;
    this.server = undefined;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    server.closeAllConnections?.();
  }
}
