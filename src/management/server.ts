import http from "node:http";
import type { Duplex } from "node:stream";
import { WebSocketServer, type WebSocket } from "ws";
import type { HitStore } from "../types.js";
import { extractApiKey, isAuthorized } from "./auth.js";
import { IncidentBroker } from "./broker.js";
import { WebhookDispatcher } from "./webhooks.js";
import { computeActors, computeIoc, computeSessions, computeStats, getIncident, listIncidents } from "./rest.js";
import { renderMetrics } from "./metrics.js";
import { hardenHttpServer } from "../http-hardening.js";
import type { ManagementConfig } from "./types.js";

export interface ManagementServerOptions extends ManagementConfig {
  /** The same store the honeypot writes hits to — REST queries read from it. */
  store: HitStore;
  /** Optional shared broker; one is created if omitted. Feed it via `publish()`. */
  broker?: IncidentBroker;
  onError?: (error: Error) => void;
  /**
   * Extra numeric gauges to include on `GET /metrics` (Prometheus). Wire live
   * values a store can't provide — e.g. active blocks or open honeypot connections.
   * Names must be `[a-zA-Z_][a-zA-Z0-9_]*`; each is emitted as `hackerpot_<name>`.
   */
  metrics?: () => Record<string, number> | Promise<Record<string, number>>;
}

/**
 * Standalone HTTP server for retrieving incidents, bound to its own configurable
 * host/port and protected by API keys — kept entirely separate from the
 * attacker-facing honeypot listener. Exposes REST endpoints, a WebSocket live
 * feed, and drives webhook delivery.
 */
export class ManagementServer {
  readonly broker: IncidentBroker;
  private readonly store: HitStore;
  private readonly apiKeys: string[];
  private readonly host: string;
  private readonly port: number;
  private readonly wsEnabled: boolean;
  private readonly onError: ((error: Error) => void) | undefined;
  private readonly metricsProvider: (() => Record<string, number> | Promise<Record<string, number>>) | undefined;
  private server?: http.Server;
  private wss?: WebSocketServer;
  private webhooks?: WebhookDispatcher;
  private readonly webhookConfigs;
  /** Failed-auth timestamps per peer IP, for rate-limiting API-key brute force. */
  private readonly authFailures = new Map<string, number[]>();
  private static readonly AUTH_WINDOW_MS = 60_000;
  private static readonly AUTH_MAX_FAILURES = 20;

  constructor(options: ManagementServerOptions) {
    this.store = options.store;
    this.broker = options.broker ?? new IncidentBroker();
    this.apiKeys = options.apiKeys ?? [];
    this.host = options.host ?? "127.0.0.1";
    this.port = options.port ?? 9500;
    this.wsEnabled = options.websocket ?? true;
    this.webhookConfigs = options.webhooks ?? [];
    this.onError = options.onError;
    this.metricsProvider = options.metrics;
  }

  /** Feed an incident into the live feed + webhooks. Wire the engine's onHit to this. */
  publish = (incident: Parameters<IncidentBroker["publish"]>[0]): void => {
    this.broker.publish(incident);
  };

  async listen(): Promise<void> {
    this.server = http.createServer((req, res) => void this.handleHttp(req, res));
    hardenHttpServer(this.server);

    if (this.wsEnabled) {
      this.wss = new WebSocketServer({ noServer: true });
      this.server.on("upgrade", (req, socket, head) => this.handleUpgrade(req, socket as Duplex, head));
    }

    if (this.webhookConfigs.length > 0) {
      this.webhooks = new WebhookDispatcher({
        webhooks: this.webhookConfigs,
        onError: (url, err) => this.onError?.(new Error(`webhook ${url}: ${err.message}`)),
      });
      this.webhooks.attach(this.broker);
    }

    // Reject on a failed bind rather than letting the `error` event surface as an
    // uncaughtException past the caller's `await` — same rail as `HoneypotServer.listen`.
    const server = this.server;
    await new Promise<void>((resolve, reject) => {
      const onError = (err: Error): void => reject(err);
      server.once("error", onError);
      server.listen(this.port, this.host, () => {
        server.removeListener("error", onError);
        resolve();
      });
    });
  }

  /** This peer's failures inside the current window, pruning what has aged out. */
  private recentAuthFailures(ip: string, now: number): number[] {
    const recorded = this.authFailures.get(ip);
    if (!recorded) return [];
    const recent = recorded.filter((t) => now - t < ManagementServer.AUTH_WINDOW_MS);
    // Write the pruned list back so a peer that stops failing shrinks instead of
    // being re-filtered from its full history on every subsequent request.
    if (recent.length === 0) this.authFailures.delete(ip);
    else if (recent.length !== recorded.length) this.authFailures.set(ip, recent);
    return recent;
  }

  /** True if this peer IP has exceeded the failed-auth budget in the current window. */
  private tooManyAuthFailures(ip: string): boolean {
    return this.recentAuthFailures(ip, Date.now()).length >= ManagementServer.AUTH_MAX_FAILURES;
  }

  /** Record a failed auth for a peer IP (windowed), keeping the map bounded. */
  private recordAuthFailure(ip: string): void {
    const now = Date.now();
    const recent = this.recentAuthFailures(ip, now);
    recent.push(now);
    this.authFailures.set(ip, recent);
    // Bound the map: drop entries whose most recent failure has aged out of the window.
    if (this.authFailures.size > 10_000) {
      for (const [k, ts] of this.authFailures) {
        if (ts.length === 0 || now - ts[ts.length - 1]! >= ManagementServer.AUTH_WINDOW_MS) this.authFailures.delete(k);
      }
    }
  }

  /** Decode a path segment, returning undefined on malformed percent-encoding (→ 404, not 500). */
  private static decodeSegment(segment: string): string | undefined {
    try {
      return decodeURIComponent(segment);
    } catch {
      return undefined;
    }
  }

  private sendJson(res: http.ServerResponse, status: number, body: unknown): void {
    // The catch-all in `handleHttp` calls this after a handler has already begun
    // writing (`/metrics` streams its body before it can fail). Setting a status or a
    // header then throws ERR_HTTP_HEADERS_SENT, which replaces the real error with a
    // second one and leaves the socket open until it times out.
    if (res.writableEnded) return;
    if (res.headersSent) {
      res.end();
      return;
    }
    const payload = JSON.stringify(body);
    res.statusCode = status;
    res.setHeader("Content-Type", "application/json");
    res.end(payload);
  }

  private async handleHttp(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    try {
      const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
      const path = url.pathname;
      const method = req.method ?? "GET";

      // Unauthenticated liveness probe.
      if (method === "GET" && path === "/health") {
        this.sendJson(res, 200, { status: "ok" });
        return;
      }

      // Rate-limit API-key brute force per peer IP. Keyed on the real socket address
      // (never a client header — this API is private and directly connected), so it
      // can't be evaded or weaponized against a victim via a forged header.
      const peerIp = req.socket.remoteAddress ?? "unknown";
      if (this.tooManyAuthFailures(peerIp)) {
        res.setHeader("Retry-After", "60");
        this.sendJson(res, 429, { error: "too many failed authentications" });
        return;
      }

      if (!isAuthorized(extractApiKey(req), this.apiKeys)) {
        this.recordAuthFailure(peerIp);
        res.setHeader("WWW-Authenticate", "Bearer");
        this.sendJson(res, 401, { error: "unauthorized" });
        return;
      }

      if (method === "GET" && path === "/incidents") {
        this.sendJson(res, 200, { incidents: await listIncidents(this.store, url.searchParams) });
        return;
      }
      const idMatch = path.match(/^\/incidents\/([^/]+)$/);
      if (method === "GET" && idMatch) {
        const id = ManagementServer.decodeSegment(idMatch[1]!);
        const incident = id !== undefined ? await getIncident(this.store, id) : undefined;
        if (!incident) {
          this.sendJson(res, 404, { error: "not found" });
          return;
        }
        this.sendJson(res, 200, { incident });
        return;
      }
      if (method === "GET" && path === "/stats") {
        this.sendJson(res, 200, await computeStats(this.store));
        return;
      }
      if (method === "GET" && path === "/metrics") {
        const extra = this.metricsProvider ? await this.metricsProvider() : undefined;
        const body = await renderMetrics(this.store, extra);
        res.statusCode = 200;
        res.setHeader("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
        res.end(body);
        return;
      }
      if (method === "GET" && path === "/ioc") {
        const minScore = Number(url.searchParams.get("min_score") ?? 0) || 0;
        this.sendJson(res, 200, { indicators: await computeIoc(this.store, minScore) });
        return;
      }
      if (method === "GET" && path === "/ioc.txt") {
        // Plain newline-separated IPs for direct firewall / ipset consumption.
        const minScore = Number(url.searchParams.get("min_score") ?? 0) || 0;
        const ips = (await computeIoc(this.store, minScore)).map((e) => e.ip);
        res.statusCode = 200;
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.end(ips.length ? ips.join("\n") + "\n" : "");
        return;
      }
      if (method === "GET" && path === "/sessions") {
        this.sendJson(res, 200, { sessions: await computeSessions(this.store) });
        return;
      }
      const sessionMatch = path.match(/^\/sessions\/([^/]+)$/);
      if (method === "GET" && sessionMatch) {
        const sip = ManagementServer.decodeSegment(sessionMatch[1]!);
        const sessions = sip !== undefined ? await computeSessions(this.store, sip) : [];
        if (sessions.length === 0) {
          this.sendJson(res, 404, { error: "no session for that IP" });
          return;
        }
        this.sendJson(res, 200, { session: sessions[0] });
        return;
      }
      if (method === "GET" && path === "/actors") {
        this.sendJson(res, 200, { actors: await computeActors(this.store) });
        return;
      }
      const actorMatch = path.match(/^\/actors\/([^/]+)$/);
      if (method === "GET" && actorMatch) {
        const fp = ManagementServer.decodeSegment(actorMatch[1]!);
        const actors = fp !== undefined ? await computeActors(this.store, fp) : [];
        if (actors.length === 0) {
          this.sendJson(res, 404, { error: "no actor with that fingerprint" });
          return;
        }
        this.sendJson(res, 200, { actor: actors[0] });
        return;
      }

      this.sendJson(res, 404, { error: "not found" });
    } catch (err) {
      this.onError?.(err as Error);
      this.sendJson(res, 500, { error: "internal error" });
    }
  }

  private handleUpgrade(req: http.IncomingMessage, socket: Duplex, head: Buffer): void {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    if (url.pathname !== "/stream" || !this.wss) {
      socket.destroy();
      return;
    }
    // The upgrade path authenticates with the same keys as REST, so it must feed the
    // same failed-auth budget. Rate-limiting only the REST handler left this route as an
    // unmetered API-key brute-force oracle: an attacker who could reach the management
    // port simply guessed over `GET /stream?api_key=…` forever, and the 20-failures-per
    // -minute ceiling on /incidents never saw a single one of those attempts.
    const peerIp = req.socket.remoteAddress ?? "unknown";
    if (this.tooManyAuthFailures(peerIp)) {
      socket.write("HTTP/1.1 429 Too Many Requests\r\nRetry-After: 60\r\n\r\n");
      socket.destroy();
      return;
    }
    if (!isAuthorized(extractApiKey(req), this.apiKeys)) {
      this.recordAuthFailure(peerIp);
      socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
      socket.destroy();
      return;
    }
    this.wss.handleUpgrade(req, socket, head, (ws) => this.onWsConnection(ws));
  }

  private onWsConnection(ws: WebSocket): void {
    ws.send(JSON.stringify({ type: "connected", ts: new Date().toISOString() }));
    const unsubscribe = this.broker.subscribe((incident) => {
      if (ws.readyState === ws.OPEN) ws.send(JSON.stringify({ type: "incident", incident }));
    });
    ws.on("close", unsubscribe);
    ws.on("error", unsubscribe);
  }

  address(): ReturnType<http.Server["address"]> {
    return this.server?.address() ?? null;
  }

  async close(): Promise<void> {
    this.webhooks?.detach();
    for (const client of this.wss?.clients ?? []) client.terminate();
    this.wss?.close();
    await new Promise<void>((resolve, reject) => {
      if (!this.server) return resolve();
      this.server.close((err) => (err ? reject(err) : resolve()));
    });
  }
}
