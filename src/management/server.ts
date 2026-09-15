import http from "node:http";
import type { Duplex } from "node:stream";
import { WebSocketServer, type WebSocket } from "ws";
import type { HitStore } from "../types.js";
import { extractApiKey, isAuthorized } from "./auth.js";
import { IncidentBroker } from "./broker.js";
import { WebhookDispatcher } from "./webhooks.js";
import { computeActors, computeIoc, computeSessions, computeStats, getIncident, listIncidents } from "./rest.js";
import { IncidentCounters } from "./metrics.js";
import { hardenHttpServer } from "../http-hardening.js";
import type { ManagementConfig } from "./types.js";
import type { TrafficAnomaly } from "../audit.js";

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
  /**
   * Failures and timeouts per detector, for `hackerpot_detector_failures_total`. Pass
   * `() => engine.detectorFailures`. A failure is not an incident, so the store cannot supply it.
   */
  detectorFailures?: () => Map<string, number> | Record<string, number>;
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
  private readonly detectorFailures: (() => Map<string, number> | Record<string, number>) | undefined;
  private server?: http.Server;
  private wss?: WebSocketServer;
  private webhooks?: WebhookDispatcher;
  private readonly webhookConfigs;
  private readonly webhookGlobalMaxPerMinute: number | undefined;
  /** Failed-auth timestamps per peer IP, for rate-limiting API-key brute force. */
  private readonly authFailures = new Map<string, number[]>();
  private static readonly AUTH_WINDOW_MS = 60_000;
  private static readonly AUTH_MAX_FAILURES = 20;
  /** Unread bytes a live-feed viewer may accumulate before incidents are dropped for it. */
  private static readonly WS_MAX_BUFFERED_BYTES = 1024 * 1024;
  /** How long a viewer may stay over that ceiling before it is disconnected. */
  private static readonly WS_STALL_MS = 20_000;
  private streamDroppedTotal = 0;
  /** `/metrics` numbers, counted as incidents are published rather than read from the store. */
  private readonly counters = new IncidentCounters();

  constructor(options: ManagementServerOptions) {
    this.store = options.store;
    // A broker we create reports a misbehaving subscriber on the server's own error
    // channel; a broker passed in keeps whatever channel its owner gave it.
    this.broker = options.broker ?? new IncidentBroker((err) => options.onError?.(err as Error));
    // Subscribed at construction, so incidents published before `listen()` still count.
    this.broker.subscribe((incident) => this.counters.record(incident));
    this.apiKeys = options.apiKeys ?? [];
    this.host = options.host ?? "127.0.0.1";
    this.port = options.port ?? 9500;
    this.wsEnabled = options.websocket ?? true;
    this.webhookConfigs = options.webhooks ?? [];
    this.webhookGlobalMaxPerMinute = options.webhookGlobalMaxPerMinute;
    this.onError = options.onError;
    this.metricsProvider = options.metrics;
    this.detectorFailures = options.detectorFailures;
  }

  /**
   * Sends a traffic anomaly (see `TrafficAudit`) to every webhook that accepts them. Does
   * nothing before `listen()` or without webhooks. Never throws.
   */
  announce = (anomaly: TrafficAnomaly): void => {
    this.webhooks?.announce(anomaly);
  };

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
        ...(this.webhookGlobalMaxPerMinute ? { globalMaxPerMinute: this.webhookGlobalMaxPerMinute } : {}),
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

  /**
   * Parses a request target into a `URL`, returning undefined when it will not parse.
   *
   * The base is the fixed literal `http://management.invalid` rather than the client's
   * `Host` header. Building the base out of that header made an attacker-supplied string
   * part of a URL the constructor has to accept — and `Host: ]` is not a parseable
   * authority, so `new URL()` threw `TypeError: Invalid URL`. On the HTTP path that
   * surfaced as a spurious 500; on the **upgrade** path, which runs inside an event
   * handler with no `try`, it was an uncaughtException that killed the process. One
   * unauthenticated request — the throw happens before the API-key check — took down
   * the management server and, in standalone mode, the honeypot sharing the process.
   *
   * Nothing here routes on the host: every endpoint dispatches on pathname and query
   * alone. So the header is simply not an input to this, and a request target that is
   * itself malformed is now reported rather than thrown.
   */
  private static parseUrl(req: http.IncomingMessage): URL | undefined {
    try {
      return new URL(req.url ?? "/", "http://management.invalid");
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
      const url = ManagementServer.parseUrl(req);
      if (!url) {
        this.sendJson(res, 400, { error: "bad request target" });
        return;
      }
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
        const body = await this.metricsText();
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
    const url = ManagementServer.parseUrl(req);
    if (!url || url.pathname !== "/stream" || !this.wss) {
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

  /** Live-feed incidents dropped because a viewer was not reading fast enough. */
  get streamDropped(): number {
    return this.streamDroppedTotal;
  }

  private onWsConnection(ws: WebSocket): void {
    ws.send(JSON.stringify({ type: "connected", ts: new Date().toISOString() }));
    // `ws.send` never refuses. A viewer that stops reading (a frozen tab, a closed laptop,
    // a deliberately stalled client holding an API key) made every send queue in this
    // process: during a flood, one serialized incident per request, per stalled viewer,
    // with no bound. So past a buffer ceiling incidents are dropped for that viewer, it
    // is told how many it missed once it catches up, and a viewer stuck over the ceiling
    // for WS_STALL_MS is disconnected.
    let dropped = 0;
    let stalledSince: number | undefined;
    const unsubscribe = this.broker.subscribe((incident) => {
      if (ws.readyState !== ws.OPEN) return;
      if (ws.bufferedAmount > ManagementServer.WS_MAX_BUFFERED_BYTES) {
        dropped += 1;
        this.streamDroppedTotal += 1;
        const now = Date.now();
        stalledSince ??= now;
        if (now - stalledSince >= ManagementServer.WS_STALL_MS) ws.terminate();
        return;
      }
      stalledSince = undefined;
      if (dropped > 0) {
        ws.send(JSON.stringify({ type: "lagged", dropped }));
        dropped = 0;
      }
      ws.send(JSON.stringify({ type: "incident", incident }));
    });
    ws.on("close", unsubscribe);
    ws.on("error", unsubscribe);
  }

  /**
   * The Prometheus exposition `GET /metrics` serves: counted as incidents are published, so it
   * never reads the store and its counters only rise. Public so an in-process dashboard shows
   * the same numbers the scrape does.
   */
  async metricsText(): Promise<string> {
    const extra = this.metricsProvider ? await this.metricsProvider() : undefined;
    return this.counters.render(extra, { stream_dropped_total: this.streamDroppedTotal }, this.detectorFailures?.());
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
      // `close()` waits for live connections; a peer mid-request (a half-sent header
      // line) holds one until `requestTimeout` fires, stalling shutdown by up to 30s.
      // See `HoneypotServer.close` — same reasoning, same fix.
      this.server.closeAllConnections();
    });
  }
}
