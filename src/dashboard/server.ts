import { randomBytes, timingSafeEqual, createHash } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { hostname } from "node:os";
import type { Socket } from "node:net";
import { IpAllowlist } from "../allowlist.js";
import { hardenHttpServer } from "../http-hardening.js";
import { redactIncident } from "../management/redact.js";
import type { Incident } from "../management/types.js";
import { VERSION } from "../version.js";
import { renderDashboardPage } from "./page.js";
import { toDashboardSource, type DashboardSource, type DashboardSourceLike } from "./source.js";
import type {
  DashboardAuth,
  DashboardBootstrap,
  DashboardHandlerOptions,
  DashboardOptions,
  DashboardRedaction,
  DashboardRefusal,
  DashboardRequestHandler,
  DashboardSections,
  DashboardServer,
} from "./types.js";

/**
 * The operator dashboard, served by the library. Adapted from bothandlerjs.
 *
 * Three ways to run the same page:
 *
 * - `startDashboard(source)` on a listener of its own: loopback by default, the page at `/`.
 * - `createDashboardHandler(source, { basePath, auth })` mounted on a server you already run.
 * - `<hackerpot-dashboard src="/_hackerpot">` from `@osqd/hackerpot/element`, dropped into
 *   an admin page of yours and backed by a mounted handler.
 *
 * And two kinds of source behind any of them: this process (an engine, a management server,
 * a store) or another HackerPot's management API, which is how `hackerpot dashboard` runs the
 * page as a service beside the stack.
 *
 * Everything on the page is attacker-written text: paths, User-Agents, request bodies, shell
 * commands captured by the protocol honeypots. The page therefore never assembles HTML from
 * data, runs under a nonce CSP with `default-src 'none'`, and sends no CORS headers.
 */

export class DashboardConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DashboardConfigError";
  }
}

/**
 * Beside the management API's 9500, and deliberately not bothandlerjs's 9674: a deployment
 * running both libraries should get both dashboards without editing a port.
 */
const DEFAULT_PORT = 9501;
const DEFAULT_HOST = "127.0.0.1";
const HEARTBEAT_MS = 15_000;
const DEFAULT_EVENTS_PER_SECOND = 100;
/** A viewer stuck this long, or this far behind, is disconnected; its browser reconnects. */
const LAG_LIMIT_MS = 20_000;
const LAG_DROP_LIMIT = 5_000;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost", "[::1]"]);
const MOUNTED = "a server of your own";
const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
/** Most incidents one listing may return. The page asks for its analytics window, never the whole store. */
const MAX_LIST_LIMIT = 5_000;

/**
 * Headers on every response. `no-store` because a cached dashboard is a cached evidence
 * trail; `DENY` because a page like this has no business inside somebody else's frame;
 * `no-referrer` because a token can be in the query.
 */
const SECURITY_HEADERS: Record<string, string> = {
  "cache-control": "no-store, max-age=0",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
};

interface Stream {
  response: ServerResponse;
  lagging: boolean;
  laggingSince: number;
  dropped: number;
  windowStart: number;
  windowCount: number;
  skipped: number;
}

interface Dashboard {
  serve(request: IncomingMessage, response: ServerResponse): void;
  readonly clients: number;
  close(): Promise<void>;
}

function buildDashboard(sourceLike: DashboardSourceLike, options: DashboardOptions, host: string | undefined): Dashboard {
  const mounted = host === undefined;
  const source: DashboardSource = toDashboardSource(sourceLike);
  const basePath = normalizeBase(options.basePath ?? "/");
  const auth = validateAuth(options.auth, host ?? MOUNTED);
  const refusal = validateRefusal(options.refusal ?? "unauthorized", auth);
  const allowedHosts = mounted ? resolveMountedHosts(options.allowedHosts) : resolveAllowedHosts(host, options.allowedHosts);
  const allowedClients = validateClients(options.allowedClients);
  const throttle = createAuthThrottle(options.authThrottle);
  const sections = resolveSections(options.sections);
  const redaction: Required<DashboardRedaction> = { credentials: options.redact?.credentials !== false, maskIp: options.redact?.maskIp === true };
  const maxClients = Math.max(1, options.maxClients ?? 16);
  const maxEventsPerSecond = Math.max(0, options.maxEventsPerSecond ?? DEFAULT_EVENTS_PER_SECOND);
  const onError = options.onError ?? (() => undefined);

  const bootstrap: DashboardBootstrap = {
    base: basePath === "/" ? "" : basePath,
    title: options.title ?? "hackerpot",
    instance: options.instance ?? hostname(),
    version: VERSION,
    sections,
    links: (options.links ?? []).map((link) => ({ label: String(link.label), href: String(link.href) })),
    source: source.description,
    redaction,
  };
  const page = renderDashboardPage(bootstrap);
  const bootstrapJson = JSON.stringify(bootstrap);

  const shape = (incident: Incident): Incident => {
    let shaped = redaction.credentials ? redactIncident(incident) : incident;
    if (redaction.maskIp) shaped = { ...shaped, ip: maskIp(shaped.ip) };
    // With the incidents section off, what the other screens still need (path, detections,
    // scores, the User-Agent for the identity charts) is sent, and the captured request is
    // not: no body, and no header but the User-Agent. Withholding a section has to mean the
    // data does not leave the process, not that one route stops answering.
    if (!sections.incidents) {
      const userAgent = shaped.headers["user-agent"];
      const { body: _body, ...rest } = shaped;
      shaped = { ...rest, headers: userAgent === undefined ? {} : { "user-agent": userAgent } };
    }
    return shaped;
  };

  const streams = new Set<Stream>();
  let nextId = 0;
  let unsubscribe: (() => void) | undefined;
  let heartbeat: ReturnType<typeof setInterval> | undefined;

  function writeFrame(stream: Stream, frame: string, droppable: boolean): void {
    if (stream.lagging && droppable) {
      stream.dropped += 1;
      return;
    }
    if (stream.response.write(frame) || stream.lagging) return;
    stream.lagging = true;
    stream.laggingSince = Date.now();
    stream.response.once("drain", () => {
      stream.lagging = false;
      if (stream.dropped === 0) return;
      const dropped = stream.dropped;
      stream.dropped = 0;
      stream.response.write(frameFor("lagged", { dropped }));
    });
  }

  /** Subscribed only while somebody watches, so an idle dashboard holds no remote connection. */
  function ensureSubscribed(): void {
    if (unsubscribe !== undefined) return;
    unsubscribe = source.subscribe((incident) => {
      const frame = frameFor("incident", shape(incident), ++nextId);
      const now = Date.now();
      for (const stream of streams) {
        if (stream.lagging && (now - stream.laggingSince > LAG_LIMIT_MS || stream.dropped > LAG_DROP_LIMIT)) {
          stream.response.end();
          streams.delete(stream);
          continue;
        }
        if (maxEventsPerSecond > 0) {
          if (now - stream.windowStart >= 1000) {
            if (stream.skipped > 0) writeFrame(stream, frameFor("skipped", { skipped: stream.skipped }), false);
            stream.windowStart = now;
            stream.windowCount = 0;
            stream.skipped = 0;
          }
          if (stream.windowCount >= maxEventsPerSecond) {
            stream.skipped += 1;
            continue;
          }
          stream.windowCount += 1;
        }
        writeFrame(stream, frame, true);
      }
    });
    heartbeat = setInterval(() => {
      for (const stream of streams) writeFrame(stream, ": heartbeat\n\n", false);
    }, HEARTBEAT_MS);
    heartbeat.unref();
  }

  function releaseIfIdle(): void {
    if (streams.size > 0) return;
    unsubscribe?.();
    unsubscribe = undefined;
    if (heartbeat !== undefined) clearInterval(heartbeat);
    heartbeat = undefined;
  }

  function openStream(request: IncomingMessage, response: ServerResponse): void {
    if (streams.size >= maxClients) {
      sendJson(response, 503, { error: `this dashboard already has ${maxClients} live viewers` });
      return;
    }
    response.writeHead(200, { ...SECURITY_HEADERS, "content-type": "text/event-stream; charset=utf-8", connection: "keep-alive", "x-accel-buffering": "no" });
    const stream: Stream = { response, lagging: false, laggingSince: 0, dropped: 0, windowStart: Date.now(), windowCount: 0, skipped: 0 };
    streams.add(stream);
    ensureSubscribed();
    response.write(`retry: 3000\n\n${frameFor("hello", { version: VERSION, source: source.description })}`);
    const close = (): void => {
      streams.delete(stream);
      releaseIfIdle();
    };
    request.on("close", close);
    response.on("error", (err) => {
      onError(err);
      close();
    });
  }

  async function route(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const url = new URL(request.url ?? "/", "http://dashboard.invalid");
    const path = routeOf(url.pathname, basePath, mounted);
    const peer = request.socket.remoteAddress ?? "";

    // Before authentication: these ask whether the request was addressed to this server by
    // something allowed to address it, which credentials cannot settle.
    if (allowedClients !== undefined && !allowedClients.allows(peer)) {
      refuse(request, response, refusal, () => sendText(response, 403, "403 forbidden\n\nThis dashboard answers only the client addresses it was configured for.\n"));
      return;
    }
    const locked = throttle.check(peer);
    if (locked !== undefined) {
      refuse(request, response, refusal, () => {
        response.writeHead(429, { ...SECURITY_HEADERS, "content-type": "text/plain; charset=utf-8", "retry-after": String(Math.ceil(locked / 1000)) });
        response.end("429 too many attempts\n");
      });
      return;
    }
    if (!hostAllowed(request, allowedHosts)) {
      refuse(request, response, refusal, () => sendText(response, 421, "421 misdirected request\n\nThis dashboard answers only the host names it was configured for. Add yours with `allowedHosts`.\n"));
      return;
    }
    if (request.method !== undefined && UNSAFE_METHODS.has(request.method) && !isSameOrigin(request)) {
      refuse(request, response, refusal, () => sendText(response, 403, "403 cross-site request\n"));
      return;
    }

    const viewer = await authorize(request, url, auth);
    if (viewer) throttle.succeeded(peer);
    else throttle.failed(peer);
    if (!viewer) {
      refuse(request, response, refusal, () => {
        const headers: Record<string, string> = { ...SECURITY_HEADERS, "content-type": "text/plain; charset=utf-8" };
        if (auth !== false && "username" in auth) headers["www-authenticate"] = 'Basic realm="hackerpot dashboard", charset="UTF-8"';
        response.writeHead(401, headers);
        response.end("401 unauthorized\n");
      });
      return;
    }

    if (path === undefined) {
      sendText(response, 404, "404 not found\n");
      return;
    }
    if (request.method !== "GET" && request.method !== "HEAD") {
      sendJson(response, 405, { error: "the dashboard is read-only" });
      return;
    }

    if (path === "/") {
      const nonce = randomBytes(16).toString("base64");
      response.writeHead(200, {
        ...SECURITY_HEADERS,
        "content-type": "text/html; charset=utf-8",
        "content-security-policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
      });
      response.end(page(nonce));
      return;
    }
    if (path === "/api/bootstrap") return send(response, 200, "application/json; charset=utf-8", bootstrapJson);
    if (path === "/api/events") {
      if (!sections.incidents && !sections.overview) return sectionOff(response, "incidents");
      return openStream(request, response);
    }

    // Reads. A source that cannot answer (a remote management API that is down) is a 502
    // with the reason, so the page can say what is wrong rather than show an empty store.
    try {
      if (path === "/api/incidents") {
        if (!sections.incidents && !sections.overview && !sections.statistics) return sectionOff(response, "incidents");
        const query = new URLSearchParams(url.searchParams);
        const limit = Number(query.get("limit") ?? 100);
        query.set("limit", String(Number.isFinite(limit) && limit > 0 ? Math.min(limit, MAX_LIST_LIMIT) : 100));
        return sendJson(response, 200, { incidents: (await source.listIncidents(query)).map(shape) });
      }
      const incidentMatch = /^\/api\/incidents\/([^/]+)$/.exec(path);
      if (incidentMatch) {
        if (!sections.incidents) return sectionOff(response, "incidents");
        const id = decodeSegment(incidentMatch[1]!);
        const incident = id === undefined ? undefined : await source.getIncident(id);
        return incident === undefined ? sendJson(response, 404, { error: "no such incident" }) : sendJson(response, 200, { incident: shape(incident) });
      }
      if (path === "/api/stats") {
        if (!sections.overview && !sections.statistics) return sectionOff(response, "statistics");
        const stats = await source.stats();
        return sendJson(response, 200, redaction.maskIp ? { ...stats, topOffenders: stats.topOffenders.map((entry) => ({ ...entry, ip: maskIp(entry.ip) })) } : stats);
      }
      const sessionMatch = /^\/api\/sessions(?:\/([^/]+))?$/.exec(path);
      if (sessionMatch) {
        if (!sections.sessions) return sectionOff(response, "sessions");
        const ip = sessionMatch[1] === undefined ? undefined : decodeSegment(sessionMatch[1]);
        if (sessionMatch[1] !== undefined && ip === undefined) return sendJson(response, 404, { error: "no session for that address" });
        const sessions = await source.sessions(ip);
        const shaped = sessions.map((session) => ({ ...session, ip: redaction.maskIp ? maskIp(session.ip) : session.ip }));
        if (ip !== undefined) return shaped.length === 0 ? sendJson(response, 404, { error: "no session for that address" }) : sendJson(response, 200, { session: shaped[0] });
        return sendJson(response, 200, { sessions: shaped });
      }
      const actorMatch = /^\/api\/actors(?:\/([^/]+))?$/.exec(path);
      if (actorMatch) {
        if (!sections.actors) return sectionOff(response, "actors");
        const fingerprint = actorMatch[1] === undefined ? undefined : decodeSegment(actorMatch[1]);
        const actors = await source.actors(fingerprint);
        const shaped = actors.map((actor) => ({ ...actor, ips: redaction.maskIp ? actor.ips.map(maskIp) : actor.ips }));
        if (fingerprint !== undefined) return shaped.length === 0 ? sendJson(response, 404, { error: "no actor with that fingerprint" }) : sendJson(response, 200, { actor: shaped[0] });
        return sendJson(response, 200, { actors: shaped });
      }
      if (path === "/api/ioc") {
        if (!sections.intel) return sectionOff(response, "intel");
        const minScore = Number(url.searchParams.get("min_score") ?? 0) || 0;
        const indicators = await source.ioc(minScore);
        return sendJson(response, 200, { indicators: redaction.maskIp ? indicators.map((entry) => ({ ...entry, ip: maskIp(entry.ip) })) : indicators });
      }
      if (path === "/api/metrics") {
        if (!sections.intel) return sectionOff(response, "intel");
        return send(response, 200, "text/plain; version=0.0.4; charset=utf-8", await source.metrics());
      }
    } catch (err) {
      onError(err);
      return sendJson(response, 502, { error: `the dashboard's source could not answer: ${err instanceof Error ? err.message : String(err)}` });
    }

    sendText(response, 404, "404 not found\n");
  }

  return {
    serve(request, response) {
      route(request, response).catch((err: unknown) => {
        onError(err);
        if (!response.headersSent) response.writeHead(500, { ...SECURITY_HEADERS, "content-type": "text/plain; charset=utf-8" });
        response.end("dashboard error\n");
      });
    },
    get clients() {
      return streams.size;
    },
    async close() {
      for (const stream of streams) stream.response.end();
      streams.clear();
      releaseIfIdle();
      await source.close?.();
    },
  };
}

/**
 * The dashboard as a request handler for a server you already run, e.g.
 * `app.use("/_hackerpot", createDashboardHandler(engine, { basePath: "/_hackerpot", auth }))`.
 *
 * `auth` is required, including the explicit `auth: false`: mounted, there is no bind
 * address to inspect. Routing accepts paths with or without `basePath`, so it works whether
 * or not your framework strips the mount point. Mount it outside the honeypot middleware, so
 * reading the dashboard never shows up in it.
 */
export function createDashboardHandler(source: DashboardSourceLike, options: DashboardHandlerOptions): DashboardRequestHandler {
  const dashboard = buildDashboard(source, options, undefined);
  const handler = ((request: IncomingMessage, response: ServerResponse): void => dashboard.serve(request, response)) as DashboardRequestHandler & { close: () => Promise<void> };
  Object.defineProperty(handler, "clients", { get: () => dashboard.clients });
  handler.close = () => dashboard.close();
  return handler;
}

/**
 * Starts the dashboard on a listener of its own, loopback by default.
 *
 * A separate listener from the honeypot on purpose: the honeypot's port is the one attackers
 * are invited to, and the dashboard describes them. Binding anything but loopback needs an
 * explicit `auth`; the server refuses to start otherwise rather than warn in a log.
 */
export async function startDashboard(source: DashboardSourceLike, options: DashboardOptions = {}): Promise<DashboardServer> {
  const host = options.host ?? DEFAULT_HOST;
  const port = options.port ?? DEFAULT_PORT;
  const basePath = normalizeBase(options.basePath ?? "/");
  const dashboard = buildDashboard(source, options, host);
  const sockets = new Set<Socket>();
  const server = createServer((request, response) => dashboard.serve(request, response));
  hardenHttpServer(server);
  // An event stream never ends on its own, so it must not be cut by the request timeout.
  server.requestTimeout = 0;
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });

  await new Promise<void>((resolve, reject) => {
    const onError = (err: NodeJS.ErrnoException): void => {
      reject(err.code === "EADDRINUSE" ? new DashboardConfigError(`the dashboard cannot listen on ${host}:${port}: the port is in use. Pass another port, or 0.`) : err);
    };
    server.once("error", onError);
    server.listen(port, host, () => {
      server.removeListener("error", onError);
      server.on("error", (err) => options.onError?.(err));
      resolve();
    });
  });

  const address = server.address();
  const boundPort = typeof address === "object" && address !== null ? address.port : port;
  let closed = false;
  return {
    url: `http://${displayHost(host)}:${boundPort}${basePath === "/" ? "/" : `${basePath}/`}`,
    port: boundPort,
    host,
    get clients() {
      return dashboard.clients;
    },
    async close() {
      if (closed) return;
      closed = true;
      await dashboard.close();
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        for (const socket of sockets) socket.destroy();
        sockets.clear();
      });
    },
  };
}

// ---------------------------------------------------------------------------------------

function frameFor(event: string, payload: unknown, id?: number): string {
  return `${id === undefined ? "" : `id: ${id}\n`}event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`;
}

function send(response: ServerResponse, status: number, contentType: string, body: string): void {
  response.writeHead(status, { ...SECURITY_HEADERS, "content-type": contentType });
  response.end(body);
}

function sendText(response: ServerResponse, status: number, body: string): void {
  send(response, status, "text/plain; charset=utf-8", body);
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  send(response, status, "application/json; charset=utf-8", JSON.stringify(body));
}

function sectionOff(response: ServerResponse, section: string): void {
  sendJson(response, 404, { error: `the ${section} section is switched off on this dashboard` });
}

function decodeSegment(segment: string): string | undefined {
  try {
    return decodeURIComponent(segment);
  } catch {
    return undefined;
  }
}

/** `/24` for IPv4, `/48` for IPv6: enough to see a network, not enough to name a household. */
export function maskIp(ip: string): string {
  const v4 = /^(?:::ffff:)?(\d+)\.(\d+)\.(\d+)\.\d+$/i.exec(ip);
  if (v4) return `${v4[1]}.${v4[2]}.${v4[3]}.0/24`;
  if (ip.includes(":")) {
    const groups = ip.split("::")[0]!.split(":").filter(Boolean).slice(0, 3);
    while (groups.length < 3) groups.push("0");
    return `${groups.join(":")}::/48`;
  }
  return ip;
}

export function normalizeBase(basePath: string): string {
  const trimmed = basePath.trim();
  if (trimmed === "" || trimmed === "/") return "/";
  const withSlash = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  return withSlash.endsWith("/") ? withSlash.slice(0, -1) : withSlash;
}

/** The path within the mount, or undefined when the request is for something else. */
function routeOf(pathname: string, basePath: string, mounted: boolean): string | undefined {
  if (basePath === "/") return pathname === "" ? "/" : pathname;
  if (pathname === basePath || pathname === `${basePath}/`) return "/";
  if (pathname.startsWith(`${basePath}/`)) return pathname.slice(basePath.length);
  // Mounted, the surrounding router may already have removed the prefix.
  return mounted ? (pathname === "" ? "/" : pathname) : undefined;
}

function displayHost(host: string): string {
  if (host === "0.0.0.0" || host === "::" || host === "") return "localhost";
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

function headerValue(request: IncomingMessage, name: string): string | undefined {
  const value = request.headers[name];
  return (Array.isArray(value) ? value[0] : value)?.trim().toLowerCase();
}

function stripPort(host: string): string {
  if (host.startsWith("[")) {
    const end = host.indexOf("]");
    return end === -1 ? host : host.slice(0, end + 1);
  }
  const colon = host.lastIndexOf(":");
  return colon !== -1 && /^\d+$/.test(host.slice(colon + 1)) ? host.slice(0, colon) : host;
}

/**
 * On loopback, the names a browser uses to reach loopback plus any you add. This is the DNS
 * rebinding defence: a site pointing its own name at 127.0.0.1 becomes same-origin with this
 * page, but cannot make the browser send a `Host` you did not list. On a public bind, only the
 * names you list, when you list any.
 */
function resolveAllowedHosts(host: string, extra: readonly string[] | undefined): Set<string> | undefined {
  if (extra?.includes("*")) return undefined;
  // A public bind has no rebinding to defend against and cannot guess the name a reverse
  // proxy uses, so it checks nothing by default; but names you list are enforced, which is
  // what a dashboard behind a proxy wants: only its public name answers.
  if (!LOOPBACK_HOSTS.has(host)) return extra === undefined || extra.length === 0 ? undefined : new Set(extra.map((name) => stripPort(name).toLowerCase()));
  const allowed = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
  for (const entry of extra ?? []) allowed.add(stripPort(entry).toLowerCase());
  return allowed;
}

function resolveMountedHosts(extra: readonly string[] | undefined): Set<string> | undefined {
  if (extra === undefined || extra.length === 0 || extra.includes("*")) return undefined;
  return new Set(extra.map((name) => stripPort(name).toLowerCase()));
}

function hostAllowed(request: IncomingMessage, allowed: ReadonlySet<string> | undefined): boolean {
  if (allowed === undefined) return true;
  const host = headerValue(request, "host");
  return host !== undefined && allowed.has(stripPort(host));
}

/** `Sec-Fetch-Site` when the browser sent it (script cannot forge it), `Origin` otherwise. */
function isSameOrigin(request: IncomingMessage): boolean {
  const site = headerValue(request, "sec-fetch-site");
  if (site !== undefined) return site === "same-origin" || site === "none";
  const origin = headerValue(request, "origin");
  if (origin === undefined) return true;
  try {
    return new URL(origin).host === headerValue(request, "host");
  } catch {
    return false;
  }
}

function validateClients(entries: readonly string[] | undefined): IpAllowlist | undefined {
  if (entries === undefined || entries.length === 0) return undefined;
  const list = new IpAllowlist([...entries]);
  if (list.invalid.length > 0) throw new DashboardConfigError(`\`allowedClients\` contains ${list.invalid.join(", ")}, which are not addresses or CIDRs; nothing could reach this dashboard.`);
  return list;
}

/** One answer for every pre-routing refusal, so that under concealment they cannot be told apart. */
function refuse(request: IncomingMessage, response: ServerResponse, refusal: DashboardRefusal, honest: () => void): void {
  if (refusal === "unauthorized") return honest();
  if (refusal === "close") {
    request.socket.destroy();
    return;
  }
  if (refusal === "not-found") return sendText(response, 404, "404 not found\n");
  response.writeHead(refusal.status ?? 302, { ...SECURITY_HEADERS, location: refusal.redirect });
  response.end();
}

function validateRefusal(refusal: DashboardRefusal, auth: DashboardAuth): DashboardRefusal {
  if (typeof refusal === "object") {
    if (typeof refusal.redirect !== "string" || refusal.redirect === "") throw new DashboardConfigError("`refusal.redirect` needs a URL or path to send people to.");
    return refusal;
  }
  if ((refusal === "not-found" || refusal === "close") && auth !== false && "username" in auth) {
    throw new DashboardConfigError(
      `refusal "${refusal}" cannot work with basic auth: a browser prompts for a password only when a 401 asks it to, so nobody could log in. Use \`auth: { token }\` or \`auth: { authorize }\`, or keep refusal "unauthorized".`,
    );
  }
  return refusal;
}

function validateAuth(auth: DashboardAuth | undefined, host: string): DashboardAuth {
  if (auth === undefined) {
    if (host === MOUNTED) {
      throw new DashboardConfigError(
        "A mounted dashboard needs `auth`: there is no bind address to inspect, and the page shows attackers, captured requests and what your detectors caught. Configure `auth: { username, password }`, `{ token }` or `{ authorize }`, or write `auth: false` to state that the server you mount it on already authenticates.",
      );
    }
    if (!LOOPBACK_HOSTS.has(host)) {
      throw new DashboardConfigError(
        `The dashboard is set to bind ${host}, which publishes it beyond this machine, and no \`auth\` was configured. Configure \`auth\`, keep the default host "127.0.0.1", or write \`auth: false\` to state that something in front of it already authenticates.`,
      );
    }
    return false;
  }
  if (auth === false) return false;
  if ("username" in auth) {
    if (auth.username === "" || auth.password === "") throw new DashboardConfigError("The dashboard's basic auth needs a non-empty username and password.");
    return auth;
  }
  if ("token" in auth) {
    if (auth.token.length < 16) throw new DashboardConfigError(`The dashboard's token is ${auth.token.length} characters. Use at least 16 from a random source.`);
    return auth;
  }
  if (typeof auth.authorize !== "function") throw new DashboardConfigError("`auth.authorize` must be a function.");
  return auth;
}

/** Hashing first makes the comparison length-independent, so it reveals neither content nor length. */
function sameSecret(presented: string, expected: string): boolean {
  return timingSafeEqual(createHash("sha256").update(presented).digest(), createHash("sha256").update(expected).digest());
}

async function authorize(request: IncomingMessage, url: URL, auth: DashboardAuth): Promise<boolean> {
  if (auth === false) return true;
  if ("authorize" in auth) {
    try {
      const answer = await auth.authorize(request);
      return typeof answer === "string" ? answer !== "" : answer === true;
    } catch {
      return false;
    }
  }
  const header = request.headers.authorization ?? "";
  if ("token" in auth) {
    const presented = header.startsWith("Bearer ") ? header.slice(7) : (url.searchParams.get("token") ?? "");
    return sameSecret(presented, auth.token);
  }
  if (!header.startsWith("Basic ")) return false;
  const decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
  const separator = decoded.indexOf(":");
  if (separator === -1) return false;
  // Both halves are always compared, so a wrong username is not faster than a wrong password.
  const userOk = sameSecret(decoded.slice(0, separator), auth.username);
  const passOk = sameSecret(decoded.slice(separator + 1), auth.password);
  return userOk && passOk;
}

interface AuthThrottle {
  check(address: string): number | undefined;
  failed(address: string): void;
  succeeded(address: string): void;
}

/** Most addresses remembered; the oldest are forgotten first, so an address pool cannot grow this. */
const MAX_THROTTLED = 10_000;

function createAuthThrottle(options: DashboardOptions["authThrottle"]): AuthThrottle {
  if (options === false) return { check: () => undefined, failed: () => undefined, succeeded: () => undefined };
  const maxAttempts = Math.max(1, options?.maxAttempts ?? 5);
  const lockoutMs = Math.max(100, options?.lockoutMs ?? 1_000);
  const maxLockoutMs = Math.max(lockoutMs, options?.maxLockoutMs ?? 5 * 60_000);
  const attempts = new Map<string, { failures: number; until: number; seen: number }>();
  return {
    check(address) {
      const record = attempts.get(address);
      const now = Date.now();
      return record !== undefined && record.until > now ? record.until - now : undefined;
    },
    failed(address) {
      const now = Date.now();
      const record = attempts.get(address) ?? { failures: 0, until: 0, seen: now };
      // A record untouched for longer than the longest lockout starts over.
      if (now - record.seen > maxLockoutMs * 2) record.failures = 0;
      record.failures += 1;
      record.seen = now;
      if (record.failures >= maxAttempts) record.until = now + Math.min(maxLockoutMs, lockoutMs * 2 ** (record.failures - maxAttempts));
      attempts.delete(address);
      attempts.set(address, record);
      if (attempts.size > MAX_THROTTLED) attempts.delete(attempts.keys().next().value!);
    },
    succeeded(address) {
      attempts.delete(address);
    },
  };
}

function resolveSections(sections: DashboardSections | undefined): Required<DashboardSections> {
  const on = (value: boolean | undefined): boolean => value !== false;
  return {
    overview: on(sections?.overview),
    incidents: on(sections?.incidents),
    statistics: on(sections?.statistics),
    sessions: on(sections?.sessions),
    actors: on(sections?.actors),
    intel: on(sections?.intel),
  };
}
