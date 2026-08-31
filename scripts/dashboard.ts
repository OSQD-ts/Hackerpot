import http from "node:http";
import { readFileSync } from "node:fs";
import { WebSocket, WebSocketServer } from "ws";

/**
 * A tiny dev server for the test dashboard. It serves the styled single-page UI
 * and proxies its API calls (REST + WebSocket) to the honeypot's management API.
 * Proxying keeps the browser same-origin, so the management API needs no CORS
 * and stays exactly as locked-down as it is in production.
 */

const MGMT_URL = (process.env.MGMT_URL ?? "http://127.0.0.1:9500").replace(/\/$/, "");
const HOST = process.env.DASHBOARD_HOST ?? "127.0.0.1";
const PORT = Number(process.env.DASHBOARD_PORT ?? 8080);

/**
 * Optional API key baked into the page so `npm run dev:gui` / `start:gui` land on a
 * working dashboard with no copy/paste step.
 *
 * Served ONLY when this listener is bound to loopback. The key is a management-API
 * credential and the page is handed to whoever connects, so on any other interface
 * embedding it would publish the credential to the network — the launcher passes it
 * unconditionally, and this is the check that decides whether it is safe to honour.
 * A stored key in the browser still wins, so it never overwrites one you typed.
 */
const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);
const bootstrapKey = LOOPBACK.has(HOST.toLowerCase()) ? (process.env.DASHBOARD_API_KEY ?? "") : "";
if (process.env.DASHBOARD_API_KEY && !bootstrapKey) {
  console.warn(`refusing to embed DASHBOARD_API_KEY in a page served on ${HOST} — enter the key in the UI instead`);
}

const html = readFileSync(new URL("./dashboard.html", import.meta.url), "utf8")
  .replace(/\{\{MGMT_URL\}\}/g, MGMT_URL)
  // JSON-encoded so the value lands as a proper JS string literal and cannot break out
  // of it, whatever the key contains.
  .replace(/"\{\{API_KEY\}\}"/g, JSON.stringify(bootstrapKey));

function forwardedAuth(req: http.IncomingMessage): Record<string, string> {
  const headers: Record<string, string> = {};
  if (typeof req.headers["authorization"] === "string") headers["authorization"] = req.headers["authorization"];
  if (typeof req.headers["x-api-key"] === "string") headers["x-api-key"] = req.headers["x-api-key"];
  return headers;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);

  // REST proxy: /api/<path> -> <MGMT_URL>/<path>
  if (url.pathname.startsWith("/api/")) {
    const target = `${MGMT_URL}${url.pathname.slice("/api".length)}${url.search}`;
    try {
      const upstream = await fetch(target, { method: req.method, headers: forwardedAuth(req) });
      const body = await upstream.text();
      res.statusCode = upstream.status;
      res.setHeader("Content-Type", upstream.headers.get("content-type") ?? "application/json");
      res.end(body);
    } catch (err) {
      res.statusCode = 502;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ error: "management API unreachable", target: MGMT_URL, detail: (err as Error).message }));
    }
    return;
  }

  if (url.pathname === "/" || url.pathname === "/index.html") {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.end(html);
    return;
  }

  res.statusCode = 404;
  res.end("Not Found");
});

// WebSocket proxy: browser -> /api/stream -> <MGMT_URL>/stream (live feed).
const wss = new WebSocketServer({ noServer: true });
server.on("upgrade", (req, socket, head) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  if (!url.pathname.startsWith("/api/stream")) {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (client) => {
    // A `ws` socket that emits 'error' with no listener rethrows it as an
    // uncaughtException — so a browser tab closing mid-frame took the whole dashboard
    // down. The upstream socket had a handler; the browser-facing one did not.
    client.on("error", () => client.close());
    const target = `${MGMT_URL.replace(/^http/, "ws")}/stream${url.search}`;
    let upstream: WebSocket;
    try {
      upstream = new WebSocket(target);
    } catch {
      client.close();
      return;
    }
    upstream.on("message", (data) => client.readyState === client.OPEN && client.send(data.toString()));
    upstream.on("close", () => client.close());
    upstream.on("error", () => client.close());
    client.on("close", () => upstream.close());
  });
});

// 8080 is one of the most commonly occupied ports on a dev machine; report the clash
// the way dev-server.ts does rather than dumping a bind stack trace.
server.on("error", (err: NodeJS.ErrnoException) => {
  if (err.code === "EADDRINUSE") {
    console.error(`hackerpot dashboard: TCP ${PORT} is already in use. Set DASHBOARD_PORT=<free port> (e.g. DASHBOARD_PORT=${PORT + 1} npm run dashboard) or free the port.`);
    process.exit(1);
  }
  throw err;
});

server.listen(PORT, HOST, () => {
  console.log(`hackerpot dashboard: http://${HOST}:${PORT}`);
  console.log(`proxying the management API at ${MGMT_URL}`);
  console.log(`(start the honeypot with its management API first, e.g. npm run dev)\n`);
});
