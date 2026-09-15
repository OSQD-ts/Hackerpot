import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import { createDashboardHandler, engineSource, managementApiSource, maskIp, startDashboard } from "../src/dashboard/index.js";
import type { DashboardServer } from "../src/dashboard/index.js";
import type { RequestFacts } from "../src/detectors/types.js";
import { ManagementServer } from "../src/management/index.js";
import { MemoryStore } from "../src/stores/index.js";

const TOKEN = "dashboard-token-0123456789";
const probe = (extra: Partial<RequestFacts> = {}): RequestFacts => ({
  method: "GET",
  path: "/.env",
  query: {},
  headers: { host: "shop.example", "user-agent": "sqlmap/1.7", authorization: "Bearer stolen-secret-value" },
  ip: "203.0.113.50",
  ...extra,
});

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

async function started(engine: HoneypotEngine, options: Parameters<typeof startDashboard>[1] = {}): Promise<DashboardServer> {
  const server = await startDashboard(engine, { port: 0, ...options });
  cleanups.push(() => server.close());
  return server;
}

describe("startDashboard", () => {
  it("serves the page under a nonce CSP and the API on loopback without auth", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    await engine.evaluate(probe());
    const server = await started(engine);
    const page = await fetch(server.url);
    expect(page.status).toBe(200);
    const csp = page.headers.get("content-security-policy") ?? "";
    const nonce = /script-src 'nonce-([^']+)'/.exec(csp)?.[1];
    expect(nonce).toBeDefined();
    const html = await page.text();
    expect(html).toContain(`nonce="${nonce}"`);
    expect(page.headers.get("x-frame-options")).toBe("DENY");

    const { incidents } = (await (await fetch(`${server.url}api/incidents`)).json()) as { incidents: Array<{ headers: Record<string, string> }> };
    expect(incidents).toHaveLength(1);
    // Credentials are redacted by default.
    expect(incidents[0]!.headers["authorization"]).toBe("[redacted]");
  });

  it("refuses a public bind without auth, and a short token", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    await expect(startDashboard(engine, { port: 0, host: "0.0.0.0" })).rejects.toThrow(/no `auth`/);
    await expect(startDashboard(engine, { port: 0, auth: { token: "short" } })).rejects.toThrow(/at least 16/);
    await expect(startDashboard(engine, { port: 0, auth: { username: "a", password: "b" }, refusal: "not-found" })).rejects.toThrow(/basic auth/);
  });

  it("requires a token by header or query when configured, and answers concealed refusals as 404", async () => {
    const server = await started(new HoneypotEngine({ enricher: null }), { auth: { token: TOKEN }, refusal: "not-found" });
    expect((await fetch(`${server.url}api/stats`)).status).toBe(404);
    expect((await fetch(`${server.url}api/stats`, { headers: { authorization: `Bearer ${TOKEN}` } })).status).toBe(200);
    expect((await fetch(`${server.url}api/stats?token=${TOKEN}`)).status).toBe(200);
  });

  it("checks basic credentials and slows repeated failures", async () => {
    const server = await started(new HoneypotEngine({ enricher: null }), { auth: { username: "ops", password: "correct-horse" }, authThrottle: { maxAttempts: 2, lockoutMs: 60_000 } });
    const basic = (user: string, pass: string) => ({ authorization: `Basic ${Buffer.from(`${user}:${pass}`).toString("base64")}` });
    const wrong = await fetch(`${server.url}api/stats`, { headers: basic("ops", "nope") });
    expect(wrong.status).toBe(401);
    expect(wrong.headers.get("www-authenticate")).toMatch(/Basic/);
    await fetch(`${server.url}api/stats`, { headers: basic("ops", "nope") });
    expect((await fetch(`${server.url}api/stats`, { headers: basic("ops", "correct-horse") })).status).toBe(429);
  });

  it("refuses a Host header it was not configured for, which is what DNS rebinding sends", async () => {
    const server = await started(new HoneypotEngine({ enricher: null }));
    const status = await new Promise<number>((resolve) => {
      http.get({ host: "127.0.0.1", port: server.port, path: "/api/stats", headers: { host: `attacker.example:${server.port}` } }, (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
    });
    expect(status).toBe(421);
  });

  it("withholds a section on the server, and masks addresses when asked", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    await engine.evaluate(probe());
    const server = await started(engine, { sections: { intel: false }, redact: { maskIp: true } });
    expect((await fetch(`${server.url}api/ioc`)).status).toBe(404);
    const boot = (await (await fetch(`${server.url}api/bootstrap`)).json()) as { sections: { intel: boolean }; source: string };
    expect(boot.sections.intel).toBe(false);
    expect(boot.source).toBe("this process");
    const { incidents } = (await (await fetch(`${server.url}api/incidents`)).json()) as { incidents: Array<{ ip: string }> };
    expect(incidents[0]!.ip).toBe("203.0.113.0/24");
  });

  it("streams new incidents over server-sent events, including hits published from elsewhere", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    const server = await started(engine);
    const controller = new AbortController();
    const response = await fetch(`${server.url}api/events`, { signal: controller.signal });
    expect(response.headers.get("content-type")).toMatch(/text\/event-stream/);
    const reader = response.body!.getReader();
    const decoder = new TextDecoder();
    let text = "";
    const until = async (needle: string): Promise<void> => {
      while (!text.includes(needle)) text += decoder.decode((await reader.read()).value, { stream: true });
    };
    await until("event: hello");
    await engine.evaluate(probe());
    await until("event: incident");
    expect(text).toContain('"path":"/.env"');
    expect(server.clients).toBe(1);
    controller.abort();
  });

  it("is read-only", async () => {
    const server = await started(new HoneypotEngine({ enricher: null }));
    expect((await fetch(`${server.url}api/stats`, { method: "POST", headers: { "sec-fetch-site": "same-origin" } })).status).toBe(405);
    expect((await fetch(`${server.url}api/stats`, { method: "POST", headers: { "sec-fetch-site": "cross-site" } })).status).toBe(403);
  });
});

describe("createDashboardHandler", () => {
  it("needs auth, and serves under its base path whether or not the router strips it", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    expect(() => createDashboardHandler(engine, {} as never)).toThrow(/mounted dashboard needs `auth`/);
    const handler = createDashboardHandler(engine, { auth: false, basePath: "/_hackerpot" });
    const server = http.createServer((req, res) => {
      if (req.url?.startsWith("/_hackerpot")) return handler(req, res);
      if (req.url?.startsWith("/stripped")) {
        req.url = req.url.slice("/stripped".length) || "/";
        return handler(req, res);
      }
      res.end("app");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    cleanups.push(async () => {
      await handler.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    expect((await fetch(`${base}/_hackerpot/api/bootstrap`)).status).toBe(200);
    const boot = (await (await fetch(`${base}/stripped/api/bootstrap`)).json()) as { base: string };
    expect(boot.base).toBe("/_hackerpot");
    expect(await (await fetch(`${base}/`)).text()).toBe("app");
  });
});

describe("managementApiSource", () => {
  it("reads a running HackerPot's management API, and follows its live stream", async () => {
    const store = new MemoryStore();
    const management = new ManagementServer({ store, host: "127.0.0.1", port: 0, apiKeys: ["management-key-0123456789"] });
    await management.listen();
    cleanups.push(() => management.close());
    const port = (management.address() as AddressInfo).port;
    const engine = new HoneypotEngine({ enricher: null, store, onHit: (hit) => management.publish(hit) });
    await engine.evaluate(probe());

    const source = managementApiSource({ url: `http://127.0.0.1:${port}`, apiKey: "management-key-0123456789" });
    cleanups.push(async () => source.close?.());
    expect(source.description).toBe(`management API at 127.0.0.1:${port}`);
    expect(await source.listIncidents(new URLSearchParams({ limit: "10" }))).toHaveLength(1);
    expect((await source.stats()).totalIncidents).toBe(1);
    expect(await source.sessions("198.51.100.99")).toEqual([]);
    expect(await source.metrics()).toContain("hackerpot_incidents_total");

    const heard = new Promise<string>((resolve) => {
      const stop = source.subscribe((incident) => {
        stop();
        resolve(incident.path);
      });
    });
    // The WebSocket opens on subscribe; give it a moment before publishing.
    await new Promise((resolve) => setTimeout(resolve, 200));
    await engine.evaluate(probe({ path: "/.git/config", ip: "203.0.113.51" }));
    expect(await heard).toBe("/.git/config");
  });

  it("reports a wrong key as a source failure the dashboard turns into a 502", async () => {
    const store = new MemoryStore();
    const management = new ManagementServer({ store, host: "127.0.0.1", port: 0, apiKeys: ["management-key-0123456789"] });
    await management.listen();
    cleanups.push(() => management.close());
    const port = (management.address() as AddressInfo).port;
    const dashboard = await startDashboard(managementApiSource({ url: `http://127.0.0.1:${port}`, apiKey: "wrong-key" }), { port: 0 });
    cleanups.push(() => dashboard.close());
    const response = await fetch(`${dashboard.url}api/stats`);
    expect(response.status).toBe(502);
    expect(((await response.json()) as { error: string }).error).toMatch(/401/);
  });

  it("an in-process engine source describes itself", () => {
    expect(engineSource(new HoneypotEngine({ enricher: null })).description).toBe("this process");
  });
});

describe("maskIp", () => {
  it("keeps a network and drops the host", () => {
    expect(maskIp("198.51.100.23")).toBe("198.51.100.0/24");
    expect(maskIp("::ffff:198.51.100.23")).toBe("198.51.100.0/24");
    expect(maskIp("2001:db8:abcd:12::1")).toBe("2001:db8:abcd::/48");
  });
});
