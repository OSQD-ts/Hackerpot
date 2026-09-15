import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import { brokerSource, createDashboardHandler, managementApiSource, managementServerSource, startDashboard, storeSource } from "../src/dashboard/index.js";
import type { DashboardServer, DashboardSource } from "../src/dashboard/index.js";
import type { RequestFacts } from "../src/detectors/types.js";
import { IncidentBroker, ManagementServer } from "../src/management/index.js";
import { MemoryStore } from "../src/stores/index.js";

/**
 * The dashboard server's less travelled paths: every refusal mode, the viewer cap, sections
 * withheld route by route, single-record routes, masking across every list, a source that
 * fails, and each in-process and remote source shape. The common paths are in
 * `dashboard-server.test.ts`.
 */

const probe = (ip: string, extra: Partial<RequestFacts> = {}): RequestFacts => ({
  method: "GET",
  path: "/.env",
  query: {},
  headers: { host: "shop.example", "user-agent": "sqlmap/1.7" },
  ip,
  ...extra,
});

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

async function started(source: Parameters<typeof startDashboard>[0], options: Parameters<typeof startDashboard>[1] = {}): Promise<DashboardServer> {
  const server = await startDashboard(source, { port: 0, ...options });
  cleanups.push(() => server.close());
  return server;
}

/** A raw request, for statuses and headers fetch would follow or hide. */
function raw(port: number, path: string, headers: Record<string, string> = {}): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string } | "closed"> {
  return new Promise((resolve) => {
    const request = http.get({ host: "127.0.0.1", port, path, headers: { host: `127.0.0.1:${port}`, ...headers } }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk: string) => (body += chunk));
      response.on("end", () => resolve({ status: response.statusCode ?? 0, headers: response.headers, body }));
    });
    request.on("error", () => resolve("closed"));
  });
}

describe("refusals", () => {
  const TOKEN = "dashboard-token-0123456789";

  it("drops the connection with nothing written under refusal close", async () => {
    const server = await started(new HoneypotEngine({ enricher: null }), { auth: { token: TOKEN }, refusal: "close" });
    expect(await raw(server.port, "/api/stats")).toBe("closed");
  });

  it("redirects to a sign-in page under a redirect refusal", async () => {
    const server = await started(new HoneypotEngine({ enricher: null }), { auth: { token: TOKEN }, refusal: { redirect: "https://sso.example/login", status: 303 } });
    const answer = await raw(server.port, "/api/stats");
    expect(answer).not.toBe("closed");
    if (answer === "closed") return;
    expect(answer.status).toBe(303);
    expect(answer.headers.location).toBe("https://sso.example/login");
  });

  it("refuses an empty redirect target and a bad client list at startup", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    await expect(startDashboard(engine, { port: 0, refusal: { redirect: "" } })).rejects.toThrow(/redirect/);
    await expect(startDashboard(engine, { port: 0, allowedClients: ["10.0.0.0/8x"] })).rejects.toThrow(/not addresses or CIDRs/);
  });

  it("answers only the client addresses it was configured for", async () => {
    const denied = await started(new HoneypotEngine({ enricher: null }), { allowedClients: ["192.0.2.0/24"] });
    expect((await fetch(`${denied.url}api/stats`)).status).toBe(403);
    const allowed = await started(new HoneypotEngine({ enricher: null }), { allowedClients: ["127.0.0.0/8", "::1"] });
    expect((await fetch(`${allowed.url}api/stats`)).status).toBe(200);
  });

  it("admits a custom check, names nobody on an empty answer, and fails closed when it throws", async () => {
    let answer: boolean | string | Error = "ops@example.com";
    const server = await started(new HoneypotEngine({ enricher: null }), {
      auth: {
        authorize: () => {
          if (answer instanceof Error) throw answer;
          return answer;
        },
      },
    });
    expect((await fetch(`${server.url}api/stats`)).status).toBe(200);
    answer = "";
    expect((await fetch(`${server.url}api/stats`)).status).toBe(401);
    answer = new Error("session store down");
    expect((await fetch(`${server.url}api/stats`)).status).toBe(401);
  });

  it("checks Host on a mounted handler only when names are given", async () => {
    const handler = createDashboardHandler(new HoneypotEngine({ enricher: null }), { auth: false, allowedHosts: ["ops.example"] });
    const server = http.createServer(handler);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    cleanups.push(async () => {
      await handler.close();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });
    const port = (server.address() as AddressInfo).port;
    const wrong = await raw(port, "/api/stats");
    expect(wrong !== "closed" && wrong.status).toBe(421);
    const right = await raw(port, "/api/stats", { host: "ops.example" });
    expect(right !== "closed" && right.status).toBe(200);
    expect(handler.clients).toBe(0);
  });
});

describe("routes", () => {
  it("serves single records and 404s the ones that do not exist", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    const first = await engine.evaluate(probe("203.0.113.80"));
    const server = await started(engine);
    const { incidents } = (await (await fetch(`${server.url}api/incidents?limit=abc`)).json()) as { incidents: Array<{ id: string; fingerprint: string }> };
    expect(incidents).toHaveLength(1);
    expect(first.fingerprint).toBe(incidents[0]!.fingerprint);

    expect((await fetch(`${server.url}api/incidents/${incidents[0]!.id}`)).status).toBe(200);
    expect((await fetch(`${server.url}api/incidents/no-such-id`)).status).toBe(404);
    expect((await fetch(`${server.url}api/incidents/%E0%A4%A`)).status).toBe(404);
    expect((await fetch(`${server.url}api/sessions/203.0.113.80`)).status).toBe(200);
    expect((await fetch(`${server.url}api/sessions/198.51.100.1`)).status).toBe(404);
    expect((await fetch(`${server.url}api/sessions/%E0%A4%A`)).status).toBe(404);
    expect((await fetch(`${server.url}api/actors/${incidents[0]!.fingerprint}`)).status).toBe(200);
    expect((await fetch(`${server.url}api/actors/nobody`)).status).toBe(404);
    const metrics = await fetch(`${server.url}api/metrics`);
    expect(metrics.headers.get("content-type")).toMatch(/text\/plain/);
    // Counted from the store, so incidents recorded before the dashboard started are included.
    expect(await metrics.text()).toContain("hackerpot_incidents_total 1");
    expect((await fetch(`${server.url}nothing-here`)).status).toBe(404);
  });

  it("withholds every section it was told to", async () => {
    const server = await started(new HoneypotEngine({ enricher: null }), {
      sections: { overview: false, incidents: false, statistics: false, sessions: false, actors: false, intel: false },
    });
    for (const path of ["api/incidents", "api/incidents/x", "api/stats", "api/sessions", "api/actors", "api/ioc", "api/metrics", "api/events"]) {
      const response = await fetch(`${server.url}${path}`);
      expect(response.status, path).toBe(404);
      expect(((await response.json()) as { error: string }).error).toMatch(/switched off/);
    }
  });

  it("masks addresses in every list it serves", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    await engine.evaluate(probe("203.0.113.81"));
    await engine.evaluate(probe("203.0.113.82"));
    const server = await started(engine, { redact: { maskIp: true, credentials: false } });
    const stats = (await (await fetch(`${server.url}api/stats`)).json()) as { topOffenders: Array<{ ip: string }> };
    const sessions = (await (await fetch(`${server.url}api/sessions`)).json()) as { sessions: Array<{ ip: string }> };
    const actors = (await (await fetch(`${server.url}api/actors`)).json()) as { actors: Array<{ ips: string[] }> };
    const ioc = (await (await fetch(`${server.url}api/ioc`)).json()) as { indicators: Array<{ ip: string }> };
    const ips = [...stats.topOffenders.map((e) => e.ip), ...sessions.sessions.map((e) => e.ip), ...actors.actors.flatMap((e) => e.ips), ...ioc.indicators.map((e) => e.ip)];
    expect(ips.length).toBeGreaterThan(0);
    for (const ip of ips) expect(ip).toBe("203.0.113.0/24");
    const single = (await (await fetch(`${server.url}api/sessions/203.0.113.81`)).json()) as { session?: { ip: string } };
    // A masked single session is looked up by the real address and served masked.
    expect(single.session?.ip ?? "203.0.113.0/24").toBe("203.0.113.0/24");
  });

  it("turns a source that cannot answer into a 502 with the reason, and reports it", async () => {
    const errors: unknown[] = [];
    const failing: DashboardSource = {
      description: "a source that is down",
      listIncidents: () => Promise.reject(new Error("connection refused")),
      getIncident: () => Promise.reject(new Error("connection refused")),
      stats: () => Promise.reject(new Error("connection refused")),
      sessions: () => Promise.reject(new Error("connection refused")),
      actors: () => Promise.reject(new Error("connection refused")),
      ioc: () => Promise.reject(new Error("connection refused")),
      metrics: () => Promise.reject(new Error("connection refused")),
      subscribe: () => () => undefined,
    };
    const server = await started(failing, { onError: (error) => void errors.push(error) });
    for (const path of ["api/incidents", "api/stats", "api/sessions", "api/actors", "api/ioc", "api/metrics"]) {
      const response = await fetch(`${server.url}${path}`);
      expect(response.status, path).toBe(502);
      expect(((await response.json()) as { error: string }).error).toMatch(/connection refused/);
    }
    expect(errors.length).toBeGreaterThanOrEqual(6);
  });
});

describe("the live feed", () => {
  it("caps concurrent viewers, and releases the subscription when the last one leaves", async () => {
    let subscribed = 0;
    const engine = new HoneypotEngine({ enricher: null });
    const source: DashboardSource = {
      ...storeSource({ store: engine.store, subscribe: (listener) => engine.subscribe(listener) }),
      subscribe: (listener) => {
        subscribed += 1;
        const stop = engine.subscribe(listener);
        return () => {
          subscribed -= 1;
          stop();
        };
      },
    };
    const server = await started(source, { maxClients: 1 });
    const controller = new AbortController();
    const first = await fetch(`${server.url}api/events`, { signal: controller.signal });
    expect(first.status).toBe(200);
    expect(subscribed).toBe(1);
    expect((await fetch(`${server.url}api/events`)).status).toBe(503);
    controller.abort();
    for (let i = 0; i < 50 && subscribed > 0; i++) await new Promise((resolve) => setTimeout(resolve, 20));
    expect(subscribed).toBe(0);
  });

  it("counts incidents over the per-second cap instead of sending them", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    const server = await started(engine, { maxEventsPerSecond: 1 });
    const controller = new AbortController();
    const response = await fetch(`${server.url}api/events`, { signal: controller.signal });
    const reader = response.body!.getReader();
    const decoder = new TextDecoder();
    let text = "";
    const read = async (needle: string, deadline = Date.now() + 5_000): Promise<void> => {
      while (!text.includes(needle) && Date.now() < deadline) text += decoder.decode((await reader.read()).value, { stream: true });
    };
    await read("event: hello");
    for (let i = 0; i < 5; i++) await engine.evaluate(probe(`203.0.113.${90 + i}`));
    await new Promise((resolve) => setTimeout(resolve, 1_100));
    // The next incident opens a new window, which reports how many the last one skipped.
    await engine.evaluate(probe("203.0.113.99"));
    await read("event: skipped");
    expect(text.match(/event: incident/g)?.length).toBeLessThanOrEqual(2);
    expect(text).toMatch(/event: skipped\ndata: \{"skipped":4\}/);
    controller.abort();
  });
});

describe("sources", () => {
  it("reads a store through a broker, a management server, or custom metrics", async () => {
    const store = new MemoryStore();
    const broker = new IncidentBroker();
    const engine = new HoneypotEngine({ enricher: null, store, onHit: (hit) => broker.publish(hit) });
    await engine.evaluate(probe("203.0.113.100"));

    const viaBroker = brokerSource(broker, store);
    const heard: string[] = [];
    const stop = viaBroker.subscribe((incident) => heard.push(incident.ip));
    await engine.evaluate(probe("203.0.113.101"));
    stop();
    expect(heard).toEqual(["203.0.113.101"]);
    expect((await viaBroker.stats()).totalIncidents).toBe(2);
    expect(await viaBroker.metrics()).toContain("hackerpot_incidents_total 2");

    const management = new ManagementServer({ store, host: "127.0.0.1", port: 0, apiKeys: ["k-0123456789abcdef"] });
    const viaManagement = managementServerSource(management, store);
    expect(await viaManagement.ioc(0)).toHaveLength(2);
    expect(await viaManagement.getIncident("missing")).toBeUndefined();

    const custom = storeSource({ store, subscribe: () => () => undefined, metrics: () => "custom_metric 1\n", description: "custom" });
    expect(custom.description).toBe("custom");
    expect(await custom.metrics()).toBe("custom_metric 1\n");
    expect(await custom.actors()).toHaveLength(1);
  });

  it("refuses a remote source it could never use", () => {
    expect(() => managementApiSource({ url: "ftp://honeypot:9500", apiKey: "k" })).toThrow(/http or https/);
    expect(() => managementApiSource({ url: "http://honeypot:9500", apiKey: "" })).toThrow(/API key/);
  });

  it("reads single records remotely, and reconnects the live stream after it drops", async () => {
    const store = new MemoryStore();
    const port = await new Promise<number>((resolve) => {
      const probeServer = http.createServer();
      probeServer.listen(0, "127.0.0.1", () => {
        const chosen = (probeServer.address() as AddressInfo).port;
        probeServer.close(() => resolve(chosen));
      });
    });
    let management = new ManagementServer({ store, host: "127.0.0.1", port, apiKeys: ["management-key-0123456789"] });
    await management.listen();
    const engine = new HoneypotEngine({ enricher: null, store, onHit: (hit) => management.publish(hit) });
    const result = await engine.evaluate(probe("203.0.113.110"));
    const { incidents } = { incidents: await store.list() };

    const errors: unknown[] = [];
    const source = managementApiSource({ url: `http://127.0.0.1:${port}/`, apiKey: "management-key-0123456789", onError: (error) => void errors.push(error) });
    cleanups.push(async () => {
      await source.close?.();
      await management.close();
    });
    expect((await source.getIncident(incidents[0]!.id))?.ip).toBe("203.0.113.110");
    expect(await source.getIncident("missing")).toBeUndefined();
    expect(await source.sessions("203.0.113.110")).toHaveLength(1);
    expect(await source.actors(result.fingerprint)).toHaveLength(1);
    expect(await source.actors("nobody")).toEqual([]);
    expect(await source.ioc(0)).toHaveLength(1);

    const heard: string[] = [];
    source.subscribe((incident) => heard.push(incident.ip));
    await new Promise((resolve) => setTimeout(resolve, 200));

    // The management API goes away and comes back on the same port: the source reconnects.
    await management.close();
    management = new ManagementServer({ store, host: "127.0.0.1", port, apiKeys: ["management-key-0123456789"] });
    await management.listen();
    for (let i = 0; i < 100 && heard.length === 0; i++) {
      await engine.evaluate(probe(`203.0.113.${120 + (i % 100)}`));
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    expect(heard.length).toBeGreaterThan(0);
  }, 30_000);
});

describe("fixes to what the dashboard promises", () => {
  it("keeps the captured request in the process when the incidents section is off", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    await engine.evaluate(probe("203.0.113.130", { method: "POST", headers: { host: "shop.example", "user-agent": "sqlmap/1.7", cookie: "session=abc" }, body: "password=hunter2" }));
    const server = await started(engine, { sections: { incidents: false }, redact: { credentials: false } });
    const { incidents } = (await (await fetch(`${server.url}api/incidents`)).json()) as { incidents: Array<{ headers: Record<string, string>; body?: string; detections: unknown[] }> };
    expect(incidents).toHaveLength(1);
    expect(incidents[0]!.body).toBeUndefined();
    expect(incidents[0]!.headers).toEqual({ "user-agent": "sqlmap/1.7" });
    expect(incidents[0]!.detections.length).toBeGreaterThan(0);
  });

  it("enforces listed host names on a public bind", async () => {
    const server = await started(new HoneypotEngine({ enricher: null }), { host: "0.0.0.0", auth: false, allowedHosts: ["dash.example"] });
    const wrong = await raw(server.port, "/api/stats");
    expect(wrong !== "closed" && wrong.status).toBe(421);
    const right = await raw(server.port, "/api/stats", { host: "dash.example" });
    expect(right !== "closed" && right.status).toBe(200);
  });

  it("shows a management server's own counters, which only rise", async () => {
    const store = new MemoryStore();
    const management = new ManagementServer({ store, host: "127.0.0.1", port: 0, apiKeys: ["k-0123456789abcdef"] });
    const engine = new HoneypotEngine({ enricher: null, store, onHit: (hit) => management.publish(hit) });
    await engine.evaluate(probe("203.0.113.131"));
    const source = managementServerSource(management, store);
    expect(await source.metrics()).toContain("hackerpot_incidents_total 1");
    expect(await source.metrics()).toBe(await management.metricsText());
  });
});
