import http from "node:http";
import type net from "node:net";
import { describe, expect, it } from "vitest";
import { honeytokenGuard } from "../src/adapters/node.js";
import { buildDashboardOptions } from "../src/config/build.js";
import { parseConfig } from "../src/config/schema.js";
import { HoneypotEngine, type RefusedEvent } from "../src/core.js";
import { honeytokenDetector, scannerSignatureDetector, uaRotationDetector } from "../src/detectors/index.js";
import type { Detection, DetectionContext } from "../src/detectors/types.js";
import { IncidentBroker, MetricsListener } from "../src/management/index.js";
import { protectApp, rulePolicy } from "../src/policy/index.js";
import { VerdictTracker } from "../src/service.js";
import { facts, hit, portOf } from "./helpers.js";

/** What an edge ban and a scrape read: refusals, verdicts, metrics without the API, and the new signals. */

const inspectWith = (detector: ReturnType<typeof uaRotationDetector>, ip: string, userAgent: string, at: number): Detection | undefined =>
  detector.inspect({ ...facts({ path: "/", ip, headers: { "user-agent": userAgent } }), tracker: undefined as never, timestamp: new Date(at), fingerprint: "", fingerprintRegistry: undefined as never } as DetectionContext) as Detection | undefined;

describe("ua-rotation", () => {
  it("fires on three User-Agents from one address within the window", () => {
    const detector = uaRotationDetector();
    expect(inspectWith(detector, "203.0.113.1", "Mozilla/5.0 A", 0)).toBeUndefined();
    expect(inspectWith(detector, "203.0.113.1", "Mozilla/5.0 B", 1_000)).toBeUndefined();
    const found = inspectWith(detector, "203.0.113.1", "ReconX-L2S/1.0", 2_000);
    expect(found?.detector).toBe("ua-rotation");
    expect(found?.certain).toBeUndefined();
  });

  it("ignores the same User-Agent repeated, other addresses, and changes spread past the window", () => {
    const detector = uaRotationDetector();
    for (let i = 0; i < 5; i++) expect(inspectWith(detector, "203.0.113.2", "Mozilla/5.0 A", i)).toBeUndefined();
    expect(inspectWith(detector, "203.0.113.3", "Mozilla/5.0 B", 10)).toBeUndefined();
    expect(inspectWith(detector, "203.0.113.2", "Mozilla/5.0 B", 20_000)).toBeUndefined();
    expect(inspectWith(detector, "203.0.113.2", "Mozilla/5.0 C", 40_000)).toBeUndefined();
  });

  it("is off by default and refuses a threshold it could never reach", () => {
    expect(parseConfig({}, "<test>").detectors["ua-rotation"].enabled).toBe(false);
    expect(() => parseConfig({ detectors: { "ua-rotation": { distinct_threshold: 40 } } }, "<test>")).toThrow(/distinct_threshold/);
    expect(() => parseConfig({ detectors: { "ua-rotation": { distinct_threshold: 1 } } }, "<test>")).toThrow(/distinct_threshold/);
  });
});

describe("scanner signatures", () => {
  const detector = scannerSignatureDetector();
  const ua = (userAgent: string): Detection | undefined => detector.inspect({ ...facts({ path: "/", headers: { "user-agent": userAgent } }), tracker: undefined as never, timestamp: new Date(), fingerprint: "", fingerprintRegistry: undefined as never } as DetectionContext) as Detection | undefined;

  it("takes an exploitation tool naming itself as proof", () => {
    expect(ua("ReconX-WP2Shell/1.0")?.certain).toBe(true);
    expect(ua("WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)")?.certain).toBe(true);
  });

  it("records a survey scanner as suspicion only", () => {
    for (const agent of ["Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)", "l9explore/1.2.2", "l9tcpid/v1.1.0", "python-httpx/0.27.0"]) {
      const found = ua(agent);
      expect(found, agent).toBeDefined();
      expect(found?.certain, agent).toBeUndefined();
    }
  });
});

describe("requests refused while blocked", () => {
  it("are counted and reported at most once a minute per address", async () => {
    let now = 1_000_000;
    const engine = new HoneypotEngine({ enricher: null, clock: { now: () => now } });
    const events: RefusedEvent[] = [];
    engine.on("refused", (event) => events.push(event));
    await engine.blocklist.block("203.0.113.9", now + 3_600_000);
    for (let i = 0; i < 5; i++) expect(await engine.isBlocked("203.0.113.9")).toBe(true);
    expect(await engine.isBlocked("198.51.100.1")).toBe(false);
    expect(engine.counters().refusedWhileBlocked).toBe(5);
    expect(events).toHaveLength(1);
    now += 61_000;
    await engine.isBlocked("203.0.113.9");
    expect(events).toHaveLength(2);
    // The second event carries the refusals since the first: four unreported, plus this one.
    expect(events[1]!.count).toBe(5);
  });
});

describe("verdicts", () => {
  it("names proof and blocks at once, and a burst only at machine speed", () => {
    const tracker = new VerdictTracker(3, 5_000);
    expect(tracker.judge(hit({ ip: "203.0.113.20", detections: [{ detector: "honeytoken", summary: "x", score: 15, certain: true }] }))).toEqual({ reason: "proof" });
    expect(tracker.judge(hit({ ip: "203.0.113.21", respondedWith: "block" }))).toEqual({ reason: "block" });

    const at = (ms: number) => new Date(Date.UTC(2026, 0, 1) + ms).toISOString();
    expect(tracker.judge(hit({ ip: "203.0.113.22", timestamp: at(0) }))).toBeUndefined();
    expect(tracker.judge(hit({ ip: "203.0.113.22", timestamp: at(100) }))).toBeUndefined();
    expect(tracker.judge(hit({ ip: "203.0.113.22", timestamp: at(200) }))).toEqual({ reason: "burst", hits: 3 });
    // Reported once: the window starts over.
    expect(tracker.judge(hit({ ip: "203.0.113.22", timestamp: at(300) }))).toBeUndefined();

    // A person typing three bait addresses a minute apart is not a burst.
    for (const ms of [0, 60_000, 120_000]) expect(tracker.judge(hit({ ip: "203.0.113.23", timestamp: at(ms) }))).toBeUndefined();
  });

  it("reads its settings from [logging]", () => {
    expect(parseConfig({}, "<test>").logging).toMatchObject({ verdicts: true, burstHits: 3, burstWindowMs: 5_000, refusals: true });
    expect(() => parseConfig({ logging: { burst_hits: 1 } }, "<test>")).toThrow(/burst_hits/);
  });
});

describe("the metrics listener", () => {
  it("serves counters on its one path and nothing else", async () => {
    const broker = new IncidentBroker();
    const engine = new HoneypotEngine({ enricher: null });
    const listener = new MetricsListener({ port: 0, broker, engineCounters: () => engine.counters(), gauges: () => ({ active_blocks: 2 }) });
    await listener.listen();
    try {
      broker.publish(hit());
      const get = (path: string, method = "GET") =>
        new Promise<{ status: number; body: string }>((resolve, reject) => {
          const req = http.request({ host: "127.0.0.1", port: portOf(listener), path, method }, (res) => {
            let body = "";
            res.on("data", (chunk) => (body += chunk));
            res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
          });
          req.on("error", reject);
          req.end();
        });
      const metrics = await get("/metrics");
      expect(metrics.status).toBe(200);
      expect(metrics.body).toContain("hackerpot_incidents_total 1");
      expect(metrics.body).toContain("hackerpot_refused_blocked_total 0");
      expect(metrics.body).toContain("hackerpot_active_blocks 2");
      expect((await get("/incidents")).status).toBe(404);
      expect((await get("/metrics", "POST")).status).toBe(405);
    } finally {
      await listener.close();
    }
  });

  it("is configured from [metrics], and refuses a path no request could reach", () => {
    expect(parseConfig({}, "<test>").metrics).toEqual({ enabled: false, host: "127.0.0.1", port: 9502, path: "/metrics", allowedClients: [] });
    expect(() => parseConfig({ metrics: { path: "metrics" } }, "<test>")).toThrow(/path/);
    expect(() => parseConfig({ metrics: { enabled: true, port: 4004 } }, "<test>")).toThrow(/port 4004/);
  });
});

describe("[dashboard.controls]", () => {
  it("grants the controls the file names, and nothing by default", () => {
    expect(buildDashboardOptions(parseConfig({}, "<test>")).controls).toBeUndefined();
    const options = buildDashboardOptions(parseConfig({ dashboard: { username: "ops", password: "a-long-password", controls: { test_request: true, preview_policy: true } } }, "<test>"));
    expect(options.controls).toEqual({ testRequest: true, previewPolicy: true, editPolicy: false });
  });

  it("refuses edit_policy without authentication", () => {
    expect(() => parseConfig({ dashboard: { auth: "none", controls: { edit_policy: true } } }, "<test>")).toThrow(/edit_policy/);
  });
});

describe("honeytokenGuard", () => {
  const TOKEN = "pkp_9b1f0c3e7a5d4c2b8e6f";
  const request = (body: unknown) =>
    Object.assign(new http.IncomingMessage(null as unknown as net.Socket), {
      method: "POST",
      url: "/api/settings",
      headers: { "user-agent": "Mozilla/5.0", accept: "application/json" },
      socket: { remoteAddress: "203.0.113.30" },
      body,
    });

  it("catches a honeytoken replayed in a parsed JSON body, nested or in an array", async () => {
    for (const body of [{ token: TOKEN }, { auth: { panel: [TOKEN] } }, [{ key: TOKEN }]]) {
      // protect-app blocks on proof at once; the shipped ladder would tarpit for seconds.
      const engine = new HoneypotEngine({ enricher: null, policy: rulePolicy(protectApp()), extraDetectors: [honeytokenDetector({ tokens: [TOKEN] })] });
      const req = request(body);
      const res = new http.ServerResponse(req);
      let continued = 0;
      await honeytokenGuard(engine)(req, res, () => void continued++);
      expect(continued, JSON.stringify(body)).toBe(0);
      expect(res.statusCode).toBe(403);
      const recorded = await engine.store.list();
      expect(recorded.some((h) => h.detections.some((d) => d.detector === "honeytoken"))).toBe(true);
    }
  });

  it("passes an ordinary body to the application", async () => {
    const engine = new HoneypotEngine({ enricher: null, extraDetectors: [honeytokenDetector({ tokens: [TOKEN] })] });
    const req = request({ name: "Alice", theme: "dark" });
    let continued = 0;
    await honeytokenGuard(engine)(req, new http.ServerResponse(req), () => void continued++);
    expect(continued).toBe(1);
  });
});
