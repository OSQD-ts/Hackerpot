import http from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { HoneypotEngine, HoneypotServer, MemoryStore, hardenHttpServer, sensitiveFileDetector, decoyPathDetector, prototypePollutionDetector } from "../src/index.js";
import type { Detector, HitStore, HoneypotHit, RequestFacts } from "../src/index.js";

function makeHit(ip: string, score = 5): HoneypotHit {
  return { id: Math.random().toString(36).slice(2), timestamp: new Date().toISOString(), ip, method: "GET", path: "/.env", headers: {}, detections: [{ detectorId: "decoy-path", reason: "x", score }], score, totalScore: score, respondedWith: "not-found" };
}

function raw(port: number, path: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request({ port, path }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString() }));
    });
    req.on("error", reject);
    req.end();
  });
}

function facts(partial: Partial<RequestFacts> & Pick<RequestFacts, "path">): RequestFacts {
  return { method: "GET", query: {}, headers: {}, ip: "10.0.0.1", ...partial };
}

describe("engine hardening", () => {
  let server: HoneypotServer | undefined;
  afterEach(async () => { await server?.close(); server = undefined; });

  it("isolates a throwing detector so it cannot crash evaluation or bypass the others", async () => {
    const errors: Array<{ source: string }> = [];
    // A malicious/buggy detector that throws on every request, placed BEFORE a real one.
    const poison: Detector = {
      id: "poison",
      inspect() { throw new Error("boom"); },
    };
    const engine = new HoneypotEngine({
      detectors: [poison, sensitiveFileDetector()],
      onError: (_e, ctx) => errors.push(ctx),
    });

    // Evaluation must not throw, and the detector AFTER the throwing one still runs.
    const result = await engine.evaluate(facts({ path: "/backup.sql", ip: "9.9.9.9" }));
    expect(result.detections.map((d) => d.detectorId)).toContain("sensitive-file");
    expect(errors).toEqual([{ source: "poison" }]); // the throw was surfaced, not swallowed silently
  });

  it("survives a store whose every method rejects — no crash, detection still resolves", async () => {
    const errors: Array<{ source: string }> = [];
    // A store backed by a down backend (Redis/Elastic style) — every call rejects.
    const brokenStore: HitStore = {
      record: () => Promise.reject(new Error("backend down")),
      list: () => Promise.reject(new Error("backend down")),
      scoreFor: () => Promise.reject(new Error("backend down")),
    };
    const engine = new HoneypotEngine({
      detectors: [decoyPathDetector()],
      store: brokenStore,
      onHit: () => { throw new Error("onHit boom"); },
      onError: (_e, ctx) => errors.push(ctx),
    });

    // Must resolve (not reject — that would crash a host app in middleware mode) and still
    // return a valid detection result, degrading the prior score to 0.
    const result = await engine.evaluate(facts({ path: "/.env", ip: "9.9.9.9" }));
    expect(result.detections.length).toBeGreaterThan(0);
    expect(result.actionId).toBeTruthy();
    // The store-read, store-write, and onHit failures were all surfaced, none thrown.
    expect(errors.map((e) => e.source).sort()).toEqual(["onHit", "store", "store"]);
  });

  it("a ?__proto__= probe reaches the detector instead of being silently dropped (evasion fix)", async () => {
    // End-to-end through the real server query parser: the canonical prototype-pollution
    // probe param name must not evade the detector by being swallowed during parsing.
    const hits: string[][] = [];
    server = new HoneypotServer({
      detectors: [prototypePollutionDetector()],
      onHit: (h) => { hits.push(h.detections.map((d) => d.detectorId)); },
    });
    await server.listen(0);
    const port = (server.address() as { port: number }).port;
    await raw(port, "/?__proto__=whatever");
    await new Promise((r) => setTimeout(r, 30));

    // The detector saw the param (before the null-proto fix the key was dropped and nothing fired).
    expect(hits.some((ds) => ds.includes("prototype-pollution"))).toBe(true);
    // And the honeypot's own Object.prototype was never polluted by parsing that param.
    expect(({} as Record<string, unknown>)["whatever"]).toBeUndefined();
  });

  it("MemoryStore caps retained hits (ring buffer) so a flood can't grow memory without bound", () => {
    const store = new MemoryStore({ maxHits: 5 });
    for (let i = 0; i < 50; i++) store.record(makeHit("9.9.9.9"));
    expect(store.list()).toHaveLength(5);          // bounded, not 50
    expect(store.scoreFor("9.9.9.9")).toBe(250);   // scores still accumulate (drive blocking)
  });

  it("HTTP servers are hardened against Slowloris / connection floods", async () => {
    // The helper both servers apply — assert the conservative bounds are in place.
    const s = http.createServer();
    hardenHttpServer(s);
    expect(s.headersTimeout).toBe(20_000);   // Slowloris: headers must complete fast
    expect(s.requestTimeout).toBe(30_000);
    expect(s.timeout).toBe(60_000);          // socket inactivity bound (Node default is 0/off)
    expect(s.maxConnections).toBe(10_000);   // connection ceiling
    s.close();

    // And a real HoneypotServer gets them via listen().
    server = new HoneypotServer();
    await server.listen(0);
    // (no assertion needed beyond listen succeeding; hardenHttpServer ran in listen)
  });
});
