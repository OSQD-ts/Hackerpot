import http from "node:http";
import { describe, expect, it } from "vitest";
import {
  HoneypotEngine,
  HoneypotServer,
  MemoryStore,
  createMiddleware,
  pathBruteforceDetector,
  payloadInjectionDetector,
  credentialBruteforceDetector,
  decoyPathDetector,
} from "../src/index.js";
import type { RequestFacts } from "../src/index.js";
import type { EvaluationResult } from "../src/index.js";

function request(port: number, path: string, method = "GET", headers: Record<string, string> = {}, body?: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request({ port, path, method, headers }, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: data }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

function facts(partial: Partial<RequestFacts> & Pick<RequestFacts, "path">): RequestFacts {
  return { method: "GET", query: {}, headers: {}, ip: "10.0.0.1", ...partial };
}

describe("detectors", () => {
  it("decoy path detector flags a known bait path", async () => {
    const engine = new HoneypotEngine({ detectors: [decoyPathDetector()] });
    const result = await engine.evaluate(facts({ path: "/.env" }));
    expect(result.detections[0]?.detectorId).toBe("decoy-path");
    expect(result.actionId).toBe("decoy-content");
  });

  it("payload injection detector flags a traversal attempt in the query", async () => {
    const engine = new HoneypotEngine({ detectors: [payloadInjectionDetector()] });
    const result = await engine.evaluate(facts({ path: "/x", query: { file: "../../../../etc/passwd" } }));
    expect(result.detections[0]?.detectorId).toBe("payload-injection");
    expect(result.detections[0]?.metadata?.["kind"]).toBe("path-traversal");
  });

  it("path bruteforce detector flags many distinct paths from one IP", async () => {
    const engine = new HoneypotEngine({ detectors: [pathBruteforceDetector({ uniquePathThreshold: 5, windowMs: 10_000 })] });
    let last: EvaluationResult | undefined;
    for (let i = 0; i < 6; i++) last = await engine.evaluate(facts({ path: `/dir-${i}` }));
    expect(last?.detections[0]?.detectorId).toBe("path-bruteforce");
  });

  it("credential bruteforce detector flags repeated auth POSTs", async () => {
    const engine = new HoneypotEngine({ detectors: [credentialBruteforceDetector({ attemptThreshold: 3, windowMs: 10_000 })] });
    let last: EvaluationResult | undefined;
    for (let i = 0; i < 3; i++) last = await engine.evaluate(facts({ method: "POST", path: "/login", body: "u=a&p=b" }));
    expect(last?.detections[0]?.detectorId).toBe("credential-bruteforce");
  });

  it("leaves ordinary traffic alone", async () => {
    const engine = new HoneypotEngine();
    const result = await engine.evaluate(facts({ path: "/api/users", headers: { "user-agent": "Mozilla/5.0", host: "example.com" } }));
    expect(result.detections).toHaveLength(0);
  });
});

describe("scoring", () => {
  it("accumulates score per IP and escalates the response action", async () => {
    const store = new MemoryStore();
    const engine = new HoneypotEngine({ store, detectors: [decoyPathDetector()] });
    let last: EvaluationResult | undefined;
    for (let i = 0; i < 6; i++) last = await engine.evaluate(facts({ path: "/.git/config" }));
    expect(await store.scoreFor("10.0.0.1")).toBeGreaterThanOrEqual(40);
    expect(last?.actionId).toBe("block"); // policy escalates past the block threshold
  });
});

describe("middleware", () => {
  it("falls through to next() when nothing fires", async () => {
    const engine = new HoneypotEngine();
    const middleware = createMiddleware(engine);
    let nextCalled = false;
    await middleware(
      { method: "GET", url: "/healthz", headers: { "user-agent": "Mozilla/5.0", host: "example.com" }, socket: { remoteAddress: "1.2.3.4" }, on: () => undefined } as never,
      {} as never,
      () => {
        nextCalled = true;
      },
    );
    expect(nextCalled).toBe(true);
  });
});

describe("HoneypotServer", () => {
  it("serves decoy content and blocks a persistent attacker", async () => {
    const hits: string[] = [];
    const server = new HoneypotServer({
      onHit: (hit) => {
        hits.push(hit.respondedWith);
      },
    });
    await server.listen(0);
    const port = (server.address() as { port: number }).port;

    const env = await request(port, "/.env");
    expect(env.status).toBe(200);
    expect(env.body).toContain("AWS_ACCESS_KEY_ID");

    // Hammer decoys until the block threshold trips.
    for (let i = 0; i < 6; i++) await request(port, "/.git/config");
    const blocked = await request(port, "/anything");
    expect(blocked.status).toBe(403);

    expect(hits).toContain("decoy-content");
    expect(hits).toContain("block");

    await server.close();
  });
});
