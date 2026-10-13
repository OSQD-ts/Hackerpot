import http from "node:http";
import net from "node:net";
import { describe, expect, it } from "vitest";
import { HoneypotEngine, MemoryStore, decoyPathDetector, type EvaluationResult, sensitiveFileDetector, headerAnomalyDetector } from "../src/index.js";
import { createMiddleware } from "../src/adapters/node.js";
import { MemoryBlocklist } from "../src/blocklist.js";
import { parseConfig } from "../src/config/schema.js";
import { ElasticStore } from "../src/stores/elastic.js";
import { facts } from "./helpers.js";

/**
 * Paths a coverage pass showed were never executed, chosen because they are the
 * error and resource-management branches — the ones that only run when something has
 * already gone wrong, and so are exactly the ones a test has to reach deliberately.
 */

/** Run one request through a middleware-mounted server and report what came back. */
async function through(engine: HoneypotEngine, path: string, init: RequestInit = {}): Promise<{ status: number; body: string }> {
  const middleware = createMiddleware(engine);
  const server = http.createServer((req, res) => {
    void middleware(req, res, () => {
      res.statusCode = 204;
      res.end();
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as { port: number };
  try {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, init);
    return { status: res.status, body: await res.text() };
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}

/**
 * A TCP listener that accepts connections and does whatever `onSocket` says, plus a
 * `close()` that actually resolves.
 *
 * `server.close()` alone waits for every live connection to end, and these tests
 * deliberately leave sockets paused with unread data queued behind them — exactly the
 * state in which the peer's close is not observed promptly. Holding the accepted sockets
 * and destroying them first is what makes teardown deterministic instead of a hang.
 */
function stalledServer(onSocket: (socket: net.Socket) => void): Promise<{ port: number; close: () => Promise<void> }> {
  const sockets: net.Socket[] = [];
  const server = net.createServer((socket) => {
    sockets.push(socket);
    onSocket(socket);
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        port: (server.address() as net.AddressInfo).port,
        close: async () => {
          for (const socket of sockets) socket.destroy();
          await new Promise<void>((done) => server.close(() => done()));
        },
      });
    });
  });
}

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

describe("reconfigure (hot reload)", () => {
  it("swaps detectors/policy/allowlist in place while preserving accrued scores and blocks", async () => {
    const engine = new HoneypotEngine({ detectors: [sensitiveFileDetector()] });
    // Accrue some suspicion and a block under the old config.
    await engine.evaluate(facts({ path: "/dump.sql", ip: "7.7.7.7" }));
    await engine.blocklist.block("7.7.7.7", Date.now() + 3_600_000);
    const scoreBefore = await engine.scoreFor("7.7.7.7");
    expect(scoreBefore).toBeGreaterThan(0);

    // Reload: a different detector set + a new allowlist. Store/blocklist untouched.
    engine.reconfigure({
      detectors: [headerAnomalyDetector()],
      allowlist: ["5.5.5.0/24"],
    });

    // Live state survived the swap.
    expect(await engine.scoreFor("7.7.7.7")).toBe(scoreBefore);
    expect(await engine.isBlocked("7.7.7.7")).toBe(true);

    // The old detector is gone; a /secret.sql probe no longer trips sensitive-file.
    const after = await engine.evaluate(facts({ path: "/secret.sql", ip: "6.6.6.6" }));
    expect(after.detections.map((d) => d.detector)).not.toContain("sensitive-file");
    // The new allowlist is in force.
    expect(engine.isAllowlisted("5.5.5.42")).toBe(true);
  });

  it("only replaces the fields provided", async () => {
    const engine = new HoneypotEngine({ detectors: [sensitiveFileDetector()] });
    const before = engine.policy;
    engine.reconfigure({ allowlist: ["1.2.3.4"] });
    expect(engine.policy).toBe(before); // untouched
    expect(engine.detectors[0]?.id).toBe("sensitive-file"); // untouched
    expect(engine.isAllowlisted("1.2.3.4")).toBe(true); // applied
  });
});

describe("a blocked IP is short-circuited before any detector runs", () => {
  it("answers 403 in middleware mode without recording another hit", async () => {
    const store = new MemoryStore();
    const blocklist = new MemoryBlocklist();
    const engine = new HoneypotEngine({ store, blocklist });

    // Block the loopback address the test client will connect from.
    for (const ip of ["127.0.0.1", "::1", "::ffff:127.0.0.1"]) await blocklist.block(ip, Date.now() + 60_000);

    const res = await through(engine, "/.env");
    expect(res.status).toBe(403);
    expect(res.body).toBe("Forbidden");
    // The whole point of the short-circuit: a blocked attacker costs nothing to serve,
    // so evaluation never runs and nothing new is stored.
    expect(await store.list()).toHaveLength(0);
  });
});

describe("client IP resolution cannot be forged into something that isn't an IP", () => {
  it("ignores a non-IP X-Forwarded-For and falls back to the socket address", () => {
    const engine = new HoneypotEngine({ trustProxy: true });
    expect(engine.resolveIp("203.0.113.9", { "x-forwarded-for": "not-an-ip" })).toBe("203.0.113.9");
    expect(engine.resolveIp("203.0.113.9", { "x-forwarded-for": "" })).toBe("203.0.113.9");
  });

  it("still honours a well-formed forwarded address when trustProxy is on", () => {
    const engine = new HoneypotEngine({ trustProxy: true });
    expect(engine.resolveIp("10.9.9.9", { "x-forwarded-for": "198.51.100.7, 10.0.0.1" })).toBe("198.51.100.7");
    expect(engine.resolveIp("10.9.9.9", { "x-forwarded-for": "[2001:db8::5]" })).toBe("2001:db8::5");
  });

  it("never reads the header at all when trustProxy is off", () => {
    const engine = new HoneypotEngine({ trustProxy: false, allowlist: ["10.0.0.0/8"] });
    const ip = engine.resolveIp("203.0.113.9", { "x-forwarded-for": "10.1.2.3" });
    expect(ip).toBe("203.0.113.9");
    expect(engine.isAllowlisted(ip)).toBe(false);
  });

  it("defaults trust_proxy off in the standalone config", () => {
    expect(parseConfig({}, "<test>").server.trustProxy).toBe(false);
  });
});

describe("a store that stalls must not stall the request path", () => {
  // `HoneypotEngine.safeScore` wraps `store.scoreFor()` in a try/catch so a broken store
  // degrades to a score of 0 rather than failing the request — and `scoreFor()` runs on
  // EVERY request. That degradation only works if the read actually fails: a promise
  // that never settles never reaches the catch, so a stalled backend turned every
  // request into a hang rather than into the handled failure the engine was built for.
  it("gives the Elastic store a deadline rather than waiting on a silent cluster", async () => {
    // Accept, read the request, and never answer.
    const server = await stalledServer((socket) => socket.resume());

    const store = new ElasticStore({
      node: `http://127.0.0.1:${server.port}`,
      timeoutMs: 300,
      onError: () => {},
    });

    const started = Date.now();
    // Degraded, not hung: the engine's contract for a store it cannot reach.
    await expect(store.scoreFor("203.0.113.9")).resolves.toBe(0);
    expect(Date.now() - started).toBeLessThan(5_000);

    await server.close();
  });

  it("builds the Redis client so a command fails instead of queueing forever", () => {
    // `maxRetriesPerRequest: null` is ioredis's wait-forever mode. The default config
    // must not select it; an operator can still ask for it explicitly with 0.
    const config = parseConfig({}, "<defaults>");
    expect(config.store.redis.maxRetriesPerRequest).toBeGreaterThan(0);
    expect(config.store.redis.commandTimeoutMs).toBeGreaterThan(0);
    expect(config.store.elastic.timeoutMs).toBeGreaterThan(0);
  });
});

describe("detector deadline", () => {
  it("skips a detector that never settles, reports it, and still runs the rest", async () => {
    const sources: string[] = [];
    const engine = new HoneypotEngine({
      enricher: null,
      detectorTimeoutMs: 50,
      extraDetectors: [{ id: "stuck", inspect: () => new Promise(() => undefined) }],
      onError: (_error, context) => void sources.push(context.source),
    });
    const started = Date.now();
    const result = await engine.evaluate({ method: "GET", path: "/.env", query: {}, headers: { host: "x", "user-agent": "curl/8" }, ip: "203.0.113.30" });
    expect(Date.now() - started).toBeLessThan(1_000);
    expect(result.detections.map((d) => d.detector)).toContain("decoy-path");
    expect(sources).toContain("stuck");
  });
});
