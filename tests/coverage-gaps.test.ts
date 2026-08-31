import { describe, expect, it } from "vitest";
import http from "node:http";
import net from "node:net";
import { HoneypotEngine } from "../src/core.js";
import { createMiddleware, dispatch } from "../src/middleware.js";
import { MemoryStore } from "../src/stores/index.js";
import { MemoryBlocklist } from "../src/blocklist.js";
import { PortScanSentinel } from "../src/detectors/index.js";
import { dripFeedAction } from "../src/responses/index.js";
import type { ResponseContext } from "../src/responses/types.js";
import type { PortScanEvent } from "../src/detectors/index.js";

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

describe("dispatch degrades rather than throwing when no action can be resolved", () => {
  it("answers a bare 404 when even the not-found fallback is missing", async () => {
    // A caller can configure a response set without "not-found" — the id `dispatch`
    // falls back to. Nothing should throw into the request path.
    const engine = new HoneypotEngine({ responseActions: [], store: new MemoryStore() });
    expect(engine.actions.size).toBe(0);

    let status = 0;
    const server = http.createServer((_req, res) => {
      void (async () => {
        const result = await engine.evaluate({ method: "GET", path: "/.env", query: {}, headers: {}, ip: "203.0.113.5" });
        await dispatch(engine, res, result, "203.0.113.5", "/.env");
      })();
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const { port } = server.address() as { port: number };
    try {
      status = (await fetch(`http://127.0.0.1:${port}/.env`)).status;
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
    expect(status).toBe(404);
  });
});

describe("the port-scan sentinel captures and bounds a probe banner", () => {
  /** A port the OS just told us is free — the sentinel needs a concrete one to report. */
  async function freePort(): Promise<number> {
    const probe = net.createServer();
    await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
    const { port } = probe.address() as { port: number };
    await new Promise<void>((r) => probe.close(() => r()));
    return port;
  }

  /** Connect, optionally send bytes, and resolve with the event the sentinel emitted. */
  async function probe(send: Buffer[], options: { maxTrackedIps?: number } = {}): Promise<PortScanEvent> {
    const events: PortScanEvent[] = [];
    let resolveEvent!: (e: PortScanEvent) => void;
    const first = new Promise<PortScanEvent>((r) => (resolveEvent = r));
    const port = await freePort();
    const sentinel = new PortScanSentinel({
      ports: [port],
      host: "127.0.0.1",
      ...options,
      onEvent: (e) => {
        events.push(e);
        resolveEvent(e);
      },
    });
    await sentinel.listen();
    try {
      await new Promise<void>((resolve) => {
        const socket = net.createConnection({ host: "127.0.0.1", port }, () => {
          for (const chunk of send) socket.write(chunk);
          socket.end();
        });
        socket.on("close", () => resolve());
        socket.on("error", () => resolve());
      });
      return await first;
    } finally {
      await sentinel.close();
    }
  }

  it("records the connection and the bytes the client sent", async () => {
    const event = await probe([Buffer.from("SSH-2.0-libssh_0.9\r\n")]);
    expect(event.port).toBeGreaterThan(0);
    expect(event.isScan).toBe(false); // one port touched, threshold is 2
    expect(event.portsTouched).toBe(1);
    expect(event.banner).toContain("SSH-2.0-libssh_0.9");
  });

  it("reassembles a multi-byte character split across two writes", async () => {
    // The decoder is why this works: decoding each chunk alone yields replacement
    // characters, silently corrupting the captured probe.
    const euro = Buffer.from("€", "utf8");
    const event = await probe([Buffer.concat([Buffer.from("HELO "), euro.subarray(0, 2)]), euro.subarray(2)]);
    expect(event.banner).toBe("HELO €");
  });

  it("bounds the retained banner instead of holding a whole oversized write", async () => {
    const event = await probe([Buffer.alloc(64 * 1024, 0x41)]);
    expect(event.banner).toHaveLength(512);
  });

  it("emits an event even when the client sends nothing at all", async () => {
    const event = await probe([]);
    expect(event.banner).toBeUndefined();
    expect(event.portsTouched).toBe(1);
  });
});

describe("drip-feed pins a connection but never unboundedly", () => {
  /** Serve one request with the given action and report what the client received. */
  async function serve(action: ReturnType<typeof dripFeedAction>, opts: { abortAfterMs?: number } = {}): Promise<{ status: number; body: string; aborted: boolean }> {
    const server = http.createServer((_req, res) => {
      const ctx = {
        res,
        detection: { detectorId: "x", reason: "r", score: 1 },
        detections: [{ detectorId: "x", reason: "r", score: 1 }],
        ip: "203.0.113.9",
        path: "/",
        totalScore: 10,
        tracker: undefined as never,
        blocklist: new MemoryBlocklist(),
      } satisfies Partial<ResponseContext> as ResponseContext;
      void Promise.resolve(action.execute(ctx)).catch(() => undefined);
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const { port } = server.address() as { port: number };
    try {
      const controller = new AbortController();
      if (opts.abortAfterMs !== undefined) setTimeout(() => controller.abort(), opts.abortAfterMs);
      const res = await fetch(`http://127.0.0.1:${port}/`, { signal: controller.signal });
      const body = await res.text();
      return { status: res.status, body, aborted: false };
    } catch {
      return { status: 0, body: "", aborted: true };
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  }

  it("streams a trickle and closes itself at the deadline", async () => {
    const action = dripFeedAction({ chunkBytes: 4, intervalMs: 10, maxDurationMs: 120 });
    const out = await serve(action);
    expect(out.status).toBe(200);
    expect(out.body.startsWith("<!doctype html><html><body>")).toBe(true);
    expect(out.body.endsWith("</body></html>")).toBe(true);
  });

  it("stops when the client hangs up, instead of writing into a dead socket", async () => {
    const action = dripFeedAction({ chunkBytes: 1, intervalMs: 10, maxDurationMs: 5_000 });
    const out = await serve(action, { abortAfterMs: 60 });
    expect(out.aborted).toBe(true);
    // The action must release its slot rather than run to the 5s deadline; the next
    // request proving it is served is what shows the slot came back.
    const after = await serve(dripFeedAction({ chunkBytes: 4, intervalMs: 10, maxDurationMs: 80 }));
    expect(after.status).toBe(200);
  });

  it("answers immediately once every drip slot is held", async () => {
    // At capacity the action must send a complete short body rather than pin another
    // socket — otherwise a flood inverts the tarpit onto us.
    const action = dripFeedAction({ chunkBytes: 1, intervalMs: 20, maxDurationMs: 3_000, maxConcurrent: 1 });
    const held = serve(action, { abortAfterMs: 400 });
    await new Promise((r) => setTimeout(r, 80)); // let the first take the only slot
    const overflow = await serve(action);
    expect(overflow.status).toBe(200);
    expect(overflow.body).toBe("<!doctype html><html><body></body></html>");
    await held;
  });
});
