import http from "node:http";
import net from "node:net";
import { gunzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import { HoneypotServer, tarpitAction } from "../src/index.js";
import { MemoryBlocklist } from "../src/blocklist.js";
import { dripFeedAction, largePayloadAction } from "../src/actions/index.js";
import type { ResponseContext } from "../src/actions/types.js";
import { EventEmitter } from "node:events";
import { portOf } from "./helpers.js";

function raw(port: number, path: string, headers: Record<string, string> = {}): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const req = http.request({ port, path, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on("error", reject);
    req.end();
  });
}

describe("new responses (over HTTP)", () => {
  let server: HoneypotServer | undefined;
  afterEach(async () => { await server?.close(); server = undefined; });

  async function serve(respondWith: string): Promise<number> {
    // A trivial detector that routes to the response under test (low score, so the policy honors respondWith).
    const detector = { id: "test", inspect: () => ({ detector: "test", summary: "x", score: 1, respondWith }) };
    server = new HoneypotServer({ detectors: [detector] });
    await server.listen(0);
    return (server.address() as { port: number }).port;
  }

  it("fake-success returns 200 + a session cookie", async () => {
    const res = await raw(await serve("fake-success"), "/wp-login.php");
    expect(res.status).toBe(200);
    expect(String(res.headers["set-cookie"])).toContain("session=");
    expect(JSON.parse(res.body.toString()).authenticated).toBe(true);
  });

  it("gzip-bomb returns a small payload that inflates hugely", async () => {
    const res = await raw(await serve("gzip-bomb"), "/x");
    expect(res.headers["content-encoding"]).toBe("gzip");
    expect(res.body.length).toBeLessThan(200_000);       // small on the wire
    expect(gunzipSync(res.body).length).toBe(10 * 1024 * 1024); // 10 MB inflated
  });

  it("rate-limit returns 429 with Retry-After", async () => {
    const res = await raw(await serve("rate-limit"), "/x");
    expect(res.status).toBe(429);
    expect(res.headers["retry-after"]).toBeDefined();
  });

  it("chaos returns either a 5xx or garbage bytes", async () => {
    const res = await raw(await serve("chaos"), "/x");
    const ok = res.status >= 500 || (res.status === 200 && res.headers["content-type"] === "application/octet-stream");
    expect(ok).toBe(true);
  });

  it("fake-data tailors synthesized secrets to the request and never repeats", async () => {
    const port = await serve("fake-data");
    const env = await raw(port, "/.env");
    expect(env.status).toBe(200);
    expect(env.body.toString()).toContain("DATABASE_URL=postgres://");
    expect(env.body.toString()).toContain("AWS_SECRET_ACCESS_KEY=");

    const users = await raw(port, "/api/users");
    expect(users.headers["content-type"]).toContain("application/json");
    const parsed = JSON.parse(users.body.toString());
    expect(Array.isArray(parsed.users)).toBe(true);
    expect(parsed.users[0].password_hash).toMatch(/^\$2b\$12\$/); // bcrypt-shaped, but noise

    // Two hits to the same decoy produce different values — undiffable, unfingerprintable.
    const a = (await raw(port, "/.env")).body.toString();
    const b = (await raw(port, "/.env")).body.toString();
    expect(a).not.toBe(b);
  });
});

describe("drip-feed pins a connection but never unboundedly", () => {
  /** Serve one request with the given action and report what the client received. */
  async function serve(action: ReturnType<typeof dripFeedAction>, opts: { abortAfterMs?: number } = {}): Promise<{ status: number; body: string; aborted: boolean }> {
    const server = http.createServer((_req, res) => {
      const ctx = {
        res,
        detection: { detector: "x", summary: "r", score: 1 },
        detections: [{ detector: "x", summary: "r", score: 1 }],
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

describe("holding-response concurrency cap", () => {
  function mockRes(): EventEmitter & { statusCode: number; writableEnded: boolean; setHeader(): void; end(): void; write(): boolean } {
    const ee = new EventEmitter() as EventEmitter & { statusCode: number; writableEnded: boolean; setHeader(): void; end(): void; write(): boolean };
    ee.statusCode = 0;
    ee.writableEnded = false;
    ee.setHeader = () => {};
    ee.end = () => { ee.writableEnded = true; };
    ee.write = () => true;
    return ee;
  }
  const ctx = (res: ReturnType<typeof mockRes>): ResponseContext => ({ res: res as never, detection: { detector: "x", summary: "x", score: 1 }, detections: [], ip: "1.2.3.4", path: "/", totalScore: 1, tracker: {} as never, blocklist: new MemoryBlocklist() });

  it("tarpit answers immediately once maxConcurrent is reached instead of holding another socket", async () => {
    // Wide separation between "held" (1000ms) and "immediate" (bound 300ms) so the
    // distinction survives load — the immediate path is a synchronous end(), so 300ms
    // is enormous headroom, not a tight race.
    const heldMs = 1000;
    const action = tarpitAction({ maxConcurrent: 1, delayMs: heldMs, escalate: false });

    const held = mockRes();
    const p1 = action.execute(ctx(held)); // occupies the single slot for ~1000ms
    await new Promise((r) => setTimeout(r, 20));

    const overflow = mockRes();
    const t = performance.now();
    await action.execute(ctx(overflow)); // over capacity → immediate
    const elapsed = performance.now() - t;
    expect(elapsed).toBeLessThan(300);       // absolute headroom for a sync response
    expect(elapsed).toBeLessThan(heldMs / 2); // and unmistakably not held for the delay
    expect(overflow.writableEnded).toBe(true);

    await p1; // let the held one drain
  });
});

describe("large-payload releases its concurrency slot when the peer disappears", () => {
  it("keeps serving after transfers are aborted mid-backpressure", async () => {
    const action = largePayloadAction({ totalBytes: 200 * 1024 * 1024, chunkBytes: 64 * 1024, maxConcurrent: 2 });
    const server = http.createServer((_req, res) => {
      void action.execute({
        res,
        detection: { detector: "t", summary: "t", score: 1 },
        detections: [{ detector: "t", summary: "t", score: 1 }],
        ip: "198.51.100.5",
        path: "/backup.sql",
        totalScore: 0,
        tracker: undefined as never,
        blocklist: undefined as never,
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = portOf(server);

    // Request, refuse to read (forcing backpressure), then hard-kill the socket.
    for (let i = 0; i < 5; i += 1) {
      await new Promise<void>((resolve) => {
        const socket = net.connect(port, "127.0.0.1", () => {
          socket.write("GET /backup.sql HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
          socket.pause();
          setTimeout(() => {
            socket.destroy();
            resolve();
          }, 120);
        });
        socket.on("error", () => resolve());
      });
    }
    await new Promise((resolve) => setTimeout(resolve, 400));

    const bytes = await new Promise<number>((resolve) => {
      const req = http.request({ host: "127.0.0.1", port, path: "/backup.sql" }, (res) => {
        let total = 0;
        res.on("data", (chunk: Buffer) => (total += chunk.length));
        setTimeout(() => {
          res.destroy();
          resolve(total);
        }, 600);
      });
      req.end();
    });
    expect(bytes).toBeGreaterThan(0);
    server.close();
  }, 20_000);
});

describe("a tarpit slot is released as soon as the attacker hangs up", () => {
  it("does not hold the slot for the full delay after the response closes", async () => {
    const action = tarpitAction({ delayMs: 5_000, escalate: false, maxConcurrent: 1 });
    const listeners = new Map<string, Array<() => void>>();
    const res = {
      writableEnded: false,
      statusCode: 200,
      setHeader: () => undefined,
      end: () => undefined,
      once: (event: string, fn: () => void) => {
        listeners.set(event, [...(listeners.get(event) ?? []), fn]);
      },
      off: (event: string, fn: () => void) => {
        listeners.set(event, (listeners.get(event) ?? []).filter((f) => f !== fn));
      },
    };
    const ctx = { res, totalScore: 0 } as never;

    const started = Date.now();
    const inFlight = action.execute(ctx);
    // The attacker disconnects immediately — a scanner timing out does exactly this.
    for (const fn of listeners.get("close") ?? []) fn();
    await inFlight;
    expect(Date.now() - started).toBeLessThan(1_000);

    // Slot is free again: the next request is genuinely tarpitted rather than being
    // waved through by the at-capacity branch.
    const second = tarpitAction({ delayMs: 40, escalate: false, maxConcurrent: 1 });
    const t = Date.now();
    await second.execute({ res: { ...res, once: () => undefined, off: () => undefined }, totalScore: 0 } as never);
    expect(Date.now() - t).toBeGreaterThanOrEqual(30);
  });
});
