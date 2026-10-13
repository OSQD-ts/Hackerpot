import http from "node:http";
import { describe, expect, it } from "vitest";
import { HoneypotEngine, createMiddleware } from "../src/index.js";
import { dispatch, type MiddlewareOptions, type NextFn } from "../src/adapters/node.js";
import { MemoryStore } from "../src/stores/index.js";
import type { HoneypotHit } from "../src/types.js";

/** Drive a middleware over a real socket and report what the host app saw. */
async function throughMiddleware(
  engine: HoneypotEngine,
  init: { path: string; method?: string; body?: string },
  options: MiddlewareOptions = {},
): Promise<{ status: number; nexted: boolean; nextErr: unknown }> {
  const middleware = createMiddleware(engine, options);
  let nexted = false;
  let nextErr: unknown;
  const next: NextFn = (err) => {
    nexted = true;
    nextErr = err;
  };
  const server = http.createServer((req, res) => {
    void middleware(req, res, (err) => {
      next(err);
      if (!res.writableEnded) {
        res.statusCode = err ? 500 : 204;
        res.end();
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as { port: number };
  try {
    const res = await fetch(`http://127.0.0.1:${port}${init.path}`, {
      method: init.method ?? "POST",
      ...(init.body !== undefined ? { body: init.body } : {}),
    });
    await res.arrayBuffer();
    return { status: res.status, nexted, nextErr };
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}

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

describe("the body phase re-evaluates a request without counting it twice", () => {
  // The middleware evaluates on headers alone, then — if something fired and a
  // body-inspecting detector exists — reads the body and evaluates again. Both passes
  // used to commit, so ONE probe produced two stored incidents, two onHit alerts, two
  // entries in the activity window, and double the score: an attacker crossed the block
  // threshold on half the evidence, and the incident log double-counted every hit.
  it("records one incident and one score for one request", async () => {
    const store = new MemoryStore();
    const alerts: HoneypotHit[] = [];
    const engine = new HoneypotEngine({ store, onHit: (hit) => void alerts.push(hit) });

    await throughMiddleware(engine, { path: "/.env", method: "POST", body: "x=1" });

    const hits = await store.list();
    expect(hits).toHaveLength(1);
    expect(alerts).toHaveLength(1);
    // The decoy is worth 10; it must not be banked twice.
    expect(hits[0]!.score).toBe(10);
    expect(hits[0]!.totalScore).toBe(10);
    expect(await store.scoreFor(hits[0]!.ip)).toBe(10);
  });

  it("counts the request in the activity window exactly once", async () => {
    const store = new MemoryStore();
    const engine = new HoneypotEngine({ store });
    await throughMiddleware(engine, { path: "/.env", method: "POST", body: "x=1" });

    const hits = await store.list();
    // Two evaluations of one request used to append two events, inflating every
    // rate/enumeration threshold by 2x.
    expect(engine.trackerFor(hits[0]!.ip).recent()).toHaveLength(1);
  });

  it("still catches a payload that only appears in the body", async () => {
    const store = new MemoryStore();
    const engine = new HoneypotEngine({ store });
    await throughMiddleware(engine, { path: "/.env", method: "POST", body: "q=' UNION SELECT password FROM users" });

    const detectors = (await store.list())[0]!.detections.map((d) => d.detector);
    expect(detectors).toContain("decoy-path");
    expect(detectors).toContain("payload-injection");
  });

  it("leaves an unflagged request's body unread and falls through to the host app", async () => {
    const engine = new HoneypotEngine({ store: new MemoryStore() });
    const result = await throughMiddleware(engine, { path: "/api/orders", method: "POST", body: "totally=benign" });
    expect(result.nexted).toBe(true);
    expect(result.status).toBe(204);
  });
});

describe("the middleware never rejects into the host application", () => {
  // An async middleware that rejects is not caught by Express 4 — the request hangs
  // until it times out. The engine isolates detectors and the store, but the blocklist
  // is a live backend call that can throw on its own. By default the request then goes on
  // to the app and the failure is reported; `failOpen: false` hands it to next(err).
  const failingBlocklist = {
    block: () => undefined,
    isBlocked: (): boolean => {
      throw new Error("redis is down");
    },
  };

  it("lets the request through to the app and reports the failure", async () => {
    const errors: Array<{ error: unknown; source: string }> = [];
    const engine = new HoneypotEngine({
      store: new MemoryStore(),
      blocklist: failingBlocklist,
      onError: (error, context) => void errors.push({ error, source: context.source }),
    });
    const result = await throughMiddleware(engine, { path: "/.env", method: "GET" });
    expect(result.nexted).toBe(true);
    expect(result.nextErr).toBeUndefined();
    expect(result.status).toBe(204);
    expect(errors).toHaveLength(1);
    expect(errors[0]!.source).toBe("middleware");
    expect((errors[0]!.error as Error).message).toBe("redis is down");
  });

  it("routes the failure to next(err) when failOpen is false", async () => {
    const engine = new HoneypotEngine({ store: new MemoryStore(), blocklist: failingBlocklist });
    const result = await throughMiddleware(engine, { path: "/.env", method: "GET" }, { failOpen: false });
    expect((result.nextErr as Error).message).toBe("redis is down");
    expect(result.status).toBe(500);
  });
});
