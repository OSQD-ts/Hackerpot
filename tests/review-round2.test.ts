import { describe, expect, it } from "vitest";
import http from "node:http";
import { createMiddleware } from "../src/middleware.js";
import { HoneypotEngine } from "../src/core.js";
import { HoneypotServer } from "../src/server.js";
import { MemoryStore } from "../src/stores/index.js";
import { cefFormat, syslogLine } from "../src/formats.js";
import { uaClass } from "../src/fingerprint.js";
import { readBody } from "../src/http-request.js";
import { applyEnvOverrides, createBlocklist, parseConfigText } from "../src/config/index.js";
import type { HackerpotConfig } from "../src/config/index.js";
import type { HoneypotHit } from "../src/types.js";
import type { MiddlewareOptions, NextFn } from "../src/middleware.js";

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

    const detectors = (await store.list())[0]!.detections.map((d) => d.detectorId);
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

describe("CEF output cannot be used to forge log lines", () => {
  const hit = (overrides: Partial<HoneypotHit> = {}): HoneypotHit => ({
    id: "abc-123",
    timestamp: "2026-08-27T12:34:56.000Z",
    ip: "203.0.113.7",
    method: "GET",
    path: "/",
    headers: {},
    detections: [{ detectorId: "sensitive-file", reason: "benign", score: 6 }],
    score: 6,
    totalScore: 6,
    respondedWith: "not-found",
    ...overrides,
  });

  // Every value here is attacker-chosen: the path, and the detector reasons that quote
  // it back. CEF is line-oriented, so a raw CR or LF closes our event and opens one the
  // attacker wrote — with a source IP of their choosing — that no SIEM can tell from a
  // real detection.
  it("escapes CR and LF smuggled through the request path", () => {
    const line = cefFormat(hit({ path: "/a\r\nCEF:0|evil|evil|1|forged|forged|10|src=9.9.9.9" }));
    expect(line).not.toMatch(/[\r\n]/);
    expect(line).toContain("\\r\\n");
  });

  it("escapes CR and LF smuggled through a detector reason (the CEF header half)", () => {
    const line = cefFormat(hit({ detections: [{ detectorId: "x\ny", reason: "boom\r\nCEF:0|evil", score: 1 }] }));
    expect(line).not.toMatch(/[\r\n]/);
  });

  it("strips the remaining control characters rather than emitting them raw", () => {
    const line = cefFormat(hit({ path: "/a\u0001b\u0007c" }));
    expect(line).not.toMatch(/[\u0000-\u001f\u007f]/);
    expect(line).toContain("request=/abc");
  });

  it("keeps the syslog envelope on a single line too", () => {
    const line = syslogLine(hit({ path: "/a\r\n<108>Aug 27 00:00:00 forged hackerpot: CEF:0|evil" }));
    expect(line).not.toMatch(/[\r\n]/);
  });

  it("still escapes pipes and equals, and leaves clean values alone", () => {
    const line = cefFormat(hit({ detections: [{ detectorId: "x", reason: "a|b reason", score: 1 }], path: "/a=b" }));
    expect(line).toContain("a\\|b reason");
    expect(line).toContain("request=/a\\=b");
  });
});

describe("request bodies are decoded and bounded correctly", () => {
  /** Feed `chunks` to readBody() through a real HTTP request. */
  async function bodyFrom(chunks: Buffer[]): Promise<string | undefined> {
    let seen: string | undefined;
    const server = http.createServer((req, res) => {
      void readBody(req).then((body) => {
        seen = body;
        res.end();
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const { port } = server.address() as { port: number };
    try {
      await fetch(`http://127.0.0.1:${port}/`, {
        method: "POST",
        body: new ReadableStream({
          start(controller) {
            for (const chunk of chunks) controller.enqueue(new Uint8Array(chunk));
            controller.close();
          },
        }),
        // undici requires this for a streaming request body
        duplex: "half",
      });
      return seen;
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  }

  it("reassembles a multi-byte character split across two chunks", async () => {
    // "€" is E2 82 AC. Decoding each chunk on its own yields replacement characters,
    // silently mutating the bytes every body detector then matches against.
    const euro = Buffer.from("€", "utf8");
    const body = await bodyFrom([Buffer.concat([Buffer.from("a="), euro.subarray(0, 2)]), euro.subarray(2)]);
    expect(body).toBe("a=€");
  });

  it("keeps the prefix of an oversized body rather than dropping the chunk that crossed the cap", async () => {
    // The payload always sits near the front, so truncation must cut at the cap — not
    // discard whole chunks and end the body at an arbitrary boundary.
    const body = await bodyFrom([Buffer.from("q=' UNION SELECT 1"), Buffer.alloc(128 * 1024, 0x41)]);
    expect(body?.startsWith("q=' UNION SELECT 1AAA")).toBe(true);
    expect(body).toContain("[truncated]");
    expect(body!.length).toBeLessThan(70 * 1024);
  });

  it("does not read a body for methods that cannot carry one", async () => {
    const engine = new HoneypotEngine({ store: new MemoryStore() });
    const result = await throughMiddleware(engine, { path: "/api/orders", method: "GET" });
    expect(result.nexted).toBe(true);
  });
});

describe("HTTP listener lifecycle", () => {
  it("rejects when the port is already bound instead of crashing the process", async () => {
    const first = new HoneypotServer();
    await first.listen(0, "127.0.0.1");
    const { port } = first.address() as { port: number };
    try {
      const second = new HoneypotServer();
      await expect(second.listen(port, "127.0.0.1")).rejects.toMatchObject({ code: "EADDRINUSE" });
      // The failed bind must leave nothing behind that a later close() would hang on.
      await expect(second.close()).resolves.toBeUndefined();
    } finally {
      await first.close();
    }
  });

  it("resolves close() on a server that never listened", async () => {
    await expect(new HoneypotServer().close()).resolves.toBeUndefined();
  });

  it("refuses a second listen() rather than orphaning the first listener", async () => {
    const server = new HoneypotServer();
    await server.listen(0, "127.0.0.1");
    try {
      await expect(server.listen(0, "127.0.0.1")).rejects.toThrow(/already listening/);
    } finally {
      await server.close();
    }
  });
});

describe("uaClass groups crawler user agents as bots", () => {
  // The alternation used to bind its word boundaries to only the first and last branch,
  // so the mainstream crawlers — the entire point of the "bot" class — were classified
  // "other". Tool and browser classes must keep winning where they overlap.
  it("classifies the crawlers that actually appear in logs", () => {
    for (const ua of ["Googlebot/2.1", "Mozilla/5.0 (compatible; Googlebot/2.1)", "bingbot/2.0", "AhrefsBot", "zgrabber"]) {
      expect(uaClass(ua), `misclassified ${ua}`).toBe("bot");
    }
  });

  it("keeps the existing tool, browser and empty classifications", () => {
    expect(uaClass("sqlmap/1.7")).toBe("bot");
    expect(uaClass("curl/8.4.0")).toBe("tool:curl");
    expect(uaClass("Mozilla/5.0 ... Chrome/123.0 Safari/537")).toBe("browser:chrome");
    expect(uaClass(undefined)).toBe("none");
    expect(uaClass("Mozilla/5.0 (X11; Linux) AppleWebKit Firefox/121.0")).toBe("browser:firefox");
  });
});

describe("port numbers are validated where the operator can still see the file", () => {
  // The schema already refuses two listeners claiming one port "rather than at bind
  // time". An out-of-range port is the same class of mistake and was not caught at all:
  // it validated cleanly, printed cleanly from --print-config, and then failed at bind
  // with a RangeError from inside Node.
  it("rejects an out-of-range port in every listener section", () => {
    for (const toml of [
      "[server]\nport = 70000\n",
      "[management]\nenabled = true\napi_keys = [\"k\"]\nport = 99999\n",
      "[smtp]\nenabled = true\nport = 65536\n",
      "[ssh]\nenabled = true\nport = 123456\n",
    ]) {
      expect(() => parseConfigText(toml, "t.toml"), toml).toThrow(/TCP port between 0 and 65535/);
    }
  });

  it("rejects an out-of-range sentinel port", () => {
    expect(() => parseConfigText("[port-scan]\nports = [80, 70000]\n", "t.toml")).toThrow(/not a TCP port between 1 and 65535/);
    expect(() => parseConfigText("[port-scan]\nports = [0]\n", "t.toml")).toThrow(/not a TCP port between 1 and 65535/);
  });

  it("applies the same rail to the environment overrides", () => {
    const base = (): HackerpotConfig => parseConfigText("", "t.toml");
    expect(() => applyEnvOverrides(base(), { PORT: "70000" })).toThrow(/TCP port between 0 and 65535/);
    expect(() => applyEnvOverrides(base(), { MANAGEMENT_PORT: "99999" })).toThrow(/TCP port between 0 and 65535/);
    expect(() => applyEnvOverrides(base(), { SCAN_PORTS: "80,70000" })).toThrow(/TCP port between 0 and 65535/);
  });

  it("still accepts the ports people actually use", () => {
    const config = parseConfigText("[server]\nport = 65535\n\n[port-scan]\nports = [23, 3389]\n", "t.toml");
    expect(config.server.port).toBe(65535);
    expect(config.portScan.ports).toEqual([23, 3389]);
    expect(applyEnvOverrides(parseConfigText("", "t.toml"), { PORT: "8080" }).server.port).toBe(8080);
  });
});

describe("memory ceilings settable on the library API are reachable from the config file", () => {
  // Every other bound in the engine is tunable from TOML (store.memory.max_hits,
  // max_score_entries, the engine windows). These three were settable only by a
  // library caller, so the standalone service — the primary deployment — was stuck
  // with the defaults for the blocklist and the port-scan sentinel's growth surface.
  it("plumbs [blocklist] max_entries through to the memory blocklist", () => {
    const config = parseConfigText("[blocklist]\nmax_entries = 250\n", "t.toml");
    expect(config.blocklist.maxEntries).toBe(250);
    const built = createBlocklist(config);
    expect(built.describe).toContain("250");
  });

  it("plumbs the port-scan sentinel's memory bounds", () => {
    const config = parseConfigText("[port-scan]\nports = [9999]\nmax_tracked_ips = 32\nretention_ms = 5000\n", "t.toml");
    expect(config.portScan.maxTrackedIps).toBe(32);
    expect(config.portScan.retentionMs).toBe(5000);
  });

  it("enforces the cap it configures", () => {
    const config = parseConfigText("[blocklist]\nmax_entries = 5\n", "t.toml");
    const { blocklist } = createBlocklist(config);
    const until = Date.now() + 60_000;
    for (let i = 0; i < 50; i += 1) void blocklist.block(`203.0.113.${i}`, until);
    // Without the plumbing this stayed at the 100 000 default and held all 50.
    expect(blocklist.size?.()).toBeLessThanOrEqual(5);
  });

  it("refuses the values that would silently disable the feature", () => {
    expect(() => parseConfigText("[port-scan]\nports = [9999]\nmax_tracked_ips = 0\n", "t.toml")).toThrow(/no sweep is ever reported/);
    expect(() => parseConfigText("[port-scan]\nports = [9999]\nretention_ms = 0\n", "t.toml")).toThrow(/forgotten immediately/);
  });
});
