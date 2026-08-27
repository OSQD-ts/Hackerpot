import { describe, expect, it } from "vitest";
import http from "node:http";
import net from "node:net";
import { mkdtempSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { HoneypotEngine } from "../src/core.js";
import { ActivityRegistry, FingerprintRegistry } from "../src/state.js";
import { ManagementServer } from "../src/management/index.js";
import { MemoryStore, FileStore } from "../src/stores/index.js";
import { largePayloadAction } from "../src/responses/index.js";
import { PortScanSentinel } from "../src/detectors/port-scan.js";
import { fetchIocFeed } from "../src/intel/index.js";
import { parseConfig } from "../src/config/schema.js";

const portOf = (s: { address(): unknown }): number => {
  const a = s.address();
  return typeof a === "object" && a !== null ? (a as { port: number }).port : 0;
};

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

describe("per-IP state caps are hard ceilings under active traffic", () => {
  it("ActivityRegistry stays at or under maxTrackedIps when nothing is idle", () => {
    const registry = new ActivityRegistry(60_000, 100);
    for (let i = 0; i < 5_000; i += 1) {
      registry.for(`10.0.${(i >> 8) & 255}.${i & 255}`).record({ method: "GET", path: "/", status: "seen" });
    }
    expect(registry.size).toBeLessThanOrEqual(100);
  });

  it("FingerprintRegistry stays at or under maxTracked when nothing has expired", () => {
    const registry = new FingerprintRegistry(3_600_000, 100);
    for (let i = 0; i < 5_000; i += 1) registry.record(`fingerprint-${i}`, "198.51.100.4");
    expect(registry.size).toBeLessThanOrEqual(100);
  });

  it("keeps the most recent tracker rather than evicting the caller's own IP", () => {
    const registry = new ActivityRegistry(60_000, 10);
    for (let i = 0; i < 200; i += 1) {
      registry.for(`10.0.0.${i % 256}`).record({ method: "GET", path: "/", status: "seen" });
    }
    const tracker = registry.for("203.0.113.1");
    tracker.record({ method: "GET", path: "/x", status: "seen" });
    expect(registry.for("203.0.113.1").recent()).toHaveLength(1);
  });
});

describe("port-scan sentinel tracking map is bounded", () => {
  it("evicts least-recently-seen sources past the cap", async () => {
    const sentinel = new PortScanSentinel({ ports: [0], maxTrackedIps: 5 });
    const remember = (sentinel as unknown as { remember(ip: string, port: number, now: number): Set<number> }).remember.bind(sentinel);
    for (let i = 0; i < 500; i += 1) remember(`10.0.0.${i % 256}`, 8022 + (i % 3), 1_000 + i);
    expect(sentinel.trackedIps).toBeLessThanOrEqual(5);
  });

  it("forgets sources whose last touch fell outside the retention window", () => {
    const sentinel = new PortScanSentinel({ ports: [0], retentionMs: 1_000 });
    const remember = (sentinel as unknown as { remember(ip: string, port: number, now: number): Set<number> }).remember.bind(sentinel);
    remember("198.51.100.1", 8022, 0);
    remember("198.51.100.2", 9200, 10_000);
    expect(sentinel.portsTouchedBy("198.51.100.1")).toBe(0);
    expect(sentinel.portsTouchedBy("198.51.100.2")).toBe(1);
  });
});

describe("management API auth rate limiting covers every authenticated route", () => {
  it("counts failed WebSocket upgrades against the same budget as REST", async () => {
    const management = new ManagementServer({ store: new MemoryStore(), host: "127.0.0.1", port: 0, apiKeys: ["real-key"] });
    await management.listen();
    const port = portOf(management);

    const attemptUpgrade = (guess: string): Promise<string> =>
      new Promise((resolve) => {
        const socket = net.connect(port, "127.0.0.1", () => {
          socket.write(
            `GET /stream?api_key=${guess} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
              `Sec-WebSocket-Key: ${Buffer.from("0123456789abcdef").toString("base64")}\r\nSec-WebSocket-Version: 13\r\n\r\n`,
          );
        });
        let seen = "";
        socket.on("data", (chunk) => {
          seen += chunk.toString();
          socket.destroy();
        });
        socket.on("close", () => resolve(seen));
        socket.on("error", () => resolve(seen));
      });

    let sawThrottle = false;
    for (let i = 0; i < 40; i += 1) {
      if ((await attemptUpgrade(`guess-${i}`)).includes("429")) {
        sawThrottle = true;
        break;
      }
    }
    expect(sawThrottle).toBe(true);

    // The budget is shared, so REST is throttled by those WebSocket failures too.
    const status = await new Promise<number>((resolve) => {
      const req = http.request({ host: "127.0.0.1", port, path: "/stats", headers: { "x-api-key": "wrong" } }, (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
      req.end();
    });
    expect(status).toBe(429);
    await management.close();
  }, 20_000);
});

describe("large-payload releases its concurrency slot when the peer disappears", () => {
  it("keeps serving after transfers are aborted mid-backpressure", async () => {
    const action = largePayloadAction({ totalBytes: 200 * 1024 * 1024, chunkBytes: 64 * 1024, maxConcurrent: 2 });
    const server = http.createServer((_req, res) => {
      void action.execute({
        res,
        detection: { detectorId: "t", reason: "t", score: 1 },
        detections: [{ detectorId: "t", reason: "t", score: 1 }],
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

describe("IOC feed transport rules survive redirects", () => {
  it("refuses a redirect that downgrades to plaintext", async () => {
    const fakeFetch = (async (input: string | URL) => {
      const url = String(input);
      if (url.startsWith("https://")) {
        return new Response(null, { status: 302, headers: { location: "http://169.254.169.254/latest/meta-data/" } });
      }
      return new Response("203.0.113.1\n", { status: 200 });
    }) as unknown as typeof fetch;

    await expect(fetchIocFeed("https://peer.example/ioc.txt", { fetch: fakeFetch })).rejects.toThrow(/https required/);
  });

  it("follows a redirect that stays on https", async () => {
    const fakeFetch = (async (input: string | URL) => {
      const url = String(input);
      if (url === "https://peer.example/ioc.txt") {
        return new Response(null, { status: 302, headers: { location: "https://peer.example/v2/ioc.txt" } });
      }
      return new Response("203.0.113.1\n198.51.100.2\n", { status: 200 });
    }) as unknown as typeof fetch;

    await expect(fetchIocFeed("https://peer.example/ioc.txt", { fetch: fakeFetch })).resolves.toEqual(["203.0.113.1", "198.51.100.2"]);
  });
});

describe("FileStore reads survive a damaged line", () => {
  // `record()` is awaited: writes are batched and asynchronous now (a synchronous
  // append blocked the event loop on the request path), so durability is what the
  // returned promise settles on. Every production caller already awaits it.
  it("returns the intact hits instead of throwing", async () => {
    const path = join(mkdtempSync(join(tmpdir(), "hackerpot-")), "hits.jsonl");
    const store = new FileStore({ path });
    await store.record({
      id: "a",
      timestamp: new Date().toISOString(),
      ip: "198.51.100.1",
      method: "GET",
      path: "/.env",
      headers: {},
      detections: [{ detectorId: "decoy-path", reason: "probe", score: 10 }],
      score: 10,
      totalScore: 10,
      respondedWith: "decoy-content",
    });
    appendFileSync(path, '{"id":"truncated","ip":"198.5\n');

    expect(() => store.list()).not.toThrow();
    expect(store.list()).toHaveLength(1);
  });
});

describe("gzip-bomb size is bounded at config parse time", () => {
  it("rejects a decompressed_bytes that would be allocated in this process", () => {
    expect(() => parseConfig({ responses: { "gzip-bomb": { decompressed_bytes: 8 * 1024 * 1024 * 1024 } } }, "<test>")).toThrow(/decompressed_bytes/);
  });

  it("accepts a sane value", () => {
    expect(() => parseConfig({ responses: { "gzip-bomb": { decompressed_bytes: 10 * 1024 * 1024 } } }, "<test>")).not.toThrow();
  });
});
