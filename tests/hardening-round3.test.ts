import net from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { IpAllowlist } from "../src/allowlist.js";
import { webhookEnforcer } from "../src/firewall.js";
import { listIncidents } from "../src/management/rest.js";
import { ManagementServer } from "../src/management/server.js";
import { parseConfig } from "../src/config/schema.js";
import { ElasticStore } from "../src/stores/elastic.js";
import { SyslogSink } from "../src/syslog.js";
import { MemoryStore } from "../src/stores/index.js";
import type { HoneypotHit } from "../src/types.js";

function hit(overrides: Partial<HoneypotHit> = {}): HoneypotHit {
  return {
    id: overrides.id ?? Math.random().toString(36).slice(2),
    timestamp: overrides.timestamp ?? new Date().toISOString(),
    ip: overrides.ip ?? "203.0.113.7",
    method: "GET",
    path: "/.env",
    headers: {},
    detections: [{ detectorId: "decoy-path", reason: "probe", score: 10 }],
    score: 10,
    totalScore: 10,
    respondedWith: "decoy-content",
    ...overrides,
  };
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

/** Speaks raw HTTP so a request line / header the `fetch` client would refuse to send can be tested. */
function rawRequest(port: number, payload: string, waitMs = 500): Promise<string> {
  return new Promise((resolve) => {
    const socket = net.connect(port, "127.0.0.1", () => socket.write(payload));
    let out = "";
    socket.on("data", (chunk) => (out += chunk));
    socket.on("close", () => resolve(out));
    socket.on("error", () => resolve(out));
    setTimeout(() => {
      socket.destroy();
      resolve(out);
    }, waitMs);
  });
}

describe("a malformed Host header cannot take the management server down", () => {
  let server: ManagementServer | undefined;
  afterEach(async () => {
    await server?.close();
    server = undefined;
  });

  async function start(): Promise<number> {
    server = new ManagementServer({ store: new MemoryStore(), host: "127.0.0.1", port: 0, apiKeys: ["secret-key"] });
    await server.listen();
    return (server.address() as { port: number }).port;
  }

  // `handleUpgrade` built its URL base out of the client's `Host` header. `Host: ]` is
  // not a parseable authority, so `new URL()` threw — inside an `upgrade` event handler
  // with no `try`, which Node reports as an uncaughtException and the process dies. The
  // throw happened *before* the API-key check, so one unauthenticated request killed the
  // management server and, in standalone mode, the honeypot sharing the process.
  it("answers the WebSocket upgrade path and stays up", async () => {
    const port = await start();
    for (const host of ["]", "a]b", "%", "[", "foo:bar:baz"]) {
      const response = await rawRequest(
        port,
        `GET /stream HTTP/1.1\r\nHost: ${host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
          `Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`,
      );
      // Unauthenticated, so 401 — the point is that we answered at all.
      expect(response).toContain("401");
    }
    // Still serving after every one of those.
    const res = await fetch(`http://127.0.0.1:${port}/health`);
    expect(res.status).toBe(200);
  });

  it("answers the REST path with a malformed Host rather than a 500", async () => {
    const port = await start();
    const response = await rawRequest(port, "GET /health HTTP/1.1\r\nHost: ]\r\n\r\n");
    expect(response).toContain("200");
    expect(response).not.toContain("500");
  });
});

describe("the /incidents row cap cannot be lifted by a junk limit", () => {
  // `Number("abc")` is NaN, and NaN survives `Math.min(Math.max(1, n), 1000)` untouched
  // — every comparison against it is false, so both bounds pass it through. It reached
  // the stores as `limit: NaN`, where `limit >= 0` is likewise false and the read falls
  // back to "no limit", so `?limit=abc` returned the entire corpus past the documented
  // 1000-row ceiling: an authenticated full-log read at whatever size the attacker has
  // grown it to.
  it("falls back to the default limit for a non-numeric value", async () => {
    const store = new MemoryStore({ maxHits: 5000 });
    for (let i = 0; i < 1500; i += 1) {
      await store.record(hit({ id: `h${i}`, timestamp: new Date(Date.now() + i).toISOString() }));
    }
    for (const value of ["abc", "Infinity", "-Infinity", "NaN", ""]) {
      const rows = await listIncidents(store, new URLSearchParams(value ? `limit=${value}` : ""));
      expect(rows).toHaveLength(100);
    }
    // A real value is still honored, and still clamped at the ceiling.
    expect(await listIncidents(store, new URLSearchParams("limit=10"))).toHaveLength(10);
    expect(await listIncidents(store, new URLSearchParams("limit=100000"))).toHaveLength(1000);
  });
});

describe("an allowlisted IPv6 address matches however it is spelled", () => {
  // These entries used to be compared as strings, which for IPv6 is not an equality test
  // at all: one address has many valid spellings and which one arrives is decided by the
  // peer's stack, not by what the operator typed. A monitor that failed to match was not
  // merely un-exempted — it was scored, blocked and (with external enforcement wired)
  // firewalled, silently.
  const forms = ["2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:DB8::0:1", "2001:db8:0:0:0:0:0:1"];

  it("matches every equivalent form, whichever one is configured", () => {
    for (const configured of forms) {
      const allowlist = new IpAllowlist([configured]);
      expect(allowlist.invalid).toEqual([]);
      expect(allowlist.size).toBe(1);
      for (const presented of forms) expect(allowlist.allows(presented)).toBe(true);
    }
  });

  it("still refuses an address that is merely similar", () => {
    const allowlist = new IpAllowlist(["2001:db8::1"]);
    expect(allowlist.allows("2001:db8::2")).toBe(false);
    expect(allowlist.allows("2001:db9::1")).toBe(false);
    expect(allowlist.allows("::1")).toBe(false);
  });

  it("keeps IPv4, v4-mapped and CIDR behaviour unchanged", () => {
    const allowlist = new IpAllowlist(["10.0.0.5", "192.168.0.0/16", "2001:db8:1::/48", "nonsense"]);
    expect(allowlist.invalid).toEqual(["nonsense"]);
    expect(allowlist.allows("10.0.0.5")).toBe(true);
    expect(allowlist.allows("::ffff:10.0.0.5")).toBe(true);
    expect(allowlist.allows("192.168.4.4")).toBe(true);
    expect(allowlist.allows("2001:db8:1:2::9")).toBe(true);
    expect(allowlist.allows("2001:db8:2::9")).toBe(false);
    expect(allowlist.allows("10.0.0.6")).toBe(false);
  });
});

describe("the firewall webhook enforcer bounds each request", () => {
  // `WebhookDispatcher` already carried a per-attempt deadline, with a comment on why
  // `fetch` has no usable timeout of its own. This enforcer did not, so a WAF endpoint
  // that accepted the connection and went quiet held the request open indefinitely —
  // and `maxPerWindow` caps requests *started*, not requests in flight, so each window
  // simply added more hung fetches.
  it("aborts a request that never answers", async () => {
    // Accept, read, and never reply. The classic silently-stalled endpoint.
    const server = await stalledServer((socket) => socket.resume());
    const port = server.port;

    const errors: Error[] = [];
    const enforce = webhookEnforcer({
      url: `http://127.0.0.1:${port}/block`,
      timeoutMs: 300,
      onError: (err) => errors.push(err),
    });

    const started = Date.now();
    await enforce("203.0.113.9", Date.now() + 60_000);
    const elapsed = Date.now() - started;

    expect(errors).toHaveLength(1);
    // Bounded by the deadline, not by whatever undici would eventually decide.
    expect(elapsed).toBeLessThan(5_000);
    await server.close();
  });
});

describe("the syslog TCP sink drops rather than queueing for a stalled collector", () => {
  // "Drop, never queue" only covered a collector that was *down* — no socket, nothing to
  // queue into. A collector that is connected and simply not reading is the more common
  // failure, and there `socket.write()` returns false while Node buffers the message in
  // `writableBuffer` anyway: the queue we refused to keep was being kept for us, in the
  // same process, growing at the rate the attacker chooses.
  it("stops writing once the unflushed backlog passes the ceiling", async () => {
    // Accept the connection and never read a byte, so the send buffer fills.
    const server = await stalledServer((socket) => socket.pause());
    const port = server.port;

    const errors: Error[] = [];
    const sink = new SyslogSink({
      host: "127.0.0.1",
      port,
      protocol: "tcp",
      maxQueuedBytes: 4096,
      // Carry the body so each message reaches the size cap — fewer of them are then
      // needed to fill the kernel's buffers and reach the in-process backlog.
      includeBody: true,
      format: "json",
      onError: (err) => errors.push(err),
    });
    sink.start();
    // Let the connection establish before the flood.
    await new Promise((resolve) => setTimeout(resolve, 100));

    // The kernel's loopback send/receive buffers absorb the first few MB before a write
    // starts backing up in the process, so this pushes until the sink actually refuses —
    // the assertion is that it refuses at all, not how quickly.
    const body = "A".repeat(4096);
    let sent = 0;
    for (; sent < 100_000 && sink.droppedCount === 0; sent += 1) sink.send(hit({ id: `h${sent}`, body }));

    expect(sink.droppedCount).toBeGreaterThan(0);
    // It stopped on the backlog, not after exhausting the loop.
    expect(sent).toBeLessThan(100_000);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]!.message).toContain("not draining");

    await sink.close();
    await server.close();
  }, 30_000);
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
