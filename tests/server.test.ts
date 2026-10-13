import http from "node:http";
import net from "node:net";
import { describe, expect, it } from "vitest";
import { HoneypotServer } from "../src/index.js";
import { ManagementServer } from "../src/management/server.js";
import { PortScanSentinel } from "../src/detectors/port-scan.js";
import { SmtpHoneypot } from "../src/protocols/smtp/index.js";
import { FtpHoneypot } from "../src/protocols/ftp/index.js";
import { TelnetHoneypot } from "../src/protocols/telnet/index.js";
import { MemoryStore } from "../src/stores/index.js";

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

/**
 * Opens a connection and keeps writing to it, so every *idle* timeout is continuously
 * reset. This is the state a shutdown has to cope with: who holds a socket open is the
 * attacker's choice, and an idle timeout is no bound at all against a client that drips.
 */
async function busyConnection(port: number): Promise<() => void> {
  const socket = net.connect(port, "127.0.0.1");
  await new Promise((resolve) => socket.once("connect", resolve));
  const drip = setInterval(() => {
    if (!socket.destroyed) socket.write("x");
  }, 200);
  await new Promise((resolve) => setTimeout(resolve, 150));
  return () => {
    clearInterval(drip);
    socket.destroy();
  };
}

/**
 * The HTTP equivalent: a request whose headers are begun but never terminated, kept
 * alive by a trickle of further header bytes.
 *
 * Raw junk will not do here — Node's HTTP parser rejects it and closes the socket on
 * its own, so the connection never reaches the mid-request state that `close()` waits
 * on, and the test would pass with or without the fix. This is the slowloris shape the
 * timeouts in `http-hardening.ts` exist for, held open the way a real one is.
 */
async function halfSentRequest(port: number): Promise<() => void> {
  const socket = net.connect(port, "127.0.0.1");
  await new Promise((resolve) => socket.once("connect", resolve));
  socket.write("GET / HTTP/1.1\r\nHost: x\r\n");
  const drip = setInterval(() => {
    if (!socket.destroyed) socket.write("X-Pad: 1\r\n");
  }, 200);
  await new Promise((resolve) => setTimeout(resolve, 150));
  return () => {
    clearInterval(drip);
    socket.destroy();
  };
}

/** Resolves to how long `close()` took, or rejects if it outlives the budget. */
async function closesPromptly(close: () => Promise<void>, budgetMs = 4_000): Promise<string> {
  return Promise.race([
    close().then(() => "closed"),
    new Promise<string>((resolve) => setTimeout(() => resolve("still hanging"), budgetMs)),
  ]);
}

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

describe("a pathological payload does not stall the honeypot end to end", () => {
  it("serves a 16 KB brace body without blocking the event loop", async () => {
    const server = new HoneypotServer({});
    await server.listen(0, "127.0.0.1");
    const address = server.address();
    const port = typeof address === "object" && address !== null ? address.port : 0;

    // A complete, browser-shaped header set: no detector fires, so this measures the cost
    // of *scanning* the payload and not a response action's deliberate delay. (Without
    // these, `scanner-signature` and `client-anomaly` score the request into a tarpit and
    // the timing says nothing about the regex.)
    const headers = {
      "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
      accept: "text/html,application/xhtml+xml",
      "accept-language": "en-US,en;q=0.9",
      "accept-encoding": "gzip, deflate",
    };
    const hit = (body: string): Promise<void> =>
      new Promise((resolve) => {
        const req = http.request({ host: "127.0.0.1", port, path: "/probe", method: "POST", headers }, (res) => {
          res.resume();
          res.on("end", () => resolve());
        });
        req.end(body);
      });

    const evil = "{{".repeat(8192);
    await hit(evil); // warm up
    const started = Date.now();
    await Promise.all(Array.from({ length: 20 }, () => hit(evil)));
    const elapsed = Date.now() - started;
    await server.close();

    // These are serialized on one event loop. Before the fix, 20 requests took ~4s.
    expect(elapsed).toBeLessThan(1500);
  }, 20_000);
});

describe("shutting down does not wait on connections the attacker controls", () => {
  // `server.close()` stops accepting but then waits for every live connection to end.
  // Node ends *idle* keep-alive sockets itself; it does not end a socket mid-request,
  // and the raw TCP listeners were bounded only by idle timeouts that every byte resets
  // — so a client dripping one character kept the port-scan sentinel's shutdown blocked
  // indefinitely. A deploy, a restart or a test teardown then hangs on hostile traffic.

  it("closes the HTTP honeypot with a request in flight", async () => {
    const server = new HoneypotServer({});
    await server.listen(0, "127.0.0.1");
    const release = await halfSentRequest((server.address() as net.AddressInfo).port);
    await expect(closesPromptly(() => server.close())).resolves.toBe("closed");
    release();
  });

  it("closes the management server with a request in flight", async () => {
    const server = new ManagementServer({ store: new MemoryStore(), host: "127.0.0.1", port: 0, apiKeys: ["k"] });
    await server.listen();
    const release = await halfSentRequest((server.address() as net.AddressInfo).port);
    await expect(closesPromptly(() => server.close())).resolves.toBe("closed");
    release();
  });

  it("closes the port-scan sentinel, whose sockets have no lifetime cap at all", async () => {
    const sentinel = new PortScanSentinel({ ports: [0], host: "127.0.0.1" });
    await sentinel.listen();
    const port = (sentinel as unknown as { servers: net.Server[] }).servers[0]!.address() as net.AddressInfo;
    const release = await busyConnection(port.port);
    await expect(closesPromptly(() => sentinel.close())).resolves.toBe("closed");
    release();
  });

  it("closes each protocol emulator", async () => {
    const emulators = [
      ["smtp", new SmtpHoneypot({ host: "127.0.0.1", port: 0 })],
      ["ftp", new FtpHoneypot({ host: "127.0.0.1", port: 0 })],
      ["telnet", new TelnetHoneypot({ host: "127.0.0.1", port: 0 })],
    ] as const;
    for (const [name, emulator] of emulators) {
      await emulator.listen();
      const release = await busyConnection((emulator.address() as net.AddressInfo).port);
      await expect(closesPromptly(() => emulator.close()), name).resolves.toBe("closed");
      release();
    }
  }, 20_000);
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
