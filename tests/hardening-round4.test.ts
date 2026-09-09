import net from "node:net";
import { describe, expect, it } from "vitest";
import { formatTextLine } from "../src/logfmt.js";
import { HoneypotServer } from "../src/server.js";
import { ManagementServer } from "../src/management/server.js";
import { PortScanSentinel } from "../src/detectors/port-scan.js";
import { SmtpHoneypot } from "../src/smtp/index.js";
import { FtpHoneypot } from "../src/ftp/index.js";
import { TelnetHoneypot } from "../src/telnet/index.js";
import { MemoryStore } from "../src/stores/index.js";
import { parseConfig } from "../src/config/schema.js";

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

describe("the SMTP emulator caps a session's total lifetime", () => {
  // SSH, FTP and Telnet all carry this cap and document why; SMTP had only the 30s idle
  // timeout, which every byte resets. A client dripping one character every 20 seconds
  // held its slot forever, and with 256 slots a few hundred of them take the SMTP
  // honeypot offline without ever completing a transaction.
  it("drops a connection that stays busy past max_session_ms", async () => {
    const honeypot = new SmtpHoneypot({ host: "127.0.0.1", port: 0, maxSessionMs: 300 });
    await honeypot.listen();
    const port = (honeypot.address() as net.AddressInfo).port;

    const socket = net.connect(port, "127.0.0.1");
    await new Promise((resolve) => socket.once("connect", resolve));
    await new Promise((resolve) => socket.once("data", resolve)); // the 220 greeting
    // Drip well inside the idle timeout: only a lifetime cap can end this.
    const drip = setInterval(() => {
      if (!socket.destroyed) socket.write("X");
    }, 50);

    const outcome = await Promise.race([
      new Promise<string>((resolve) => socket.once("close", () => resolve("closed by server"))),
      new Promise<string>((resolve) => setTimeout(() => resolve("held open"), 2_500)),
    ]);
    clearInterval(drip);
    socket.destroy();
    await honeypot.close();

    expect(outcome).toBe("closed by server");
  });

  it("refuses an uncapped session in config, as its siblings already do", () => {
    expect(parseConfig({}, "<defaults>").smtp.maxSessionMs).toBeGreaterThan(0);
    expect(() => parseConfig({ smtp: { max_session_ms: 0 } }, "<test>")).toThrow(/max_session_ms/);
  });
});

describe("every field of a text log line is escaped, including the timestamp", () => {
  // `formatValue` exists because log values are attacker-controlled and a newline in one
  // would end the line and let the rest be read as further entries. `ts` was the single
  // field interpolated raw — and `SyslogSink` fills it from a *stored* record, which this
  // codebase already treats as something a foreign writer may have touched.
  it("does not let a timestamp break the line", () => {
    const line = formatTextLine({ ts: "2026-01-01\nkind=hit ip=9.9.9.9", kind: "hit" });
    expect(line.split(/\r|\n/)).toHaveLength(1);
  });

  it("still renders an ordinary timestamp readably", () => {
    expect(formatTextLine({ ts: "2026-01-01T00:00:00.000Z", kind: "hit" })).toBe("[2026-01-01T00:00:00.000Z] kind=hit");
  });
});
