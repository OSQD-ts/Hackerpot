import net from "node:net";
import { describe, expect, it } from "vitest";
import { SyslogSink } from "../src/notify/syslog.js";
import type { HoneypotHit } from "../src/types.js";

function hit(overrides: Partial<HoneypotHit> = {}): HoneypotHit {
  return {
    id: overrides.id ?? Math.random().toString(36).slice(2),
    timestamp: overrides.timestamp ?? new Date().toISOString(),
    ip: overrides.ip ?? "203.0.113.7",
    method: "GET",
    path: "/.env",
    headers: {},
    detections: [{ detector: "decoy-path", summary: "probe", score: 10 }],
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
