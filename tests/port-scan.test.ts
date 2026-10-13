import net from "node:net";
import { describe, expect, it } from "vitest";
import { PortScanSentinel, type PortScanEvent } from "../src/detectors/index.js";
import { ManualClock } from "../src/index.js";

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

describe("port-scan sentinel tracking map is bounded", () => {
  it("evicts least-recently-seen sources past the cap", async () => {
    const clock = new ManualClock(1_000);
    const sentinel = new PortScanSentinel({ ports: [0], maxTrackedIps: 5, clock });
    const remember = (sentinel as unknown as { remember(ip: string, port: number): Set<number> }).remember.bind(sentinel);
    for (let i = 0; i < 500; i += 1) {
      remember(`10.0.0.${i % 256}`, 8022 + (i % 3));
      clock.advance(1);
    }
    expect(sentinel.trackedIps).toBeLessThanOrEqual(5);
  });

  it("forgets sources whose last touch fell outside the retention window", () => {
    const clock = new ManualClock(0);
    const sentinel = new PortScanSentinel({ ports: [0], retentionMs: 1_000, clock });
    const remember = (sentinel as unknown as { remember(ip: string, port: number): Set<number> }).remember.bind(sentinel);
    remember("198.51.100.1", 8022);
    clock.advance(10_000);
    remember("198.51.100.2", 9200);
    expect(sentinel.portsTouchedBy("198.51.100.1")).toBe(0);
    expect(sentinel.portsTouchedBy("198.51.100.2")).toBe(1);
  });
});
