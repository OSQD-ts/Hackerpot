import net from "node:net";
import { describe, expect, it } from "vitest";
import { HoneypotServer } from "../src/server.js";
import { MemoryStore } from "../src/stores/index.js";
import { dripFeedAction, largePayloadAction, tarpitAction } from "../src/responses/index.js";
import type { ResponseAction } from "../src/responses/types.js";
import type { HitStore } from "../src/types.js";

/** A store with a real round-trip, the way Redis or Elasticsearch behave. */
function slowStore(): HitStore {
  const inner = new MemoryStore();
  return {
    record: (hit) => inner.record(hit),
    list: () => inner.list(),
    scoreFor: async (ip) => {
      await new Promise((r) => setTimeout(r, 50));
      return inner.scoreFor(ip);
    },
  };
}

/**
 * Sends one probe that a detector flags, resets the connection while evaluation is still
 * awaiting the store, and reports how long the response action kept its slot.
 */
async function slotHeldAfterEarlyReset(inner: ResponseAction): Promise<number> {
  let resolveHeld!: (ms: number) => void;
  const held = new Promise<number>((r) => (resolveHeld = r));
  const timed: ResponseAction = {
    id: inner.id,
    async execute(ctx) {
      const started = Date.now();
      await inner.execute(ctx);
      resolveHeld(Date.now() - started);
    },
  };
  const server = new HoneypotServer({ store: slowStore(), responseActions: [timed], policy: () => inner.id, enricher: null });
  await server.listen(0, "127.0.0.1");
  const { port } = server.address() as net.AddressInfo;
  try {
    const socket = net.connect(port, "127.0.0.1", () => {
      socket.write("GET /.env HTTP/1.1\r\nHost: target\r\nUser-Agent: curl/8.4.0\r\n\r\n");
      setTimeout(() => socket.resetAndDestroy(), 5);
    });
    socket.on("error", () => undefined);
    return await held;
  } finally {
    await server.close();
  }
}

describe("a connection that is gone before the response action starts holds no slot", () => {
  // The disconnect lands while evaluation awaits the store, so the `close` event has
  // already fired by the time the action would subscribe to it. Waiting on that event
  // then means waiting out the whole delay on a socket that no longer exists.
  it("tarpit returns at once instead of sleeping on a dead socket", async () => {
    const held = await slotHeldAfterEarlyReset(tarpitAction({ delayMs: 5_000, escalate: false }));
    expect(held).toBeLessThan(1_000);
  }, 10_000);

  it("drip-feed returns at once instead of trickling into a dead socket until its deadline", async () => {
    const held = await slotHeldAfterEarlyReset(dripFeedAction({ intervalMs: 50, maxDurationMs: 5_000 }));
    expect(held).toBeLessThan(1_000);
  }, 10_000);

  it("large-payload settles instead of waiting on a drain or close that already happened", async () => {
    const held = await slotHeldAfterEarlyReset(largePayloadAction({ totalBytes: 8 * 1024 * 1024, throttleMs: 20 }));
    expect(held).toBeLessThan(1_000);
  }, 10_000);
});
