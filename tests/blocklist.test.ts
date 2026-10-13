import net from "node:net";
import { EventEmitter } from "node:events";
import { describe, expect, it } from "vitest";
import { HoneypotEngine, MemoryBlocklist, blockAction } from "../src/index.js";
import { HoneypotServer } from "../src/adapters/server.js";
import type { Blocklist } from "../src/blocklist.js";

describe("optional shared blocklist", () => {
  function mockRes() {
    const ee = new EventEmitter() as EventEmitter & { statusCode: number; writableEnded: boolean; setHeader(): void; end(): void };
    ee.statusCode = 0; ee.writableEnded = false; ee.setHeader = () => {}; ee.end = () => { ee.writableEnded = true; };
    return ee;
  }

  it("a block on one engine is visible to another sharing the blocklist (opt-in)", async () => {
    const shared = new MemoryBlocklist();
    const a = new HoneypotEngine({ blocklist: shared });
    const b = new HoneypotEngine({ blocklist: shared });

    // Fire the block action as engine A would, against the shared blocklist.
    await blockAction({ durationMs: 60_000 }).execute({
      res: mockRes() as never, detection: { detector: "x", summary: "x", score: 40 }, detections: [], ip: "9.9.9.9", path: "/", totalScore: 40, tracker: {} as never, blocklist: a.blocklist,
    });

    expect(await b.isBlocked("9.9.9.9")).toBe(true); // shared → visible on the other instance
    expect(await b.isBlocked("8.8.8.8")).toBe(false);
  });

  it("the default (no shared blocklist) keeps blocks isolated per instance", async () => {
    const a = new HoneypotEngine();
    const b = new HoneypotEngine();
    await blockAction({ durationMs: 60_000 }).execute({
      res: mockRes() as never, detection: { detector: "x", summary: "x", score: 40 }, detections: [], ip: "9.9.9.9", path: "/", totalScore: 40, tracker: {} as never, blocklist: a.blocklist,
    });
    expect(await a.isBlocked("9.9.9.9")).toBe(true);
    expect(await b.isBlocked("9.9.9.9")).toBe(false); // separate in-memory blocklists
  });
});

describe("the in-memory blocklist is bounded", () => {
  it("stays at or under maxEntries under a flood of distinct live blocks", () => {
    const blocklist = new MemoryBlocklist({ maxEntries: 100 });
    const until = Date.now() + 3_600_000;
    for (let i = 0; i < 5_000; i += 1) blocklist.block(`10.0.${(i >> 8) & 255}.${i & 255}`, until);
    expect(blocklist.size()).toBeLessThanOrEqual(100);
  });

  it("sheds expired entries before live ones", () => {
    const now = Date.now();
    const blocklist = new MemoryBlocklist({ maxEntries: 10 });
    for (let i = 0; i < 9; i += 1) blocklist.block(`10.0.0.${i}`, now - 1_000); // already expired
    blocklist.block("203.0.113.1", now + 3_600_000);
    for (let i = 0; i < 5; i += 1) blocklist.block(`198.51.100.${i}`, now + 3_600_000);
    // The expired nine were free to drop, so the live block survives.
    expect(blocklist.isBlocked("203.0.113.1", now)).toBe(true);
    expect(blocklist.size(now)).toBeLessThanOrEqual(10);
  });

  it("still blocks and expires normally", () => {
    const now = Date.now();
    const blocklist = new MemoryBlocklist();
    blocklist.block("203.0.113.9", now + 1_000);
    expect(blocklist.isBlocked("203.0.113.9", now)).toBe(true);
    expect(blocklist.isBlocked("203.0.113.9", now + 2_000)).toBe(false);
    // A later, longer block extends; a shorter one never shortens.
    blocklist.block("203.0.113.9", now + 10_000);
    blocklist.block("203.0.113.9", now + 5_000);
    expect(blocklist.isBlocked("203.0.113.9", now + 7_000)).toBe(true);
  });
});

describe("a blocklist backend that is down does not change what the attacker sees", () => {
  // `blockAction` awaited `blocklist.block()` and let a rejection propagate. That call
  // reaches a live backend whenever the blocklist is Redis-backed or wraps an external
  // enforcer, so it fails for reasons unrelated to the request — and the result was a
  // 500, which is a honeypot tell: every other response here is a plausible one, so an
  // outage turned every flagged request into a distinctive "you broke something" signal.
  // The failure was also reported nowhere, so blocking could stop working entirely with
  // no signal to the operator.
  const brokenBlocklist: Blocklist = {
    block: async () => {
      throw new Error("backend unreachable");
    },
    isBlocked: () => false,
  };

  it("still answers 403 and reports the failure", async () => {
    const errors: Array<{ source: string; message: string }> = [];
    const server = new HoneypotServer({
      blocklist: brokenBlocklist,
      policy: () => "block",
      onError: (error, context) => errors.push({ source: context.source, message: (error as Error).message }),
    });
    await server.listen(0, "127.0.0.1");
    const port = (server.address() as net.AddressInfo).port;

    const response = await fetch(`http://127.0.0.1:${port}/.env`);
    expect(response.status).toBe(403);
    // Not a 500 — nothing about the response distinguishes a broken backend.
    expect(await response.text()).toBe("Forbidden");
    expect(errors).toEqual([{ source: "blocklist", message: "backend unreachable" }]);

    await server.close();
  });

  it("a working blocklist is unaffected", async () => {
    const blocked: string[] = [];
    const server = new HoneypotServer({
      blocklist: { block: (ip) => void blocked.push(ip), isBlocked: () => false },
      policy: () => "block",
    });
    await server.listen(0, "127.0.0.1");
    const port = (server.address() as net.AddressInfo).port;

    expect((await fetch(`http://127.0.0.1:${port}/.env`)).status).toBe(403);
    expect(blocked).toHaveLength(1);

    await server.close();
  });
});
