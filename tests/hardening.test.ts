import net from "node:net";
import { EventEmitter } from "node:events";
import { describe, expect, it } from "vitest";
import { HoneypotEngine, MemoryBlocklist, SmtpHoneypot, blockAction, tarpitAction } from "../src/index.js";
import type { RequestFacts, ResponseContext } from "../src/index.js";

const facts = (p: Partial<RequestFacts> & Pick<RequestFacts, "path">): RequestFacts => ({ method: "GET", query: {}, headers: { host: "x", "user-agent": "m" }, ip: "1.2.3.4", ...p });

describe("ReDoS resistance", () => {
  it("stays fast on adversarial inputs across every detector", async () => {
    const engine = new HoneypotEngine();
    const big = "a".repeat(60000);
    const cases: RequestFacts[] = [
      facts({ path: "/x", query: { q: `{{${big}` } }), // template-injection
      facts({ path: "/x", query: { q: `union${" ".repeat(60000)}` } }), // sql-injection
      facts({ path: `/uploads/${big}` }), // web-shell
      facts({ path: `/${big}.bak` }), // sensitive-file
      facts({ path: "/x", query: { url: `http://${big}` } }), // ssrf
      facts({ path: "/x", query: { redirect: `//${big}` } }), // open-redirect
      facts({ path: "/x", headers: { host: "x", "user-agent": big } }), // scanner-signature
      facts({ method: "POST", path: "/x", body: `{{${big}` }), // body scanning
    ];
    for (const f of cases) {
      const t = performance.now();
      await engine.evaluate(f);
      // A loose absolute bound on purpose: real catastrophic backtracking is orders
      // of magnitude (seconds+), so 500ms catches it with room to spare while never
      // flaking on a loaded box — a ReDoS guard that cries wolf under CI load is one
      // that gets muted. Typical run here is single-digit ms.
      expect(performance.now() - t, `slow on ${f.path}`).toBeLessThan(500);
    }
  });
});

describe("holding-response concurrency cap", () => {
  function mockRes(): EventEmitter & { statusCode: number; writableEnded: boolean; setHeader(): void; end(): void; write(): boolean } {
    const ee = new EventEmitter() as EventEmitter & { statusCode: number; writableEnded: boolean; setHeader(): void; end(): void; write(): boolean };
    ee.statusCode = 0;
    ee.writableEnded = false;
    ee.setHeader = () => {};
    ee.end = () => { ee.writableEnded = true; };
    ee.write = () => true;
    return ee;
  }
  const ctx = (res: ReturnType<typeof mockRes>): ResponseContext => ({ res: res as never, detection: { detectorId: "x", reason: "x", score: 1 }, detections: [], ip: "1.2.3.4", path: "/", totalScore: 1, tracker: {} as never, blocklist: new MemoryBlocklist() });

  it("tarpit answers immediately once maxConcurrent is reached instead of holding another socket", async () => {
    // Wide separation between "held" (1000ms) and "immediate" (bound 300ms) so the
    // distinction survives load — the immediate path is a synchronous end(), so 300ms
    // is enormous headroom, not a tight race.
    const heldMs = 1000;
    const action = tarpitAction({ maxConcurrent: 1, delayMs: heldMs, escalate: false });

    const held = mockRes();
    const p1 = action.execute(ctx(held)); // occupies the single slot for ~1000ms
    await new Promise((r) => setTimeout(r, 20));

    const overflow = mockRes();
    const t = performance.now();
    await action.execute(ctx(overflow)); // over capacity → immediate
    const elapsed = performance.now() - t;
    expect(elapsed).toBeLessThan(300);       // absolute headroom for a sync response
    expect(elapsed).toBeLessThan(heldMs / 2); // and unmistakably not held for the delay
    expect(overflow.writableEnded).toBe(true);

    await p1; // let the held one drain
  });
});

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
      res: mockRes() as never, detection: { detectorId: "x", reason: "x", score: 40 }, detections: [], ip: "9.9.9.9", path: "/", totalScore: 40, tracker: {} as never, blocklist: a.blocklist,
    });

    expect(await b.isBlocked("9.9.9.9")).toBe(true); // shared → visible on the other instance
    expect(await b.isBlocked("8.8.8.8")).toBe(false);
  });

  it("the default (no shared blocklist) keeps blocks isolated per instance", async () => {
    const a = new HoneypotEngine();
    const b = new HoneypotEngine();
    await blockAction({ durationMs: 60_000 }).execute({
      res: mockRes() as never, detection: { detectorId: "x", reason: "x", score: 40 }, detections: [], ip: "9.9.9.9", path: "/", totalScore: 40, tracker: {} as never, blocklist: a.blocklist,
    });
    expect(await a.isBlocked("9.9.9.9")).toBe(true);
    expect(await b.isBlocked("9.9.9.9")).toBe(false); // separate in-memory blocklists
  });
});

describe("SMTP connection cap", () => {
  it("refuses connections past maxConnections", async () => {
    const smtp = new SmtpHoneypot({ port: 0, maxConnections: 1 });
    await smtp.listen();
    const port = (smtp.address() as { port: number }).port;

    // First connection: read the greeting and hold it open.
    const c1 = net.createConnection(port);
    await new Promise<void>((resolve) => c1.once("data", () => resolve()));

    // Second connection while the first is still open: must be refused.
    const c2 = net.createConnection(port);
    const banner = await new Promise<string>((resolve) => c2.once("data", (d) => resolve(d.toString())));
    expect(banner).toContain("421");

    c1.destroy();
    c2.destroy();
    await smtp.close();
  });
});
