import http from "node:http";
import { createHmac } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { EnforcingBlocklist, MemoryBlocklist, commandEnforcer, webhookEnforcer } from "../src/index.js";

const dir = mkdtempSync(join(tmpdir(), "hackerpot-fw-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("EnforcingBlocklist", () => {
  it("fires the enforcer on every block and still delegates isBlocked", async () => {
    const calls: Array<{ ip: string; until: number }> = [];
    const bl = new EnforcingBlocklist(new MemoryBlocklist(), (ip, until) => { calls.push({ ip, until }); });

    const until = Date.now() + 60_000;
    await bl.block("203.0.113.7", until);
    expect(calls).toEqual([{ ip: "203.0.113.7", until }]);
    expect(await bl.isBlocked("203.0.113.7")).toBe(true);
    expect(await bl.isBlocked("203.0.113.8")).toBe(false);
  });

  it("never hands a non-IP source to the enforcer (central validation for all enforcers)", async () => {
    const seen: string[] = [];
    const errors: Error[] = [];
    const bl = new EnforcingBlocklist(new MemoryBlocklist(), (ip) => { seen.push(ip); }, (e) => errors.push(e));
    await bl.block("unknown", Date.now() + 1000);      // resolveIp() returns this when there's no address
    await bl.block("203.0.113.1", Date.now() + 1000);
    expect(seen).toEqual(["203.0.113.1"]);             // the non-IP never reached the enforcer
    expect(errors[0]?.message).toContain("non-IP");
    expect(await bl.isBlocked("unknown")).toBe(true);  // base block still recorded
  });

  it("reports enforcement errors instead of throwing (a failing firewall can't break blocking)", async () => {
    const errors: Error[] = [];
    const bl = new EnforcingBlocklist(new MemoryBlocklist(), () => { throw new Error("iptables exploded"); }, (e) => errors.push(e));
    await expect(bl.block("203.0.113.9", Date.now() + 1000)).resolves.toBeUndefined();
    expect(await bl.isBlocked("203.0.113.9")).toBe(true); // block still recorded
    expect(errors[0]?.message).toBe("iptables exploded");
  });
});

describe("commandEnforcer", () => {
  it("runs the command with {ip} substituted (via execFile, no shell)", async () => {
    const script = join(dir, "capture.js");
    const out = join(dir, "captured.txt");
    writeFileSync(script, "require('fs').writeFileSync(process.argv[3], process.argv[2]);");
    const enforce = commandEnforcer({ argv: ["node", script, "{ip}", out] });

    await enforce("198.51.100.5", Date.now() + 1000);
    expect(readFileSync(out, "utf8")).toBe("198.51.100.5");
  });

  it("refuses to run for a non-IP source (no injection surface)", async () => {
    const errors: Error[] = [];
    const out = join(dir, "should-not-exist.txt");
    const enforce = commandEnforcer({ argv: ["node", "-e", "require('fs').writeFileSync('" + out.replace(/\\/g, "\\\\") + "','x')"], onError: (e) => errors.push(e) });

    await enforce("not-an-ip; rm -rf /", Date.now() + 1000);
    expect(errors[0]?.message).toContain("non-IP");
    expect(() => readFileSync(out)).toThrow(); // command never ran
  });

  it("drops spawns beyond the rate cap (fork-bomb guard) — in-process block still holds", async () => {
    const out = join(dir, "spawn-count.txt");
    writeFileSync(out, "");
    const errors: Error[] = [];
    // Each allowed spawn appends a byte; count files to see how many actually ran.
    const enforce = commandEnforcer({
      argv: ["node", "-e", `require('fs').appendFileSync(${JSON.stringify(out)}, 'x')`, "{ip}"],
      maxPerWindow: 2,
      windowMs: 60_000,
      onError: (e) => errors.push(e),
    });

    for (let i = 0; i < 5; i++) await enforce(`203.0.113.${i}`, Date.now() + 1000);
    // give the 2 allowed node processes a moment to write
    await new Promise((r) => setTimeout(r, 300));

    const dropped = errors.filter((e) => e.message.includes("rate limit"));
    expect(dropped).toHaveLength(3);                       // 2 allowed, 3 dropped
    expect(readFileSync(out, "utf8").length).toBeLessThanOrEqual(2); // at most 2 processes spawned
  });
});

describe("webhookEnforcer", () => {
  it("POSTs the block with an HMAC signature", async () => {
    const received: Array<{ sig: string | undefined; body: any }> = [];
    const server = http.createServer((req, res) => {
      let data = "";
      req.on("data", (c) => (data += c));
      req.on("end", () => { received.push({ sig: req.headers["x-hackerpot-signature"] as string | undefined, body: JSON.parse(data) }); res.end("ok"); });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;

    const enforce = webhookEnforcer({ url: `http://127.0.0.1:${port}/block`, secret: "s3cr3t" });
    const until = Date.now() + 900_000;
    await enforce("203.0.113.42", until);

    expect(received).toHaveLength(1);
    expect(received[0]!.body.ip).toBe("203.0.113.42");
    expect(received[0]!.body.type).toBe("block");
    const expected = `sha256=${createHmac("sha256", "s3cr3t").update(JSON.stringify(received[0]!.body)).digest("hex")}`;
    expect(received[0]!.sig).toBe(expected);

    await new Promise<void>((r) => server.close(() => r()));
  });
});
