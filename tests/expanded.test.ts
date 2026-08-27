import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
  HoneypotEngine,
  FileStore,
  CompositeStore,
  MemoryStore,
  honeytokenDetector,
  sensitiveFileDetector,
  headerAnomalyDetector,
} from "../src/index.js";
import type { RequestFacts } from "../src/index.js";

function facts(partial: Partial<RequestFacts> & Pick<RequestFacts, "path">): RequestFacts {
  return { method: "GET", query: {}, headers: {}, ip: "10.0.0.1", ...partial };
}

describe("new detectors", () => {
  it("honeytoken detector flags a seeded token replayed in a header", async () => {
    const engine = new HoneypotEngine({
      detectors: [honeytokenDetector({ tokens: [{ value: "AKIAI_HONEY_TOKEN_123", label: "fake-aws-key" }] })],
    });
    const clean = await engine.evaluate(facts({ path: "/", headers: { authorization: "Bearer real" } }));
    expect(clean.detections).toHaveLength(0);

    const tripped = await engine.evaluate(facts({ path: "/api", headers: { authorization: "AKIAI_HONEY_TOKEN_123" }, ip: "10.0.0.2" }));
    expect(tripped.detections[0]?.detectorId).toBe("honeytoken");
    expect(tripped.detections[0]?.metadata?.["label"]).toBe("fake-aws-key");
  });

  it("sensitive-file detector flags backup and dump file requests", async () => {
    const engine = new HoneypotEngine({ detectors: [sensitiveFileDetector()] });
    for (const path of ["/wp-config.php.bak", "/index.php~", "/db.sql", "/.svn/entries", "/backup.tar.gz"]) {
      const r = await engine.evaluate(facts({ path, ip: `1.1.1.${path.length}` }));
      expect(r.detections[0]?.detectorId, path).toBe("sensitive-file");
    }
    const ok = await engine.evaluate(facts({ path: "/assets/app.js", ip: "1.1.1.99" }));
    expect(ok.detections).toHaveLength(0);
  });

  it("header-anomaly detector flags smuggling, shellshock and absolute-URI", async () => {
    const engine = new HoneypotEngine({ detectors: [headerAnomalyDetector()] });

    const smuggle = await engine.evaluate(facts({ method: "POST", path: "/", headers: { "content-length": "5", "transfer-encoding": "chunked" }, ip: "2.2.2.1" }));
    expect(smuggle.detections[0]?.metadata?.["kind"]).toBe("smuggling");

    const shell = await engine.evaluate(facts({ path: "/", headers: { "user-agent": "() { :; }; echo vuln", host: "x" }, ip: "2.2.2.2" }));
    expect(shell.detections[0]?.metadata?.["kind"]).toBe("shellshock");

    const proxy = await engine.evaluate(facts({ path: "http://evil.example/", headers: { host: "x" }, ip: "2.2.2.3" }));
    expect(proxy.detections[0]?.metadata?.["kind"]).toBe("absolute-uri");
  });
});

describe("reconfigure (hot reload)", () => {
  it("swaps detectors/policy/allowlist in place while preserving accrued scores and blocks", async () => {
    const engine = new HoneypotEngine({ detectors: [sensitiveFileDetector()] });
    // Accrue some suspicion and a block under the old config.
    await engine.evaluate(facts({ path: "/dump.sql", ip: "7.7.7.7" }));
    await engine.blocklist.block("7.7.7.7", Date.now() + 3_600_000);
    const scoreBefore = await engine.scoreFor("7.7.7.7");
    expect(scoreBefore).toBeGreaterThan(0);

    // Reload: a different detector set + a new allowlist. Store/blocklist untouched.
    engine.reconfigure({
      detectors: [headerAnomalyDetector()],
      allowlist: ["5.5.5.0/24"],
    });

    // Live state survived the swap.
    expect(await engine.scoreFor("7.7.7.7")).toBe(scoreBefore);
    expect(await engine.isBlocked("7.7.7.7")).toBe(true);

    // The old detector is gone; a /secret.sql probe no longer trips sensitive-file.
    const after = await engine.evaluate(facts({ path: "/secret.sql", ip: "6.6.6.6" }));
    expect(after.detections.map((d) => d.detectorId)).not.toContain("sensitive-file");
    // The new allowlist is in force.
    expect(engine.isAllowlisted("5.5.5.42")).toBe(true);
  });

  it("only replaces the fields provided", async () => {
    const engine = new HoneypotEngine({ detectors: [sensitiveFileDetector()] });
    const before = engine.policy;
    engine.reconfigure({ allowlist: ["1.2.3.4"] });
    expect(engine.policy).toBe(before); // untouched
    expect(engine.detectors[0]?.id).toBe("sensitive-file"); // untouched
    expect(engine.isAllowlisted("1.2.3.4")).toBe(true); // applied
  });
});

describe("stores", () => {
  const dir = mkdtempSync(join(tmpdir(), "hackerpot-store-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("FileStore persists hits and rebuilds scores on reload", async () => {
    const path = join(dir, "hits.jsonl");
    const engine = new HoneypotEngine({ store: new FileStore({ path }), detectors: [sensitiveFileDetector()] });
    await engine.evaluate(facts({ path: "/secret.sql", ip: "9.9.9.9" }));
    await engine.evaluate(facts({ path: "/backup.zip", ip: "9.9.9.9" }));

    expect(readFileSync(path, "utf8").trim().split("\n")).toHaveLength(2);

    // A fresh store over the same file replays the score.
    const reopened = new FileStore({ path });
    expect(reopened.scoreFor("9.9.9.9")).toBeGreaterThan(0);
    expect(reopened.list()).toHaveLength(2);
  });

  it("CompositeStore fans out to every store and reads from the primary", async () => {
    const primary = new MemoryStore();
    const path = join(dir, "audit.jsonl");
    const audit = new FileStore({ path });
    const engine = new HoneypotEngine({ store: new CompositeStore(primary, audit), detectors: [sensitiveFileDetector()] });

    await engine.evaluate(facts({ path: "/dump.sql", ip: "8.8.8.8" }));
    expect(primary.scoreFor("8.8.8.8")).toBeGreaterThan(0);
    expect(audit.list()).toHaveLength(1); // durably logged too
  });
});
