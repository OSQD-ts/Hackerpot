import { describe, expect, it } from "vitest";
import { createGunzip } from "node:zlib";
import { createReadStream, existsSync, mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { text } from "node:stream/consumers";
import { parse as parseToml } from "smol-toml";
import { FileStore, MemoryStore, RotatingJsonlWriter, ScoreLedger } from "../src/stores/index.js";
import { ActivityRegistry, IpTracker } from "../src/state.js";
import { parseConfig } from "../src/config/schema.js";
import type { HoneypotHit } from "../src/types.js";

const dir = (): string => mkdtempSync(join(tmpdir(), "hackerpot-archive-"));

const hit = (over: Partial<HoneypotHit> = {}): HoneypotHit => ({
  id: "id",
  timestamp: new Date().toISOString(),
  ip: "203.0.113.9",
  method: "GET",
  path: "/.env",
  headers: {},
  detections: [],
  score: 1,
  totalScore: 1,
  respondedWith: "not-found",
  ...over,
});

describe("the hit log rotates instead of filling the disk", () => {
  it("rolls the live file at maxBytes and gzips what it rolled", async () => {
    const path = join(dir(), "hits.jsonl");
    const writer = new RotatingJsonlWriter({ path, maxBytes: 2048, maxArchives: 10 });
    for (let i = 0; i < 200; i += 1) await writer.append(JSON.stringify({ i, pad: "x".repeat(100) }));
    await writer.close();

    const archives = writer.archives();
    expect(archives.length).toBeGreaterThan(0);
    expect(archives.every((f) => f.endsWith(".jsonl.gz"))).toBe(true);
    // The live file was started fresh at the last roll, so it is under the roll point.
    expect(statSync(path).size).toBeLessThanOrEqual(2048 + 200);
  });

  it("keeps the archived records readable and intact", async () => {
    const path = join(dir(), "hits.jsonl");
    const writer = new RotatingJsonlWriter({ path, maxBytes: 1024, maxArchives: 50 });
    for (let i = 0; i < 100; i += 1) await writer.append(JSON.stringify({ i, pad: "y".repeat(80) }));
    await writer.close();

    const seen: number[] = [];
    for (const archive of writer.archives()) {
      const body = await text(createReadStream(archive).pipe(createGunzip()));
      for (const line of body.split("\n")) if (line.trim()) seen.push(JSON.parse(line).i);
    }
    for (const line of readFileSync(path, "utf8").split("\n")) if (line.trim()) seen.push(JSON.parse(line).i);
    // Rotation moves records, it never loses or corrupts them.
    expect(seen.sort((a, b) => a - b)).toEqual(Array.from({ length: 100 }, (_, i) => i));
  });

  it("prunes archives past maxArchives, oldest first", async () => {
    const path = join(dir(), "hits.jsonl");
    const writer = new RotatingJsonlWriter({ path, maxBytes: 512, maxArchives: 3 });
    for (let i = 0; i < 200; i += 1) await writer.append(JSON.stringify({ i, pad: "z".repeat(80) }));
    await writer.close();
    expect(writer.archives().length).toBeLessThanOrEqual(3);
  });

  it("prunes archives past maxAgeMs", async () => {
    const path = join(dir(), "hits.jsonl");
    const writer = new RotatingJsonlWriter({ path, maxBytes: 512, maxArchives: 0, maxAgeMs: 1 });
    for (let i = 0; i < 60; i += 1) await writer.append(JSON.stringify({ i, pad: "q".repeat(80) }));
    await new Promise((r) => setTimeout(r, 20));
    await writer.append(JSON.stringify({ i: "trigger", pad: "q".repeat(600) }));
    await writer.close();
    // Everything rolled before the sleep is older than the 1ms age limit.
    expect(writer.archives().length).toBeLessThanOrEqual(1);
  });

  it("does not rotate when maxBytes is 0", async () => {
    const path = join(dir(), "hits.jsonl");
    const writer = new RotatingJsonlWriter({ path, maxBytes: 0 });
    for (let i = 0; i < 100; i += 1) await writer.append(JSON.stringify({ i, pad: "w".repeat(100) }));
    await writer.close();
    expect(writer.archives()).toEqual([]);
    expect(statSync(path).size).toBeGreaterThan(10_000);
  });

  it("bounds the in-memory write buffer rather than relocating the growth into the heap", () => {
    const path = join(dir(), "hits.jsonl");
    const writer = new RotatingJsonlWriter({ path, maxPendingLines: 10 });
    // Queue far more than the buffer holds without ever yielding, so nothing can flush.
    for (let i = 0; i < 5_000; i += 1) void writer.append(`{"i":${i}}`).catch(() => undefined);
    expect(writer.dropped).toBeGreaterThan(0);
    void writer.close();
  });
});

describe("the file store writes without blocking the event loop", () => {
  it("record() resolves only once the line is durable", async () => {
    const path = join(dir(), "hits.jsonl");
    const store = new FileStore({ path });
    await store.record(hit({ id: "a" }));
    await store.record(hit({ id: "b" }));
    expect(store.list().map((h) => h.id)).toEqual(["a", "b"]);
    await store.close();
  });

  it("leaves the event loop responsive while recording a burst", async () => {
    const path = join(dir(), "hits.jsonl");
    const store = new FileStore({ path });

    // A timer scheduled for ~0ms measures how long the loop was unavailable. With
    // appendFileSync the writes ran to completion before any timer could fire.
    let ticks = 0;
    const interval = setInterval(() => (ticks += 1), 1);
    await Promise.all(Array.from({ length: 500 }, (_, i) => store.record(hit({ id: `n${i}` }))));
    clearInterval(interval);
    await store.close();

    expect(ticks).toBeGreaterThan(0);
    expect(store.list()).toHaveLength(500);
  });

  it("rotates through the store and still serves reads from the live segment", async () => {
    const path = join(dir(), "hits.jsonl");
    const store = new FileStore({ path, maxBytes: 4096, maxArchives: 5 });
    for (let i = 0; i < 300; i += 1) await store.record(hit({ id: `r${i}`, body: "p".repeat(200) }));
    await store.close();

    expect(store.archives().length).toBeGreaterThan(0);
    const live = store.list();
    expect(live.length).toBeGreaterThan(0);
    // Reads are bounded by the live segment, and the newest record is always in it.
    expect(live[live.length - 1]!.id).toBe("r299");
  });

  it("flushes buffered writes on close", async () => {
    const path = join(dir(), "hits.jsonl");
    const store = new FileStore({ path });
    void store.record(hit({ id: "unflushed" }));
    await store.close();
    expect(readFileSync(path, "utf8")).toContain("unflushed");
  });
});

describe("per-IP score caches are bounded", () => {
  it("evicts least-recently-updated, never the IP under active attack", () => {
    const ledger = new ScoreLedger(100);
    ledger.add("203.0.113.1", 10);
    for (let i = 0; i < 5_000; i += 1) {
      ledger.add(`10.0.${(i >> 8) & 255}.${i & 255}`, 1);
      // The attacker keeps scoring, so it keeps being refreshed to the newest position.
      if (i % 10 === 0) ledger.add("203.0.113.1", 1);
    }
    expect(ledger.size).toBeLessThanOrEqual(100);
    expect(ledger.get("203.0.113.1")).toBeGreaterThan(10);
  });

  it("bounds MemoryStore scores under a flood of distinct sources", () => {
    const store = new MemoryStore({ maxHits: 10, maxScoreEntries: 50 });
    for (let i = 0; i < 2_000; i += 1) store.record(hit({ ip: `10.1.${(i >> 8) & 255}.${i & 255}` }));
    expect(store.scoreFor("10.1.7.208")).toBeGreaterThanOrEqual(0);
    // Nothing observable broke; the cap is what the ledger test asserts directly.
    expect(store.list().length).toBeLessThanOrEqual(10);
  });

  it("keeps an attacker's accrued score across rotation AND restart", async () => {
    // Rotation empties the live segment, and replay reads the live segment — so without
    // a checkpoint an unrelated restart would hand a long-running attacker a clean
    // slate, which is what the block threshold is measured against.
    const path = join(dir(), "hits.jsonl");
    const store = new FileStore({ path, maxBytes: 2048, maxArchives: 20 });
    for (let i = 0; i < 200; i += 1) await store.record(hit({ ip: "203.0.113.66", score: 3, body: "d".repeat(150) }));
    expect(store.archives().length).toBeGreaterThan(0);
    expect(store.scoreFor("203.0.113.66")).toBe(600);
    await store.close();

    const reopened = new FileStore({ path, maxBytes: 2048, maxArchives: 20 });
    expect(reopened.scoreFor("203.0.113.66")).toBe(600);
    await reopened.close();
  });

  it("does not double-count the live segment on top of the checkpoint", async () => {
    const path = join(dir(), "hits.jsonl");
    const store = new FileStore({ path, maxBytes: 1024, maxArchives: 20 });
    // Enough to roll several times, then a tail that stays in the live segment.
    for (let i = 0; i < 60; i += 1) await store.record(hit({ ip: "198.51.100.9", score: 2, body: "e".repeat(120) }));
    await store.close();

    const reopened = new FileStore({ path, maxBytes: 1024, maxArchives: 20 });
    expect(reopened.scoreFor("198.51.100.9")).toBe(120);
    await reopened.close();
  });

  it("starts clean when load_on_start is off", async () => {
    const path = join(dir(), "hits.jsonl");
    const store = new FileStore({ path, maxBytes: 1024 });
    for (let i = 0; i < 40; i += 1) await store.record(hit({ ip: "203.0.113.77", score: 5, body: "f".repeat(120) }));
    await store.close();
    const reopened = new FileStore({ path, loadOnStart: false });
    expect(reopened.scoreFor("203.0.113.77")).toBe(0);
    await reopened.close();
  });

  it("still accumulates and reports a score normally", async () => {
    const path = join(dir(), "hits.jsonl");
    const store = new FileStore({ path });
    await store.record(hit({ ip: "198.51.100.3", score: 7 }));
    await store.record(hit({ ip: "198.51.100.3", score: 5 }));
    expect(store.scoreFor("198.51.100.3")).toBe(12);
    await store.close();
  });
});

describe("per-IP activity windows are bounded", () => {
  it("caps retained events per IP", () => {
    const tracker = new IpTracker("203.0.113.4", 60_000, 100);
    for (let i = 0; i < 10_000; i += 1) tracker.record({ method: "GET", path: `/p${i}`, status: "seen" });
    expect(tracker.recent().length).toBeLessThanOrEqual(100);
  });

  it("truncates the attacker-controlled path instead of retaining it whole", () => {
    const tracker = new IpTracker("203.0.113.4", 60_000);
    tracker.record({ method: "GET", path: `/${"a".repeat(16_000)}`, status: "seen" });
    expect(tracker.recent()[0]!.path.length).toBeLessThanOrEqual(512);
  });

  it("keeps counts saturating above every detector threshold, so no decision changes", () => {
    // The cap is safe precisely because consumers ask `count >= threshold`. At 4096 the
    // count still clears any default threshold (the largest is rate-spike's 60).
    const tracker = new IpTracker("203.0.113.4", 60_000, 4096);
    for (let i = 0; i < 50_000; i += 1) tracker.record({ method: "GET", path: "/login", status: "seen" });
    expect(tracker.countIn(60_000)).toBeGreaterThanOrEqual(60);
    expect(tracker.countPathIn("/login", 60_000)).toBeGreaterThanOrEqual(60);
  });

  it("still distinguishes paths for enumeration detection", () => {
    const tracker = new IpTracker("203.0.113.4", 60_000);
    for (let i = 0; i < 40; i += 1) tracker.record({ method: "GET", path: `/admin${i}`, status: "seen" });
    expect(tracker.uniquePathsIn(30_000)).toBe(40);
  });

  it("registry hands its cap down to the trackers it creates", () => {
    const registry = new ActivityRegistry(60_000, 10_000, 25);
    const tracker = registry.for("203.0.113.7");
    for (let i = 0; i < 1_000; i += 1) tracker.record({ method: "GET", path: "/x", status: "seen" });
    expect(tracker.recent().length).toBeLessThanOrEqual(25);
  });
});

describe("the rotation config refuses settings that cannot do what they say", () => {
  it("rejects archives requested with rotation disabled", () => {
    expect(() =>
      parseConfig({ store: { file: { path: "/tmp/h.jsonl", max_bytes: 0, max_archives: 5 } } }, "<test>"),
    ).toThrow(/rotation disabled/);
  });

  it("accepts rotation disabled when archives are disabled too", () => {
    const config = parseConfig({ store: { file: { path: "/tmp/h.jsonl", max_bytes: 0, max_archives: 0 } } }, "<test>");
    expect(config.store.file.maxBytes).toBe(0);
  });

  it("rejects a zero score cache, which would stop anything ever being blocked", () => {
    expect(() => parseConfig({ store: { file: { path: "/tmp/h.jsonl", max_score_entries: 0 } } }, "<test>")).toThrow(/max_score_entries/);
    expect(() => parseConfig({ store: { memory: { max_score_entries: 0 } } }, "<test>")).toThrow(/max_score_entries/);
  });

  it("defaults to rotating at 128 MB keeping 10 compressed archives", () => {
    const config = parseConfig({}, "<test>");
    expect(config.store.file.maxBytes).toBe(134_217_728);
    expect(config.store.file.maxArchives).toBe(10);
    expect(config.store.file.compressArchives).toBe(true);
    expect(config.store.file.maxScoreEntries).toBe(100_000);
  });
});

describe("the shipped hackerpot.toml stays valid", () => {
  it("parses, and its documented rotation keys are the ones the schema reads", () => {
    // The reader rejects unknown keys, so this also catches a documented-but-misspelled
    // option in the shipped config — silently leaving the default in place is the worst
    // failure mode for a retention setting.
    const config = parseConfig(parseToml(readFileSync("hackerpot.toml", "utf8")) as Record<string, unknown>, "hackerpot.toml");
    expect(config.store.file.maxBytes).toBe(134_217_728);
    expect(config.store.file.maxArchives).toBe(10);
    expect(config.store.file.compressArchives).toBe(true);
    expect(config.store.file.maxScoreEntries).toBe(100_000);
    expect(config.store.memory.maxScoreEntries).toBe(100_000);
  });
});

describe("archive names survive rotations inside the same millisecond", () => {
  // The archive name is the roll time, and `toISOString()` resolves to milliseconds, so
  // two rolls in the same millisecond produced the same name and `renameSync` silently
  // overwrote the earlier archive — whole segments of captured evidence destroyed, with
  // nothing logged. Rotation frequency follows write volume, which follows the attack,
  // so the attacker sets the rate. Measured before the fix: 12 of 12 runs lost records,
  // 462 in total. The pre-existing "readable and intact" test caught it only
  // intermittently, because it depends on how fast the writes happen to land.
  it("loses nothing across many fast rotations", async () => {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const path = join(dir(), "hits.jsonl");
      const writer = new RotatingJsonlWriter({ path, maxBytes: 512, maxArchives: 100 });
      for (let i = 0; i < 120; i += 1) await writer.append(JSON.stringify({ i, pad: "z".repeat(60) }));
      await writer.close();

      const seen: number[] = [];
      for (const archive of writer.archives()) {
        const body = await text(createReadStream(archive).pipe(createGunzip()));
        for (const line of body.split("\n")) if (line.trim()) seen.push(JSON.parse(line).i);
      }
      for (const line of readFileSync(path, "utf8").split("\n")) if (line.trim()) seen.push(JSON.parse(line).i);

      expect(seen.sort((a, b) => a - b), `attempt ${attempt}`).toEqual(Array.from({ length: 120 }, (_, i) => i));
    }
  }, 20_000);

  it("gives every archive a distinct path, and still recognizes them all", async () => {
    const path = join(dir(), "hits.jsonl");
    const writer = new RotatingJsonlWriter({ path, maxBytes: 256, maxArchives: 100 });
    for (let i = 0; i < 60; i += 1) await writer.append(JSON.stringify({ i, pad: "q".repeat(40) }));
    await writer.close();

    const archives = writer.archives();
    expect(archives.length).toBeGreaterThan(1);
    // Every rolled segment is still discoverable — a discriminator must not fall
    // outside the pattern `archives()` filters on, or pruning would stop seeing it.
    expect(new Set(archives).size).toBe(archives.length);
    for (const archive of archives) expect(existsSync(archive)).toBe(true);
  }, 15_000);
});
