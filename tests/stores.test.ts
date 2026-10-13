import { mkdtempSync, readFileSync, rmSync, appendFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, afterEach } from "vitest";
import { HoneypotEngine, FileStore, CompositeStore, MemoryStore, sensitiveFileDetector } from "../src/index.js";
import { applyEnvOverrides } from "../src/config/env.js";
import { parseConfig } from "../src/config/schema.js";
import { MAX_BODY_BYTES } from "../src/internal/http.js";
import { facts } from "./helpers.js";

/** Every file store a test opens, closed after it so no file handle is left for the collector. */
const opened: FileStore[] = [];
function fileStore(options: ConstructorParameters<typeof FileStore>[0]): FileStore {
  const store = new FileStore(options);
  opened.push(store);
  return store;
}
afterEach(async () => {
  await Promise.all(opened.splice(0).map((store) => store.close()));
});

describe("stores", () => {
  const dir = mkdtempSync(join(tmpdir(), "hackerpot-store-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("FileStore persists hits and rebuilds scores on reload", async () => {
    const path = join(dir, "hits.jsonl");
    const engine = new HoneypotEngine({ store: fileStore({ path }), detectors: [sensitiveFileDetector()] });
    await engine.evaluate(facts({ path: "/secret.sql", ip: "9.9.9.9" }));
    await engine.evaluate(facts({ path: "/backup.zip", ip: "9.9.9.9" }));

    expect(readFileSync(path, "utf8").trim().split("\n")).toHaveLength(2);

    // A fresh store over the same file replays the score.
    const reopened = fileStore({ path });
    expect(reopened.scoreFor("9.9.9.9")).toBeGreaterThan(0);
    expect(reopened.list()).toHaveLength(2);
  });

  it("CompositeStore fans out to every store and reads from the primary", async () => {
    const primary = new MemoryStore();
    const path = join(dir, "audit.jsonl");
    const audit = fileStore({ path });
    const engine = new HoneypotEngine({ store: new CompositeStore(primary, audit), detectors: [sensitiveFileDetector()] });

    await engine.evaluate(facts({ path: "/dump.sql", ip: "8.8.8.8" }));
    expect(primary.scoreFor("8.8.8.8")).toBeGreaterThan(0);
    expect(audit.list()).toHaveLength(1); // durably logged too
  });
});

describe("FileStore reads survive a damaged line", () => {
  // `record()` is awaited: writes are batched and asynchronous now (a synchronous
  // append blocked the event loop on the request path), so durability is what the
  // returned promise settles on. Every production caller already awaits it.
  it("returns the intact hits instead of throwing", async () => {
    const path = join(mkdtempSync(join(tmpdir(), "hackerpot-")), "hits.jsonl");
    const store = fileStore({ path });
    await store.record({
      id: "a",
      timestamp: new Date().toISOString(),
      ip: "198.51.100.1",
      method: "GET",
      path: "/.env",
      headers: {},
      detections: [{ detector: "decoy-path", summary: "probe", score: 10 }],
      score: 10,
      totalScore: 10,
      respondedWith: "decoy-content",
    });
    appendFileSync(path, '{"id":"truncated","ip":"198.5\n');

    expect(() => store.list()).not.toThrow();
    expect(store.list()).toHaveLength(1);
  });
});

describe("the file store never loads an attacker-grown file whole", () => {
  const write = (lines: string[]): string => {
    const path = join(mkdtempSync(join(tmpdir(), "hackerpot-file-")), "hits.jsonl");
    writeFileSync(path, lines.map((l) => `${l}\n`).join(""));
    return path;
  };
  const hit = (ip: string, score: number, id: string): string =>
    JSON.stringify({ id, timestamp: new Date().toISOString(), ip, method: "GET", path: "/x", headers: {}, detections: [], score, totalScore: score, respondedWith: "not-found" });

  it("reads only the newest records once the file exceeds maxReadBytes", () => {
    const path = write(Array.from({ length: 400 }, (_, i) => hit(`10.0.0.${i % 255}`, 1, `id-${i}`)));
    const store = fileStore({ path, maxReadBytes: 4096, loadOnStart: false });
    const hits = store.list();
    expect(store.truncated).toBe(true);
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.length).toBeLessThan(400);
    // Newest survive; no partial leading record slipped through as a parsed row.
    expect(hits[hits.length - 1]!.id).toBe("id-399");
    expect(hits.every((h) => typeof h.ip === "string" && typeof h.score === "number")).toBe(true);
  });

  it("returns everything, untruncated, when the file fits", () => {
    const path = write([hit("10.0.0.1", 3, "a"), hit("10.0.0.2", 4, "b")]);
    const store = fileStore({ path, loadOnStart: false });
    expect(store.list().map((h) => h.id)).toEqual(["a", "b"]);
    expect(store.truncated).toBe(false);
  });

  it("replays complete scores at startup even for a large file", () => {
    const path = write(Array.from({ length: 400 }, () => hit("203.0.113.5", 2, "x")));
    // maxReadBytes bounds reads, but scores must still reflect every record.
    const store = fileStore({ path, maxReadBytes: 4096 });
    expect(store.scoreFor("203.0.113.5")).toBe(800);
  });

  it("still skips corrupt lines instead of failing the read", () => {
    const path = write([hit("10.0.0.1", 1, "a"), "{not json", hit("10.0.0.2", 1, "b")]);
    const store = fileStore({ path, loadOnStart: false });
    expect(store.list().map((h) => h.id)).toEqual(["a", "b"]);
  });

  it("does not buffer a file that contains no newline at all", () => {
    const path = join(mkdtempSync(join(tmpdir(), "hackerpot-file-")), "hits.jsonl");
    writeFileSync(path, "x".repeat(9 * 1024 * 1024));
    const store = fileStore({ path, loadOnStart: false });
    expect(store.list()).toEqual([]);
  });
});

describe("Redis hit retention is bounded by what the deployment can hold", () => {
  // The Redis hit log is one list holding whole incidents, captured body included, so
  // its worst case is max_hits x the 64 KB body cap — ~630 MB at the 10000 default,
  // against the 256 MB the shipped compose file gives Redis. An attacker reaches that by
  // doing the thing a honeypot invites, and the container is OOM-killed and restarted
  // empty: every accrued score and active block gone. A maxmemory-policy is no help
  // because the list is a single key, so LRU drops the small score/block keys first.
  it("exposes retention as an environment override", () => {
    const config = applyEnvOverrides(parseConfig({}, "<defaults>"), { REDIS_URL: "redis://r:6379", REDIS_MAX_HITS: "1500" });
    expect(config.store.redis.maxHits).toBe(1500);
    expect(config.store.redis.enabled).toBe(true);
  });

  it("the shipped compose file sets a retention that fits its own memory limit", () => {
    const compose = readFileSync(new URL("../docker-compose.yml", import.meta.url), "utf8");
    const retention = /REDIS_MAX_HITS:\s*"(\d+)"/.exec(compose);
    const memLimit = /redis:[\s\S]*?mem_limit:\s*(\d+)m/.exec(compose);
    expect(retention, "docker-compose.yml must pin REDIS_MAX_HITS").not.toBeNull();
    expect(memLimit, "the redis service must keep a mem_limit").not.toBeNull();

    const worstCaseBytes = Number(retention![1]) * MAX_BODY_BYTES;
    const limitBytes = Number(memLimit![1]) * 1024 * 1024;
    // Leave headroom for the score and block keys living beside the list.
    expect(worstCaseBytes).toBeLessThan(limitBytes * 0.6);
  });
});
