import { describe, expect, it, vi } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CompositeStore, FileStore, MemoryStore, RedisStore, ElasticStore } from "../src/stores/index.js";
import { applyQuery } from "../src/stores/query.js";
import { listIncidents } from "../src/management/index.js";
import type { HitQuery, HitStore, HoneypotHit } from "../src/index.js";

/** A corpus with enough variety that every filter dimension actually discriminates. */
function corpus(): HoneypotHit[] {
  const hits: HoneypotHit[] = [];
  for (let i = 0; i < 40; i += 1) {
    const ip = `203.0.113.${(i % 4) + 1}`;
    const detector = i % 3 === 0 ? "decoy-path" : i % 3 === 1 ? "payload-injection" : "rate-spike";
    hits.push({
      id: `hit-${i}`,
      // One minute apart, so `sinceMs` has real boundaries to land on.
      timestamp: new Date(Date.UTC(2026, 7, 27, 10, i)).toISOString(),
      ip,
      method: "GET",
      path: `/probe/${i}`,
      headers: {},
      fingerprint: i % 2 === 0 ? "fp-even" : "fp-odd",
      detections: [{ detectorId: detector, reason: "r", score: 5 }],
      score: 5,
      totalScore: 5 * (i + 1),
      respondedWith: "not-found",
    });
  }
  return hits;
}

/** An in-memory stand-in for Redis's list + string ops, enough for RedisStore. */
function fakeRedis() {
  const list: string[] = [];
  const strings = new Map<string, string>();
  const commands: string[] = [];
  return {
    commands,
    client: {
      multi() {
        const ops: Array<() => void> = [];
        const chain = {
          incrby: (k: string, n: number) => (ops.push(() => strings.set(k, String(Number(strings.get(k) ?? 0) + n))), chain),
          expire: () => chain,
          rpush: (_k: string, v: string) => (ops.push(() => void list.push(v)), chain),
          ltrim: () => chain,
          exec: async () => (ops.forEach((op) => op()), []),
        };
        return chain;
      },
      async lrange(_key: string, start: number, stop: number) {
        commands.push(`lrange ${start} ${stop}`);
        const from = start < 0 ? Math.max(0, list.length + start) : start;
        const to = stop < 0 ? list.length + stop : stop;
        return list.slice(from, to + 1);
      },
      async get(k: string) {
        return strings.get(k) ?? null;
      },
    },
  };
}

/** An Elasticsearch stand-in that honours the filters this store pushes down. */
function fakeElastic() {
  const docs: HoneypotHit[] = [];
  const searches: Array<Record<string, any>> = [];
  const fetch = vi.fn(async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    const method = init?.method ?? "GET";
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, any>) : undefined;
    if (method === "PUT") return new Response("{}", { status: 200 });
    if (method === "POST" && /_doc/.test(u)) {
      docs.push(body as HoneypotHit);
      return new Response("{}", { status: 201 });
    }
    if (method === "POST" && /_search$/.test(u)) {
      searches.push(body!);
      let out = [...docs];
      for (const f of (body!.query?.bool?.filter ?? []) as Array<Record<string, any>>) {
        if (f["term"]?.ip) out = out.filter((d) => d.ip === f["term"].ip);
        if (f["range"]?.timestamp?.gte) {
          const gte = Date.parse(f["range"].timestamp.gte);
          out = out.filter((d) => Date.parse(d.timestamp) >= gte);
        }
      }
      out.sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)); // desc, as asked
      return new Response(JSON.stringify({ hits: { hits: out.slice(0, body!.size).map((d) => ({ _source: d })) } }), { status: 200 });
    }
    return new Response("{}", { status: 404 });
  });
  return { fetch: fetch as unknown as typeof globalThis.fetch, searches };
}

async function seed(store: HitStore, hits: HoneypotHit[]): Promise<void> {
  for (const hit of hits) await store.record(hit);
}

const QUERIES: Array<[string, HitQuery]> = [
  ["no constraints", {}],
  ["limit only", { limit: 5 }],
  ["ip only", { ip: "203.0.113.2" }],
  ["detector only", { detector: "decoy-path" }],
  ["fingerprint only", { fingerprint: "fp-even" }],
  ["since only", { sinceMs: Date.UTC(2026, 7, 27, 10, 30) }],
  ["ip + limit", { ip: "203.0.113.2", limit: 3 }],
  ["detector + limit", { detector: "rate-spike", limit: 4 }],
  ["ip + since + limit", { ip: "203.0.113.1", sinceMs: Date.UTC(2026, 7, 27, 10, 20), limit: 2 }],
  ["every dimension", { ip: "203.0.113.1", detector: "decoy-path", fingerprint: "fp-even", sinceMs: Date.UTC(2026, 7, 27, 10, 4), limit: 3 }],
  ["limit 0", { limit: 0 }],
  ["matches nothing", { ip: "198.51.100.9" }],
];

describe("every store answers a query identically", () => {
  // The point of query() is to move work into the backend. That is only safe if the
  // answer is unchanged — so the reference (filter the full corpus in memory) is
  // compared against each store's native path, over every combination of filters.
  const hits = corpus();

  async function stores(): Promise<Array<[string, HitStore]>> {
    const memory = new MemoryStore({ maxHits: 1000 });
    const file = new FileStore({ path: join(mkdtempSync(join(tmpdir(), "hp-q-")), "hits.jsonl"), loadOnStart: false });
    const redis = new RedisStore({ client: fakeRedis().client as never });
    const elastic = new ElasticStore({ node: "http://es:9200", fetch: fakeElastic().fetch });
    const composite = new CompositeStore(new MemoryStore({ maxHits: 1000 }));
    const all: Array<[string, HitStore]> = [
      ["memory", memory],
      ["file", file],
      ["redis", redis],
      ["elastic", elastic],
      ["composite", composite],
    ];
    for (const [, store] of all) await seed(store, hits);
    await file.close();
    return all;
  }

  it.each(QUERIES)("%s", async (_label, query) => {
    const expected = applyQuery(hits, query).map((h) => h.id);
    for (const [name, store] of await stores()) {
      const actual = (await store.query!(query)).map((h) => h.id);
      expect(actual, `${name} disagreed`).toEqual(expected);
    }
  });
});

describe("limit means the most recent N, not the oldest", () => {
  // list() is oldest-first, so a naive slice(0, limit) would show a busy honeypot only
  // its earliest traffic — the opposite of what an operator opening /incidents wants.
  it("returns the newest hits and keeps them in chronological order", async () => {
    const hits = corpus();
    const store = new MemoryStore({ maxHits: 1000 });
    await seed(store, hits);
    const got = await store.query!({ limit: 3 });
    expect(got.map((h) => h.id)).toEqual(["hit-37", "hit-38", "hit-39"]);
  });
});

describe("the filters actually reach the backend", () => {
  it("Elasticsearch receives ip and time as a query, not as a client-side pass", async () => {
    const cluster = fakeElastic();
    const store = new ElasticStore({ node: "http://es:9200", fetch: cluster.fetch });
    await seed(store, corpus());
    cluster.searches.length = 0;

    await store.query({ ip: "203.0.113.2", sinceMs: Date.UTC(2026, 7, 27, 10, 10), limit: 5 });
    const sent = cluster.searches.at(-1)!;
    expect(sent["query"].bool.filter).toEqual([
      { term: { ip: "203.0.113.2" } },
      { range: { timestamp: { gte: new Date(Date.UTC(2026, 7, 27, 10, 10)).toISOString() } } },
    ]);
    // Nothing needs local filtering here, so the cluster caps the rows too.
    expect(sent["size"]).toBe(5);
  });

  it("Elasticsearch does NOT cap rows when a filter still has to run locally", async () => {
    // `detector` is left to dynamic mapping, so it is matched here — capping `size`
    // would cap the candidates, and the newest N matches could fall outside the
    // newest N documents.
    const cluster = fakeElastic();
    const store = new ElasticStore({ node: "http://es:9200", fetch: cluster.fetch, maxHits: 1000 });
    await seed(store, corpus());
    cluster.searches.length = 0;

    const got = await store.query({ detector: "decoy-path", limit: 2 });
    expect(cluster.searches.at(-1)!["size"]).toBe(1000);
    expect(got).toHaveLength(2);
    expect(got.every((h) => h.detections.some((d) => d.detectorId === "decoy-path"))).toBe(true);
  });

  it("Redis slices server-side for a plain limit, and only then", async () => {
    const redis = fakeRedis();
    const store = new RedisStore({ client: redis.client as never });
    await seed(store, corpus());

    redis.commands.length = 0;
    await store.query({ limit: 5 });
    expect(redis.commands).toEqual(["lrange -5 -1"]); // bounded transfer

    redis.commands.length = 0;
    await store.query({ ip: "203.0.113.2", limit: 5 });
    // Trimming before filtering would answer from the newest N records rather than
    // the newest N matches, so the full list is fetched and matched here.
    expect(redis.commands).toEqual(["lrange 0 -1"]);
  });

  it("the file store retains only the window, not every parsed record", async () => {
    const path = join(mkdtempSync(join(tmpdir(), "hp-q-")), "hits.jsonl");
    const store = new FileStore({ path, loadOnStart: false });
    await seed(store, corpus());
    await store.close();

    const got = store.query({ limit: 4 });
    expect(got.map((h) => h.id)).toEqual(["hit-36", "hit-37", "hit-38", "hit-39"]);
    // The ring wraps many times over 40 records with a window of 4 — the unwrap has to
    // put them back in order, which the assertion above is what proves.
    expect(store.query({ limit: 100 })).toHaveLength(40);
  });
});

describe("/incidents keeps its contract on top of the pushdown", () => {
  it("answers most-recent-first, honours filters, and caps at the documented maximum", async () => {
    const store = new MemoryStore({ maxHits: 1000 });
    await seed(store, corpus());

    const recent = await listIncidents(store, new URLSearchParams({ limit: "3" }));
    expect(recent.map((h) => h.id)).toEqual(["hit-39", "hit-38", "hit-37"]);

    const byIp = await listIncidents(store, new URLSearchParams({ ip: "203.0.113.2" }));
    expect(byIp.every((h) => h.ip === "203.0.113.2")).toBe(true);
    expect(byIp).toHaveLength(10);

    const byDetector = await listIncidents(store, new URLSearchParams({ detector: "decoy-path", limit: "2" }));
    expect(byDetector.map((h) => h.id)).toEqual(["hit-39", "hit-36"]);

    const since = await listIncidents(store, new URLSearchParams({ since: new Date(Date.UTC(2026, 7, 27, 10, 38)).toISOString() }));
    expect(since.map((h) => h.id)).toEqual(["hit-39", "hit-38"]);

    // A malformed `since` must not silently filter everything out.
    const bogus = await listIncidents(store, new URLSearchParams({ since: "not-a-date" }));
    expect(bogus).toHaveLength(40);
  });
});
