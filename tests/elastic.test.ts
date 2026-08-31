import { describe, expect, it, vi } from "vitest";
import { ElasticStore } from "../src/index.js";
import type { HoneypotHit } from "../src/index.js";

function hit(overrides: Partial<HoneypotHit> = {}): HoneypotHit {
  return {
    id: overrides.id ?? Math.random().toString(36).slice(2),
    timestamp: overrides.timestamp ?? new Date().toISOString(),
    ip: overrides.ip ?? "203.0.113.7",
    method: "GET",
    path: overrides.path ?? "/.env",
    headers: {},
    detections: overrides.detections ?? [{ detectorId: "decoy-path", reason: "probe", score: 10 }],
    score: overrides.score ?? 10,
    totalScore: overrides.totalScore ?? 10,
    respondedWith: overrides.respondedWith ?? "decoy-content",
  };
}

/** A tiny in-memory fake of the ES REST endpoints ElasticStore uses. */
function fakeCluster() {
  const docs: HoneypotHit[] = [];
  let indexCreated = false;
  const calls: string[] = [];
  /** Bodies of the _search requests, so a test can assert what was actually asked for. */
  const searches: Array<Record<string, unknown>> = [];
  const fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const u = String(url);
    const method = init?.method ?? "GET";
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push(`${method} ${u.replace(/^https?:\/\/[^/]+/, "")}`);

    if (method === "PUT" && /\/hackerpot-hits$/.test(u)) {
      if (indexCreated) return new Response(JSON.stringify({ error: "exists" }), { status: 400 });
      indexCreated = true;
      return new Response(JSON.stringify({ acknowledged: true }), { status: 200 });
    }
    if (method === "POST" && /\/_doc/.test(u)) {
      docs.push(body as HoneypotHit);
      return new Response(JSON.stringify({ result: "created" }), { status: 201 });
    }
    if (method === "POST" && /\/_search$/.test(u)) {
      searches.push(body as Record<string, unknown>);
      if (body.size === 0) {
        const ip = body.query.term.ip;
        const sum = docs.filter((d) => d.ip === ip).reduce((a, d) => a + d.score, 0);
        return new Response(JSON.stringify({ aggregations: { total: { value: sum } } }), { status: 200 });
      }
      const sorted = [...docs].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
      return new Response(JSON.stringify({ hits: { hits: sorted.slice(0, body.size).map((d) => ({ _source: d })) } }), { status: 200 });
    }
    return new Response("not found", { status: 404 });
  });
  return { fetch: fetch as unknown as typeof globalThis.fetch, calls, docs, searches };
}

describe("ElasticStore", () => {
  it("indexes hits, lists them newest-first, and sums scores per IP", async () => {
    const cluster = fakeCluster();
    const store = new ElasticStore({ node: "http://es:9200", fetch: cluster.fetch });

    await store.record(hit({ ip: "1.1.1.1", score: 10, timestamp: "2026-08-27T10:00:00.000Z" }));
    await store.record(hit({ ip: "1.1.1.1", score: 8, timestamp: "2026-08-27T10:00:05.000Z" }));
    await store.record(hit({ ip: "2.2.2.2", score: 3, timestamp: "2026-08-27T10:00:02.000Z" }));

    expect(await store.scoreFor("1.1.1.1")).toBe(18);
    expect(await store.scoreFor("2.2.2.2")).toBe(3);
    expect(await store.scoreFor("9.9.9.9")).toBe(0);

    // Oldest first — the contract every store shares (see `HitStore.list`). The query
    // still sorts descending so `size` selects the newest N; only the order returned
    // is normalized, so a caller need not know which backend is behind it.
    const list = await store.list();
    expect(list).toHaveLength(3);
    expect(list.map((h) => h.timestamp)).toEqual([
      "2026-08-27T10:00:00.000Z",
      "2026-08-27T10:00:02.000Z",
      "2026-08-27T10:00:05.000Z",
    ]);
    // The QUERY must stay descending: with `size`, that is what selects the newest N.
    // Only the returned order is normalized. Flipping the query to ascending would
    // silently return the N *oldest* documents in the index.
    expect(cluster.searches.at(-1)).toMatchObject({ sort: [{ timestamp: "desc" }] });

    // The index is created exactly once, not on every write.
    expect(cluster.calls.filter((c) => c.startsWith("PUT")).length).toBe(1);
  });

  it("sends API-key auth when configured", async () => {
    const cluster = fakeCluster();
    const withAuth = vi.fn(cluster.fetch);
    const store = new ElasticStore({ node: "http://es:9200", apiKey: "secret==", fetch: withAuth as unknown as typeof fetch });
    await store.record(hit());
    const init = withAuth.mock.calls[0]![1] as RequestInit;
    expect((init.headers as Record<string, string>)["Authorization"]).toBe("ApiKey secret==");
  });

  it("never throws out of record() when the cluster is down, and reports via onError", async () => {
    const errors: Error[] = [];
    const store = new ElasticStore({
      node: "http://es:9200",
      onError: (e) => errors.push(e),
      fetch: (async () => { throw new Error("ECONNREFUSED"); }) as unknown as typeof fetch,
    });
    await expect(store.record(hit())).resolves.toBeUndefined(); // does not throw
    expect(await store.list()).toEqual([]);
    expect(await store.scoreFor("1.1.1.1")).toBe(0);
    expect(errors.length).toBeGreaterThan(0);
  });
});
