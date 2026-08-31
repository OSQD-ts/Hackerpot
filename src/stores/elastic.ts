import { applyQuery } from "./query.js";
import type { HitQuery, HitStore, HoneypotHit } from "../types.js";

export interface ElasticStoreOptions {
  /** Base URL of the cluster, e.g. "http://localhost:9200" (Elasticsearch or OpenSearch). */
  node: string;
  /** Index that hits are written to. Default "hackerpot-hits". */
  index?: string;
  /** API-key auth: sent as `Authorization: ApiKey <apiKey>`. */
  apiKey?: string;
  /** Basic auth: sent as `Authorization: Basic base64(username:password)`. Ignored if `apiKey` is set. */
  username?: string;
  password?: string;
  /** Max hits `list()` pulls back (most recent first, capped at 10000 by ES `size`). Default 1000. */
  maxHits?: number;
  /**
   * Make each write immediately searchable (`?refresh=wait_for`). Default false —
   * leave it off in production so indexing stays fast; turn it on in tests where you
   * read back what you just wrote.
   */
  refresh?: boolean;
  /**
   * Called when a request to the cluster fails. Writes never throw out of `record()`
   * — a honeypot must keep serving even if its log sink is down — so wire this to
   * your own alerting if you need to know the store is unreachable.
   */
  onError?: (error: Error) => void;
  /** Injected for tests; defaults to the global `fetch`. */
  fetch?: typeof fetch;
}

/**
 * Elasticsearch / OpenSearch-backed store — dependency-free, talking to the cluster's
 * REST API over `fetch`. Hits become searchable documents you can dashboard in Kibana
 * or OpenSearch Dashboards and retain far beyond an in-memory or file store. Scores are
 * computed with a `sum` aggregation over an IP's documents (no decay, matching
 * `MemoryStore`); use `RedisStore` instead if you want TTL-based score decay.
 */
export class ElasticStore implements HitStore {
  private readonly node: string;
  private readonly index: string;
  private readonly authHeader: string | undefined;
  private readonly maxHits: number;
  private readonly refresh: boolean;
  private readonly onError: ((error: Error) => void) | undefined;
  private readonly doFetch: typeof fetch;
  private ensured: Promise<void> | undefined;

  constructor(options: ElasticStoreOptions) {
    this.node = options.node.replace(/\/+$/, "");
    this.index = options.index ?? "hackerpot-hits";
    this.maxHits = Math.min(options.maxHits ?? 1000, 10_000);
    this.refresh = options.refresh ?? false;
    this.onError = options.onError;
    this.doFetch = options.fetch ?? fetch;
    if (options.apiKey) {
      this.authHeader = `ApiKey ${options.apiKey}`;
    } else if (options.username !== undefined) {
      this.authHeader = `Basic ${Buffer.from(`${options.username}:${options.password ?? ""}`).toString("base64")}`;
    }
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { "Content-Type": "application/json" };
    if (this.authHeader) h["Authorization"] = this.authHeader;
    return h;
  }

  private async request(method: string, path: string, body?: unknown): Promise<Response> {
    const res = await this.doFetch(`${this.node}${path}`, {
      method,
      headers: this.headers(),
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    return res;
  }

  /** Create the index with a mapping (ip/timestamp typed for term + range queries) once. */
  private ensureIndex(): Promise<void> {
    if (!this.ensured) {
      this.ensured = (async () => {
        const res = await this.request("PUT", `/${this.index}`, {
          mappings: {
            properties: {
              ip: { type: "keyword" },
              timestamp: { type: "date" },
              method: { type: "keyword" },
              path: { type: "keyword" },
              score: { type: "integer" },
              totalScore: { type: "integer" },
              respondedWith: { type: "keyword" },
            },
          },
        });
        // 400 with resource_already_exists_exception is fine — someone got there first.
        if (!res.ok && res.status !== 400) {
          throw new Error(`create index failed: ${res.status} ${await res.text()}`);
        }
      })().catch((err) => {
        // Let the next call retry rather than caching a permanent failure.
        this.ensured = undefined;
        throw err instanceof Error ? err : new Error(String(err));
      });
    }
    return this.ensured;
  }

  async record(hit: HoneypotHit): Promise<void> {
    try {
      await this.ensureIndex();
      const qs = this.refresh ? "?refresh=wait_for" : "";
      const res = await this.request("POST", `/${this.index}/_doc${qs}`, hit);
      if (!res.ok) throw new Error(`index failed: ${res.status} ${await res.text()}`);
    } catch (err) {
      // Never let a logging failure take down the honeypot.
      this.onError?.(err instanceof Error ? err : new Error(String(err)));
    }
  }

  /**
   * The most recent `maxHits` hits, **oldest first** — the same order every other
   * store returns, so a caller can rely on one contract regardless of backend.
   *
   * The query itself must stay `sort: desc`: paired with `size` that is what selects
   * *which* documents come back (the newest N rather than an arbitrary N), so the
   * ordering is reversed here rather than asked for from Elasticsearch. Sorting
   * ascending server-side would return the N oldest documents in the index, which is
   * the opposite of what every caller wants.
   */
  async list(): Promise<HoneypotHit[]> {
    try {
      await this.ensureIndex();
      const res = await this.request("POST", `/${this.index}/_search`, {
        size: this.maxHits,
        sort: [{ timestamp: "desc" }],
      });
      if (!res.ok) throw new Error(`search failed: ${res.status} ${await res.text()}`);
      const json = (await res.json()) as { hits?: { hits?: Array<{ _source: HoneypotHit }> } };
      return (json.hits?.hits ?? []).map((h) => h._source).reverse();
    } catch (err) {
      this.onError?.(err instanceof Error ? err : new Error(String(err)));
      return [];
    }
  }

  /**
   * A filtered read, pushed into the search request rather than done here.
   *
   * Only `ip` and `sinceMs` are pushed down: they are the fields this store's own
   * mapping declares (`ip` as a keyword, `timestamp` as a date), so a term/range query
   * on them is exact. `detector` and `fingerprint` are left to dynamic mapping — their
   * queryable form depends on cluster settings this store does not control — so they
   * are matched here instead, over whatever the pushed-down filters already narrowed.
   * The answer is identical either way; only the volume moved over HTTP changes.
   *
   * That volume was the point: every management read previously pulled `maxHits`
   * documents (1000 by default) and filtered them in JS, so `/incidents?ip=X&limit=10`
   * transferred a thousand documents to return ten.
   */
  async query(query: HitQuery): Promise<HoneypotHit[]> {
    try {
      await this.ensureIndex();
      const filters: unknown[] = [];
      if (query.ip !== undefined) filters.push({ term: { ip: query.ip } });
      if (query.sinceMs !== undefined) filters.push({ range: { timestamp: { gte: new Date(query.sinceMs).toISOString() } } });
      // Only a limit that needs no local filtering can be applied server-side: with a
      // client-side filter still to run, `size` would cap the candidates rather than
      // the results, and the newest N matches could fall outside the newest N documents.
      const localFilter = query.detector !== undefined || query.fingerprint !== undefined;
      const size = !localFilter && query.limit !== undefined && query.limit >= 0 ? Math.min(query.limit, this.maxHits) : this.maxHits;

      const res = await this.request("POST", `/${this.index}/_search`, {
        size,
        sort: [{ timestamp: "desc" }],
        ...(filters.length > 0 ? { query: { bool: { filter: filters } } } : {}),
      });
      if (!res.ok) throw new Error(`search failed: ${res.status} ${await res.text()}`);
      const json = (await res.json()) as { hits?: { hits?: Array<{ _source: HoneypotHit }> } };
      // Descending from the cluster (that is what `size` selects on), ascending out.
      const hits = (json.hits?.hits ?? []).map((h) => h._source).reverse();
      return applyQuery(hits, query);
    } catch (err) {
      this.onError?.(err instanceof Error ? err : new Error(String(err)));
      return [];
    }
  }

  async scoreFor(ip: string): Promise<number> {
    try {
      await this.ensureIndex();
      const res = await this.request("POST", `/${this.index}/_search`, {
        size: 0,
        query: { term: { ip } },
        aggs: { total: { sum: { field: "score" } } },
      });
      if (!res.ok) throw new Error(`aggregation failed: ${res.status} ${await res.text()}`);
      const json = (await res.json()) as { aggregations?: { total?: { value?: number } } };
      return json.aggregations?.total?.value ?? 0;
    } catch (err) {
      this.onError?.(err instanceof Error ? err : new Error(String(err)));
      return 0;
    }
  }
}
