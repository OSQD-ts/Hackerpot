import type { HitQuery, HoneypotHit } from "../types.js";

/**
 * Shared query semantics, so every store filters identically.
 *
 * `HitStore.query()` is optional: a store that cannot do better than reading
 * everything simply omits it and the caller falls back to `list()` plus these same
 * helpers. That keeps the *meaning* of a query in one place — a store that pushed
 * `since` down to its backend with different boundary semantics than the fallback
 * would make an endpoint's answer depend on which backend was configured.
 */

/** True when `hit` satisfies every constraint in `query`. */
export function matchesQuery(hit: HoneypotHit, query: HitQuery): boolean {
  if (query.ip !== undefined && hit.ip !== query.ip) return false;
  if (query.fingerprint !== undefined && hit.fingerprint !== query.fingerprint) return false;
  if (query.detector !== undefined && !hit.detections.some((d) => d.detectorId === query.detector)) return false;
  if (query.sinceMs !== undefined) {
    const at = Date.parse(hit.timestamp);
    // An unparseable timestamp cannot be shown to satisfy "at or after T", and a
    // NaN comparison would silently drop it either way — be explicit about excluding it.
    if (Number.isNaN(at) || at < query.sinceMs) return false;
  }
  return true;
}

/**
 * The last `limit` entries of an already-ordered, already-filtered list.
 *
 * `limit` means "the most recent N", and `list()` is oldest-first, so this trims the
 * head rather than the tail — the opposite of `slice(0, limit)`, which would return
 * the oldest N and make a busy honeypot's `/incidents` show only its earliest traffic.
 */
export function takeLatest<T>(hits: T[], limit: number | undefined): T[] {
  if (limit === undefined || limit < 0 || hits.length <= limit) return hits;
  return hits.slice(hits.length - limit);
}

/**
 * Applies a whole query to an in-memory array. The reference implementation, and the
 * fallback for any store without a native `query()`.
 */
export function applyQuery(hits: HoneypotHit[], query: HitQuery): HoneypotHit[] {
  const filtered = query.ip !== undefined || query.detector !== undefined || query.fingerprint !== undefined || query.sinceMs !== undefined
    ? hits.filter((hit) => matchesQuery(hit, query))
    : hits;
  return takeLatest(filtered, query.limit);
}

/**
 * Reads a store through `query()` when it has one, else through `list()` + `applyQuery`.
 *
 * Callers go through this rather than branching themselves, so adding a native
 * implementation to a store changes performance and nothing else.
 */
export async function queryHits(
  store: { query?(query: HitQuery): HoneypotHit[] | Promise<HoneypotHit[]>; list(): HoneypotHit[] | Promise<HoneypotHit[]> },
  query: HitQuery,
): Promise<HoneypotHit[]> {
  if (store.query) return store.query(query);
  return applyQuery(await store.list(), query);
}
