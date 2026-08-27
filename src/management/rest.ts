import type { HitStore } from "../types.js";
import type { Incident } from "./types.js";

export interface IncidentQuery {
  /** Only incidents at or after this ISO timestamp. */
  since?: string;
  /** Filter by source IP. */
  ip?: string;
  /** Filter to incidents where this detector fired. */
  detector?: string;
  /** Max rows returned (most recent first). Default 100, max 1000. */
  limit?: number;
}

export interface StatsSummary {
  totalIncidents: number;
  uniqueIps: number;
  byDetector: Record<string, number>;
  byResponse: Record<string, number>;
  topOffenders: Array<{ ip: string; score: number; incidents: number }>;
  firstSeen?: string;
  lastSeen?: string;
}

function parseQuery(search: URLSearchParams): IncidentQuery {
  const query: IncidentQuery = {};
  const since = search.get("since");
  if (since) query.since = since;
  const ip = search.get("ip");
  if (ip) query.ip = ip;
  const detector = search.get("detector");
  if (detector) query.detector = detector;
  const limit = search.get("limit");
  if (limit) query.limit = Number(limit);
  return query;
}

export async function listIncidents(store: HitStore, search: URLSearchParams): Promise<Incident[]> {
  const query = parseQuery(search);
  const all = await store.list();
  const limit = Math.min(Math.max(1, query.limit ?? 100), 1000);
  const sinceMs = query.since ? Date.parse(query.since) : undefined;

  const filtered = all.filter((hit) => {
    if (query.ip && hit.ip !== query.ip) return false;
    if (query.detector && !hit.detections.some((d) => d.detectorId === query.detector)) return false;
    if (sinceMs !== undefined && Date.parse(hit.timestamp) < sinceMs) return false;
    return true;
  });

  // Most recent first.
  filtered.sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
  return filtered.slice(0, limit);
}

export async function getIncident(store: HitStore, id: string): Promise<Incident | undefined> {
  const all = await store.list();
  return all.find((hit) => hit.id === id);
}

export async function computeStats(store: HitStore): Promise<StatsSummary> {
  const all = await store.list();
  const byDetector: Record<string, number> = {};
  const byResponse: Record<string, number> = {};
  const perIp = new Map<string, { score: number; incidents: number }>();

  for (const hit of all) {
    byResponse[hit.respondedWith] = (byResponse[hit.respondedWith] ?? 0) + 1;
    for (const detection of hit.detections) {
      byDetector[detection.detectorId] = (byDetector[detection.detectorId] ?? 0) + 1;
    }
    const entry = perIp.get(hit.ip) ?? { score: 0, incidents: 0 };
    entry.score += hit.score;
    entry.incidents += 1;
    perIp.set(hit.ip, entry);
  }

  const timestamps = all.map((hit) => hit.timestamp).sort();
  const topOffenders = [...perIp.entries()]
    .map(([ip, v]) => ({ ip, score: v.score, incidents: v.incidents }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 10);

  const summary: StatsSummary = {
    totalIncidents: all.length,
    uniqueIps: perIp.size,
    byDetector,
    byResponse,
    topOffenders,
  };
  if (timestamps.length > 0) {
    summary.firstSeen = timestamps[0]!;
    summary.lastSeen = timestamps[timestamps.length - 1]!;
  }
  return summary;
}

export interface IocEntry {
  ip: string;
  score: number;
  incidents: number;
  detectors: string[];
  firstSeen: string;
  lastSeen: string;
}

/**
 * Indicators of Compromise: the source IPs seen, aggregated with their cumulative
 * score, incident count, and which detectors they tripped — a feed your firewall
 * or other honeypots can pull. `minScore` filters to IPs at or above a threshold.
 */
export async function computeIoc(store: HitStore, minScore = 0): Promise<IocEntry[]> {
  const all = await store.list();
  const perIp = new Map<string, { score: number; incidents: number; detectors: Set<string>; first: string; last: string }>();
  for (const hit of all) {
    const e = perIp.get(hit.ip) ?? { score: 0, incidents: 0, detectors: new Set<string>(), first: hit.timestamp, last: hit.timestamp };
    e.score += hit.score;
    e.incidents += 1;
    for (const d of hit.detections) e.detectors.add(d.detectorId);
    if (hit.timestamp < e.first) e.first = hit.timestamp;
    if (hit.timestamp > e.last) e.last = hit.timestamp;
    perIp.set(hit.ip, e);
  }
  return [...perIp.entries()]
    .map(([ip, e]) => ({ ip, score: e.score, incidents: e.incidents, detectors: [...e.detectors].sort(), firstSeen: e.first, lastSeen: e.last }))
    .filter((e) => e.score >= minScore)
    .sort((a, b) => b.score - a.score);
}

export interface AttackSession {
  ip: string;
  score: number;
  incidents: number;
  detectors: string[];
  responses: string[];
  firstSeen: string;
  lastSeen: string;
  /** Ordered timeline of what this IP did — the attack as a narrative, not a flat list. */
  timeline: Array<{ timestamp: string; method: string; path: string; detectors: string[]; score: number; totalScore: number; respondedWith: string }>;
}

/**
 * Groups an IP's incidents into an attack **session** — an ordered timeline plus
 * the detectors/responses seen and the score progression — so you read what an
 * attacker actually did rather than scanning a flat incident list. Pass an `ip` for
 * a single detailed session; omit it for every IP's session, newest activity first.
 */
export async function computeSessions(store: HitStore, ip?: string): Promise<AttackSession[]> {
  const all = (await store.list()).filter((h) => (ip ? h.ip === ip : true));
  const byIp = new Map<string, Incident[]>();
  for (const hit of all) {
    const list = byIp.get(hit.ip) ?? [];
    list.push(hit);
    byIp.set(hit.ip, list);
  }
  const sessions: AttackSession[] = [];
  for (const [sessionIp, hits] of byIp) {
    hits.sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
    const detectors = new Set<string>();
    const responses = new Set<string>();
    let score = 0;
    for (const h of hits) {
      score += h.score;
      responses.add(h.respondedWith);
      for (const d of h.detections) detectors.add(d.detectorId);
    }
    sessions.push({
      ip: sessionIp,
      score,
      incidents: hits.length,
      detectors: [...detectors].sort(),
      responses: [...responses].sort(),
      firstSeen: hits[0]!.timestamp,
      lastSeen: hits[hits.length - 1]!.timestamp,
      timeline: hits.map((h) => ({ timestamp: h.timestamp, method: h.method, path: h.path, detectors: h.detections.map((d) => d.detectorId), score: h.score, totalScore: h.totalScore, respondedWith: h.respondedWith })),
    });
  }
  return sessions.sort((a, b) => Date.parse(b.lastSeen) - Date.parse(a.lastSeen));
}

export interface ActorGroup {
  fingerprint: string;
  /** The distinct source IPs this one actor fingerprint attacked from. */
  ips: string[];
  score: number;
  incidents: number;
  detectors: string[];
  firstSeen: string;
  lastSeen: string;
}

/**
 * Groups incidents by **actor fingerprint** (header order + UA family) rather than by
 * IP, so an attacker who rotated through many source addresses collapses into a single
 * actor with all their IPs listed. Only incidents carrying a fingerprint are included.
 * Pass a `fingerprint` for one actor; omit it for all, most IPs first (the rotators).
 */
export async function computeActors(store: HitStore, fingerprint?: string): Promise<ActorGroup[]> {
  const all = (await store.list()).filter((h) => h.fingerprint && (fingerprint ? h.fingerprint === fingerprint : true));
  const byFp = new Map<string, { ips: Set<string>; score: number; incidents: number; detectors: Set<string>; first: string; last: string }>();
  for (const hit of all) {
    const fp = hit.fingerprint!;
    const e = byFp.get(fp) ?? { ips: new Set<string>(), score: 0, incidents: 0, detectors: new Set<string>(), first: hit.timestamp, last: hit.timestamp };
    e.ips.add(hit.ip);
    e.score += hit.score;
    e.incidents += 1;
    for (const d of hit.detections) e.detectors.add(d.detectorId);
    if (hit.timestamp < e.first) e.first = hit.timestamp;
    if (hit.timestamp > e.last) e.last = hit.timestamp;
    byFp.set(fp, e);
  }
  return [...byFp.entries()]
    .map(([fp, e]) => ({ fingerprint: fp, ips: [...e.ips].sort(), score: e.score, incidents: e.incidents, detectors: [...e.detectors].sort(), firstSeen: e.first, lastSeen: e.last }))
    // Actors using the most IPs first — those are the rotators worth seeing.
    .sort((a, b) => b.ips.length - a.ips.length || b.score - a.score);
}
