import { decodeCandidates } from "./decode.js";
import type { Incident } from "./types.js";

/**
 * Every statistic on the page, derived in the browser from the incident corpus the API
 * returned.
 *
 * Derived here rather than asked of the server so the numbers always agree with the rows
 * you can click through to: there is one source of truth on screen, and it is the list.
 * The cost is that the analytics cover the corpus the page pulled (the most recent
 * thousand incidents), which the Statistics screen says in so many words.
 *
 * No document in this file. Everything is a function of its arguments, so the parts that
 * are easy to get subtly wrong (bucketing, percentiles, co-occurrence, the funnel) are
 * unit-tested directly.
 */

/**
 * How many incidents the page asks for. An in-process dashboard would serve up to 5000, but a
 * dashboard reading a remote management API is held to that API's cap of 1000, and the page
 * asks for the same number either way so the charts mean the same thing either way.
 */
export const CORPUS_LIMIT = 1000;

export const timeOf = (incident: Incident): number => Date.parse(incident.timestamp);

/** Linear-interpolated percentile of an ascending array. `undefined` for an empty one. */
export function percentile(sorted: readonly number[], p: number): number | undefined {
  if (sorted.length === 0) return undefined;
  const idx = (sorted.length - 1) * Math.min(1, Math.max(0, p));
  const lo = Math.floor(idx);
  const hi = Math.ceil(idx);
  const low = sorted[lo] as number;
  const high = sorted[hi] as number;
  return lo === hi ? low : low + (high - low) * (idx - lo);
}

export function tally<K>(map: Map<K, number>, key: K, n = 1): void {
  map.set(key, (map.get(key) ?? 0) + n);
}

/** Biggest first, ties by name so the order is stable between renders. */
export function ranked(map: ReadonlyMap<string, number>, limit = 12): Array<[string, number]> {
  return [...map.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, limit);
}

/** Ranked entries with everything past `limit` folded into one "other" row, never a ninth hue. */
export function rankedWithOther(map: ReadonlyMap<string, number>, limit: number): Array<[string, number]> {
  const all = [...map.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  if (all.length <= limit) return all;
  const head = all.slice(0, limit - 1);
  const rest = all.slice(limit - 1).reduce((sum, entry) => sum + entry[1], 0);
  head.push([`other (${all.length - limit + 1})`, rest]);
  return head;
}

/** Bucket sizes on a ladder a person recognises: 1s, 5s, 15s, 30s, 1m, 5m, 15m, 30m, 1h, 3h, 6h, 12h, 1d. */
export const BUCKETS = [1e3, 5e3, 15e3, 3e4, 6e4, 3e5, 9e5, 18e5, 36e5, 108e5, 216e5, 432e5, 864e5] as const;

/** The smallest ladder step that lands at most `target` buckets across the span. */
export function chooseBucket(span: number, target = 48): number {
  for (const size of BUCKETS) if (span / size <= target) return size;
  return BUCKETS[BUCKETS.length - 1] as number;
}

/**
 * An axis scale with round tick values: a step from the 1/2/5 ladder, and as many whole
 * steps as it takes to cover the data, so gridlines read 5, 10, 15 rather than 6.25.
 */
export function niceScale(value: number, wanted = 4): { max: number; step: number; ticks: number } {
  if (!(value > 0)) return { max: 1, step: 1, ticks: 1 };
  const raw = value / wanted;
  const e = 10 ** Math.floor(Math.log10(raw));
  const m = raw / e;
  const step = (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * e;
  const ticks = Math.max(1, Math.ceil(value / step - 1e-9));
  return { max: step * ticks, step, ticks };
}

/** Protocol honeypots prefix their detector ids with the protocol; everything else is HTTP. */
export const PROTOCOLS = ["http", "ssh", "smtp", "ftp", "telnet"] as const;

export function protoOf(incident: Incident): string {
  for (const detection of incident.detections) {
    const prefix = detection.detectorId.split("-", 1)[0] ?? "";
    if (prefix !== "http" && (PROTOCOLS as readonly string[]).includes(prefix)) return prefix;
  }
  return "http";
}

export function uaOf(incident: Incident): string {
  const value = incident.headers?.["user-agent"];
  const first = Array.isArray(value) ? value[0] : value;
  return typeof first === "string" && first !== "" ? first : "(none)";
}

export const basePath = (path: string): string => String(path ?? "").split("?")[0] ?? "";

// ---- responses ------------------------------------------------------------------

export const DECOY_RESPONSES: ReadonlySet<string> = new Set(["decoy-content", "fake-data", "fake-success", "redirect"]);
export const COST_RESPONSES: ReadonlySet<string> = new Set(["tarpit", "drip-feed", "large-payload", "gzip-bomb", "chaos", "rate-limit"]);

/** How far up the escalation ladder a response is: seen, deceived, slowed, blocked. */
export function rung(response: string): number {
  return response === "block" ? 3 : COST_RESPONSES.has(response) ? 2 : DECOY_RESPONSES.has(response) ? 1 : 0;
}

export const RUNGS = [
  { name: "Seen", note: "recorded at least one incident" },
  { name: "Deceived", note: "served a decoy, fake data, or a redirect into the trap" },
  { name: "Slowed", note: "tarpitted, drip-fed, or otherwise made to pay for the scan" },
  { name: "Blocked", note: "crossed the block threshold and was cut off at the door" },
] as const;

/**
 * Response classes. Individual response ids are many; the classes are few and stable, so a
 * part-to-whole bar keeps the same colour for the same class whichever responses happen
 * to be present. `slot` is the categorical palette slot, `-1` the neutral "other".
 */
export const RESPONSE_CLASSES: ReadonlyArray<{ name: string; slot: number; test: (response: string) => boolean; note: string }> = [
  { name: "decoy", slot: 0, test: (r) => DECOY_RESPONSES.has(r), note: "fake content served, so the probe looks like it worked" },
  { name: "time cost", slot: 1, test: (r) => COST_RESPONSES.has(r), note: "tarpit, drip-feed, bomb: the attacker pays for the scan" },
  { name: "block", slot: 2, test: (r) => r === "block", note: "address cut off before any detector runs" },
  { name: "protocol capture", slot: 3, test: (r) => r.endsWith("-capture"), note: "SSH, SMTP, FTP or Telnet attempt logged and refused" },
  { name: "silent 404", slot: -1, test: () => true, note: "plain not-found: the probe itself was the signal" },
];

export function classOf(response: string): string {
  return (RESPONSE_CLASSES.find((c) => c.test(response)) ?? RESPONSE_CLASSES[RESPONSE_CLASSES.length - 1])?.name ?? "silent 404";
}

export function classSlot(name: string): number {
  return RESPONSE_CLASSES.find((c) => c.name === name)?.slot ?? -1;
}

/** Response counts rolled up into classes, in the fixed class order so colours never shuffle. */
export function responseClassEntries(byResponse: ReadonlyMap<string, number>): Array<[string, number]> {
  const classes = new Map<string, number>();
  for (const [response, n] of byResponse) tally(classes, classOf(response), n);
  return RESPONSE_CLASSES.map((c): [string, number] => [c.name, classes.get(c.name) ?? 0]).filter((entry) => entry[1] > 0);
}

// ---- the analysis ----------------------------------------------------------------

export interface IpAggregate {
  ip: string;
  incidents: number;
  score: number;
  /** Highest cumulative score seen: what the block threshold is compared against. */
  peak: number;
  first: number;
  last: number;
  detectors: Set<string>;
  responses: Set<string>;
  rung: number;
  times: number[];
}

export interface ActorAggregate {
  fingerprint: string;
  ips: Set<string>;
  incidents: number;
  score: number;
}

export interface Bucket {
  start: number;
  n: number;
  score: number;
  ips: Set<string>;
  cumIps: number;
  cumActors: number;
  blocked: number;
}

export interface Analysis {
  n: number;
  byDetector: Map<string, number>;
  detectorScore: Map<string, number>;
  /** Unordered detector pair, joined by a space, to incidents where both fired. */
  cooc: Map<string, number>;
  byResponse: Map<string, number>;
  byMethod: Map<string, number>;
  byPath: Map<string, number>;
  byUa: Map<string, number>;
  byCategory: Map<string, number>;
  byCountry: Map<string, number>;
  byAsn: Map<string, number>;
  byProto: Map<string, number>;
  byEncoding: Map<string, number>;
  /** Per-incident scores, ascending. */
  scores: number[];
  ips: Map<string, IpAggregate>;
  actors: Map<string, ActorAggregate>;
  /** `hourDow[day][hour]`, local time, Sunday first. */
  hourDow: number[][];
  buckets: Bucket[];
  bucketSize: number;
  span: number;
  /** Gaps between consecutive requests from the same address, ascending. */
  gaps: number[];
  obfuscated: number;
  withBody: number;
  bodyBytes: number;
  headerCount: number;
  noUa: number;
  multiDetector: number;
  singletonPaths: number;
  firstMs: number | undefined;
  lastMs: number | undefined;
  peakBucket: Bucket | undefined;
}

/** Most buckets a chart is given, whatever the span. */
const MAX_BUCKETS = 400;

/** Timestamped incidents only, oldest first. A record with an unparseable time cannot be placed on any chart. */
export function chronological(list: readonly Incident[]): Incident[] {
  return list.filter((incident) => Number.isFinite(timeOf(incident))).sort((a, b) => timeOf(a) - timeOf(b));
}

/**
 * The statistics window and protocol filter applied to the corpus.
 *
 * The window is measured back from the newest incident rather than from now, so a
 * dashboard opened on a quiet store still shows "the last hour of activity" instead of an
 * empty page.
 */
export function scopeIncidents(list: readonly Incident[], rangeMs: number, proto: string): Incident[] {
  let scoped = chronological(list);
  if (proto !== "") scoped = scoped.filter((incident) => protoOf(incident) === proto);
  if (rangeMs > 0 && scoped.length > 0) {
    const newest = timeOf(scoped[scoped.length - 1] as Incident);
    scoped = scoped.filter((incident) => newest - timeOf(incident) <= rangeMs);
  }
  return scoped;
}

export function analyze(input: readonly Incident[]): Analysis {
  const list = chronological(input);
  const a: Analysis = {
    n: list.length,
    byDetector: new Map(),
    detectorScore: new Map(),
    cooc: new Map(),
    byResponse: new Map(),
    byMethod: new Map(),
    byPath: new Map(),
    byUa: new Map(),
    byCategory: new Map(),
    byCountry: new Map(),
    byAsn: new Map(),
    byProto: new Map(),
    byEncoding: new Map(),
    scores: [],
    ips: new Map(),
    actors: new Map(),
    hourDow: Array.from({ length: 7 }, () => new Array<number>(24).fill(0)),
    buckets: [],
    bucketSize: 0,
    span: 0,
    gaps: [],
    obfuscated: 0,
    withBody: 0,
    bodyBytes: 0,
    headerCount: 0,
    noUa: 0,
    multiDetector: 0,
    singletonPaths: 0,
    firstMs: undefined,
    lastMs: undefined,
    peakBucket: undefined,
  };
  if (list.length === 0) return a;
  const firstMs = timeOf(list[0] as Incident);
  const lastMs = timeOf(list[list.length - 1] as Incident);
  a.firstMs = firstMs;
  a.lastMs = lastMs;
  a.span = lastMs - firstMs;

  for (const incident of list) {
    const t = timeOf(incident);
    const ids = [...new Set(incident.detections.map((d) => d.detectorId))];
    for (const detection of incident.detections) tally(a.detectorScore, detection.detectorId, Number(detection.score) || 0);
    for (const id of ids) tally(a.byDetector, id);
    for (let i = 0; i < ids.length; i++) {
      for (let j = i + 1; j < ids.length; j++) tally(a.cooc, pairKey(ids[i] as string, ids[j] as string));
    }
    if (ids.length > 1) a.multiDetector++;
    tally(a.byResponse, incident.respondedWith);
    tally(a.byMethod, incident.method || "-");
    tally(a.byPath, basePath(incident.path));
    const ua = uaOf(incident);
    tally(a.byUa, ua);
    tally(a.byProto, protoOf(incident));
    if (incident.enrichment !== undefined) {
      tally(a.byCategory, incident.enrichment.category || "unknown");
      if (incident.enrichment.country) tally(a.byCountry, incident.enrichment.country);
      if (incident.enrichment.asn) tally(a.byAsn, `AS${incident.enrichment.asn}${incident.enrichment.org ? ` ${incident.enrichment.org}` : ""}`);
    }
    a.scores.push(Number(incident.score) || 0);
    const date = new Date(t);
    (a.hourDow[date.getDay()] as number[])[date.getHours()]! += 1;
    if (ua === "(none)") a.noUa++;
    a.headerCount += Object.keys(incident.headers ?? {}).length;
    if (typeof incident.body === "string" && incident.body !== "") {
      a.withBody++;
      a.bodyBytes += incident.body.length;
    }
    const decoded = decodeCandidates(incident);
    if (decoded.length > 0) {
      a.obfuscated++;
      for (const row of decoded) tally(a.byEncoding, row.encoding);
    }

    let ip = a.ips.get(incident.ip);
    if (ip === undefined) {
      ip = { ip: incident.ip, incidents: 0, score: 0, peak: 0, first: t, last: t, detectors: new Set(), responses: new Set(), rung: 0, times: [] };
      a.ips.set(incident.ip, ip);
    }
    ip.incidents++;
    ip.score += Number(incident.score) || 0;
    ip.peak = Math.max(ip.peak, Number(incident.totalScore) || 0);
    ip.first = Math.min(ip.first, t);
    ip.last = Math.max(ip.last, t);
    for (const id of ids) ip.detectors.add(id);
    ip.responses.add(incident.respondedWith);
    ip.rung = Math.max(ip.rung, rung(incident.respondedWith));
    ip.times.push(t);

    if (incident.fingerprint) {
      let actor = a.actors.get(incident.fingerprint);
      if (actor === undefined) {
        actor = { fingerprint: incident.fingerprint, ips: new Set(), incidents: 0, score: 0 };
        a.actors.set(incident.fingerprint, actor);
      }
      actor.ips.add(incident.ip);
      actor.incidents++;
      actor.score += Number(incident.score) || 0;
    }
  }

  // Inter-arrival gaps are measured per address. A global gap would mostly measure how
  // many addresses are talking at once, not how fast any one of them fires.
  for (const ip of a.ips.values()) {
    for (let i = 1; i < ip.times.length; i++) a.gaps.push((ip.times[i] as number) - (ip.times[i - 1] as number));
  }
  a.gaps.sort((x, y) => x - y);
  a.scores.sort((x, y) => x - y);

  a.bucketSize = chooseBucket(Math.max(a.span, 1), 48);
  const start = Math.floor(firstMs / a.bucketSize) * a.bucketSize;
  const count = Math.max(1, Math.floor((lastMs - start) / a.bucketSize) + 1);
  a.buckets = Array.from({ length: Math.min(count, MAX_BUCKETS) }, (_, i) => ({ start: start + i * a.bucketSize, n: 0, score: 0, ips: new Set<string>(), cumIps: 0, cumActors: 0, blocked: 0 }));
  const seenIps = new Set<string>();
  const seenActors = new Set<string>();
  for (const incident of list) {
    const index = Math.max(0, Math.min(a.buckets.length - 1, Math.floor((timeOf(incident) - start) / a.bucketSize)));
    const bucket = a.buckets[index] as Bucket;
    bucket.n++;
    bucket.score += Number(incident.score) || 0;
    bucket.ips.add(incident.ip);
    if (incident.respondedWith === "block") bucket.blocked++;
    seenIps.add(incident.ip);
    if (incident.fingerprint) seenActors.add(incident.fingerprint);
    bucket.cumIps = seenIps.size;
    bucket.cumActors = seenActors.size;
  }
  // A quiet bucket inherits the running totals, so the cumulative line is flat across a
  // lull instead of dropping to zero.
  for (let i = 0; i < a.buckets.length; i++) {
    const bucket = a.buckets[i] as Bucket;
    if (bucket.n === 0 && i > 0) {
      const previous = a.buckets[i - 1] as Bucket;
      bucket.cumIps = previous.cumIps;
      bucket.cumActors = previous.cumActors;
    }
  }
  a.peakBucket = a.buckets.reduce<Bucket | undefined>((max, bucket) => (max === undefined || bucket.n > max.n ? bucket : max), undefined);
  a.singletonPaths = [...a.byPath.values()].filter((n) => n === 1).length;
  return a;
}

export function pairKey(x: string, y: string): string {
  return x < y ? `${x} ${y}` : `${y} ${x}`;
}

/** Requests per minute in the busiest bucket. */
export function peakPerMinute(a: Analysis): number {
  return a.peakBucket === undefined || a.bucketSize === 0 ? 0 : a.peakBucket.n / (a.bucketSize / 6e4);
}

// ---- derived panels ------------------------------------------------------------

export const CADENCE_EDGES = [0, 100, 500, 1000, 5000, 30000, 120000, Number.POSITIVE_INFINITY] as const;
export const CADENCE_LABELS = ["<0.1s", "0.1–0.5s", "0.5–1s", "1–5s", "5–30s", "30s–2m", ">2m"] as const;

export interface Cadence {
  median: number;
  p10: number;
  p90: number;
  mean: number;
  sd: number;
  /** Coefficient of variation: standard deviation over the mean. */
  cv: number;
  verdict: string;
  counts: number[];
}

/**
 * How regular one address's requests are. A scripted client fires on a near-constant
 * period (a coefficient of variation near zero); human browsing is bursty and irregular
 * (well above one). `undefined` when no address sent more than one request.
 */
export function cadence(gaps: readonly number[]): Cadence | undefined {
  if (gaps.length === 0) return undefined;
  const mean = gaps.reduce((x, y) => x + y, 0) / gaps.length;
  const sd = Math.sqrt(gaps.reduce((s, g) => s + (g - mean) * (g - mean), 0) / gaps.length);
  const cv = mean ? sd / mean : 0;
  const counts = new Array<number>(CADENCE_LABELS.length).fill(0);
  for (const gap of gaps) {
    for (let i = 0; i < CADENCE_LABELS.length; i++) {
      if (gap >= (CADENCE_EDGES[i] as number) && gap < (CADENCE_EDGES[i + 1] as number)) {
        counts[i]! += 1;
        break;
      }
    }
  }
  return {
    median: percentile(gaps, 0.5) ?? 0,
    p10: percentile(gaps, 0.1) ?? 0,
    p90: percentile(gaps, 0.9) ?? 0,
    mean,
    sd,
    cv,
    verdict: cv < 0.5 ? "machine-regular" : cv < 1.2 ? "mixed / bursty automation" : "irregular, human-like",
    counts,
  };
}

export interface HistogramBin {
  from: number;
  to: number;
  value: number;
}

/** Ten equal bins from zero to a round number at or above the highest score. */
export function histogram(sortedScores: readonly number[], bins = 10): HistogramBin[] {
  if (sortedScores.length === 0) return [];
  const max = niceScale(Math.max(1, sortedScores[sortedScores.length - 1] as number)).max;
  const width = max / bins;
  const counts = new Array<number>(bins).fill(0);
  for (const score of sortedScores) counts[Math.max(0, Math.min(bins - 1, Math.floor(score / width)))]! += 1;
  return counts.map((value, i) => ({ from: i * width, to: (i + 1) * width, value }));
}

/** The most frequent detectors and a lookup for how often each pair fired together. The diagonal is each detector's own total. */
export function cooccurrence(a: Analysis, limit = 9): { top: string[]; get: (row: number, column: number) => number } {
  const top = ranked(a.byDetector, limit).map((entry) => entry[0]);
  return {
    top,
    get: (row, column) => {
      const x = top[row];
      const y = top[column];
      if (x === undefined || y === undefined) return 0;
      return row === column ? (a.byDetector.get(x) ?? 0) : (a.cooc.get(pairKey(x, y)) ?? 0);
    },
  };
}

/** Addresses that reached at least each rung. The first entry is every address. */
export function funnel(a: Analysis): number[] {
  const ips = [...a.ips.values()];
  return RUNGS.map((_, level) => ips.filter((ip) => ip.rung >= level).length);
}

export type IpSortKey = "ip" | "incidents" | "score" | "peak" | "detectors" | "rung" | "first" | "duration";

export interface IpRow extends IpAggregate {
  duration: number;
  /** Activity across the observation window, in equal slots shared by every row so the sparklines compare. */
  slots: number[];
}

export function ipRows(a: Analysis, sort: { key: IpSortKey; dir: 1 | -1 }, slotCount = 28): IpRow[] {
  const span = Math.max(1, a.span);
  const first = a.firstMs ?? 0;
  const rows = [...a.ips.values()].map((ip): IpRow => {
    const slots = new Array<number>(slotCount).fill(0);
    for (const t of ip.times) slots[Math.max(0, Math.min(slotCount - 1, Math.floor(((t - first) / span) * slotCount)))]! += 1;
    return { ...ip, duration: ip.last - ip.first, slots };
  });
  const value = (row: IpRow): number | string => (sort.key === "detectors" ? row.detectors.size : row[sort.key]);
  rows.sort((x, y) => {
    const xv = value(x);
    const yv = value(y);
    const order = typeof xv === "string" || typeof yv === "string" ? String(xv).localeCompare(String(yv)) : xv - yv;
    // Ties broken by address so a re-render under the same sort never shuffles rows.
    return sort.dir * order || x.ip.localeCompare(y.ip);
  });
  return rows;
}

/** The response that stands for how far an address got: the highest rung it was served. */
export function strongestResponse(responses: ReadonlySet<string>): string {
  return [...responses].sort((p, q) => rung(q) - rung(p) || p.localeCompare(q))[0] ?? "";
}
