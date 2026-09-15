import net from "node:net";
import { IpAllowlist } from "./allowlist.js";

/**
 * Published crawler address ranges. Adapted from bothandlerjs.
 *
 * Several crawlers, the AI ones among them, publish the addresses they crawl from and no
 * reverse-DNS record at all, so `crawler-verification` could neither confirm nor refute
 * them. Where a list exists it is also the better check for the rest: a lookup rather than
 * a network round trip, and immune to somebody else's DNS having a bad afternoon.
 *
 * Nothing here ships address data. A range baked into a release is wrong by the time it is
 * installed, and wrong here means verifying whoever has since been handed the address. What
 * ships is the URL each operator publishes, fetched on a schedule you start.
 *
 * **Opt-in, and it makes outbound HTTPS requests.**
 */

/** One publisher and where it says its addresses are. */
export interface PublishedRangeSource {
  /** The crawler id these ranges belong to. Matches `VerifiableCrawler.rangeIds`. */
  id: string;
  /** HTTPS only. */
  url: string;
}

/** The operators' own lists, as pointers rather than data. */
export const PUBLISHED_CRAWLER_RANGES: readonly PublishedRangeSource[] = Object.freeze([
  { id: "googlebot", url: "https://developers.google.com/static/search/apis/ipranges/googlebot.json" },
  { id: "google-special", url: "https://developers.google.com/static/search/apis/ipranges/special-crawlers.json" },
  { id: "bingbot", url: "https://www.bing.com/toolbox/bingbot.json" },
  { id: "gptbot", url: "https://openai.com/gptbot.json" },
  { id: "oai-searchbot", url: "https://openai.com/searchbot.json" },
  { id: "chatgpt-user", url: "https://openai.com/chatgpt-user.json" },
  { id: "duckduckbot", url: "https://duckduckgo.com/duckduckbot.json" },
]);

/**
 * Largest block a published list may contain. An address inside a list is *verified*,
 * so a list that arrived wrong (a parse gone astray, a proxy serving something else, a
 * `0.0.0.0/0`) would verify whatever it covered. No crawler publishes a block this large.
 */
const MIN_V4_PREFIX = 8;
const MIN_V6_PREFIX = 19;
/** A published list is hundreds of prefixes; ten thousand is somebody else's file. */
const MAX_PREFIXES = 10_000;
const MAX_BYTES = 4 * 1024 * 1024;

export interface FetchRangesOptions {
  /** Per-request deadline. Default 10 seconds. */
  timeoutMs?: number;
  /** Injectable for tests and for deployments that reach the internet through their own proxy. */
  fetch?: typeof globalThis.fetch;
}

/** Reads the body against a running byte count, so an oversized response is refused before it is held. */
async function readCapped(response: Response): Promise<string> {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_BYTES) throw new Error(`the list declares ${Math.round(declared / 1024)} kB, which is not a list of prefixes`);
  const body = response.body;
  if (body === null || typeof body.getReader !== "function") {
    const whole = await response.text();
    if (whole.length > MAX_BYTES) throw new Error("the list is larger than any list of prefixes");
    return whole;
  }
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let text = "";
  let bytes = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > MAX_BYTES) throw new Error(`the list is over ${Math.round(MAX_BYTES / 1024)} kB, which is not a list of prefixes`);
      text += decoder.decode(value, { stream: true });
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  return text + decoder.decode();
}

/** `{ prefixes: [{ ipv4Prefix } | { ipv6Prefix }] }`, the format Google standardised; or one prefix per line. */
function extractPrefixes(text: string): string[] {
  if (text.trimStart().startsWith("{")) {
    const document = JSON.parse(text) as { prefixes?: unknown };
    if (!Array.isArray(document.prefixes)) throw new Error("no `prefixes` array in the document");
    const out: string[] = [];
    for (const entry of document.prefixes) {
      if (entry === null || typeof entry !== "object") continue;
      const record = entry as Record<string, unknown>;
      const value = record["ipv4Prefix"] ?? record["ipv6Prefix"] ?? record["ip_prefix"] ?? record["ipv6_prefix"];
      if (typeof value === "string") out.push(value.trim());
    }
    return out;
  }
  return text
    .split("\n")
    .map((line) => (line.split("#")[0] ?? "").split(";")[0]!.trim())
    .filter((line) => line !== "");
}

/**
 * Everything a list must be before it may verify anybody. An unparseable entry is dropped,
 * but a list that is empty, oversized, or holds a block wider than any crawler owns is
 * refused whole: the operation replaces a set, and a set that half-arrived is worse than
 * the one already installed.
 */
export function validateRanges(prefixes: readonly string[]): string[] {
  if (prefixes.length === 0) throw new Error("the list is empty");
  if (prefixes.length > MAX_PREFIXES) throw new Error(`${prefixes.length} prefixes is not a crawler's address list`);
  const accepted: string[] = [];
  for (const prefix of prefixes) {
    const slash = prefix.indexOf("/");
    const address = slash === -1 ? prefix : prefix.slice(0, slash);
    const family = net.isIP(address);
    if (family === 0) continue;
    const bits = slash === -1 ? (family === 4 ? 32 : 128) : Number(prefix.slice(slash + 1));
    if (!Number.isInteger(bits) || bits < 0 || bits > (family === 4 ? 32 : 128)) continue;
    if (bits < (family === 4 ? MIN_V4_PREFIX : MIN_V6_PREFIX)) {
      throw new Error(`"${prefix}" covers more of the internet than any crawler owns; refusing the whole list`);
    }
    accepted.push(prefix);
  }
  if (accepted.length === 0) throw new Error(`nothing in the list parsed as an address or CIDR (first entry: "${prefixes[0]}")`);
  const set = new IpAllowlist(accepted);
  if (set.size === 0) throw new Error("nothing in the list could be matched");
  return accepted;
}

/** Fetches and validates one published list. Throws on anything unusable. */
export async function fetchCrawlerRanges(source: PublishedRangeSource, options: FetchRangesOptions = {}): Promise<string[]> {
  const url = new URL(source.url);
  // Over plain HTTP anything in between would decide which addresses count as a crawler.
  if (url.protocol !== "https:") throw new Error(`crawler ranges must be published over HTTPS; "${source.url}" is not`);
  const fetcher = options.fetch ?? globalThis.fetch;
  const response = await fetcher(url, {
    signal: AbortSignal.timeout(options.timeoutMs ?? 10_000),
    headers: { accept: "application/json, text/plain", "user-agent": "hackerpot" },
    redirect: "follow",
  });
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error(`HTTP ${response.status}`);
  }
  return validateRanges(extractPrefixes(await readCapped(response)));
}

/** The installed ranges, per crawler id. Replaced whole per id, never merged. */
export class CrawlerRanges {
  private readonly sets = new Map<string, { set: IpAllowlist; prefixes: number; updatedAt: number }>();

  /** Installs a validated list for one crawler id. Throws, leaving the previous list, if it is unusable. */
  update(id: string, prefixes: readonly string[], now = Date.now()): void {
    const accepted = validateRanges(prefixes);
    this.sets.set(id, { set: new IpAllowlist(accepted), prefixes: accepted.length, updatedAt: now });
  }

  /** True when a list is installed for this id. */
  has(id: string): boolean {
    return this.sets.has(id);
  }

  /** Whether `ip` is inside the list for `id`. Undefined when no list is installed: no data, no answer. */
  contains(id: string, ip: string): boolean | undefined {
    const entry = this.sets.get(id);
    return entry === undefined ? undefined : entry.set.allows(ip);
  }

  list(): Array<{ id: string; prefixes: number; updatedAt: string }> {
    return [...this.sets.entries()].map(([id, entry]) => ({ id, prefixes: entry.prefixes, updatedAt: new Date(entry.updatedAt).toISOString() }));
  }
}

export interface RefreshResult {
  updated: Array<{ id: string; prefixes: number }>;
  failed: Array<{ id: string; reason: string }>;
}

export interface RefreshOptions extends FetchRangesOptions {
  /** Which lists to fetch. Default `PUBLISHED_CRAWLER_RANGES`. */
  sources?: readonly PublishedRangeSource[];
}

/**
 * Fetches every list and installs what arrived intact. Never throws and never partially
 * applies: a publisher that is down, has moved its file or serves something unrecognisable
 * leaves that crawler's previous ranges in place, and is reported in `failed`.
 */
export async function refreshCrawlerRanges(ranges: CrawlerRanges, options: RefreshOptions = {}): Promise<RefreshResult> {
  const result: RefreshResult = { updated: [], failed: [] };
  const fetched = await Promise.all(
    (options.sources ?? PUBLISHED_CRAWLER_RANGES).map(async (source) => {
      try {
        return { source, prefixes: await fetchCrawlerRanges(source, options) };
      } catch (error) {
        return { source, reason: error instanceof Error ? error.message : String(error) };
      }
    }),
  );
  for (const entry of fetched) {
    if ("reason" in entry) {
      result.failed.push({ id: entry.source.id, reason: entry.reason });
      continue;
    }
    try {
      ranges.update(entry.source.id, entry.prefixes);
      result.updated.push({ id: entry.source.id, prefixes: entry.prefixes.length });
    } catch (error) {
      result.failed.push({ id: entry.source.id, reason: error instanceof Error ? error.message : String(error) });
    }
  }
  return result;
}

export interface ScheduleOptions extends RefreshOptions {
  /** How often to refresh. Default 12 hours; at least one hour. */
  intervalMs?: number;
  /** Fetch now as well as on the interval. Default true. */
  immediate?: boolean;
  /** Called after every refresh, with what changed and what failed. */
  onRefresh?: (result: RefreshResult) => void;
}

/**
 * Refreshes on a schedule and returns the way to stop. Twice a day by default: these lists
 * change over weeks, and polling somebody else's endpoint more often is rude to both sides.
 * The timer never keeps the process alive.
 */
export function startCrawlerRangeRefresh(ranges: CrawlerRanges, options: ScheduleOptions = {}): () => void {
  const intervalMs = Math.max(60 * 60_000, options.intervalMs ?? 12 * 60 * 60_000);
  const run = (): void => {
    refreshCrawlerRanges(ranges, options)
      .then((result) => options.onRefresh?.(result))
      .catch(() => undefined);
  };
  if (options.immediate !== false) run();
  const timer = setInterval(run, intervalMs);
  timer.unref();
  return () => clearInterval(timer);
}
