import net from "node:net";
import type { IpAllowlist } from "../allowlist.js";
import type { Blocklist } from "../blocklist.js";

export interface FetchIocOptions {
  /** Sent as `Authorization: Bearer <key>` — feeds are usually behind the management API's auth. */
  apiKey?: string;
  /** Abort the fetch after this long. Default 10000. */
  timeoutMs?: number;
  /** Hard cap on the response body read, in bytes — a runaway feed can't OOM the poller. Default 2 MB. */
  maxBytes?: number;
  /** Injected for tests; defaults to the global `fetch`. */
  fetch?: typeof fetch;
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

/** Redirect hops followed before giving up — each one re-validated. */
const MAX_REDIRECTS = 3;

function isRedirect(res: Response): boolean {
  return res.status >= 300 && res.status < 400;
}

/**
 * The transport rail for a feed URL: https, or plaintext only to a loopback host.
 * Applied to the configured URL *and* to every redirect hop, so the rule cannot be
 * escaped by a feed that answers with a `Location:` pointing somewhere else.
 */
function assertFeedUrlAllowed(url: string): void {
  const parsed = new URL(url);
  const host = parsed.hostname.toLowerCase();
  if (parsed.protocol !== "https:" && !LOOPBACK_HOSTS.has(host) && !LOOPBACK_HOSTS.has(parsed.host.toLowerCase())) {
    throw new Error(`refusing to fetch IOC feed over ${parsed.protocol} (https required except for loopback): ${url}`);
  }
}

/** scheme + host + port — the unit that decides who may see the `Authorization` header. */
function originOf(url: string): string {
  const parsed = new URL(url);
  return `${parsed.protocol}//${parsed.host}`;
}

/**
 * Fetches a peer honeypot's `/ioc.txt` feed and returns the source IPs it lists.
 *
 * A threat feed is as trusted as root on this host — whoever controls its contents can
 * decide which IPs you block — so this is deliberately defensive: it requires **https**
 * (plaintext is allowed only for a loopback host, for local testing and same-box peers),
 * bounds the response body so a 2 GB reply can't exhaust memory, and times out. It does
 * NOT block anything itself — parsing is separated from applying so the caller stays in
 * control of provenance (see `applyIocEntries`).
 */
export async function fetchIocFeed(url: string, options: FetchIocOptions = {}): Promise<string[]> {
  assertFeedUrlAllowed(url);
  const doFetch = options.fetch ?? fetch;
  const maxBytes = options.maxBytes ?? 2 * 1024 * 1024;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 10_000);
  try {
    const headers: Record<string, string> = {};
    if (options.apiKey) headers["Authorization"] = `Bearer ${options.apiKey}`;
    // `redirect: "manual"` — never let the transport rail be redirected away.
    // Following redirects silently (fetch's default) meant the https requirement
    // applied only to the URL we typed: a feed could answer 302 and send us to
    // plaintext http, or to a link-local address like 169.254.169.254, and the reply
    // that decides which IPs we block would arrive over a channel we explicitly
    // refused. Each hop is re-checked against the same rule instead.
    //
    // Following redirects by hand means we also inherit the duty the platform was
    // discharging for us: `fetch` (and curl, and every browser) STRIPS `Authorization`
    // when a redirect crosses to another origin. Re-sending it by hand would have made
    // any feed able to harvest the operator's key — answer `302 Location: https://
    // attacker.example/` and the next request hands over `Authorization: Bearer <key>`.
    // That key is usually a *management API* key (feeds are peer honeypots behind the
    // same auth), so the leak is not read access to a public IOC list, it is read access
    // to the operator's captured-incident API. The origin is therefore re-derived at each
    // hop and the header dropped the moment it changes.
    let current = url;
    let origin = originOf(url);
    let res = await doFetch(current, { headers, signal: controller.signal, redirect: "manual" });
    for (let hop = 0; isRedirect(res) && hop < MAX_REDIRECTS; hop += 1) {
      const location = res.headers.get("location");
      if (!location) break;
      const next = new URL(location, current).toString();
      assertFeedUrlAllowed(next);
      // Same-origin hops keep the credential; anything else gets an anonymous request.
      const hopHeaders = originOf(next) === origin ? headers : {};
      current = next;
      origin = originOf(next);
      res = await doFetch(current, { headers: hopHeaders, signal: controller.signal, redirect: "manual" });
    }
    if (isRedirect(res)) throw new Error(`IOC feed ${url}: too many redirects`);
    if (!res.ok) throw new Error(`IOC feed ${url} returned ${res.status}`);
    const text = await readCapped(res, maxBytes);
    return parseIps(text);
  } finally {
    clearTimeout(timer);
  }
}

/** Read a response body up to `maxBytes`, then stop — never buffer an unbounded stream. */
async function readCapped(res: Response, maxBytes: number): Promise<string> {
  if (!res.body) return (await res.text()).slice(0, maxBytes);
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let out = "";
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    const remaining = maxBytes - total;
    // Truncate an oversized chunk to the remaining budget — a single huge chunk must
    // not blow past the cap — then stop.
    if (value.byteLength >= remaining) {
      out += decoder.decode(value.subarray(0, remaining));
      await reader.cancel();
      break;
    }
    total += value.byteLength;
    out += decoder.decode(value, { stream: true });
  }
  // Flush any partial multi-byte sequence the stream ended on.
  return out + decoder.decode();
}

/** One IP per line (the `/ioc.txt` shape); ignores blanks, comments, and anything that isn't an IP. */
export function parseIps(text: string): string[] {
  const ips: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const ip = line.trim();
    if (!ip || ip.startsWith("#")) continue;
    if (net.isIP(ip) !== 0) ips.push(ip);
  }
  return ips;
}

export interface ApplyIocOptions {
  /**
   * Where ingested blocks are written. For safe provenance this must be a
   * **non-enforcing** blocklist (e.g. the `feed` child of a `CompositeBlocklist`) so
   * hearsay from a feed short-circuits requests here but never reaches the firewall
   * enforcer. Only pass an enforcing blocklist if the operator has explicitly opted in.
   */
  blocklist: Blocklist;
  /** The engine's allowlist — consulted BEFORE every ingested block, always. */
  allowlist: IpAllowlist;
  /** How long an ingested block lasts, in ms. Default 3600000 (1h) — hearsay expires. */
  ttlMs?: number;
  /** Hard cap on IPs applied per call — a poisoned or runaway feed can't grow the blocklist without bound. Default 10000. */
  maxEntries?: number;
  /**
   * Called if a `block()` rejects — relevant when `blocklist` is async (e.g. a
   * `RedisBlocklist` under an explicit enforce opt-in) and its backend is unreachable.
   * Without this the rejected promise is unhandled, which terminates the process on the
   * exact path an operator hardened; wire it to your log channel.
   */
  onError?: (error: Error) => void;
  now?: number;
}

export interface ApplyIocResult {
  blocked: number;
  skippedAllowlisted: number;
  skippedInvalid: number;
  /** Set to the cap when the feed exceeded `maxEntries` and was truncated. */
  cappedAt?: number;
}

/**
 * Applies fetched IOC IPs to a blocklist, enforcing the non-negotiable ingest rules:
 * every IP is checked against the **allowlist first** (so a poisoned feed can never take
 * out your own monitoring / office ranges — there is deliberately no option to disable
 * this), invalid entries are dropped, and no more than `maxEntries` are applied. Blocks
 * are TTL'd so stale hearsay ages out on its own.
 */
export function applyIocEntries(ips: string[], options: ApplyIocOptions): ApplyIocResult {
  const ttl = options.ttlMs ?? 3_600_000;
  const maxEntries = options.maxEntries ?? 10_000;
  const now = options.now ?? Date.now();
  const until = now + ttl;

  const result: ApplyIocResult = { blocked: 0, skippedAllowlisted: 0, skippedInvalid: 0 };
  const seen = new Set<string>();
  for (const raw of ips) {
    if (result.blocked >= maxEntries) {
      result.cappedAt = maxEntries;
      break;
    }
    const ip = raw.trim();
    if (net.isIP(ip) === 0) {
      result.skippedInvalid += 1;
      continue;
    }
    if (seen.has(ip)) continue;
    seen.add(ip);
    // Allowlist is consulted before any ingested block — no exceptions.
    if (options.allowlist.allows(ip)) {
      result.skippedAllowlisted += 1;
      continue;
    }
    // block() may be async (e.g. RedisBlocklist); a rejection here must not become an
    // unhandled rejection that kills the process — route it to onError instead.
    Promise.resolve(options.blocklist.block(ip, until)).catch((e) => options.onError?.(e instanceof Error ? e : new Error(String(e))));
    result.blocked += 1;
  }
  return result;
}
