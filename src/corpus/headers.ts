import type { CaseRequest } from "./schema.js";

/**
 * Header profiles for real clients, in the order each engine actually sends them.
 *
 * Three things here are load-bearing and easy to get wrong when writing fixtures by hand.
 *
 * **Order.** Each engine emits headers in a fixed sequence that differs between Chromium,
 * Gecko and WebKit and barely moves across releases. It is one of the few properties a
 * scraper cannot fix by copying a User-Agent, so a corpus that invents an order is
 * testing a client that does not exist — and `client-anomaly`, `header-integrity` and the
 * actor fingerprint all read from it.
 *
 * **Completeness.** A real browser sends a whole cluster together: content negotiation,
 * the `Sec-Fetch-*` set, the Client Hints on Chromium. Dropping one because it seemed
 * unimportant turns a human fixture into a bot fixture and quietly inverts what the case
 * proves — a "Chrome" missing every `Accept-*` header is exactly what `client-anomaly`
 * fires on.
 *
 * **HTTP clients send little, in their own order.** `python-requests` puts
 * `Accept-Encoding` before `Accept`; Go's client emits a bare pair; curl sends
 * `Host, User-Agent, Accept` and nothing else. Those orders are the fixtures' whole
 * point, so they are reproduced rather than normalised.
 *
 * Sources: 2026 User-Agent lists; W3C `TR/fetch-metadata` for the `Sec-Fetch-*`
 * combinations; the UA Client Hints specification for the `Sec-CH-*` set; each client
 * library's own defaults and observed request captures.
 */

export type Header = readonly [name: string, value: string];

/** Whatever else a case needs to say about the request that the header set does not. */
export interface BrowserOptions {
  /** Path plus query on the request line. Default `"/"`. */
  path?: string;
  host?: string;
  /** `Cookie` header value — a browsing session carries its jar. */
  cookie?: string;
  referer?: string;
  origin?: string;
  /** Overrides the profile's default `Accept-Language` — a real setting people change. */
  acceptLanguage?: string;
  /** What sort of fetch this is; decides the `Sec-Fetch-*` set and the `Accept` value. */
  kind?: RequestKind;
  /** `DNT: 1`, still sent by a meaningful minority. */
  dnt?: boolean;
  /** `Sec-GPC: 1` — Global Privacy Control, sent by Brave, DuckDuckGo and others. */
  gpc?: boolean;
  /** Response status the app gave, threaded through for the path-enumeration case. */
  status?: number;
  /** Milliseconds after the case start, for a request in a paced session. */
  atMs?: number;
  /** Which of the case's source addresses this request comes from. */
  from?: number;
  /** Request body, for a form or XHR POST. */
  body?: string;
  /** Overrides the method (a `form-post` kind already implies POST). */
  method?: string;
}

/** What kind of request this is. A document navigation, or a subresource a page pulled in. */
export type RequestKind = "navigate" | "same-origin-navigate" | "cross-site-navigate" | "form-post" | "xhr" | "subresource" | "stylesheet" | "script";

const HOST = "shop.example";

interface EngineProfile {
  userAgent: string;
  acceptDocument: string;
  acceptEncoding: string;
  acceptLanguage: string;
  secChUa?: string;
  secChUaPlatform?: string;
  mobile?: boolean;
  build: (self: EngineProfile, opts: Resolved) => Header[];
}

type Resolved = Required<Pick<BrowserOptions, "host" | "kind" | "acceptLanguage">> & BrowserOptions;

const CHROME_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
const FIREFOX_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8";
const SAFARI_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

function acceptFor(kind: RequestKind, documentAccept: string): string {
  switch (kind) {
    case "xhr":
    case "script":
      return "*/*";
    case "subresource":
      return "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8";
    case "stylesheet":
      return "text/css,*/*;q=0.1";
    default:
      return documentAccept;
  }
}

/** Fetch Metadata, per W3C TR/fetch-metadata. Grouped Site, Mode, User, Dest as Chromium emits them. */
function fetchMetadata(kind: RequestKind): Header[] {
  switch (kind) {
    case "navigate":
      return [["Sec-Fetch-Site", "none"], ["Sec-Fetch-Mode", "navigate"], ["Sec-Fetch-User", "?1"], ["Sec-Fetch-Dest", "document"]];
    case "same-origin-navigate":
      return [["Sec-Fetch-Site", "same-origin"], ["Sec-Fetch-Mode", "navigate"], ["Sec-Fetch-User", "?1"], ["Sec-Fetch-Dest", "document"]];
    case "cross-site-navigate":
      return [["Sec-Fetch-Site", "cross-site"], ["Sec-Fetch-Mode", "navigate"], ["Sec-Fetch-User", "?1"], ["Sec-Fetch-Dest", "document"]];
    case "form-post":
      return [["Sec-Fetch-Site", "same-origin"], ["Sec-Fetch-Mode", "navigate"], ["Sec-Fetch-User", "?1"], ["Sec-Fetch-Dest", "document"]];
    case "xhr":
      return [["Sec-Fetch-Site", "same-origin"], ["Sec-Fetch-Mode", "cors"], ["Sec-Fetch-Dest", "empty"]];
    case "subresource":
      return [["Sec-Fetch-Site", "same-origin"], ["Sec-Fetch-Mode", "no-cors"], ["Sec-Fetch-Dest", "image"]];
    case "stylesheet":
      return [["Sec-Fetch-Site", "same-origin"], ["Sec-Fetch-Mode", "no-cors"], ["Sec-Fetch-Dest", "style"]];
    case "script":
      return [["Sec-Fetch-Site", "same-origin"], ["Sec-Fetch-Mode", "no-cors"], ["Sec-Fetch-Dest", "script"]];
  }
}

const isNavigation = (kind: RequestKind): boolean => kind.endsWith("navigate") || kind === "form-post";

function privacyTail(opts: BrowserOptions): Header[] {
  const tail: Header[] = [];
  if (opts.gpc === true) tail.push(["Sec-GPC", "1"]);
  if (opts.dnt === true) tail.push(["DNT", "1"]);
  return tail;
}

/**
 * Chromium's order: connection management, then the Client Hints block, then identity,
 * then content negotiation split either side of the Fetch Metadata group.
 */
function chromiumBuild(self: EngineProfile, opts: Resolved): Header[] {
  const nav = isNavigation(opts.kind);
  return [
    ["Host", opts.host],
    ["Connection", "keep-alive"],
    ["sec-ch-ua", self.secChUa ?? ""],
    ["sec-ch-ua-mobile", self.mobile ? "?1" : "?0"],
    ["sec-ch-ua-platform", `"${self.secChUaPlatform ?? "Windows"}"`],
    ...(nav ? ([["Upgrade-Insecure-Requests", "1"]] as Header[]) : []),
    ["User-Agent", self.userAgent],
    ...(opts.origin !== undefined ? ([["Origin", opts.origin]] as Header[]) : []),
    ["Accept", acceptFor(opts.kind, self.acceptDocument)],
    ...fetchMetadata(opts.kind),
    ...(opts.referer !== undefined ? ([["Referer", opts.referer]] as Header[]) : []),
    ["Accept-Encoding", self.acceptEncoding],
    ["Accept-Language", opts.acceptLanguage],
    ...privacyTail(opts),
    ["Priority", nav ? "u=0, i" : "u=1, i"],
    ...(opts.cookie !== undefined ? ([["Cookie", opts.cookie]] as Header[]) : []),
  ];
}

/** Firefox leads with identity and content negotiation, and closes with Fetch Metadata. */
function geckoBuild(self: EngineProfile, opts: Resolved): Header[] {
  const nav = isNavigation(opts.kind);
  const metadata = new Map(fetchMetadata(opts.kind));
  const order = ["Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User"];
  return [
    ["Host", opts.host],
    ["User-Agent", self.userAgent],
    ["Accept", acceptFor(opts.kind, self.acceptDocument)],
    ["Accept-Language", opts.acceptLanguage],
    ["Accept-Encoding", self.acceptEncoding],
    ...(opts.referer !== undefined ? ([["Referer", opts.referer]] as Header[]) : []),
    ...(opts.origin !== undefined ? ([["Origin", opts.origin]] as Header[]) : []),
    ...privacyTail(opts),
    ["Connection", "keep-alive"],
    ...(opts.cookie !== undefined ? ([["Cookie", opts.cookie]] as Header[]) : []),
    ...(nav ? ([["Upgrade-Insecure-Requests", "1"]] as Header[]) : []),
    // Gecko emits Dest, Mode, Site, User — the reverse of Chromium's grouping.
    ...(order.flatMap((name) => (metadata.has(name) ? [[name, metadata.get(name)!] as Header] : [])) as Header[]),
  ];
}

/** Safari interleaves Fetch Metadata with content negotiation rather than grouping it. */
function webkitBuild(self: EngineProfile, opts: Resolved): Header[] {
  const metadata = new Map(fetchMetadata(opts.kind));
  const one = (name: string): Header[] => (metadata.has(name) ? [[name, metadata.get(name)!] as Header] : []);
  return [
    ["Host", opts.host],
    ["Connection", "keep-alive"],
    ...one("Sec-Fetch-Dest"),
    ["User-Agent", self.userAgent],
    ...(opts.origin !== undefined ? ([["Origin", opts.origin]] as Header[]) : []),
    ["Accept", acceptFor(opts.kind, self.acceptDocument)],
    ...one("Sec-Fetch-Site"),
    ["Accept-Language", opts.acceptLanguage],
    ...one("Sec-Fetch-Mode"),
    ["Accept-Encoding", self.acceptEncoding],
    ...one("Sec-Fetch-User"),
    ...(opts.referer !== undefined ? ([["Referer", opts.referer]] as Header[]) : []),
    ...privacyTail(opts),
    ...(opts.cookie !== undefined ? ([["Cookie", opts.cookie]] as Header[]) : []),
  ];
}

/** The browser engines, each with a real User-Agent and its own header order. */
export const PROFILES = {
  chromeWindows: {
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
    acceptDocument: CHROME_ACCEPT,
    acceptEncoding: "gzip, deflate, br, zstd",
    acceptLanguage: "en-US,en;q=0.9",
    secChUa: '"Not(A:Brand";v="99", "Google Chrome";v="152", "Chromium";v="152"',
    secChUaPlatform: "Windows",
    build: chromiumBuild,
  },
  chromeMac: {
    userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
    acceptDocument: CHROME_ACCEPT,
    acceptEncoding: "gzip, deflate, br, zstd",
    acceptLanguage: "en-GB,en-US;q=0.9,en;q=0.8",
    secChUa: '"Not(A:Brand";v="99", "Google Chrome";v="152", "Chromium";v="152"',
    secChUaPlatform: "macOS",
    build: chromiumBuild,
  },
  chromeAndroid: {
    userAgent: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Mobile Safari/537.36",
    acceptDocument: CHROME_ACCEPT,
    acceptEncoding: "gzip, deflate, br, zstd",
    acceptLanguage: "en-GB,en;q=0.9",
    secChUa: '"Not(A:Brand";v="99", "Google Chrome";v="150", "Chromium";v="150"',
    secChUaPlatform: "Android",
    mobile: true,
    build: chromiumBuild,
  },
  edgeWindows: {
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0",
    acceptDocument: CHROME_ACCEPT,
    acceptEncoding: "gzip, deflate, br, zstd",
    acceptLanguage: "en-US,en;q=0.9",
    secChUa: '"Microsoft Edge";v="150", "Not(A:Brand";v="24", "Chromium";v="150"',
    secChUaPlatform: "Windows",
    build: chromiumBuild,
  },
  firefoxWindows: {
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0",
    acceptDocument: FIREFOX_ACCEPT,
    acceptEncoding: "gzip, deflate, br, zstd",
    acceptLanguage: "en-US,en;q=0.5",
    build: geckoBuild,
  },
  firefoxAndroid: {
    userAgent: "Mozilla/5.0 (Android 15; Mobile; rv:148.0) Gecko/148.0 Firefox/148.0",
    acceptDocument: FIREFOX_ACCEPT,
    acceptEncoding: "gzip, deflate, br, zstd",
    acceptLanguage: "en-GB,en;q=0.5",
    build: geckoBuild,
  },
  safariMac: {
    userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7 Safari/605.1.15",
    acceptDocument: SAFARI_ACCEPT,
    acceptEncoding: "gzip, deflate, br",
    acceptLanguage: "en-GB,en;q=0.9",
    build: webkitBuild,
  },
  safariIos: {
    userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7 Mobile/15E148 Safari/604.1",
    acceptDocument: SAFARI_ACCEPT,
    acceptEncoding: "gzip, deflate, br",
    acceptLanguage: "en-US,en;q=0.9",
    build: webkitBuild,
  },
  samsungInternet: {
    userAgent: "Mozilla/5.0 (Linux; Android 15; SM-S938B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/29.0 Chrome/147.0.0.0 Mobile Safari/537.36",
    acceptDocument: CHROME_ACCEPT,
    acceptEncoding: "gzip, deflate, br",
    acceptLanguage: "en-US,en;q=0.9",
    secChUa: '"Chromium";v="147", "Not(A:Brand";v="24", "Samsung Internet";v="29.0"',
    secChUaPlatform: "Android",
    mobile: true,
    build: chromiumBuild,
  },
} as const satisfies Record<string, EngineProfile>;

export type ProfileName = keyof typeof PROFILES;
export const PROFILE_NAMES = Object.keys(PROFILES) as ProfileName[];

/** The raw User-Agent of a profile, for cases that alter it deliberately. */
export function userAgentOf(name: ProfileName): string {
  return PROFILES[name].userAgent;
}

/**
 * Builds a request from a named browser profile — the normal way to write a human case.
 *
 * The header order is the engine's real one; `path`, `cookie`, `referer`, `kind` and the
 * rest are the parts a case varies. A `form-post` kind also flips the method to POST.
 */
export function browser(name: ProfileName, options: BrowserOptions = {}): CaseRequest {
  const profile = PROFILES[name] as EngineProfile;
  const resolved: Resolved = {
    ...options,
    host: options.host ?? HOST,
    kind: options.kind ?? "navigate",
    acceptLanguage: options.acceptLanguage ?? profile.acceptLanguage,
  };
  return {
    headers: profile.build(profile, resolved),
    httpVersion: "1.1",
    ...(options.path !== undefined ? { path: options.path } : {}),
    ...(options.method !== undefined ? { method: options.method } : options.kind === "form-post" ? { method: "POST" } : {}),
    ...(options.body !== undefined ? { body: options.body } : {}),
    ...(options.from !== undefined ? { from: options.from } : {}),
    ...(options.atMs !== undefined ? { atMs: options.atMs } : {}),
    ...(options.status !== undefined ? { status: options.status } : {}),
  };
}

// --- HTTP clients, in their real header orders -------------------------------

/**
 * Common HTTP libraries and CLI clients, each sending exactly what it sends by default —
 * a short list, in its own order. These back the tooling cases and are reused wherever a
 * hostile case needs a plausible non-browser client rather than a hand-invented one.
 */
export const CLIENTS = {
  /** curl: Host, User-Agent, Accept, and nothing else. */
  curl: [["Host", HOST], ["User-Agent", "curl/8.7.1"], ["Accept", "*/*"]],
  wget: [["Host", HOST], ["User-Agent", "Wget/1.21.4"], ["Accept", "*/*"], ["Accept-Encoding", "identity"], ["Connection", "Keep-Alive"]],
  /** python-requests emits Accept-Encoding BEFORE Accept — a real, characteristic order. */
  pythonRequests: [["Host", HOST], ["User-Agent", "python-requests/2.32.3"], ["Accept-Encoding", "gzip, deflate"], ["Accept", "*/*"], ["Connection", "keep-alive"]],
  pythonUrllib: [["Accept-Encoding", "identity"], ["Host", HOST], ["User-Agent", "Python-urllib/3.12"], ["Connection", "close"]],
  goHttp: [["Host", HOST], ["User-Agent", "Go-http-client/2.0"], ["Accept-Encoding", "gzip"]],
  okhttp: [["Host", HOST], ["User-Agent", "okhttp/4.12.0"], ["Accept", "application/json"], ["Accept-Encoding", "gzip"], ["Connection", "keep-alive"]],
  /** Node's undici (fetch, axios' node adapter): a lowercase, minimal set. */
  nodeFetch: [["host", HOST], ["accept", "*/*"], ["accept-language", "*"], ["sec-fetch-mode", "cors"], ["user-agent", "node"], ["accept-encoding", "gzip, deflate"]],
  javaHttp: [["Host", HOST], ["User-Agent", "Java/21.0.2"], ["Accept", "*/*"], ["Connection", "keep-alive"]],
} as const satisfies Record<string, ReadonlyArray<Header>>;

export type ClientName = keyof typeof CLIENTS;

/** Builds a request from a named HTTP-client profile, appending any extra headers in order. */
export function client(name: ClientName, options: { path?: string; extra?: readonly Header[]; method?: string; body?: string; status?: number } = {}): CaseRequest {
  return {
    headers: [...CLIENTS[name], ...(options.extra ?? [])],
    httpVersion: "1.1",
    ...(options.path !== undefined ? { path: options.path } : {}),
    ...(options.method !== undefined ? { method: options.method } : {}),
    ...(options.body !== undefined ? { body: options.body } : {}),
    ...(options.status !== undefined ? { status: options.status } : {}),
  };
}

/**
 * A bare request with an arbitrary User-Agent and only the headers you name — the shape a
 * self-announcing bot or a crafted probe actually has. `extra` follows the defaults.
 */
export function plain(userAgent: string, extra: readonly Header[] = [], host = HOST): CaseRequest {
  const overridden = new Set(extra.map(([name]) => name.toLowerCase()));
  const defaults = ([["Host", host], ["User-Agent", userAgent], ["Accept", "*/*"]] as Header[]).filter(([name]) => !overridden.has(name.toLowerCase()));
  return { headers: [...defaults, ...extra], httpVersion: "1.1" };
}
