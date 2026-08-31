import http from "node:http";
import { describe, expect, it } from "vitest";
import { HoneypotEngine, HoneypotServer, honeytokenDetector } from "../src/index.js";
import type { HoneypotHit, RequestFacts } from "../src/index.js";
import type { EvaluationResult } from "../src/index.js";

/**
 * False-positive suite. It runs a corpus of *legitimate* traffic — real browser
 * and API-client requests — through the full default detector set and asserts
 * that nothing fires. A honeypot that flags real users is worse than useless, so
 * any detection here is a bug.
 */

const SEEDED_TOKEN = "AKIA_SEEDED_HONEYTOKEN_DO_NOT_USE_123";

// The exact production detector set, plus a seeded honeytoken that no legitimate
// request below contains.
function buildEngine(): HoneypotEngine {
  return new HoneypotEngine({
    extraDetectors: [honeytokenDetector({ tokens: [{ value: SEEDED_TOKEN, label: "seed" }] })],
  });
}

const UA = {
  chrome: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
  firefox: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
  safari: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
  iosSafari: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
  androidChrome: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
  googlebot: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
  slackbot: "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
  okhttp: "okhttp/4.12.0",
  postman: "PostmanRuntime/7.36.3",
} as const;

// The Accept headers every real browser sends on every request. Inline test
// requests include these so they read as genuine browser traffic (client-anomaly
// flags a browser UA that sends none of them).
const BROWSER = { accept: "text/html,application/xhtml+xml,*/*;q=0.8", "accept-language": "en-US,en;q=0.9", "accept-encoding": "gzip, deflate, br" } as const;

let ipCounter = 0;
function legit(partial: Partial<RequestFacts> & Pick<RequestFacts, "path"> & { label?: string }): RequestFacts {
  const headers: Record<string, string> = {
    host: "myapp.com",
    "user-agent": UA.chrome,
    accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.9",
    ...(partial.headers as Record<string, string> | undefined),
  };
  return { method: "GET", query: {}, ip: `198.51.100.${(ipCounter++ % 250) + 1}`, ...partial, headers };
}

// --- the corpus: realistic legitimate requests -----------------------------
const CORPUS: Array<Partial<RequestFacts> & Pick<RequestFacts, "path"> & { label: string }> = [
  // Pages & navigation
  { label: "home", path: "/" },
  { label: "about", path: "/about" },
  { label: "pricing", path: "/pricing" },
  { label: "blog post", path: "/blog/how-we-scaled-to-a-million-users" },
  { label: "docs", path: "/docs/getting-started" },
  { label: "contact", path: "/contact" },

  // Static assets (stress sensitive-file / web-shell without matching them)
  { label: "favicon", path: "/favicon.ico" },
  { label: "robots", path: "/robots.txt" },
  { label: "sitemap", path: "/sitemap.xml" },
  { label: "hashed js bundle", path: "/static/js/app.4f3a2b9c.js" },
  { label: "css", path: "/static/css/main.css" },
  { label: "retina image", path: "/assets/images/hero@2x.png" },
  { label: "web font", path: "/assets/fonts/inter-var.woff2" },
  { label: "spa runtime config", path: "/assets/config.json" },
  { label: "well-known security.txt", path: "/.well-known/security.txt" },
  { label: "apple app site assoc", path: "/.well-known/apple-app-site-association" },
  { label: "wp legit upload (image)", path: "/wp-content/uploads/2024/03/team-photo.jpg" },
  { label: "media file", path: "/media/videos/product-intro.mp4" },
  { label: "user avatar", path: "/images/avatars/user-42.png" },

  // Downloads with report-ish names
  { label: "pdf invoice", path: "/download/invoice-2024-Q1.pdf" },
  { label: "csv export", path: "/exports/sales-report.csv" },
  { label: "pptx", path: "/files/quarterly-deck.pptx" },

  // API — GET with query strings that superficially resemble payloads but aren't
  { label: "paginated list", path: "/api/v1/users", query: { page: "2", per_page: "50" } },
  { label: "filtered products", path: "/api/v1/products", query: { category: "home-garden", sort: "price_desc", in_stock: "true" } },
  { label: "search 'union station'", path: "/api/v1/search", query: { q: "union station apartments" } },
  { label: "search 'select rows in sql'", path: "/api/v1/search", query: { q: "how to select all rows in sql" } },
  { label: "search 'drop off'", path: "/api/v1/search", query: { q: "drop off locations near me" } },
  { label: "search apostrophe", path: "/api/v1/search", query: { q: "O'Brien & Sons Ltd." } },
  { label: "search with angle bracket", path: "/api/v1/search", query: { q: "2 < 3 is true" } },
  { label: "resource by id", path: "/api/orders/12345" },
  { label: "email in query", path: "/api/v1/invite", query: { email: "john.doe@example.com" } },
  // NoSQL-detector stressors that are legitimate: array-style bracket params, a $-price, JSON $ref/$schema
  { label: "array-style filter params", path: "/api/v1/products", query: { "filter[category]": "books", "filter[price][min]": "10", "sort[]": "title" } },
  { label: "price with dollar sign", path: "/api/v1/search", query: { q: "under $50 shipping" } },
  { label: "search discussing constructor/prototype (prose, not key access)", path: "/api/v1/search", query: { q: "how does the constructor and prototype chain work in javascript" } },
  { label: "legit base64 value (not a serialization magic)", path: "/api/v1/asset", query: { data: "eyJ0aGVtZSI6ImRhcmsiLCJsYW5nIjoiZW4ifQ==" } },
  { label: "POST with JSON Schema $ref/$schema", method: "POST", path: "/api/v1/validate", body: JSON.stringify({ $schema: "https://json-schema.org/draft/2020-12/schema", properties: { name: { $ref: "#/defs/name" } } }), headers: { "content-type": "application/json" } },
  // A JSON string that merely ends in `}()` is ordinary content for a template or
  // config API — and is not a node-serialize payload, which only executes via the
  // `_$$ND_FUNC$$_` marker. This used to score 9 for insecure-deserialization.
  { label: "template config holding an IIFE string", method: "POST", path: "/api/v1/templates", body: JSON.stringify({ transform: "function(v){return v*2}()" }), headers: { "content-type": "application/json" } },
  { label: "CMS field holding an analytics snippet", method: "POST", path: "/api/v1/pages", body: JSON.stringify({ html: "<div></div>", init: "(function(){window.dataLayer=[]})()" }), headers: { "content-type": "application/json" } },

  // Redirect params — legitimate same-site / relative targets
  { label: "relative next", path: "/login", query: { next: "/dashboard" } },
  { label: "same-site absolute redirect_uri", path: "/oauth/authorize", query: { redirect_uri: "https://myapp.com/callback", client_id: "abc" } },
  { label: "relative returnTo", path: "/signout", query: { returnTo: "/goodbye" } },
  { label: "oauth callback", path: "/auth/callback", query: { code: "4/0AeaYSHb-xyz", state: "csrf123" } },

  // Non-GET methods (all normal verbs)
  { label: "POST order", method: "POST", path: "/api/orders", body: JSON.stringify({ items: [{ sku: "ABC-1", qty: 2 }], note: "leave at the door" }), headers: { "content-type": "application/json" } },
  { label: "POST comment with URL + entities", method: "POST", path: "/api/comments", body: JSON.stringify({ body: "Great write-up! More at https://example.com/ref — and 2 < 3 always." }), headers: { "content-type": "application/json" } },
  { label: "PUT user", method: "PUT", path: "/api/users/42", body: JSON.stringify({ name: "Alice", bio: "Loves SQL & coffee" }), headers: { "content-type": "application/json" } },
  { label: "PATCH settings", method: "PATCH", path: "/api/settings", body: JSON.stringify({ theme: "dark" }), headers: { "content-type": "application/json" } },
  { label: "DELETE session", method: "DELETE", path: "/api/sessions/current" },
  { label: "HEAD health", method: "HEAD", path: "/api/health" },
  { label: "OPTIONS preflight", method: "OPTIONS", path: "/api/orders", headers: { "access-control-request-method": "POST" } },

  // Headers that stress the header-scanning detectors
  { label: "proxied request (internal IP in XFF)", path: "/api/data", headers: { "x-forwarded-for": "10.0.0.5, 203.0.113.9" } },
  { label: "legit referer", path: "/checkout", headers: { referer: "https://myapp.com/cart" } },
  { label: "legit cookies", path: "/dashboard", headers: { cookie: "session=9c2b; theme=dark; _ga=GA1.2.123456.789" } },
  { label: "legit bearer JWT", path: "/api/me", headers: { authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9.sig" } },

  // Various legitimate clients
  { label: "firefox", path: "/", headers: { "user-agent": UA.firefox } },
  { label: "safari", path: "/", headers: { "user-agent": UA.safari } },
  { label: "ios safari", path: "/", headers: { "user-agent": UA.iosSafari } },
  { label: "android chrome", path: "/", headers: { "user-agent": UA.androidChrome } },
  { label: "googlebot", path: "/blog", headers: { "user-agent": UA.googlebot } },
  { label: "slackbot link preview", path: "/blog/how-we-scaled-to-a-million-users", headers: { "user-agent": UA.slackbot } },
  { label: "mobile app (okhttp)", path: "/api/v1/feed", headers: { "user-agent": UA.okhttp } },
  { label: "postman", path: "/api/v1/status", headers: { "user-agent": UA.postman } },
];

describe("no false positives on legitimate traffic", () => {
  it("fires nothing across the whole legitimate corpus", async () => {
    const engine = buildEngine();
    const failures: string[] = [];
    for (const req of CORPUS) {
      const result = await engine.evaluate(legit(req));
      if (result.detections.length > 0) {
        failures.push(`"${req.label}" (${req.method ?? "GET"} ${req.path}) → ${result.detections.map((d) => `${d.detectorId}: ${d.reason}`).join("; ")}`);
      }
    }
    expect(failures, `\n${failures.join("\n")}\n`).toHaveLength(0);
  });

  it("a normal browsing session does not trip path-bruteforce", async () => {
    const engine = buildEngine();
    const ip = "203.0.113.50";
    const pages = ["/", "/about", "/pricing", "/blog", "/docs", "/features", "/contact", "/login", "/dashboard", "/settings", "/help", "/changelog"]; // 12 distinct < 15
    let last: EvaluationResult | undefined;
    for (const path of pages) last = await engine.evaluate({ method: "GET", path, query: {}, headers: { host: "myapp.com", "user-agent": UA.chrome, ...BROWSER }, ip });
    expect(last?.detections ?? []).toHaveLength(0);
  });

  it("a normal user logging in does not trip credential-bruteforce", async () => {
    const engine = buildEngine();
    const ip = "203.0.113.51";
    let last: EvaluationResult | undefined;
    for (let i = 0; i < 3; i++) {
      last = await engine.evaluate({ method: "POST", path: "/login", query: {}, headers: { host: "myapp.com", "user-agent": UA.chrome, "content-type": "application/x-www-form-urlencoded", ...BROWSER }, ip, body: "username=alice&password=correct-horse" });
    }
    expect(last?.detections ?? []).toHaveLength(0);
  });

  it("normal request volume does not trip rate-spike", async () => {
    const engine = buildEngine();
    const ip = "203.0.113.52";
    let last: EvaluationResult | undefined;
    for (let i = 0; i < 45; i++) last = await engine.evaluate({ method: "GET", path: "/api/v1/feed", query: { cursor: String(i) }, headers: { host: "myapp.com", "user-agent": UA.chrome, ...BROWSER }, ip }); // 45 < 60/10s
    expect(last?.detections ?? []).toHaveLength(0);
  });
});

describe("no false positives over real HTTP connections", () => {
  it("a realistic browsing session through HoneypotServer records zero incidents", async () => {
    const hits: HoneypotHit[] = [];
    const server = new HoneypotServer({ trustProxy: true, onHit: (h) => { hits.push(h); } });
    await server.listen(0);
    const port = (server.address() as { port: number }).port;

    // Each request is a different legitimate user (distinct X-Forwarded-For), so
    // no stateful detector accumulates across them.
    const requests: Array<{ method: string; path: string; headers?: Record<string, string>; body?: string }> = [
      { method: "GET", path: "/" },
      { method: "GET", path: "/favicon.ico" },
      { method: "GET", path: "/static/js/app.9f8e.js" },
      { method: "GET", path: "/assets/logo.svg" },
      { method: "GET", path: "/api/v1/products?category=books&sort=title" },
      { method: "GET", path: `/api/v1/search?q=${encodeURIComponent("union station cafe")}` },
      { method: "GET", path: `/login?next=${encodeURIComponent("/account")}` },
      { method: "GET", path: `/oauth/authorize?redirect_uri=${encodeURIComponent("https://myapp.com/cb")}&client_id=x`, headers: { host: "myapp.com" } },
      { method: "POST", path: "/api/orders", headers: { "content-type": "application/json" }, body: JSON.stringify({ sku: "A1", qty: 1 }) },
      { method: "GET", path: "/wp-content/uploads/2024/01/photo.jpg" },
      { method: "HEAD", path: "/api/health" },
      { method: "OPTIONS", path: "/api/orders" },
    ];

    for (let i = 0; i < requests.length; i++) {
      const r = requests[i]!;
      await new Promise<void>((resolve, reject) => {
        const req = http.request(
          { port, method: r.method, path: r.path, headers: { host: "myapp.com", "user-agent": UA.chrome, ...BROWSER, "x-forwarded-for": `198.51.100.${i + 1}`, ...r.headers } },
          (res) => { res.on("data", () => {}); res.on("end", () => resolve()); },
        );
        req.on("error", reject);
        if (r.body) req.write(r.body);
        req.end();
      });
    }

    await server.close();
    expect(hits.map((h) => `${h.method} ${h.path} → ${h.detections.map((d) => d.detectorId).join(",")}`)).toEqual([]);
  });
});
