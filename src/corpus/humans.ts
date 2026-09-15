import { browser, plain } from "./headers.js";
import { human } from "./schema.js";
import type { Header } from "./headers.js";
import type { TrafficCase } from "./schema.js";

/**
 * People.
 *
 * This is the most important file in the corpus. Every case here is an ordinary customer,
 * and the honeypot's whole promise is that none of them is caught in a decoy. The runner
 * enforces that as a hard rule — a human case with anything firing on it is a false
 * positive, reported first in the scorecard — so a new case here protects the library the
 * moment it is added, without anyone having to remember to write the assertion.
 *
 * The awkward cases are the point: privacy browsers, screen readers, corporate proxies
 * that strip headers, ten-year-old shared addresses. If a detector cannot tell one of
 * these from an attacker, that is a bug to fix in the detector, not a case to delete. The
 * one honest exception is `/wp-login.php`, which is a decoy path: a WordPress author who
 * hits it *is* caught, and the corpus records that as a known cost rather than pretending
 * otherwise.
 */

const CART_COOKIE = "session=8f3a2b1c9d4e5f60; cart=3; _ga=GA1.2.1957212345.1747300000; ln_pref=en";

export const HUMAN_CASES: TrafficCase[] = [
  // ---------------------------------------------------------------------------
  // Mainstream browsers loading a page. If any of these ever fires, stop and fix
  // it before anything else in the library.
  // ---------------------------------------------------------------------------
  human({
    id: "chrome-first-page-load",
    title: "Chrome on Windows loading a page and its assets",
    category: "page-load",
    provenance: "A server-rendered page and the subresources a browser pulls for it, in Chromium's header order",
    requests: [
      browser("chromeWindows", { path: "/", kind: "navigate" }),
      browser("chromeWindows", { path: "/assets/app.css", kind: "stylesheet", referer: "https://shop.example/", atMs: 40 }),
      browser("chromeWindows", { path: "/assets/app.js", kind: "script", referer: "https://shop.example/", atMs: 45 }),
      browser("chromeWindows", { path: "/images/hero.avif", kind: "subresource", referer: "https://shop.example/", atMs: 60 }),
      browser("chromeWindows", { path: "/favicon.ico", kind: "subresource", referer: "https://shop.example/", atMs: 70 }),
      browser("chromeWindows", { path: "/api/v1/session", kind: "xhr", referer: "https://shop.example/", atMs: 120 }),
    ].map((request, index) => ({ ...request, atMs: index * 30 })),
    expect: { neverDetectors: ["client-anomaly", "header-anomaly", "rate-spike", "path-bruteforce"] },
  }),
  human({ id: "chrome-mac-home", title: "Chrome on macOS opening the homepage", category: "page-load", provenance: "2026 User-Agent lists", requests: [browser("chromeMac", { path: "/" })] }),
  human({ id: "edge-windows-home", title: "Edge on Windows opening a product page", category: "page-load", provenance: "Edge reports Chromium brands alongside Edg/", requests: [browser("edgeWindows", { path: "/products/42" })] }),
  human({ id: "firefox-windows-home", title: "Firefox on Windows opening the homepage", category: "page-load", provenance: "2026 User-Agent lists; Gecko sends no Client Hints and closes with Fetch Metadata", requests: [browser("firefoxWindows", { path: "/" })] }),
  human({ id: "safari-mac-home", title: "Safari on macOS opening a page", category: "page-load", provenance: "WebKit interleaves Sec-Fetch-* with content negotiation", requests: [browser("safariMac", { path: "/collections/new" })] }),
  human({ id: "safari-ios-home", title: "Safari on iPhone opening a page", category: "mobile", provenance: "More than half the web is mobile Safari", requests: [browser("safariIos", { path: "/" })] }),
  human({ id: "chrome-android-home", title: "Chrome on Android opening a page", category: "mobile", provenance: "Android UA frozen to 'Android 10; K' since Chrome 110", requests: [browser("chromeAndroid", { path: "/" })] }),
  human({ id: "samsung-internet-home", title: "Samsung Internet opening a page", category: "mobile", provenance: "Samsung Internet ships its own brand in the Client Hints list", requests: [browser("samsungInternet", { path: "/" })] }),
  human({ id: "firefox-android-home", title: "Firefox on Android opening a page", category: "mobile", provenance: "2026 User-Agent lists", requests: [browser("firefoxAndroid", { path: "/" })] }),

  // ---------------------------------------------------------------------------
  // Behaviours that resemble an attack but are not.
  // ---------------------------------------------------------------------------
  human({
    id: "search-with-sql-words",
    title: "A shopper searching with words that look like SQL",
    category: "search",
    provenance: "A real query that happens to contain select, union and table without being an injection",
    notes: "The words appear in the wrong order and the wrong context to match a SQL-injection signature. If payload-injection fires here it is over-broad.",
    requests: [browser("chromeWindows", { path: `/search?q=${encodeURIComponent("how to select a union jack flag for a table setting")}` })],
    expect: { neverDetectors: ["payload-injection"] },
  }),
  human({
    id: "faceted-catalogue-many-params",
    title: "A faceted catalogue serialising fifty filters into the query",
    category: "search",
    provenance: "A filter UI that puts every chosen facet in the query string — dozens of parameters is normal, not a flood",
    notes: "Fifty parameters is under the engine's inspection cap, so no query-flood is reported. The 257-parameter flood is a separate hostile case.",
    requests: [browser("chromeWindows", { path: `/catalog?${Array.from({ length: 50 }, (_, i) => `f${i}=on`).join("&")}` })],
    expect: { neverDetectors: ["header-anomaly"] },
  }),
  human({
    id: "login-form-once",
    title: "One ordinary sign-in from a browser",
    category: "forms",
    provenance: "A single POST to /login well under the credential-bruteforce threshold",
    requests: [browser("chromeWindows", { path: "/login", kind: "form-post", body: "username=alice&password=correct-horse-battery-staple", host: "shop.example" })],
    expect: { neverDetectors: ["credential-bruteforce"] },
  }),
  human({
    id: "signup-form-with-honest-fields",
    title: "A sign-up form submitted with the visible fields filled and the hidden one empty",
    category: "forms",
    provenance: "A person completing a form leaves the hidden trap field untouched, which is exactly what the trap distinguishes",
    requests: [browser("chromeWindows", { path: "/signup", kind: "form-post", body: "email=alice%40example.com&password=hunter2hunter2&company_url=" })],
    requires: ["trap"],
    expect: { neverDetectors: ["trap"] },
  }),
  human({
    id: "spa-json-navigation",
    title: "A single-page app fetching JSON as the user navigates",
    category: "spa",
    provenance: "A modern SPA makes many same-origin XHRs from one page; none is a distinct-path enumeration",
    requests: [
      browser("chromeWindows", { path: "/", kind: "navigate" }),
      browser("chromeWindows", { path: "/api/v1/products?page=1", kind: "xhr", referer: "https://shop.example/", atMs: 200 }),
      browser("chromeWindows", { path: "/api/v1/products?page=2", kind: "xhr", referer: "https://shop.example/", atMs: 3200 }),
      browser("chromeWindows", { path: "/api/v1/cart", kind: "xhr", referer: "https://shop.example/", atMs: 5200 }),
    ],
    expect: { neverDetectors: ["path-bruteforce", "rate-spike"] },
  }),
  human({
    id: "spa-hs256-jwt",
    title: "A single-page app calling its API with a signed HS256 session token",
    category: "spa",
    provenance: "An ordinary session JWT: three segments, a real HMAC signature, no alg confusion",
    notes: "jwt-weakness must fire only on alg:none or an empty signature. A signed token is the norm.",
    requests: [
      browser("chromeWindows", {
        path: "/api/v1/orders",
        kind: "xhr",
        referer: "https://shop.example/account",
      }),
    ].map((request) => ({ ...request, headers: [...request.headers, ["Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsImlhdCI6MTc4ODAwMDAwMCwiZXhwIjoxNzg4MDAzNjAwfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"] as Header] })),
    expect: { neverDetectors: ["jwt-weakness"] },
  }),
  human({
    id: "storefront-graphql-query",
    title: "A storefront fetching a product list over GraphQL, no introspection",
    category: "spa",
    provenance: "An ordinary named GraphQL query, shallow and without __schema",
    requests: [browser("chromeWindows", { path: "/graphql", kind: "form-post", body: JSON.stringify({ query: "query Products { products(first: 10) { id name price } }" }) })],
    expect: { neverDetectors: ["graphql-abuse"] },
  }),
  human({
    id: "file-with-spaces",
    title: "iPhone opening a linked PDF whose name has spaces",
    category: "downloads",
    provenance: "A percent-encoded space is normal encoding, not path evasion",
    requests: [browser("safariIos", { path: "/files/Quarterly%20Report%202026.pdf", kind: "navigate" })],
    expect: { neverDetectors: ["target-integrity", "sensitive-file"] },
  }),
  human({
    id: "same-site-login-redirect",
    title: "A login link returning to a page on the same site",
    category: "navigation",
    provenance: "A next= parameter pointing at a local path is a self-redirect, not an open redirect",
    requests: [browser("chromeWindows", { path: "/login?next=%2Faccount%2Forders" })],
    expect: { neverDetectors: ["open-redirect"] },
  }),
  human({
    id: "cross-site-arrival-from-search",
    title: "A visitor arriving from a search engine result",
    category: "navigation",
    provenance: "A cross-site navigation carries a Referer and Sec-Fetch-Site: cross-site; neither is suspicious",
    requests: [browser("chromeWindows", { path: "/products/wireless-headphones", kind: "cross-site-navigate", referer: "https://www.google.com/" })],
  }),
  human({
    id: "returning-visitor-with-cookie-jar",
    title: "A returning visitor carrying a cookie jar",
    category: "page-load",
    provenance: "A repeat customer sends analytics and session cookies a browser stored on an earlier visit",
    requests: [browser("chromeWindows", { path: "/account", kind: "same-origin-navigate", referer: "https://shop.example/", cookie: CART_COOKIE })],
  }),

  // ---------------------------------------------------------------------------
  // People who look automated, and are not.
  // ---------------------------------------------------------------------------
  human({
    id: "privacy-browser-gpc",
    title: "A privacy-hardened browser sending Sec-GPC",
    category: "privacy",
    provenance: "Brave and DuckDuckGo present an unmodified Chrome identity and add Sec-GPC / DNT",
    notes: "Fewer headers than a stock Chrome, but the ones a browser always sends are all present, so client-anomaly must stay quiet.",
    requests: [browser("chromeWindows", { path: "/", gpc: true, dnt: true })],
    expect: { neverDetectors: ["client-anomaly"] },
  }),
  human({
    id: "screen-reader-session",
    title: "A screen-reader user working through a page",
    category: "assistive",
    provenance: "Assistive technology drives an ordinary browser; the requests are indistinguishable at the HTTP layer and must stay that way",
    requests: [
      browser("firefoxWindows", { path: "/", kind: "navigate" }),
      browser("firefoxWindows", { path: "/accessibility", kind: "same-origin-navigate", referer: "https://shop.example/", atMs: 9000 }),
      browser("firefoxWindows", { path: "/contact", kind: "same-origin-navigate", referer: "https://shop.example/accessibility", atMs: 21000 }),
    ],
  }),
  human({
    id: "corporate-proxy-stripped-headers",
    title: "A browser behind a corporate proxy that strips some headers",
    category: "infrastructure-mangled",
    provenance: "Some enterprise proxies remove Accept-Language and Accept-Encoding but leave Accept and the User-Agent",
    notes: "client-anomaly fires only when ALL of Accept, Accept-Language and Accept-Encoding are gone. One or two stripped is normal and must not fire.",
    requests: [{ headers: [["Host", "shop.example"], ["User-Agent", browser("chromeWindows").headers.find(([n]) => n === "User-Agent")![1]], ["Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"], ["Connection", "keep-alive"]], httpVersion: "1.1" }],
    expect: { neverDetectors: ["client-anomaly"] },
  }),
  human({
    id: "cgnat-shared-address",
    title: "Several unrelated people behind one carrier-grade NAT address",
    category: "shared-address",
    provenance: "Mobile carriers put thousands of subscribers behind one address; distinct browsers from it are distinct people, not one actor",
    notes: "Different browsers, one source address. Nothing here scores, so the fingerprint registry — which only ever holds attackers — never correlates them, and no volume threshold is near.",
    requests: [
      browser("safariIos", { path: "/", from: 0 }),
      browser("chromeAndroid", { path: "/deals", from: 0, atMs: 1500 }),
      browser("samsungInternet", { path: "/", from: 0, atMs: 4000 }),
      browser("firefoxAndroid", { path: "/support", from: 0, atMs: 8000 }),
    ].map((request) => ({ ...request, from: 0 })),
    expect: { neverDetectors: ["repeat-actor", "rate-spike", "path-bruteforce"] },
  }),
  human({
    id: "in-app-webview-support-contact",
    title: "A native app's webview naming its support address",
    category: "in-app-browser",
    provenance: "Native apps append a product token and a contact to the system webview's User-Agent; it is still a person browsing",
    requests: [plain("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Mobile Safari/537.36 ShopApp/3.1 (support@shop.example)", [["Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"], ["Accept-Language", "en-US,en;q=0.9"], ["Accept-Encoding", "gzip, deflate, br"]])],
    expect: { neverDetectors: ["scanner-signature", "client-anomaly"] },
  }),

  // ---------------------------------------------------------------------------
  // More of the ordinary web: every engine, in the scenarios people actually use
  // them for.
  // ---------------------------------------------------------------------------
  human({ id: "safari-mac-search", title: "Safari on macOS running a site search", category: "search", provenance: "A plain keyword search, no special characters", requests: [browser("safariMac", { path: "/search?q=wireless%20headphones" })] }),
  human({ id: "edge-windows-search", title: "Edge on Windows searching the catalogue", category: "search", provenance: "2026 User-Agent lists", requests: [browser("edgeWindows", { path: "/search?q=standing%20desk&sort=price" })] }),
  human({ id: "firefox-contact-form", title: "Firefox submitting a contact form", category: "forms", provenance: "A POST to a non-auth form, well-formed and honest", requests: [browser("firefoxWindows", { path: "/contact", kind: "form-post", body: "name=Jamie&email=jamie%40example.com&message=Do%20you%20ship%20to%20Canada%3F" })] }),
  human({ id: "chrome-mac-checkout", title: "Chrome on macOS completing a checkout", category: "forms", provenance: "A checkout POST carrying the session cookie", requests: [browser("chromeMac", { path: "/checkout", kind: "form-post", body: "card_token=tok_visa&save=1", cookie: CART_COOKIE })] }),
  human({ id: "safari-ios-add-to-cart", title: "Safari on iPhone adding an item to the cart", category: "forms", provenance: "A same-origin XHR POST from a product page", requests: [browser("safariIos", { path: "/api/v1/cart/items", kind: "xhr", referer: "https://shop.example/products/42" })].map((request) => ({ ...request, method: "POST", body: JSON.stringify({ sku: "WH-42", qty: 1 }) })) }),
  human({ id: "chrome-pagination-browsing", title: "A reader paging through an article list", category: "navigation", provenance: "A handful of distinct pages over a minute — nothing like an enumeration", requests: [browser("chromeWindows", { path: "/articles?page=1" }), browser("chromeWindows", { path: "/articles?page=2", kind: "same-origin-navigate", referer: "https://shop.example/articles?page=1", atMs: 18000 }), browser("chromeWindows", { path: "/articles?page=3", kind: "same-origin-navigate", referer: "https://shop.example/articles?page=2", atMs: 41000 })] }),
  human({ id: "safari-video-byte-range", title: "Safari requesting a byte range of a video", category: "media", provenance: "A <video> element fetches media with a Range header; not a suspicious method or header", requests: [{ ...browser("safariMac", { path: "/media/promo.mp4", kind: "subresource", referer: "https://shop.example/" }), headers: [...browser("safariMac", { path: "/media/promo.mp4", kind: "subresource", referer: "https://shop.example/" }).headers, ["Range", "bytes=0-524287"]] }] }),
  human({ id: "chrome-autocomplete-xhr", title: "A search box firing autocomplete XHRs as the user types", category: "spa", provenance: "Several same-origin XHRs to one endpoint with a growing query — one path, not enumeration", requests: [browser("chromeWindows", { path: "/api/suggest?q=sh", kind: "xhr", referer: "https://shop.example/" }), browser("chromeWindows", { path: "/api/suggest?q=sho", kind: "xhr", referer: "https://shop.example/", atMs: 400 }), browser("chromeWindows", { path: "/api/suggest?q=shoe", kind: "xhr", referer: "https://shop.example/", atMs: 900 }), browser("chromeWindows", { path: "/api/suggest?q=shoes", kind: "xhr", referer: "https://shop.example/", atMs: 1500 })] }),
  human({ id: "oauth-same-site-callback", title: "An OAuth callback returning to the same site", category: "navigation", provenance: "A code/state callback whose redirect stays on the site — not an open redirect", requests: [browser("chromeWindows", { path: "/auth/callback?code=abc123&state=xyz789", kind: "cross-site-navigate", referer: "https://accounts.google.com/" })], expect: { neverDetectors: ["open-redirect"] } }),
  human({ id: "unicode-path", title: "A page with non-ASCII characters in its path", category: "navigation", provenance: "A percent-encoded UTF-8 path is normal internationalisation, not evasion", requests: [browser("firefoxWindows", { path: "/caf%C3%A9/m%C3%BCnchen" })], expect: { neverDetectors: ["target-integrity", "payload-injection"] } }),
  human({ id: "emoji-search", title: "A search containing an emoji", category: "search", provenance: "A percent-encoded emoji query, which trips nothing but has caught naive filters before", requests: [browser("chromeAndroid", { path: "/search?q=%F0%9F%8E%89%20party%20supplies" })] }),
  human({ id: "samsung-product-page", title: "Samsung Internet opening a product page", category: "mobile", provenance: "2026 User-Agent lists; a common browser across its market", requests: [browser("samsungInternet", { path: "/products/wireless-earbuds", kind: "cross-site-navigate", referer: "https://www.google.com/" })] }),

  // ---------------------------------------------------------------------------
  // The honest exception.
  // ---------------------------------------------------------------------------
  human({
    id: "wordpress-author-wp-login",
    title: "A WordPress author signing in at /wp-login.php",
    category: "known-cost",
    provenance: "A real author's login, on a path the decoy set treats as bait because attackers probe it constantly",
    notes: "This is a genuine cost, written down rather than hidden. /wp-login.php is a decoy, so a legitimate WordPress author who hits it is caught. The library cannot both bait scanners with this path and serve authors on it; a site that runs WordPress should exclude the path (ignorePaths / allowlist) or drop the decoy. Reported as a known cost, not a false positive.",
    tags: ["known-cost"],
    requests: [browser("chromeWindows", { path: "/wp-login.php", kind: "navigate" })],
    expect: { detectors: ["decoy-path"] },
  }),
];
