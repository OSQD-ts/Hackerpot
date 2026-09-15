import { userAgentOf } from "./headers.js";
import { CORPUS_HONEYTOKEN, CORPUS_TRAP_FIELD, CORPUS_TRAP_PATH, hostile, repeat } from "./schema.js";
import type { CaseRequest, TrafficCase } from "./schema.js";

/**
 * Traffic that is trying to look like something it is not, and attacks that are only
 * visible across several requests.
 *
 * This is where the honeypot's sharpest signals live and where its limits are honest. A
 * forged crawler is caught by DNS, not by the claim; a replayed honeytoken and a touched
 * trap are proof because no legitimate client could produce them; a credential attack, an
 * address rotation and a rate flood exist only in the aggregate and are exercised with
 * deterministic pacing rather than by sleeping.
 */

const CHROME_UA = userAgentOf("chromeWindows");
const PYTHON_HEADERS: CaseRequest["headers"] = [["Host", "shop.example"], ["User-Agent", "python-requests/2.32.3"], ["Accept-Encoding", "gzip, deflate"], ["Accept", "*/*"]];
const GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

export const ADVERSARIAL_CASES: TrafficCase[] = [
  // ---------------------------------------------------------------------------
  // Forged identities, refuted by evidence the claim cannot fake.
  // ---------------------------------------------------------------------------
  hostile({
    id: "forged-googlebot-wrong-domain",
    title: "A fake Googlebot whose reverse DNS is a VPS",
    category: "impersonation",
    provenance: "The commonest crawler forgery: Googlebot's UA from an address whose PTR is not under googlebot.com",
    requires: ["crawler-verification"],
    requests: [{ path: "/", ip: "198.51.100.20", headers: [["Host", "shop.example"], ["User-Agent", GOOGLEBOT_UA], ["Accept", "*/*"]], httpVersion: "1.1" }],
    dns: { reverse: { "198.51.100.20": ["host-42.some-cheap-vps.example"] } },
    expect: { detectors: ["crawler-verification"], certain: true },
  }),
  hostile({
    id: "forged-googlebot-no-ptr",
    title: "A fake Googlebot from an address with no PTR record",
    category: "impersonation",
    provenance: "Every operator of a verifiable crawler publishes a PTR record; a Googlebot claim from an address without one is a forgery",
    requires: ["crawler-verification"],
    requests: [{ path: "/", ip: "198.51.100.21", headers: [["Host", "shop.example"], ["User-Agent", GOOGLEBOT_UA], ["Accept", "*/*"]], httpVersion: "1.1" }],
    dns: { reverse: {} },
    expect: { detectors: ["crawler-verification"], certain: true },
  }),
  hostile({
    id: "forged-duckduckbot-outside-range",
    title: "A fake DuckDuckBot from outside its published range",
    category: "impersonation",
    provenance: "DuckDuckGo publishes only ranges, so an address outside them refutes the claim outright",
    requires: ["crawler-verification", "published-ranges"],
    requests: [{ path: "/", ip: "198.51.100.40", headers: [["Host", "shop.example"], ["User-Agent", "Mozilla/5.0 (compatible; DuckDuckBot/1.1; +http://duckduckgo.com/duckduckbot.html)"], ["Accept", "*/*"]], httpVersion: "1.1" }],
    expect: { detectors: ["crawler-verification"], certain: true },
  }),

  hostile({
    id: "forged-googlebot-forward-mismatch",
    title: "A fake Googlebot whose PTR is under googlebot.com but forward-resolves elsewhere",
    category: "impersonation",
    provenance: "Controlling only the PTR record is not enough: forward-confirmed reverse DNS re-resolves the name and requires the original address back",
    notes: "Exercises the forward-confirmation step specifically — the reverse lookup passes the domain check, but the name resolves to a different address, so the claim is refuted.",
    requires: ["crawler-verification"],
    requests: [{ path: "/", ip: "198.51.100.23", headers: [["Host", "shop.example"], ["User-Agent", GOOGLEBOT_UA], ["Accept", "*/*"]], httpVersion: "1.1" }],
    dns: { reverse: { "198.51.100.23": ["crawl-fake.googlebot.com"] }, forward: { "crawl-fake.googlebot.com": ["8.8.8.8"] } },
    expect: { detectors: ["crawler-verification"], certain: true },
  }),
  hostile({
    id: "forged-bingbot-wrong-domain",
    title: "A fake Bingbot whose reverse DNS is not under search.msn.com",
    category: "impersonation",
    provenance: "Bingbot's UA from an address whose PTR is not under search.msn.com",
    requires: ["crawler-verification"],
    requests: [{ path: "/", ip: "198.51.100.24", headers: [["Host", "shop.example"], ["User-Agent", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"], ["Accept", "*/*"]], httpVersion: "1.1" }],
    dns: { reverse: { "198.51.100.24": ["node-9.datacenter.example"] } },
    expect: { detectors: ["crawler-verification"], certain: true },
  }),

  // ---------------------------------------------------------------------------
  // Proof by construction: values and places no legitimate client can reach.
  // ---------------------------------------------------------------------------
  hostile({
    id: "honeytoken-in-authorization",
    title: "A seeded honeytoken replayed as a Bearer token",
    category: "breach",
    provenance: "A fake credential planted in a decoy .env, harvested and tried against the API",
    notes: "The highest-confidence signal the honeypot has: no legitimate client was ever given this value.",
    requires: ["honeytoken"],
    requests: [{ path: "/api/account", ip: "203.0.113.90", headers: [["Host", "shop.example"], ["User-Agent", "curl/8.7.1"], ["Accept", "*/*"], ["Authorization", `Bearer ${CORPUS_HONEYTOKEN}`]], httpVersion: "1.1" }],
    expect: { detectors: ["honeytoken"], certain: true },
  }),
  hostile({
    id: "honeytoken-in-query",
    title: "A seeded honeytoken replayed in a query parameter",
    category: "breach",
    provenance: "The same planted credential tried as an API key in the query string",
    requires: ["honeytoken"],
    requests: [{ path: `/data?key=${encodeURIComponent(CORPUS_HONEYTOKEN)}`, ip: "203.0.113.91", headers: [["Host", "shop.example"], ["User-Agent", "curl/8.7.1"], ["Accept", "*/*"]], httpVersion: "1.1" }],
    expect: { detectors: ["honeytoken"], certain: true },
  }),
  hostile({
    id: "honeytoken-basic-auth",
    title: "A seeded honeytoken replayed as an HTTP Basic password",
    category: "breach",
    provenance: "The planted credential tried in a Basic auth header, where it appears only base64-encoded",
    notes: "Exercises the honeytoken detector's decoding of Basic credentials — a plain substring match would miss the most natural place to try a harvested password.",
    requires: ["honeytoken"],
    requests: [{ path: "/admin", ip: "203.0.113.92", headers: [["Host", "shop.example"], ["User-Agent", "curl/8.7.1"], ["Accept", "*/*"], ["Authorization", `Basic ${Buffer.from(`admin:${CORPUS_HONEYTOKEN}`).toString("base64")}`]], httpVersion: "1.1" }],
    expect: { detectors: ["honeytoken"], certain: true },
  }),
  hostile({
    id: "trap-link-followed",
    title: "A scraper following a link hidden from people",
    category: "trap",
    provenance: "A link present in the markup but hidden from layout, assistive tech and robots.txt; nothing a person does reaches it",
    requires: ["trap"],
    requests: [{ path: CORPUS_TRAP_PATH, ip: "203.0.113.93", headers: [["Host", "shop.example"], ["User-Agent", CHROME_UA], ["Accept", "text/html"]], httpVersion: "1.1" }],
    expect: { detectors: ["trap"], certain: true },
  }),
  hostile({
    id: "honeytoken-in-body",
    title: "A seeded honeytoken replayed in a request body",
    category: "breach",
    provenance: "The planted credential posted in a JSON body; it arrives from a scripting client whose UA lets the middleware read the body",
    requires: ["honeytoken"],
    requests: [{ method: "POST", path: "/api/import", ip: "203.0.113.96", headers: [["Host", "shop.example"], ["User-Agent", "python-requests/2.32.3"], ["Content-Type", "application/json"], ["Accept", "*/*"]], body: JSON.stringify({ api_key: CORPUS_HONEYTOKEN }), httpVersion: "1.1" }],
    expect: { detectors: ["honeytoken"], certain: true },
  }),
  hostile({
    id: "trap-form-field-filled",
    title: "A form filler completing a hidden trap field",
    category: "trap",
    provenance: "A hidden field that must arrive empty; a value in it was typed by something that enumerated the form's inputs",
    requires: ["trap"],
    requests: [{ path: `/newsletter?email=x%40example.com&${CORPUS_TRAP_FIELD}=${encodeURIComponent("https://spam.example")}`, ip: "203.0.113.94", headers: [["Host", "shop.example"], ["User-Agent", CHROME_UA], ["Accept", "*/*"]], httpVersion: "1.1" }],
    expect: { detectors: ["trap"], certain: true },
  }),

  // ---------------------------------------------------------------------------
  // Attacks that exist only across requests.
  // ---------------------------------------------------------------------------
  hostile({
    id: "credential-stuffing-sequence",
    title: "Password spraying one login endpoint",
    category: "credential-attack",
    provenance: "Repeated POSTs to /login from one address, each a different password, well past the attempt threshold",
    requests: Array.from({ length: 12 }, (_, index) => ({
      method: "POST",
      path: "/login",
      headers: [["Host", "shop.example"], ["User-Agent", "python-requests/2.32.3"], ["Content-Type", "application/x-www-form-urlencoded"], ["Accept", "*/*"]] as CaseRequest["headers"],
      body: `username=admin&password=guess${index}`,
      atMs: index * 800,
    })),
    expect: { detectors: ["credential-bruteforce"] },
  }),
  hostile({
    id: "distributed-rotating-addresses",
    title: "One actor probing decoys from several addresses",
    category: "rotation",
    provenance: "The same tooling — identical header order and User-Agent — probing from a rotating set of source addresses to dodge per-IP blocking",
    notes: "repeat-actor reads the fingerprint registry, which only ever holds addresses that already scored, so it confirms that these are one actor rather than manufacturing suspicion. It fires once the shared fingerprint has been seen from enough distinct addresses.",
    requests: [
      { path: "/.env", from: 0, headers: PYTHON_HEADERS, atMs: 0 },
      { path: "/.env", from: 1, headers: PYTHON_HEADERS, atMs: 1000 },
      { path: "/.env", from: 2, headers: PYTHON_HEADERS, atMs: 2000 },
      { path: "/.git/config", from: 2, headers: PYTHON_HEADERS, atMs: 3000 },
    ],
    expect: { detectors: ["repeat-actor", "decoy-path"] },
  }),
  hostile({
    id: "rate-spike-flood",
    title: "A request flood from one address",
    category: "flood",
    provenance: "Seventy requests in a burst from a single address — aggressive scraping, or the volume side of an attack",
    requests: repeat({ path: "/", headers: [["Host", "shop.example"], ["User-Agent", "Go-http-client/2.0"], ["Accept-Encoding", "gzip"]], httpVersion: "1.1" }, 70, 100),
    expect: { detectors: ["rate-spike"] },
  }),
  hostile({
    id: "spoofed-chrome-no-accept",
    title: "A script wearing Chrome's name but sending no Accept headers",
    category: "impersonation",
    provenance: "A browser User-Agent with none of the Accept / Accept-Language / Accept-Encoding headers a real browser always sends",
    requests: [{ path: "/", ip: "203.0.113.95", headers: [["Host", "shop.example"], ["User-Agent", CHROME_UA]], httpVersion: "1.1" }],
    expect: { detectors: ["client-anomaly"] },
  }),
];
