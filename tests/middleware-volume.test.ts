import { describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import { parseConfig } from "../src/config/schema.js";
import type { RequestFacts } from "../src/detectors/types.js";

const CHROME = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
const BROWSER = { host: "myapp.com", "user-agent": CHROME, accept: "text/html,*/*", "accept-language": "en-US,en;q=0.9", "accept-encoding": "gzip, deflate, br" };

/** One realistic first page load of an ordinary React/Next-style site. */
const PAGE_LOAD = [
  "/",
  "/_next/static/css/main.a1b2.css",
  "/_next/static/chunks/framework.c3d4.js",
  "/_next/static/chunks/main.e5f6.js",
  "/_next/static/chunks/pages/_app.a7b8.js",
  "/_next/static/chunks/pages/index.c9d0.js",
  "/_next/static/chunks/webpack.e1f2.js",
  "/fonts/inter-var.woff2",
  "/fonts/inter-italic.woff2",
  "/images/logo.svg",
  "/images/hero.webp",
  "/images/feature-1.webp",
  "/images/feature-2.webp",
  "/images/feature-3.webp",
  "/images/avatar-1.jpg",
  "/images/avatar-2.jpg",
  "/images/avatar-3.jpg",
  "/favicon.ico",
  "/manifest.json",
  "/api/v1/session",
  "/api/v1/config",
  "/api/v1/feed",
];

const facts = (path: string, ip: string): RequestFacts => ({ method: "GET", path, query: {}, headers: { ...BROWSER }, ip });

describe("volume detectors in middleware mode", () => {
  // In middleware mode the engine sees every request the application serves, static
  // assets included, and `path-bruteforce` counts distinct paths. The shipped default
  // (15 in 30s) is sized for standalone mode, where nothing serves real assets and many
  // distinct paths genuinely is probing. This test pins what the default actually does
  // to an ordinary visitor so the trade-off stays visible and cannot change silently —
  // it is documentation of a known sharp edge, not an endorsement of it.
  it("the shipped default blocks an ordinary visitor on one page load", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    let total = 0;
    for (const path of PAGE_LOAD) total = (await engine.evaluate(facts(path, "198.51.100.77"))).totalScore;

    const blockThreshold = parseConfig({}, "<defaults>").policy.blockThreshold;
    expect(PAGE_LOAD.length).toBeGreaterThan(parseConfig({}, "<defaults>").detectors["path-bruteforce"].options.uniquePathThreshold ?? 15);
    expect(total).toBeGreaterThan(blockThreshold);
  });

  // …and that the documented remedy actually works, which is the part an operator
  // following the README needs to be true.
  it("raising unique_path_threshold clears the same page load", async () => {
    const config = parseConfig({ detectors: { "path-bruteforce": { unique_path_threshold: 200 } } }, "<test>");
    expect(config.detectors["path-bruteforce"].options.uniquePathThreshold).toBe(200);

    const { buildDetectors } = await import("../src/config/build.js");
    const engine = new HoneypotEngine({ detectors: buildDetectors(config), enricher: null });
    let total = 0;
    for (const path of PAGE_LOAD) total = (await engine.evaluate(facts(path, "198.51.100.78"))).totalScore;
    expect(total).toBe(0);
  });

  it("disabling path-bruteforce also clears it", async () => {
    const config = parseConfig({ detectors: { "path-bruteforce": { enabled: false } } }, "<test>");
    const { buildDetectors } = await import("../src/config/build.js");
    const engine = new HoneypotEngine({ detectors: buildDetectors(config), enricher: null });
    let total = 0;
    for (const path of PAGE_LOAD) total = (await engine.evaluate(facts(path, "198.51.100.79"))).totalScore;
    expect(total).toBe(0);
  });
});
