import { EventEmitter } from "node:events";
import type { IncomingMessage, ServerResponse } from "node:http";
import { describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import { createMiddleware, type MiddlewareOptions } from "../src/middleware.js";
import { parseConfig } from "../src/config/schema.js";
import type { RequestFacts } from "../src/detectors/types.js";
import type { HoneypotHit } from "../src/types.js";

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

/** A wordlist walk: paths that do not exist and trip no per-request detector. */
const WORDLIST = Array.from({ length: 20 }, (_, i) => `/section-${i}/overview`);

const blockThreshold = parseConfig({}, "<defaults>").policy.blockThreshold;
const uniquePathThreshold = parseConfig({}, "<defaults>").detectors["path-bruteforce"].options.uniquePathThreshold ?? 15;

function fakeReq(path: string, ip: string): IncomingMessage {
  return Object.assign(new EventEmitter(), {
    method: "GET",
    url: path,
    headers: { ...BROWSER },
    rawHeaders: Object.entries(BROWSER).flat(),
    socket: { remoteAddress: ip },
  }) as unknown as IncomingMessage;
}

function fakeRes(): ServerResponse {
  const res = Object.assign(new EventEmitter(), {
    statusCode: 200,
    headersSent: false,
    writableEnded: false,
    destroyed: false,
    setHeader: () => undefined,
    write: () => true,
    end: () => {
      res.writableEnded = true;
      res.emit("finish");
    },
  });
  return res as unknown as ServerResponse;
}

/** Drives requests through the real middleware, with an app that answers `appStatus(path)`. */
function site(options: MiddlewareOptions = {}) {
  const hits: HoneypotHit[] = [];
  // Detection is under test, not the response: the default policy would tarpit an
  // escalating walk for seconds per request, and this fake response never closes.
  const engine = new HoneypotEngine({ enricher: null, policy: () => "not-found", onHit: (hit) => void hits.push(hit) });
  const middleware = createMiddleware(engine, options);
  const visit = async (path: string, ip: string, appStatus: number): Promise<void> => {
    const res = fakeRes();
    await middleware(fakeReq(path, ip), res, () => {
      res.statusCode = appStatus;
      res.end();
    });
  };
  const fired = (id: string): boolean => hits.some((hit) => hit.detections.some((d) => d.detectorId === id));
  return { engine, visit, fired };
}

describe("path-bruteforce in middleware mode counts misses, not pages", () => {
  // In middleware mode the engine sees every request the app serves, static assets
  // included. Counting every distinct path blocked an ordinary first-time visitor on one
  // page load (22 paths, past the default of 15). A path the app serves is not a guess.
  it("an ordinary page load the app serves scores nothing", async () => {
    const { engine, visit, fired } = site();
    for (const path of PAGE_LOAD) await visit(path, "198.51.100.77", 200);
    expect(PAGE_LOAD.length).toBeGreaterThan(uniquePathThreshold);
    expect(fired("path-bruteforce")).toBe(false);
    expect(await engine.scoreFor("198.51.100.77")).toBe(0);
  });

  it("a wordlist walk the app answers with 404 still trips it", async () => {
    const { visit, fired } = site();
    for (const path of WORDLIST) await visit(path, "198.51.100.80", 404);
    expect(WORDLIST.length).toBeGreaterThan(uniquePathThreshold);
    expect(fired("path-bruteforce")).toBe(true);
  });

  it("a page load with a few broken links stays under the threshold", async () => {
    const { engine, visit } = site();
    for (const path of PAGE_LOAD) await visit(path, "198.51.100.81", 200);
    for (const path of WORDLIST.slice(0, 3)) await visit(path, "198.51.100.81", 404);
    expect(await engine.scoreFor("198.51.100.81")).toBe(0);
  });

  it("countOnlyMissedPaths: false counts every path, as before", async () => {
    const { visit, fired } = site({ countOnlyMissedPaths: false });
    for (const path of PAGE_LOAD) await visit(path, "198.51.100.82", 200);
    expect(fired("path-bruteforce")).toBe(true);
  });
});

describe("standalone evaluation still counts every distinct path", () => {
  const facts = (path: string, ip: string): RequestFacts => ({ method: "GET", path, query: {}, headers: { ...BROWSER }, ip });

  // Nothing real is served in standalone mode, so many distinct paths is probing and the
  // defaults stay sized for that.
  it("the default still escalates on many distinct paths", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    let total = 0;
    for (const path of PAGE_LOAD) total = (await engine.evaluate(facts(path, "198.51.100.90"))).totalScore;
    expect(total).toBeGreaterThan(blockThreshold);
  });

  it("raising unique_path_threshold or disabling the detector clears it", async () => {
    const { buildDetectors } = await import("../src/config/build.js");
    for (const [overrides, ip] of [
      [{ unique_path_threshold: 200 }, "198.51.100.91"],
      [{ enabled: false }, "198.51.100.92"],
    ] as const) {
      const engine = new HoneypotEngine({ detectors: buildDetectors(parseConfig({ detectors: { "path-bruteforce": overrides } }, "<test>")), enricher: null });
      let total = 0;
      for (const path of PAGE_LOAD) total = (await engine.evaluate(facts(path, ip))).totalScore;
      expect(total).toBe(0);
    }
  });
});
