import { describe, expect, it } from "vitest";
import { SiteProfile } from "../src/site/index.js";
import type { RequestOutcome } from "../src/site/index.js";
import { HoneypotEngine } from "../src/core.js";
import { pathNoveltyDetector } from "../src/detectors/path-novelty.js";
import type { RequestFacts } from "../src/detectors/types.js";
import { ManualClock } from "../src/internal/clock.js";

/**
 * The baseline is the only part of the honeypot that learns from the site it protects, so the
 * question every test here asks is the same one: can an attacker teach it anything?
 */

const probe = (path: string, ip = "203.0.113.40"): RequestFacts => ({
  method: "GET",
  path,
  query: {},
  headers: { host: "shop.example", "user-agent": "curl/8.4.0" },
  ip,
});

/** Enough real traffic for the baseline to have an opinion: 20 served paths, 500 outcomes. */
const warm = (baseline: SiteProfile, over: Partial<RequestOutcome> = {}): void => {
  for (let i = 0; i < 500; i += 1) {
    baseline.record({ ip: `198.51.100.${i % 200}`, path: `/page/${i % 20}`, status: 200, ...over });
  }
};

describe("what the baseline learns", () => {
  it("learns a path is real only from the application serving it", () => {
    const baseline = new SiteProfile();
    // A thousand requests for the same path, all answered 404. This is what an attacker can
    // do, and it must never make the path look real.
    for (let i = 0; i < 1_000; i += 1) baseline.record({ ip: "203.0.113.9", path: "/.env", status: 404 });
    expect(baseline.isServed("/.env")).toBe(false);
    expect(baseline.noveltyOf("/.env")).toBe("missed");

    baseline.record({ ip: "198.51.100.1", path: "/pricing", status: 200 });
    expect(baseline.isServed("/pricing")).toBe(true);
    expect(baseline.noveltyOf("/pricing")).toBe("served");
    expect(baseline.noveltyOf("/never-asked-for")).toBe("unseen");
  });

  it("never credits the honeypot's own answer to the site", () => {
    const baseline = new SiteProfile();
    // A decoy answers 200 with convincing bait. That says nothing about the real site.
    baseline.record({ ip: "203.0.113.9", path: "/wp-admin/", status: 200, fromHoneypot: true });
    expect(baseline.isServed("/wp-admin/")).toBe(false);
    expect(baseline.noveltyOf("/wp-admin/")).toBe("missed");
  });

  it("counts distinct addresses walking a path that does not exist, and forgets them once it does", () => {
    const baseline = new SiteProfile();
    for (const ip of ["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.1"]) {
      baseline.record({ ip, path: "/admin.php", status: 404 });
    }
    expect(baseline.walkers("/admin.php")).toBe(3);

    // The site starts serving it. Whoever asked before were visitors ahead of a deploy.
    baseline.record({ ip: "198.51.100.5", path: "/admin.php", status: 200 });
    expect(baseline.walkers("/admin.php")).toBe(0);
  });

  it("is not warm until it has seen enough to be believed", () => {
    const baseline = new SiteProfile();
    expect(baseline.isWarm()).toBe(false);
    // Plenty of traffic, but across too few real paths to know the site.
    for (let i = 0; i < 600; i += 1) baseline.record({ ip: "198.51.100.1", path: "/", status: 200 });
    expect(baseline.isWarm()).toBe(false);

    warm(baseline);
    expect(baseline.isWarm()).toBe(true);
  });

  it("reports the site's own miss rate", () => {
    const baseline = new SiteProfile();
    for (let i = 0; i < 90; i += 1) baseline.record({ ip: "198.51.100.1", path: `/page/${i}`, status: 200 });
    for (let i = 0; i < 10; i += 1) baseline.record({ ip: "203.0.113.1", path: `/probe/${i}`, status: 404 });
    const snapshot = baseline.snapshot();
    expect(snapshot.observations).toBe(100);
    expect(snapshot.servedPaths).toBe(90);
    expect(snapshot.missShare).toBeCloseTo(0.1);
  });

  it("stays bounded against attacker-chosen paths, and forgets what has expired", () => {
    const clock = new ManualClock(0);
    const baseline = new SiteProfile({ maxPaths: 100, ttlMs: 1_000, maxWalkersPerPath: 4, clock });
    for (let i = 0; i < 5_000; i += 1) baseline.record({ ip: `10.0.0.${i % 256}`, path: `/probe/${i}`, status: 404 });
    expect(baseline.snapshot().paths).toBeLessThanOrEqual(100);

    for (let i = 0; i < 20; i += 1) baseline.record({ ip: `10.0.1.${i}`, path: "/walked", status: 404 });
    expect(baseline.walkers("/walked")).toBe(4);

    baseline.record({ ip: "198.51.100.1", path: "/real", status: 200 });
    expect(baseline.isServed("/real")).toBe(true);
    clock.advance(5_000);
    baseline.prune();
    expect(baseline.isServed("/real")).toBe(false);
    expect(baseline.snapshot().servedPaths).toBe(0);
  });
});

describe("path-novelty", () => {
  const engineWith = (baseline: SiteProfile, options = {}) =>
    new HoneypotEngine({ enricher: null, site: baseline, detectors: [pathNoveltyDetector(options)] });

  it("says nothing at all until the baseline is warm", async () => {
    const baseline = new SiteProfile();
    const engine = engineWith(baseline);
    for (let i = 0; i < 10; i += 1) {
      // Every one of these paths is unknown — because the baseline knows nothing yet.
      const result = await engine.evaluate(probe(`/unknown/${i}`));
      expect(result.detections).toEqual([]);
    }
  });

  it("fires on an address walking paths this site has never served", async () => {
    const baseline = new SiteProfile();
    warm(baseline);
    const engine = engineWith(baseline);

    const results = [];
    for (let i = 0; i < 5; i += 1) results.push(await engine.evaluate(probe(`/phpmyadmin/${i}`)));

    expect(results.slice(0, 4).every((result) => result.detections.length === 0)).toBe(true);
    const detection = results[4]?.detections[0];
    expect(detection?.detector).toBe("path-novelty");
    expect(detection?.summary).toContain("never served");
    expect(detection?.family).toBe("path-probing");
  });

  it("leaves the site's own pages alone, however many are requested", async () => {
    const baseline = new SiteProfile();
    warm(baseline);
    const engine = engineWith(baseline);
    for (let i = 0; i < 20; i += 1) {
      const result = await engine.evaluate(probe(`/page/${i % 20}`, "198.51.100.77"));
      expect(result.detections).toEqual([]);
    }
  });

  it("catches a walk spread across addresses that each stay quiet", async () => {
    const baseline = new SiteProfile();
    warm(baseline);
    // Four addresses, one request each — nothing any volume detector would notice.
    for (const ip of ["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"]) {
      baseline.record({ ip, path: "/cgi-bin/luci", status: 404 });
    }
    const engine = engineWith(baseline);

    const result = await engine.evaluate(probe("/cgi-bin/luci", "203.0.113.5"));
    expect(result.detections[0]?.detector).toBe("path-novelty");
    expect(result.detections[0]?.summary).toContain("distinct addresses");
  });

  it("skips a crawler DNS has confirmed", async () => {
    const baseline = new SiteProfile();
    warm(baseline);
    const detector = pathNoveltyDetector();
    const engine = new HoneypotEngine({ enricher: null, site: baseline, detectors: [] });
    const tracker = engine.registry.for("66.249.66.1");
    for (let i = 0; i < 10; i += 1) tracker.record({ method: "GET", path: `/gone/${i}`, status: "seen" });

    const base = { ...probe("/gone/1", "66.249.66.1"), tracker, timestamp: new Date(), fingerprint: "fp", fingerprintRegistry: engine.fingerprints, site: baseline };
    expect(detector.inspect(base)).toBeDefined();
    expect(detector.inspect({ ...base, verifiedCrawler: "googlebot" })).toBeUndefined();
  });
});

describe("the names it had before it matched bothandlerjs's", () => {
  it("still accepts a baseline option, exposes engine.baseline, and exports SiteBaseline", async () => {
    const { SiteBaseline } = await import("../src/index.js");
    const profile = new SiteBaseline();
    const engine = new HoneypotEngine({ enricher: null, baseline: profile, detectors: [] });
    expect(engine.site).toBe(profile);
    expect(engine.baseline).toBe(profile);
    expect(new HoneypotEngine({ enricher: null, baseline: null, detectors: [] }).site).toBeUndefined();
  });

  it("reads a detection's tier when it names no certainty", async () => {
    const { certaintyOf, tierOf } = await import("../src/evidence.js");
    expect(certaintyOf({ detector: "x", summary: "r", score: 1, tier: "strong" })).toBe("strong");
    expect(certaintyOf({ detector: "x", summary: "r", score: 1, tier: "weak", certainty: "certain" })).toBe("certain");
    expect(tierOf).toBe(certaintyOf);
  });
});

describe("reporting outcomes", () => {
  it("feeds the engine's baseline and announces the outcome", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    const heard: RequestOutcome[] = [];
    engine.on("outcome", (outcome) => heard.push(outcome));

    engine.reportOutcome({ ip: "198.51.100.1", path: "/pricing", status: 200 });
    expect(engine.site?.isServed("/pricing")).toBe(true);
    expect(heard).toEqual([{ ip: "198.51.100.1", path: "/pricing", status: 200 }]);
  });

  it("can be switched off entirely", () => {
    const engine = new HoneypotEngine({ enricher: null, site: null });
    expect(engine.site).toBeUndefined();
    // Still safe to call: a caller reporting outcomes does not need to know.
    expect(() => engine.reportOutcome({ ip: "198.51.100.1", path: "/", status: 200 })).not.toThrow();
  });
});
