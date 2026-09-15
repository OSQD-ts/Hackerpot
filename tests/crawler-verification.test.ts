import { describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import { crawlerVerificationDetector, pathBruteforceDetector, rateSpikeDetector } from "../src/detectors/index.js";
import type { RequestFacts } from "../src/detectors/types.js";
import { cachingResolver, forwardConfirmedReverseDns, type DnsResolver } from "../src/internal/dns.js";

const GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
const absent = (): Error => Object.assign(new Error("not found"), { code: "ENOTFOUND" });
const timeout = (): Error => Object.assign(new Error("timed out"), { code: "ETIMEDOUT" });

/** A resolver answering from fixed tables; an Error value is thrown instead of returned. */
function fakeResolver(ptr: Record<string, string[] | Error>, forward: Record<string, string[] | Error> = {}): DnsResolver & { calls: number } {
  const answer = (value: string[] | Error | undefined): Promise<string[]> =>
    value instanceof Error ? Promise.reject(value) : value === undefined ? Promise.reject(absent()) : Promise.resolve(value);
  const resolver = {
    calls: 0,
    reverse: (ip: string) => {
      resolver.calls += 1;
      return answer(ptr[ip]);
    },
    resolveAddresses: (hostname: string) => answer(forward[hostname]),
  };
  return resolver;
}

const facts = (ip: string, userAgent: string, path = "/"): RequestFacts => ({ method: "GET", path, query: {}, headers: { host: "shop.example", "user-agent": userAgent }, ip });

describe("forward-confirmed reverse DNS", () => {
  it("confirms a crawler whose PTR name resolves back to its address, however IPv6 is spelled", async () => {
    const resolver = fakeResolver({ "2001:4860:4801:10::1": ["crawl-1.googlebot.com"] }, { "crawl-1.googlebot.com": ["2001:4860:4801:0010:0000:0000:0000:0001"] });
    expect(await forwardConfirmedReverseDns(resolver, "2001:4860:4801:10::1", ["googlebot.com"])).toMatchObject({ status: "verified" });
  });

  it.each([
    ["a PTR name under another domain", fakeResolver({ "198.51.100.5": ["vps-5.example.net"] }), "wrong-domain"],
    ["a domain suffix that is not a label boundary", fakeResolver({ "198.51.100.5": ["googlebot.com.evil.example"] }), "wrong-domain"],
    ["a PTR name that resolves somewhere else", fakeResolver({ "198.51.100.5": ["crawl-9.googlebot.com"] }, { "crawl-9.googlebot.com": ["66.249.66.9"] }), "address-mismatch"],
    ["no PTR record at all", fakeResolver({ "198.51.100.5": absent() }), "no-ptr"],
  ])("refutes %s", async (_label, resolver, cause) => {
    expect(await forwardConfirmedReverseDns(resolver, "198.51.100.5", ["googlebot.com"])).toMatchObject({ status: "contradicted", cause });
  });

  // No answer is not a no: a resolver hiccup must never brand the real crawler an impersonator.
  it("treats a timeout as proving nothing", async () => {
    expect(await forwardConfirmedReverseDns(fakeResolver({ "66.249.66.1": timeout() }), "66.249.66.1", ["googlebot.com"])).toMatchObject({ status: "indeterminate" });
  });

  it("shares one lookup between concurrent callers", async () => {
    const inner = fakeResolver({ "66.249.66.1": ["crawl-1.googlebot.com"] });
    const cached = cachingResolver(inner);
    await Promise.all([cached.reverse("66.249.66.1"), cached.reverse("66.249.66.1"), cached.reverse("66.249.66.1")]);
    await cached.reverse("66.249.66.1");
    expect(inner.calls).toBe(1);
  });
});

describe("crawler-verification", () => {
  it("does not read a client describing itself as like a crawler as claiming to be one", async () => {
    const resolver = fakeResolver({});
    const engine = new HoneypotEngine({ enricher: null, detectors: [crawlerVerificationDetector({ resolver })] });
    const feedly = "Feedly/1.0 (+http://www.feedly.com/fetcher.html; 4 subscribers; like FeedFetcher-Google)";
    expect((await engine.evaluate(facts("198.51.100.60", feedly))).detections).toEqual([]);
    expect(resolver.calls).toBe(0);
    // A real claim beside a comparison is still a claim.
    const both = await engine.evaluate(facts("198.51.100.61", "FeedFetcher-Google; like FeedFetcher-Google"));
    expect(both.detections[0]?.detectorId).toBe("crawler-verification");
  });

  it("marks a forged Googlebot as proof", async () => {
    const detector = crawlerVerificationDetector({ resolver: fakeResolver({ "198.51.100.7": ["vps-7.example.net"] }) });
    const result = await new HoneypotEngine({ enricher: null, detectors: [detector] }).evaluate(facts("198.51.100.7", GOOGLEBOT_UA));
    expect(result.detections[0]).toMatchObject({ detectorId: "crawler-verification", score: 10, certain: true, metadata: { crawler: "googlebot", cause: "wrong-domain" } });
  });

  it("flags nothing when DNS gives no answer, or when a missing PTR is not treated as forgery", async () => {
    const hung = crawlerVerificationDetector({ resolver: fakeResolver({ "198.51.100.8": timeout() }) });
    expect((await new HoneypotEngine({ enricher: null, detectors: [hung] }).evaluate(facts("198.51.100.8", GOOGLEBOT_UA))).detections).toEqual([]);
    const lenient = crawlerVerificationDetector({ resolver: fakeResolver({ "198.51.100.8": absent() }), treatMissingPtrAsForgery: false });
    expect((await new HoneypotEngine({ enricher: null, detectors: [lenient] }).evaluate(facts("198.51.100.8", GOOGLEBOT_UA))).detections).toEqual([]);
  });

  it("never looks anything up for a request that claims no crawler", async () => {
    const resolver = fakeResolver({});
    await new HoneypotEngine({ enricher: null, detectors: [crawlerVerificationDetector({ resolver })] }).evaluate(facts("198.51.100.9", "Mozilla/5.0 Chrome/122"));
    expect(resolver.calls).toBe(0);
  });

  // The point for middleware deployments: the real Googlebot crawls fast and wide, and must
  // not be blocked for it.
  it("exempts a confirmed crawler from the volume detectors, and only a confirmed one", async () => {
    const ip = "66.249.66.1";
    const resolver = fakeResolver({ [ip]: ["crawl-66-249-66-1.googlebot.com"], "198.51.100.10": ["vps.example.net"] }, { "crawl-66-249-66-1.googlebot.com": [ip] });
    const run = async (source: string, userAgent: string): Promise<string[]> => {
      const engine = new HoneypotEngine({
        enricher: null,
        detectors: [crawlerVerificationDetector({ resolver }), rateSpikeDetector(), pathBruteforceDetector()],
      });
      const fired = new Set<string>();
      for (let i = 0; i < 80; i++) {
        for (const detection of (await engine.evaluate(facts(source, userAgent, `/products/${i}`))).detections) fired.add(detection.detectorId);
      }
      return [...fired].sort();
    };
    expect(await run(ip, GOOGLEBOT_UA)).toEqual([]);
    expect(await run("198.51.100.20", "Mozilla/5.0 Chrome/122")).toEqual(["path-bruteforce", "rate-spike"]);
  });
});
