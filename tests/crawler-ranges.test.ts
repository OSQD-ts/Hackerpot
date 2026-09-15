import { describe, expect, it } from "vitest";
import { CrawlerRanges, fetchCrawlerRanges, refreshCrawlerRanges, startCrawlerRangeRefresh, validateRanges } from "../src/crawler-ranges.js";
import { HoneypotEngine } from "../src/core.js";
import { crawlerVerificationDetector } from "../src/detectors/index.js";
import type { DnsResolver } from "../src/detectors/index.js";
import type { RequestFacts } from "../src/detectors/types.js";

const json = (prefixes: unknown[]): string => JSON.stringify({ creationTime: "2026-09-01", prefixes });
const fakeFetch =
  (responses: Record<string, () => Response>): typeof fetch =>
  async (input) => {
    const make = responses[String(input)];
    if (!make) throw new Error(`unexpected fetch ${String(input)}`);
    return make();
  };

describe("validateRanges", () => {
  it("keeps what parses and drops what does not", () => {
    expect(validateRanges(["66.249.64.0/27", "2001:4860:4801:10::/64", "not an address", "10.0.0.1"])).toEqual(["66.249.64.0/27", "2001:4860:4801:10::/64", "10.0.0.1"]);
  });

  // An address inside a list is verified, so a list covering the internet would verify everybody.
  it.each([["0.0.0.0/0"], ["10.0.0.0/7"], ["::/0"], ["2000::/3"]])("refuses the whole list when it contains %s", (block) => {
    expect(() => validateRanges(["66.249.64.0/27", block])).toThrow(/refusing the whole list/);
  });

  it("refuses an empty list or one where nothing parses", () => {
    expect(() => validateRanges([])).toThrow(/empty/);
    expect(() => validateRanges(["garbage"])).toThrow(/nothing in the list/);
  });
});

describe("fetchCrawlerRanges", () => {
  const source = { id: "gptbot", url: "https://openai.com/gptbot.json" };

  it("reads Google's JSON format and plain one-per-line lists", async () => {
    const fromJson = await fetchCrawlerRanges(source, { fetch: fakeFetch({ [source.url]: () => new Response(json([{ ipv4Prefix: "20.15.240.64/28" }, { ipv6Prefix: "2a03:2880::/32" }])) }) });
    expect(fromJson).toEqual(["20.15.240.64/28", "2a03:2880::/32"]);
    const fromLines = await fetchCrawlerRanges(source, { fetch: fakeFetch({ [source.url]: () => new Response("# comment\n20.15.240.64/28\n; note\n\n52.230.152.0/24 ; trailing\n") }) });
    expect(fromLines).toEqual(["20.15.240.64/28", "52.230.152.0/24"]);
  });

  it("refuses plain HTTP, error statuses and an oversized body", async () => {
    await expect(fetchCrawlerRanges({ id: "x", url: "http://example.com/list" })).rejects.toThrow(/HTTPS/);
    await expect(fetchCrawlerRanges(source, { fetch: fakeFetch({ [source.url]: () => new Response("nope", { status: 503 }) }) })).rejects.toThrow(/503/);
    const huge = () => new Response("1.2.3.4\n".repeat(700_000));
    await expect(fetchCrawlerRanges(source, { fetch: fakeFetch({ [source.url]: huge }) })).rejects.toThrow(/kB/);
  });
});

describe("refreshCrawlerRanges", () => {
  it("installs what arrived intact and keeps the previous list for what failed", async () => {
    const ranges = new CrawlerRanges();
    ranges.update("bingbot", ["157.55.39.0/24"]);
    const sources = [
      { id: "gptbot", url: "https://openai.com/gptbot.json" },
      { id: "bingbot", url: "https://www.bing.com/toolbox/bingbot.json" },
    ];
    const result = await refreshCrawlerRanges(ranges, {
      sources,
      fetch: fakeFetch({
        "https://openai.com/gptbot.json": () => new Response(json([{ ipv4Prefix: "20.15.240.64/28" }])),
        "https://www.bing.com/toolbox/bingbot.json": () => new Response(json([{ ipv4Prefix: "0.0.0.0/0" }])),
      }),
    });
    expect(result.updated).toEqual([{ id: "gptbot", prefixes: 1 }]);
    expect(result.failed.map((failure) => failure.id)).toEqual(["bingbot"]);
    expect(ranges.contains("gptbot", "20.15.240.70")).toBe(true);
    expect(ranges.contains("bingbot", "157.55.39.1")).toBe(true);
    expect(ranges.contains("duckduckbot", "1.2.3.4")).toBeUndefined();
  });

  it("schedules no more often than hourly and stops cleanly", async () => {
    const ranges = new CrawlerRanges();
    const results: unknown[] = [];
    const stop = startCrawlerRangeRefresh(ranges, {
      intervalMs: 1,
      sources: [{ id: "gptbot", url: "https://openai.com/gptbot.json" }],
      fetch: fakeFetch({ "https://openai.com/gptbot.json": () => new Response(json([{ ipv4Prefix: "20.15.240.64/28" }])) }),
      onRefresh: (result) => results.push(result),
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    stop();
    expect(results).toHaveLength(1);
    expect(ranges.has("gptbot")).toBe(true);
  });
});

describe("crawler verification with published ranges", () => {
  const unusedDns: DnsResolver = {
    reverse: () => Promise.reject(new Error("DNS must not be consulted")),
    resolveAddresses: () => Promise.reject(new Error("DNS must not be consulted")),
  };
  const request = (ua: string, ip: string): RequestFacts => ({ method: "GET", path: "/", query: {}, headers: { host: "x", "user-agent": ua }, ip });
  const ranges = new CrawlerRanges();
  ranges.update("gptbot", ["20.15.240.64/28"]);
  ranges.update("googlebot", ["66.249.64.0/27"]);

  it("confirms a range-only crawler inside its ranges, and refutes one outside them as proof", async () => {
    const detector = crawlerVerificationDetector({ ranges, resolver: unusedDns });
    const engine = new HoneypotEngine({ enricher: null, detectors: [detector] });
    expect((await engine.evaluate(request("Mozilla/5.0; compatible; GPTBot/1.2", "20.15.240.70"))).detections).toEqual([]);
    const forged = await engine.evaluate(request("Mozilla/5.0; compatible; GPTBot/1.2", "198.51.100.9"));
    expect(forged.detections[0]).toMatchObject({ certain: true, metadata: { cause: "outside-published-ranges" } });
  });

  it("says nothing about a range-only crawler before its ranges are installed", async () => {
    const engine = new HoneypotEngine({ enricher: null, detectors: [crawlerVerificationDetector({ ranges: new CrawlerRanges(), resolver: unusedDns })] });
    expect((await engine.evaluate(request("OAI-SearchBot/1.0", "198.51.100.9"))).detections).toEqual([]);
  });

  it("confirms Googlebot inside its ranges without DNS, and leaves DNS to decide outside them", async () => {
    let lookups = 0;
    const counting: DnsResolver = {
      reverse: async () => {
        lookups += 1;
        return ["crawl-66-249-66-1.googlebot.com"];
      },
      resolveAddresses: async () => ["198.51.100.10"],
    };
    const engine = new HoneypotEngine({ enricher: null, detectors: [crawlerVerificationDetector({ ranges, resolver: counting })] });
    const ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
    expect((await engine.evaluate(request(ua, "66.249.64.5"))).detections).toEqual([]);
    expect(lookups).toBe(0);
    expect((await engine.evaluate(request(ua, "198.51.100.10"))).detections).toEqual([]);
    expect(lookups).toBe(1);
  });
});
