import { describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import { defaultDetectors } from "../src/detectors/index.js";
import type { Detector, RequestFacts } from "../src/detectors/types.js";
import { MAX_QUERY_PARAMS, boundedQuery } from "../src/http-request.js";

const BROWSER = {
  host: "shop.example",
  "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
  accept: "text/html,*/*",
  "accept-language": "en-US,en;q=0.9",
  "accept-encoding": "gzip, deflate, br",
};

const flood = (count: number, extra: Record<string, string> = {}): Record<string, string> => {
  const query: Record<string, string> = Object.create(null);
  for (let i = 0; i < count; i++) query[`k${i}`] = "v";
  return Object.assign(query, extra);
};

const facts = (query: Record<string, string>): RequestFacts => ({ method: "GET", path: "/search", query, headers: BROWSER, ip: "203.0.113.80" });

describe("query parameters are bounded before detection", () => {
  it("keeps the first MAX_QUERY_PARAMS and counts the rest", () => {
    const { query, dropped } = boundedQuery(flood(4000));
    expect(Object.keys(query)).toHaveLength(MAX_QUERY_PARAMS);
    expect(query["k0"]).toBe("v");
    expect(dropped).toBe(4000 - MAX_QUERY_PARAMS);
    expect(boundedQuery(flood(10)).dropped).toBe(0);
  });

  // Around ten detectors scan every value, so an unbounded query was a CPU amplifier.
  it("no detector ever sees more than the cap", async () => {
    let seen = 0;
    const spy: Detector = { id: "spy", inspect: (ctx) => void (seen = Math.max(seen, Object.keys(ctx.query).length)) };
    await new HoneypotEngine({ enricher: null, detectors: [spy] }).evaluate(facts(flood(4000)));
    expect(seen).toBe(MAX_QUERY_PARAMS);
  });

  // A payload parked past the cap goes unscanned, but the request carrying it is flagged.
  it("flags the flood itself, so hiding a payload behind it does not evade detection", async () => {
    const hidden = flood(1000, { q: "' UNION SELECT password FROM users --" });
    const result = await new HoneypotEngine({ enricher: null, detectors: defaultDetectors() }).evaluate(facts(hidden));
    const anomaly = result.detections.find((d) => d.detectorId === "header-anomaly");
    expect(anomaly?.metadata?.["kind"]).toBe("query-flood");
    expect(anomaly?.reason).toContain("1001 query parameters");
  });

  it("leaves an ordinary query alone", async () => {
    const result = await new HoneypotEngine({ enricher: null }).evaluate(facts(flood(20)));
    expect(result.detections.find((d) => d.metadata?.["kind"] === "query-flood")).toBeUndefined();
  });
});
