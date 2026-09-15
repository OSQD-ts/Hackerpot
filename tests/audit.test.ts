import { describe, expect, it } from "vitest";
import { TrafficAudit, type AuditRecord } from "../src/audit.js";
import { HoneypotEngine } from "../src/core.js";
import type { Detector, RequestFacts } from "../src/detectors/types.js";
import { parseConfigText, planReload } from "../src/config/index.js";

const MINUTE = 60_000;
const T0 = Date.UTC(2026, 8, 1, 12, 0, 0);
const entry = (at: number, extra: Partial<AuditRecord> = {}): AuditRecord => ({ at, ip: "198.51.100.1", path: "/", flagged: false, blocked: false, downgraded: false, failures: 0, ...extra });

/** An hour of quiet traffic, one request every 20 seconds, 5% of it flagged. */
function quietHour(audit: TrafficAudit): void {
  for (let i = 0; i < 180; i++) audit.record(entry(T0 + i * 20_000, { flagged: i % 20 === 0, ip: `10.0.0.${i % 50}` }));
}

describe("TrafficAudit", () => {
  it("stays quiet on steady traffic", () => {
    const audit = new TrafficAudit({ minSamples: 10 });
    quietHour(audit);
    for (let i = 0; i < 15; i++) audit.record(entry(T0 + 60 * MINUTE + i * 20_000, { flagged: i === 0 }));
    expect(audit.evaluate(T0 + 65 * MINUTE)).toEqual([]);
  });

  it("reports a jump in the flagged share, then holds its cooldown", () => {
    const audit = new TrafficAudit({ minSamples: 10, cooldownMs: 15 * MINUTE });
    quietHour(audit);
    for (let i = 0; i < 40; i++) audit.record(entry(T0 + 61 * MINUTE + i * 5_000, { flagged: true, ip: `203.0.113.${i}`, path: `/probe-${i}` }));
    const first = audit.evaluate(T0 + 65 * MINUTE);
    expect(first.map((anomaly) => anomaly.id)).toContain("flagged-share-spike");
    expect(first.find((anomaly) => anomaly.id === "flagged-share-spike")?.severity).toBe("critical");
    expect(audit.evaluate(T0 + 66 * MINUTE).map((anomaly) => anomaly.id)).not.toContain("flagged-share-spike");
  });

  it("says nothing below the sample floor, however lopsided the ratio", () => {
    const audit = new TrafficAudit({ minSamples: 50 });
    for (let i = 0; i < 5; i++) audit.record(entry(T0 + i * 1000, { flagged: true }));
    expect(audit.evaluate(T0 + 10_000).filter((anomaly) => anomaly.id !== "probe-campaign")).toEqual([]);
  });

  it("reports proof-guard refusals and detector failures", () => {
    const audit = new TrafficAudit({ minSamples: 10 });
    for (let i = 0; i < 60; i++) audit.record(entry(T0 + i * 1000, { downgraded: i % 3 === 0, failures: i % 4 === 0 ? 1 : 0 }));
    const ids = audit.evaluate(T0 + 2 * MINUTE).map((anomaly) => anomaly.id);
    expect(ids).toContain("downgrade-spike");
    expect(ids).toContain("detector-failures");
  });

  it("reports a new path many sources start probing, once per cooldown", () => {
    const audit = new TrafficAudit({ campaignMinIps: 10 });
    // A path probed all along is background noise, not a campaign.
    for (let i = 0; i < 30; i++) audit.record(entry(T0 + i * MINUTE, { flagged: true, path: "/.env", ip: `10.1.0.${i}` }));
    for (let i = 0; i < 12; i++) audit.record(entry(T0 + 58 * MINUTE + i * 5_000, { flagged: true, path: "/.env", ip: `10.2.0.${i}` }));
    for (let i = 0; i < 12; i++) audit.record(entry(T0 + 58 * MINUTE + i * 5_000, { flagged: true, path: "/api/v2/new-cve-endpoint", ip: `203.0.113.${i}` }));
    const campaigns = audit.evaluate(T0 + 60 * MINUTE).filter((anomaly) => anomaly.id === "probe-campaign");
    expect(campaigns).toHaveLength(1);
    expect(campaigns[0]!.details).toEqual({ path: "/api/v2/new-cve-endpoint" });
    expect(audit.evaluate(T0 + 61 * MINUTE).filter((anomaly) => anomaly.id === "probe-campaign")).toEqual([]);
  });

  it("does not count unflagged traffic toward a campaign", () => {
    const audit = new TrafficAudit({ campaignMinIps: 5 });
    for (let i = 0; i < 20; i++) audit.record(entry(T0 + i * 1000, { path: "/launch", ip: `203.0.113.${i}` }));
    expect(audit.evaluate(T0 + MINUTE)).toEqual([]);
  });

  it("skips a check that throws", () => {
    const audit = new TrafficAudit({ minSamples: 1, checks: [{ id: "broken", description: "", evaluate: () => { throw new Error("boom"); } }] });
    audit.record(entry(T0));
    expect(audit.evaluate(T0 + 1000)).toEqual([]);
  });
});

describe("engine audit recording", () => {
  const facts = (path: string, ip: string): RequestFacts => ({ method: "GET", path, query: {}, headers: { host: "x", "user-agent": "curl/8.4.0", accept: "*/*" }, ip });

  it("counts each request once, including a deferred pass and failing detectors", async () => {
    const audit = new TrafficAudit({ minSamples: 1 });
    const broken: Detector = { id: "broken", inspect: () => { throw new Error("boom"); } };
    const engine = new HoneypotEngine({ enricher: null, audit, extraDetectors: [broken], policy: () => "not-found" });
    // A browser's ordinary page load: nothing fires.
    await engine.evaluate({
      ...facts("/", "198.51.100.1"),
      headers: { host: "x", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36", accept: "text/html", "accept-language": "en", "accept-encoding": "gzip" },
    });
    // Middleware's two passes over one flagged request: the deferred one records nothing.
    await engine.evaluate(facts("/.env", "198.51.100.2"), { recordHit: false });
    await engine.evaluate(facts("/.env", "198.51.100.2"), { trackActivity: false });
    await engine.evaluate(facts("/.env", "198.51.100.3"), { audit: false });
    const { window } = audit.summary();
    expect(window).toMatchObject({ requests: 2, flagged: 1, failures: 2 });
    expect(engine.detectorFailures.get("broken")).toBe(3);
  });

  it("is configured from [audit], and a change needs a restart", () => {
    const config = parseConfigText("[audit]\nwindow_seconds = 60\nbaseline_seconds = 600\n", "test.toml");
    expect(config.audit).toMatchObject({ enabled: true, windowSeconds: 60, baselineSeconds: 600 });
    expect(() => parseConfigText("[audit]\nwindow_seconds = 600\nbaseline_seconds = 60\n", "test.toml")).toThrow(/baseline_seconds/);
    expect(planReload(parseConfigText("", "a.toml"), config).requiresRestart.map((entry) => entry.key)).toContain("audit");
  });
});
