import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { parseConfigText, buildHoneypotConfig, planReload } from "../src/config/index.js";
import { HoneypotEngine } from "../src/core.js";
import type { RequestFacts } from "../src/detectors/types.js";
import { HoneypotServer } from "../src/server.js";
import { ServiceTokens } from "../src/service-tokens.js";

const SECRET = "monitor-secret-0123456789abcdef";
const probe = (headers: Record<string, string> = {}): RequestFacts => ({ method: "GET", path: "/.env", query: {}, headers: { host: "x", "user-agent": "curl/8.4.0", ...headers }, ip: "203.0.113.30" });

describe("ServiceTokens", () => {
  it("names the token presented, and nothing for a wrong or missing one", () => {
    const tokens = new ServiceTokens({ tokens: { monitor: SECRET, deploy: "another-secret-value-000" } });
    expect(tokens.identify({ "x-hackerpot-token": SECRET })).toBe("monitor");
    expect(tokens.identify({ "x-hackerpot-token": `${SECRET}x` })).toBeUndefined();
    expect(tokens.identify({ "x-hackerpot-token": "" })).toBeUndefined();
    expect(tokens.identify({})).toBeUndefined();
  });

  it("uses a custom header, case-insensitively, and reports weak secrets", () => {
    const tokens = new ServiceTokens({ header: "X-Monitor-Key", tokens: { short: "abc", long: SECRET } });
    expect(tokens.identify({ "x-monitor-key": "abc" })).toBe("short");
    expect(tokens.weak).toEqual(["short"]);
  });
});

describe("service-token exemption", () => {
  it("skips detection, scoring and recording for a valid token", async () => {
    const hits: unknown[] = [];
    const engine = new HoneypotEngine({ enricher: null, serviceTokens: { tokens: { monitor: SECRET } }, onHit: (hit) => void hits.push(hit) });
    const exempt = await engine.evaluate(probe({ "x-hackerpot-token": SECRET }));
    expect(exempt).toMatchObject({ detections: [], serviceToken: "monitor" });
    const wrong = await engine.evaluate(probe({ "x-hackerpot-token": "guess" }));
    expect(wrong.detections.length).toBeGreaterThan(0);
    expect(hits).toHaveLength(1);
  });

  it("replaces the tokens on reconfigure", async () => {
    const engine = new HoneypotEngine({ enricher: null, serviceTokens: { tokens: { monitor: SECRET } } });
    engine.reconfigure({ serviceTokens: { tokens: { other: "rotated-secret-value-0000" } } });
    expect(engine.serviceTokenFor({ "x-hackerpot-token": SECRET })).toBeUndefined();
    expect(engine.serviceTokenFor({ "x-hackerpot-token": "rotated-secret-value-0000" })).toBe("other");
  });

  describe("standalone server", () => {
    let server: HoneypotServer | undefined;
    afterEach(async () => server?.close());

    it("does not treat a monitor with a token as an attacker", async () => {
      const hits: unknown[] = [];
      server = new HoneypotServer({ enricher: null, serviceTokens: { tokens: { monitor: SECRET } }, onHit: (hit) => void hits.push(hit) });
      await server.listen(0, "127.0.0.1");
      const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/.env`;
      const res = await fetch(url, { headers: { "x-hackerpot-token": SECRET, "user-agent": "UptimeRobot/2.0" } });
      expect(res.status).toBe(404);
      await res.body?.cancel();
      expect(hits).toEqual([]);
    });
  });

  it("is configured from [service_tokens], reloads, and never prints a secret in the startup summary", () => {
    const config = parseConfigText(`[service_tokens]\nheader = "X-Probe"\n[service_tokens.tokens]\nmonitor = "${SECRET}"\n`, "test.toml");
    expect(config.serviceTokens).toEqual({ header: "x-probe", tokens: { monitor: SECRET } });
    const built = buildHoneypotConfig(config);
    expect(new HoneypotEngine(built.config).serviceTokenFor({ "x-probe": SECRET })).toBe("monitor");
    const next = parseConfigText(`[service_tokens.tokens]\nmonitor = "rotated-secret-value-0000"\n`, "test.toml");
    expect(planReload(config, next).applied).toContain("service_tokens");
    expect(() => parseConfigText(`[service_tokens.tokens]\nmonitor = ""\n`, "test.toml")).toThrow(/empty secret/);
  });
});
