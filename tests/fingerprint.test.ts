import { describe, expect, it } from "vitest";
import {
  HoneypotEngine,
  computeFingerprint,
  uaClass,
  decoyPathDetector,
  repeatActorDetector,
  sensitiveFileDetector,
} from "../src/index.js";
import type { RequestFacts } from "../src/index.js";

// A curl-like raw header block: [name, value, name, value, …], order + casing preserved.
const CURL = ["Host", "x", "User-Agent", "curl/8.4.0", "Accept", "*/*"];
const CHROME = ["Host", "x", "Connection", "keep-alive", "User-Agent", "Mozilla/5.0 Chrome/123.0", "Accept", "text/html", "Accept-Encoding", "gzip", "Accept-Language", "en-US"];

function facts(partial: Partial<RequestFacts> & Pick<RequestFacts, "path">): RequestFacts {
  return { method: "GET", query: {}, headers: {}, ip: "10.0.0.1", ...partial };
}

/** Build facts whose parsed headers + rawHeaders both reflect a raw block. */
function withRaw(raw: string[], partial: Partial<RequestFacts> & Pick<RequestFacts, "path">): RequestFacts {
  const headers: Record<string, string> = {};
  for (let i = 0; i < raw.length; i += 2) headers[raw[i]!.toLowerCase()] = raw[i + 1]!;
  return facts({ ...partial, headers, rawHeaders: raw });
}

describe("computeFingerprint", () => {
  it("is stable for identical header order + UA, and differs across clients", () => {
    const a = computeFingerprint(withRaw(CURL, { path: "/", ip: "1.1.1.1" }));
    const b = computeFingerprint(withRaw(CURL, { path: "/other", ip: "2.2.2.2" })); // different IP + path
    expect(a).toBe(b); // fingerprint ignores IP and path — it's the client, not the request
    expect(computeFingerprint(withRaw(CHROME, { path: "/", ip: "1.1.1.1" }))).not.toBe(a);
  });

  it("buckets the User-Agent into a coarse family", () => {
    expect(uaClass("curl/8.4.0")).toBe("tool:curl");
    expect(uaClass("Mozilla/5.0 ... Chrome/123.0 Safari/537")).toBe("browser:chrome");
    expect(uaClass("sqlmap/1.7")).toBe("bot");
    expect(uaClass(undefined)).toBe("none");
  });
});

describe("repeat-actor detector", () => {
  it("fires once one actor fingerprint attacks from >= threshold distinct IPs", async () => {
    const engine = new HoneypotEngine({
      detectors: [decoyPathDetector(), repeatActorDetector({ distinctIpThreshold: 3, windowMs: 600_000 })],
    });

    // Same curl fingerprint probing a decoy from three different IPs.
    const r1 = await engine.evaluate(withRaw(CURL, { path: "/.env", ip: "203.0.113.1" }));
    const r2 = await engine.evaluate(withRaw(CURL, { path: "/.env", ip: "203.0.113.2" }));
    expect(r1.detections.map((d) => d.detectorId)).not.toContain("repeat-actor"); // 1 IP
    expect(r2.detections.map((d) => d.detectorId)).not.toContain("repeat-actor"); // 2 IPs

    const r3 = await engine.evaluate(withRaw(CURL, { path: "/.env", ip: "203.0.113.3" }));
    const hit = r3.detections.find((d) => d.detectorId === "repeat-actor");
    expect(hit).toBeDefined(); // 3rd distinct IP, same actor → rotation
    expect(hit!.metadata?.["distinctIps"]).toBe(3);
    expect(r3.fingerprint).toBe(r1.fingerprint);
  });

  it("never correlates benign traffic — clean requests never enter the registry", async () => {
    const engine = new HoneypotEngine({
      detectors: [sensitiveFileDetector(), repeatActorDetector({ distinctIpThreshold: 2 })],
    });
    // Many IPs sharing one browser fingerprint, none tripping a detector.
    for (let i = 0; i < 5; i++) {
      const r = await engine.evaluate(withRaw(CHROME, { path: "/", ip: `198.51.100.${i}` }));
      expect(r.detections).toHaveLength(0);
    }
    // The registry stayed empty, so a later genuinely-suspicious request from that
    // same fingerprint is NOT pushed over the rotation threshold by benign siblings.
    const probe = await engine.evaluate(withRaw(CHROME, { path: "/backup.sql", ip: "198.51.100.9" }));
    expect(probe.detections.map((d) => d.detectorId)).toContain("sensitive-file");
    expect(probe.detections.map((d) => d.detectorId)).not.toContain("repeat-actor");
  });

  it("an attacker shuffling header order cannot exhaust memory (registry is bounded)", async () => {
    const engine = new HoneypotEngine({ detectors: [decoyPathDetector(), repeatActorDetector()] });
    // Distinct fingerprints from one IP; the cap + eviction keep the map bounded.
    for (let i = 0; i < 50; i++) {
      await engine.evaluate(withRaw(["Host", "x", "X-N", String(i), "User-Agent", "curl/8"], { path: "/.env", ip: "203.0.113.50" }));
    }
    expect(engine.fingerprints.size).toBeLessThanOrEqual(50);
  });
});
