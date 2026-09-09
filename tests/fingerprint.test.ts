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

    // Same curl fingerprint probing a decoy from three different IPs. Each enters the
    // registry on its own scoring request; none is counted before it has earned it.
    const r1 = await engine.evaluate(withRaw(CURL, { path: "/.env", ip: "203.0.113.1" }));
    const r2 = await engine.evaluate(withRaw(CURL, { path: "/.env", ip: "203.0.113.2" }));
    const r3 = await engine.evaluate(withRaw(CURL, { path: "/.env", ip: "203.0.113.3" }));
    for (const r of [r1, r2, r3]) expect(r.detections.map((d) => d.detectorId)).not.toContain("repeat-actor");

    // Now three IPs are confirmed under this fingerprint, so the actor's next probe —
    // from any of them — is recognized as rotation.
    const r4 = await engine.evaluate(withRaw(CURL, { path: "/.env", ip: "203.0.113.1" }));
    const hit = r4.detections.find((d) => d.detectorId === "repeat-actor");
    expect(hit).toBeDefined();
    expect(hit!.metadata?.["distinctIps"]).toBe(3);
    expect(r4.fingerprint).toBe(r1.fingerprint);
  });

  it("does not flag a benign IP that merely shares a fingerprint with known attackers", async () => {
    // The case neither of the original tests covered, and the one that mattered: the
    // registry already holds attackers under a fingerprint, and ordinary traffic
    // carrying that same fingerprint arrives. A fingerprint is header order plus UA
    // family, so every user of one browser build on one site shares it.
    //
    // Counting the current IP unconditionally (`others.length + 1`) meant two attackers
    // were enough to flag every later request with that fingerprint — and since firing
    // is itself a hit, each flagged benign request wrote its own IP into the registry,
    // guaranteeing the next one fired too. Measured before the fix: six of six ordinary
    // requests flagged, and one visitor reaching a cumulative 49 (block threshold 40)
    // in seven page views.
    const engine = new HoneypotEngine({
      detectors: [decoyPathDetector(), repeatActorDetector({ distinctIpThreshold: 3, windowMs: 600_000 })],
    });

    // Seed the registry with genuine attackers sharing the browser fingerprint.
    for (const ip of ["203.0.113.1", "203.0.113.2", "203.0.113.3"]) {
      await engine.evaluate(withRaw(CHROME, { path: "/.env", ip }));
    }

    // Ordinary users, same fingerprint, ordinary pages, fresh addresses.
    for (let i = 1; i <= 6; i++) {
      const result = await engine.evaluate(withRaw(CHROME, { path: "/pricing", ip: `198.51.100.${i}` }));
      expect(result.detections, `benign user ${i}`).toHaveLength(0);
    }

    // And repeated visits from one ordinary user never accrue toward a block.
    let total = 0;
    for (let i = 0; i < 7; i++) {
      total = (await engine.evaluate(withRaw(CHROME, { path: "/pricing", ip: "198.51.100.200" }))).totalScore;
    }
    expect(total).toBe(0);
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
