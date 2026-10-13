import { describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import { markerDriftDetector } from "../src/detectors/marker-drift.js";
import type { RequestFacts } from "../src/detectors/types.js";
import { MarkerCookie } from "../src/marker.js";
import type { HoneypotHit } from "../src/types.js";

/**
 * A marker is a stronger identifier than a fingerprint, so the tests are mostly about what it
 * is not allowed to do: be minted by whoever presents it, reach somebody who never probed, or
 * convict anybody on its own.
 */

const SECRET = "a-secret-long-enough-to-sign-with";

const probe = (ip: string, cookie?: string): RequestFacts => ({
  method: "GET",
  path: "/.env",
  query: {},
  headers: { host: "shop.example", "user-agent": "curl/8.4.0", ...(cookie !== undefined ? { cookie } : {}) },
  ip,
});

describe("the marker cookie", () => {
  const markers = new MarkerCookie({ secret: SECRET });

  it("issues a marker it can read back", () => {
    const marker = markers.issue();
    expect(markers.read({ cookie: `__hp=${marker}` })).toBe(marker.split(".")[0]);
  });

  it("refuses anything it did not sign, without saying which failure it was", () => {
    const marker = markers.issue();
    const [id, signature] = marker.split(".");
    // Minted from nothing.
    expect(markers.read({ cookie: "__hp=deadbeefdeadbeefdeadbeef.0123456789abcdef0123456789abcdef" })).toBeUndefined();
    // Somebody else's secret.
    expect(new MarkerCookie({ secret: "a-different-secret-entirely" }).read({ cookie: `__hp=${marker}` })).toBeUndefined();
    // Edited id, original signature.
    expect(markers.read({ cookie: `__hp=ffffffffffffffffffffffff.${signature}` })).toBeUndefined();
    // Truncated, malformed, absent, and a cookie of another name.
    expect(markers.read({ cookie: `__hp=${id}` })).toBeUndefined();
    expect(markers.read({ cookie: "__hp=" })).toBeUndefined();
    expect(markers.read({ cookie: "session=abc; other=def" })).toBeUndefined();
    expect(markers.read({})).toBeUndefined();
  });

  it("finds its cookie among others, whatever the spacing", () => {
    const marker = markers.issue();
    const id = marker.split(".")[0];
    expect(markers.read({ cookie: `session=abc;__hp=${marker}; theme=dark` })).toBe(id);
    expect(markers.read({ cookie: [`session=abc`, `__hp=${marker}`] })).toBe(id);
  });

  it("is set as a cookie page script cannot read or plant", () => {
    const header = markers.header(markers.issue());
    expect(header).toContain("HttpOnly");
    expect(header).toContain("SameSite=Lax");
    expect(header).toContain("Secure");
    expect(header).toContain("Path=/");
  });

  it("refuses to exist without a secret, and says when one is too short to matter", () => {
    expect(() => new MarkerCookie({ secret: "" })).toThrow(/needs a secret/);
    expect(new MarkerCookie({ secret: "short" }).weakSecret).toBe(true);
    expect(new MarkerCookie({ secret: SECRET }).weakSecret).toBe(false);
  });
});

describe("marker drift", () => {
  it("correlates one marked client across addresses", async () => {
    const markers = new MarkerCookie({ secret: SECRET });
    const engine = new HoneypotEngine({ enricher: null, markers, extraDetectors: [markerDriftDetector()] });
    const marker = markers.issue();
    const cookie = `__hp=${marker}`;

    // The same marker, from three addresses. Each request probes a decoy, so each is an
    // incident in its own right — which is the only way a marker gets recorded at all.
    await engine.evaluate(probe("203.0.113.1", cookie));
    await engine.evaluate(probe("203.0.113.2", cookie));
    const third = await engine.evaluate(probe("203.0.113.3", cookie));

    const drift = third.detections.find((detection) => detection.detector === "marker-drift");
    expect(drift).toBeDefined();
    expect(drift?.summary).toContain("3 addresses");
    expect(drift?.certain).toBeUndefined();
    expect(third.detections.some((detection) => detection.detector === "decoy-path")).toBe(true);
  });

  it("says nothing about a client that carries no marker, or one nobody issued", async () => {
    const markers = new MarkerCookie({ secret: SECRET });
    const engine = new HoneypotEngine({ enricher: null, markers, extraDetectors: [markerDriftDetector({ distinctIpThreshold: 1 })] });

    const bare = await engine.evaluate(probe("203.0.113.10"));
    expect(bare.detections.some((detection) => detection.detector === "marker-drift")).toBe(false);

    const forged = await engine.evaluate(probe("203.0.113.11", "__hp=deadbeefdeadbeefdeadbeef.0123456789abcdef0123456789abcdef"));
    expect(forged.detections.some((detection) => detection.detector === "marker-drift")).toBe(false);
  });

  it("records the marker on the incident", async () => {
    const markers = new MarkerCookie({ secret: SECRET });
    const engine = new HoneypotEngine({ enricher: null, markers });
    const marker = markers.issue();
    const hits: HoneypotHit[] = [];
    engine.on("hit", (hit) => hits.push(hit));

    await engine.evaluate(probe("203.0.113.20", `__hp=${marker}`));

    expect(hits[0]?.marker).toBe(marker.split(".")[0]);
  });

  it("does nothing at all when markers are not configured", async () => {
    const engine = new HoneypotEngine({ enricher: null, extraDetectors: [markerDriftDetector({ distinctIpThreshold: 1 })] });
    const result = await engine.evaluate(probe("203.0.113.30", "__hp=anything"));
    expect(result.detections.some((detection) => detection.detector === "marker-drift")).toBe(false);
  });
});
