import { describe, expect, it } from "vitest";
import { ActivityRegistry, FingerprintRegistry } from "../src/state.js";

describe("per-IP state caps are hard ceilings under active traffic", () => {
  it("ActivityRegistry stays at or under maxTrackedIps when nothing is idle", () => {
    const registry = new ActivityRegistry(60_000, 100);
    for (let i = 0; i < 5_000; i += 1) {
      registry.for(`10.0.${(i >> 8) & 255}.${i & 255}`).record({ method: "GET", path: "/", status: "seen" });
    }
    expect(registry.size).toBeLessThanOrEqual(100);
  });

  it("FingerprintRegistry stays at or under maxTracked when nothing has expired", () => {
    const registry = new FingerprintRegistry(3_600_000, 100);
    for (let i = 0; i < 5_000; i += 1) registry.record(`fingerprint-${i}`, "198.51.100.4");
    expect(registry.size).toBeLessThanOrEqual(100);
  });

  it("keeps the most recent tracker rather than evicting the caller's own IP", () => {
    const registry = new ActivityRegistry(60_000, 10);
    for (let i = 0; i < 200; i += 1) {
      registry.for(`10.0.0.${i % 256}`).record({ method: "GET", path: "/", status: "seen" });
    }
    const tracker = registry.for("203.0.113.1");
    tracker.record({ method: "GET", path: "/x", status: "seen" });
    expect(registry.for("203.0.113.1").recent()).toHaveLength(1);
  });
});
