import { describe, expect, it } from "vitest";
import { HoneypotEngine, IpAllowlist, type RequestFacts } from "../src/index.js";

describe("IpAllowlist", () => {
  it("matches exact IPv4 and IPv6 addresses", () => {
    const al = new IpAllowlist(["203.0.113.7", "2001:db8::1"]);
    expect(al.allows("203.0.113.7")).toBe(true);
    expect(al.allows("203.0.113.8")).toBe(false);
    expect(al.allows("2001:db8::1")).toBe(true);
    expect(al.allows("2001:db8::2")).toBe(false);
  });

  it("matches IPv4 CIDR ranges", () => {
    const al = new IpAllowlist(["10.0.0.0/8", "192.168.1.0/24", "172.16.5.5/32"]);
    expect(al.allows("10.255.1.2")).toBe(true);
    expect(al.allows("11.0.0.1")).toBe(false);
    expect(al.allows("192.168.1.200")).toBe(true);
    expect(al.allows("192.168.2.1")).toBe(false);
    expect(al.allows("172.16.5.5")).toBe(true);
    expect(al.allows("172.16.5.6")).toBe(false);
  });

  it("matches IPv6 CIDR ranges", () => {
    const al = new IpAllowlist(["2001:db8::/32", "fd00::/8"]);
    expect(al.allows("2001:db8:1234::abcd")).toBe(true);
    expect(al.allows("2001:db9::1")).toBe(false);
    expect(al.allows("fd12:3456::1")).toBe(true);
    expect(al.allows("fe80::1")).toBe(false);
  });

  it("normalizes IPv4-mapped IPv6 (::ffff:) so a v4 CIDR still matches", () => {
    const al = new IpAllowlist(["127.0.0.0/8"]);
    expect(al.allows("::ffff:127.0.0.1")).toBe(true);
    expect(al.allows("127.0.0.1")).toBe(true);
  });

  it("an empty allowlist allows nothing", () => {
    const al = new IpAllowlist([]);
    expect(al.size).toBe(0);
    expect(al.allows("127.0.0.1")).toBe(false);
  });

  it("surfaces unparseable entries instead of silently exempting nothing", () => {
    const al = new IpAllowlist(["10.0.0.0/8", "10.0.0.0/8x", "not-an-ip", "192.168.1.0/33", "300.1.2.3"]);
    expect(al.invalid).toEqual(["10.0.0.0/8x", "not-an-ip", "192.168.1.0/33", "300.1.2.3"]);
    expect(al.allows("10.1.2.3")).toBe(true); // the one valid entry still works
    expect(al.allows("300.1.2.3")).toBe(false);
  });
});

describe("engine allowlist bypass", () => {
  const probe = (ip: string): RequestFacts => ({ method: "GET", path: "/.env", query: {}, headers: { host: "x", "user-agent": "sqlmap/1.7" }, ip });

  it("exempts allowlisted IPs from all detection but still flags others", async () => {
    const engine = new HoneypotEngine({ allowlist: ["10.0.0.0/8", "monitoring.internal", "203.0.113.9"] });

    // An obvious attack (decoy path + scanner UA) from an allowlisted range: nothing fires.
    const exempt = await engine.evaluate(probe("10.1.2.3"));
    expect(exempt.detections).toHaveLength(0);
    expect(engine.isAllowlisted("10.1.2.3")).toBe(true);

    const exemptExact = await engine.evaluate(probe("203.0.113.9"));
    expect(exemptExact.detections).toHaveLength(0);

    // The same attack from a non-allowlisted IP still fires.
    const flagged = await engine.evaluate(probe("198.51.100.42"));
    expect(flagged.detections.length).toBeGreaterThan(0);
  });

  it("allowlisted traffic leaves no per-IP footprint (never scores)", async () => {
    const engine = new HoneypotEngine({ allowlist: ["10.0.0.0/8"] });
    for (let i = 0; i < 30; i++) await engine.evaluate({ method: "GET", path: `/dir-${i}`, query: {}, headers: { host: "x" }, ip: "10.5.5.5" });
    expect(await engine.scoreFor("10.5.5.5")).toBe(0); // no path-bruteforce, no scoring
  });
});

describe("an allowlisted IPv6 address matches however it is spelled", () => {
  // These entries used to be compared as strings, which for IPv6 is not an equality test
  // at all: one address has many valid spellings and which one arrives is decided by the
  // peer's stack, not by what the operator typed. A monitor that failed to match was not
  // merely un-exempted — it was scored, blocked and (with external enforcement wired)
  // firewalled, silently.
  const forms = ["2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:DB8::0:1", "2001:db8:0:0:0:0:0:1"];

  it("matches every equivalent form, whichever one is configured", () => {
    for (const configured of forms) {
      const allowlist = new IpAllowlist([configured]);
      expect(allowlist.invalid).toEqual([]);
      expect(allowlist.size).toBe(1);
      for (const presented of forms) expect(allowlist.allows(presented)).toBe(true);
    }
  });

  it("still refuses an address that is merely similar", () => {
    const allowlist = new IpAllowlist(["2001:db8::1"]);
    expect(allowlist.allows("2001:db8::2")).toBe(false);
    expect(allowlist.allows("2001:db9::1")).toBe(false);
    expect(allowlist.allows("::1")).toBe(false);
  });

  it("keeps IPv4, v4-mapped and CIDR behaviour unchanged", () => {
    const allowlist = new IpAllowlist(["10.0.0.5", "192.168.0.0/16", "2001:db8:1::/48", "nonsense"]);
    expect(allowlist.invalid).toEqual(["nonsense"]);
    expect(allowlist.allows("10.0.0.5")).toBe(true);
    expect(allowlist.allows("::ffff:10.0.0.5")).toBe(true);
    expect(allowlist.allows("192.168.4.4")).toBe(true);
    expect(allowlist.allows("2001:db8:1:2::9")).toBe(true);
    expect(allowlist.allows("2001:db8:2::9")).toBe(false);
    expect(allowlist.allows("10.0.0.6")).toBe(false);
  });
});
