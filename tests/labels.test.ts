import { describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import type { DnsResolver } from "../src/internal/dns.js";
import { ActorLabels } from "../src/labels.js";
import type { RequestFacts } from "../src/detectors/types.js";
import type { HoneypotHit } from "../src/types.js";
import { buildActorLabels } from "../src/config/build.js";
import { parseConfig } from "../src/config/schema.js";

/**
 * A label answers "who is that?" before an operator has to ask. The thing it must never do is
 * answer "should I care?" — that stays with the detectors.
 */

const probe = (ip: string, userAgent = "curl/8.4.0"): RequestFacts => ({
  method: "GET",
  path: "/.env",
  query: {},
  headers: { host: "shop.example", "user-agent": userAgent },
  ip,
});

const labels = (...entries: ConstructorParameters<typeof ActorLabels>[0]["labels"]) => new ActorLabels({ labels: entries });

describe("naming a known source", () => {
  it("matches on address ranges, organisations, networks and clients", () => {
    const set = labels(
      { name: "Office", match: { ip: ["198.51.100.0/24"] }, note: "The London office" },
      { name: "Our uptime checker", match: { userAgent: "UptimeBot" } },
      { name: "Hosting provider", match: { asn: [64500] } },
      { name: "Cloud", match: { org: "Example Cloud" } },
    );

    expect(set.labelFor({ ip: "198.51.100.9" })).toEqual({ name: "Office", note: "The London office", matchedOn: "ip" });
    expect(set.labelFor({ ip: "203.0.113.1", headers: { "user-agent": "UptimeBot/2.0" } })).toMatchObject({ name: "Our uptime checker", matchedOn: "user-agent" });
    expect(set.labelFor({ ip: "203.0.113.1", enrichment: { category: "public", global: true, asn: 64500 } })).toMatchObject({ name: "Hosting provider", matchedOn: "asn" });
    expect(set.labelFor({ ip: "203.0.113.1", enrichment: { category: "public", global: true, org: "example cloud ltd" } })).toMatchObject({ name: "Cloud", matchedOn: "org" });
    expect(set.labelFor({ ip: "203.0.113.1" })).toBeUndefined();
  });

  it("requires every field a label names, so a label can be as narrow as you like", () => {
    const set = labels({ name: "Partner integration", match: { ip: ["198.51.100.0/24"], userAgent: /partner-sync/i } });
    expect(set.labelFor({ ip: "198.51.100.4", headers: { "user-agent": "partner-sync/1" } })).toMatchObject({ name: "Partner integration" });
    // Right address, wrong client: somebody else on that network, so not this actor.
    expect(set.labelFor({ ip: "198.51.100.4", headers: { "user-agent": "curl/8.4.0" } })).toBeUndefined();
    expect(set.labelFor({ ip: "203.0.113.1", headers: { "user-agent": "partner-sync/1" } })).toBeUndefined();
  });

  it("takes the first label that matches", () => {
    const set = labels({ name: "Specific", match: { ip: ["198.51.100.4"] } }, { name: "The whole network", match: { ip: ["198.51.100.0/24"] } });
    expect(set.labelFor({ ip: "198.51.100.4" })?.name).toBe("Specific");
    expect(set.labelFor({ ip: "198.51.100.5" })?.name).toBe("The whole network");
  });

  it("refuses a label that could not be shown", () => {
    expect(() => labels({ name: "   ", match: { ip: ["10.0.0.1"] } })).toThrow(/needs a name/);
  });
});

describe("a label names, and nothing else", () => {
  it("does not exempt the actor from anything", async () => {
    const engine = new HoneypotEngine({
      enricher: null,
      labels: labels({ name: "Security vendor", match: { ip: ["203.0.113.0/24"] }, note: "Contracted scanning, weekly", hideFromFeed: true }),
    });
    const hits: HoneypotHit[] = [];
    engine.on("hit", (hit) => hits.push(hit));

    const result = await engine.evaluate(probe("203.0.113.40"));

    // Detected and scored exactly as an unnamed source would have been…
    expect(result.detections.map((detection) => detection.detector)).toContain("decoy-path");
    expect(result.score).toBeGreaterThan(0);
    // …and recorded, with the name attached and the mute flag carried alongside it.
    expect(hits[0]?.actor).toMatchObject({ name: "Security vendor", note: "Contracted scanning, weekly", hidden: true, matchedOn: "ip" });
  });

  it("leaves unlabelled traffic untouched", async () => {
    const engine = new HoneypotEngine({ enricher: null, labels: labels({ name: "Office", match: { ip: ["198.51.100.0/24"] } }) });
    const hits: HoneypotHit[] = [];
    engine.on("hit", (hit) => hits.push(hit));
    await engine.evaluate(probe("203.0.113.41"));
    expect(hits[0]?.actor).toBeUndefined();
  });
});

describe("actors in a config file", () => {
  const build = (actors: unknown[], rest: Record<string, unknown> = {}) => buildActorLabels(parseConfig({ actors, ...rest }, "<test>"));

  it("names a source, with its note and its mute flag", () => {
    const set = build([{ name: "Office", ip: ["198.51.100.0/24"], note: "The London office", hide_from_feed: true }]);
    expect(set?.labelFor({ ip: "198.51.100.9" })).toEqual({ name: "Office", note: "The London office", matchedOn: "ip", hidden: true });
  });

  it("reads a value in slashes as a pattern and anything else as plain text", () => {
    const anchored = build([{ name: "Bot", user_agent: "/^UptimeBot/" }]);
    expect(anchored?.labelFor({ ip: "203.0.113.1", headers: { "user-agent": "UptimeBot/2.0" } })).toMatchObject({ name: "Bot" });
    expect(anchored?.labelFor({ ip: "203.0.113.1", headers: { "user-agent": "curl (UptimeBot compatible)" } })).toBeUndefined();

    const substring = build([{ name: "Bot", user_agent: "UptimeBot" }]);
    expect(substring?.labelFor({ ip: "203.0.113.1", headers: { "user-agent": "curl (UptimeBot compatible)" } })).toMatchObject({ name: "Bot" });
  });

  it("refuses a label that names nobody, or that could not be told from another", () => {
    // Nothing to match on: it would be configuration that silently labels no traffic at all.
    expect(() => build([{ name: "Everyone" }])).toThrow(/nothing to match on/);
    expect(() => build([{ ip: ["10.0.0.1"] }])).toThrow(/name.*is required/s);
    expect(() => build([{ name: "Office", ip: ["10.0.0.1"] }, { name: "Office", ip: ["10.0.0.2"] }])).toThrow(/two labels named/);
    expect(() => build([{ name: "Scanner", hostname: "/([unclosed/" }])).toThrow(/not a valid regular expression/);
    expect(() => build([{ name: "Office", ip: ["198.51.100.0/64"] }])).toThrow(/invalid \/prefix/);
    expect(() => build([{ name: "Office", ip: ["10.0.0.1"], hide_from_fed: true }])).toThrow(/unknown key: hide_from_fed/);
  });

  it("builds nothing when no actors are configured", () => {
    expect(build([])).toBeUndefined();
  });
});

describe("resolving names without waiting for them", () => {
  const resolverOf = (reverse: (ip: string) => Promise<string[]>): { resolver: DnsResolver; calls: () => number } => {
    let calls = 0;
    return {
      resolver: {
        reverse: (ip: string) => {
          calls += 1;
          return reverse(ip);
        },
        resolveAddresses: async () => [],
      },
      calls: () => calls,
    };
  };

  it("never makes the current request wait for DNS", async () => {
    // A resolver that never answers — the pathological case, and one an attacker can arrange
    // by probing from addresses whose PTR servers are slow.
    const { resolver } = resolverOf(() => new Promise<string[]>(() => undefined));
    const set = new ActorLabels({ labels: [{ name: "Scanner vendor", match: { hostname: /scanner\.example$/ } }], resolver });

    const started = Date.now();
    expect(set.labelFor({ ip: "203.0.113.9" })).toBeUndefined();
    expect(Date.now() - started).toBeLessThan(50);
  });

  it("labels the next request once the name has resolved", async () => {
    const { resolver, calls } = resolverOf(async () => ["probe1.scanner.example"]);
    const set = new ActorLabels({ labels: [{ name: "Scanner vendor", match: { hostname: /scanner\.example$/ } }], resolver });

    expect(set.labelFor({ ip: "203.0.113.9" })).toBeUndefined();
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(set.labelFor({ ip: "203.0.113.9" })).toMatchObject({ name: "Scanner vendor", matchedOn: "hostname" });

    // A burst from one address is one lookup, not one per request.
    for (let i = 0; i < 50; i += 1) set.labelFor({ ip: "203.0.113.9" });
    expect(calls()).toBe(1);
  });

  it("remembers that an address does not resolve, and reports the failure", async () => {
    const seen: unknown[] = [];
    const { resolver, calls } = resolverOf(async () => {
      throw new Error("NXDOMAIN");
    });
    const set = new ActorLabels({ labels: [{ name: "Scanner vendor", match: { hostname: "scanner.example" } }], resolver, onError: (error) => seen.push(error) });

    set.labelFor({ ip: "203.0.113.9" });
    await new Promise((resolve) => setTimeout(resolve, 10));
    for (let i = 0; i < 20; i += 1) expect(set.labelFor({ ip: "203.0.113.9" })).toBeUndefined();

    expect(calls()).toBe(1);
    expect(seen).toHaveLength(1);
  });

  it("does nothing at all without a resolver", () => {
    const set = new ActorLabels({ labels: [{ name: "Scanner vendor", match: { hostname: "scanner.example" } }] });
    expect(set.labelFor({ ip: "203.0.113.9" })).toBeUndefined();
    expect(set.names()).toEqual(["Scanner vendor"]);
  });
});
