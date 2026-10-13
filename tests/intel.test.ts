import { describe, expect, it, vi } from "vitest";
import { HoneypotEngine, MemoryBlocklist, CompositeBlocklist, IpAllowlist, defaultIpEnricher, fetchIocFeed, applyIocEntries, parseIps, decoyPathDetector, type Blocklist } from "../src/index.js";
import { facts } from "./helpers.js";

describe("defaultIpEnricher", () => {
  it("classifies special-use ranges and marks public IPs global", () => {
    const e = defaultIpEnricher();
    expect(e.enrich("127.0.0.1")).toEqual({ category: "loopback", global: false });
    expect(e.enrich("10.1.2.3")).toEqual({ category: "private", global: false });
    expect(e.enrich("192.168.0.1")).toEqual({ category: "private", global: false });
    expect(e.enrich("100.64.0.1")).toEqual({ category: "cgnat", global: false });
    expect(e.enrich("169.254.1.1")).toEqual({ category: "link-local", global: false });
    expect(e.enrich("203.0.113.5")).toEqual({ category: "documentation", global: false });
    expect(e.enrich("8.8.8.8")).toEqual({ category: "public", global: true });
    expect(e.enrich("fc00::1")).toEqual({ category: "private", global: false });
  });

  it("annotates recorded hits by default, and can be disabled with null", async () => {
    const on = new HoneypotEngine({ detectors: [decoyPathDetector()] });
    const r = await on.evaluate(facts({ path: "/.env", ip: "8.8.8.8" }));
    expect(r.detections.length).toBeGreaterThan(0);
    expect((await on.store.list())[0]!.enrichment).toEqual({ category: "public", global: true });

    const off = new HoneypotEngine({ detectors: [decoyPathDetector()], enricher: null });
    await off.evaluate(facts({ path: "/.env", ip: "8.8.8.8" }));
    expect((await off.store.list())[0]!.enrichment).toBeUndefined();
  });
});

describe("CompositeBlocklist provenance", () => {
  it("reads across children, writes only to the primary", async () => {
    const local = new MemoryBlocklist();
    const feed = new MemoryBlocklist();
    const composite = new CompositeBlocklist(local, feed);

    // Ingest writes into feed directly (hearsay).
    feed.block("1.1.1.1", Date.now() + 60_000);
    // A local detection writes through the composite (first-hand).
    await composite.block("2.2.2.2", Date.now() + 60_000);

    expect(await composite.isBlocked("1.1.1.1")).toBe(true); // seen via feed
    expect(await composite.isBlocked("2.2.2.2")).toBe(true); // seen via primary
    expect(local.isBlocked("1.1.1.1")).toBe(false); // primary never got the feed entry
    expect(local.isBlocked("2.2.2.2")).toBe(true);
    expect(composite.size()).toBe(2);
  });

  it("ingested blocks never reach an enforcing primary", async () => {
    const enforced: string[] = [];
    // A stand-in enforcing blocklist that records every block it's asked to make.
    const enforcing: Blocklist = {
      block: (ip) => { enforced.push(ip); },
      isBlocked: () => false,
    };
    const feed = new MemoryBlocklist();
    const engine = new HoneypotEngine({ blocklist: new CompositeBlocklist(enforcing, feed) });

    applyIocEntries(["203.0.113.9"], { blocklist: feed, allowlist: engine.allowlist });
    expect(await engine.isBlocked("203.0.113.9")).toBe(true); // honeypot short-circuits it
    expect(enforced).toEqual([]); // but the firewall enforcer was never called
  });
});

describe("applyIocEntries safety rules", () => {
  it("consults the allowlist first, drops invalid, dedupes, and caps", () => {
    const blocklist = new MemoryBlocklist();
    const allowlist = new IpAllowlist(["10.0.0.0/8"]);
    const res = applyIocEntries(
      ["8.8.8.8", "8.8.8.8", "10.1.2.3", "not-an-ip", "1.2.3.4", "9.9.9.9"],
      { blocklist, allowlist, maxEntries: 2 },
    );
    expect(res.skippedAllowlisted).toBe(1); // 10.1.2.3 is in the operator's allowlist
    expect(res.skippedInvalid).toBe(1);
    expect(res.blocked).toBe(2);
    expect(res.cappedAt).toBe(2);
    expect(blocklist.isBlocked("8.8.8.8")).toBe(true);
    expect(blocklist.isBlocked("10.1.2.3")).toBe(false); // allowlisted, never blocked
  });

  it("routes an async block() rejection to onError instead of crashing", async () => {
    const errors: Error[] = [];
    // An async blocklist whose backend is down — like RedisBlocklist under enforce=true.
    const failing: Blocklist = {
      block: () => Promise.reject(new Error("redis down")),
      isBlocked: () => false,
    };
    applyIocEntries(["1.2.3.4"], { blocklist: failing, allowlist: new IpAllowlist(), onError: (e) => errors.push(e) });
    await new Promise((r) => setTimeout(r, 10)); // let the rejected promise settle
    expect(errors.map((e) => e.message)).toContain("redis down");
  });

  it("TTLs ingested blocks so stale hearsay expires", () => {
    const blocklist = new MemoryBlocklist();
    const now = 1_000_000;
    applyIocEntries(["1.2.3.4"], { blocklist, allowlist: new IpAllowlist(), ttlMs: 60_000, now });
    expect(blocklist.isBlocked("1.2.3.4", now + 30_000)).toBe(true);
    expect(blocklist.isBlocked("1.2.3.4", now + 61_000)).toBe(false);
  });
});

describe("fetchIocFeed", () => {
  const body = "# peer ioc feed\n203.0.113.1\n203.0.113.2\nnot-an-ip\n\n203.0.113.3\n";

  it("parses IPs, ignoring comments/blanks/junk", () => {
    expect(parseIps(body)).toEqual(["203.0.113.1", "203.0.113.2", "203.0.113.3"]);
  });

  it("refuses a plaintext http feed to a non-loopback host", async () => {
    await expect(fetchIocFeed("http://feeds.evil.example/ioc.txt")).rejects.toThrow(/https required/);
  });

  it("allows https and loopback http, sends the api key, and returns IPs", async () => {
    const doFetch = vi.fn(async (_url: string | URL | Request, _init?: RequestInit) => new Response(body, { status: 200 }));
    const ips = await fetchIocFeed("https://peer.internal/ioc.txt", { apiKey: "k", fetch: doFetch as unknown as typeof fetch });
    expect(ips).toEqual(["203.0.113.1", "203.0.113.2", "203.0.113.3"]);
    const init = doFetch.mock.calls[0]![1] as RequestInit;
    expect((init.headers as Record<string, string>)["Authorization"]).toBe("Bearer k");

    // loopback over http is allowed (local peers / tests)
    const local = vi.fn(async () => new Response(body, { status: 200 }));
    await expect(fetchIocFeed("http://127.0.0.1:9500/ioc.txt", { fetch: local as unknown as typeof fetch })).resolves.toHaveLength(3);
  });

  it("caps the response body so a runaway feed can't exhaust memory", async () => {
    // A body far larger than the cap; readCapped must stop early.
    const huge = Array.from({ length: 500_000 }, (_, i) => `203.0.113.${i % 255}`).join("\n");
    const doFetch = vi.fn(async () => new Response(huge, { status: 200 }));
    const ips = await fetchIocFeed("https://peer.internal/ioc.txt", { maxBytes: 1024, fetch: doFetch as unknown as typeof fetch });
    // Only the first ~1KB was read, so we get a small fraction, not all 500k.
    expect(ips.length).toBeLessThan(200);
  });
});

describe("IOC feed transport rules survive redirects", () => {
  it("refuses a redirect that downgrades to plaintext", async () => {
    const fakeFetch = (async (input: string | URL) => {
      const url = String(input);
      if (url.startsWith("https://")) {
        return new Response(null, { status: 302, headers: { location: "http://169.254.169.254/latest/meta-data/" } });
      }
      return new Response("203.0.113.1\n", { status: 200 });
    }) as unknown as typeof fetch;

    await expect(fetchIocFeed("https://peer.example/ioc.txt", { fetch: fakeFetch })).rejects.toThrow(/https required/);
  });

  it("follows a redirect that stays on https", async () => {
    const fakeFetch = (async (input: string | URL) => {
      const url = String(input);
      if (url === "https://peer.example/ioc.txt") {
        return new Response(null, { status: 302, headers: { location: "https://peer.example/v2/ioc.txt" } });
      }
      return new Response("203.0.113.1\n198.51.100.2\n", { status: 200 });
    }) as unknown as typeof fetch;

    await expect(fetchIocFeed("https://peer.example/ioc.txt", { fetch: fakeFetch })).resolves.toEqual(["203.0.113.1", "198.51.100.2"]);
  });
});

describe("an IOC feed cannot harvest the operator's API key via a redirect", () => {
  const responses = (...list: Array<{ status: number; location?: string; body?: string }>) => {
    const seen: Array<{ url: string; auth: string | undefined }> = [];
    let i = 0;
    const doFetch = (async (url: string, init: RequestInit) => {
      const headers = (init.headers ?? {}) as Record<string, string>;
      seen.push({ url, auth: headers["Authorization"] });
      const step = list[Math.min(i, list.length - 1)]!;
      i += 1;
      return new Response(step.body ?? "", {
        status: step.status,
        headers: step.location ? { location: step.location } : {},
      });
    }) as unknown as typeof fetch;
    return { doFetch, seen };
  };

  it("drops Authorization when a redirect leaves the original origin", async () => {
    // The management API key is what feeds authenticate with, so leaking it hands over
    // read access to the operator's captured-incident API — not just a public IOC list.
    const { doFetch, seen } = responses(
      { status: 302, location: "https://attacker.example/steal" },
      { status: 200, body: "203.0.113.7\n" },
    );
    const ips = await fetchIocFeed("https://peer.example/ioc.txt", { apiKey: "SUPER-SECRET-KEY", fetch: doFetch });

    expect(ips).toEqual(["203.0.113.7"]);
    expect(seen[0]!.auth).toBe("Bearer SUPER-SECRET-KEY");
    expect(seen[1]!.url).toBe("https://attacker.example/steal");
    expect(seen[1]!.auth).toBeUndefined();
    expect(JSON.stringify(seen)).not.toContain("SUPER-SECRET-KEY".slice(0, 6) + "-SECRET");
  });

  it("keeps Authorization on a same-origin redirect", async () => {
    const { doFetch, seen } = responses(
      { status: 301, location: "https://peer.example/ioc/v2.txt" },
      { status: 200, body: "198.51.100.4\n" },
    );
    await fetchIocFeed("https://peer.example/ioc.txt", { apiKey: "KEY", fetch: doFetch });
    expect(seen[1]!.auth).toBe("Bearer KEY");
  });

  it("never re-attaches the key after a hop has left the origin", async () => {
    const { doFetch, seen } = responses(
      { status: 302, location: "https://attacker.example/a" },
      { status: 302, location: "https://peer.example/back" },
      { status: 200, body: "" },
    );
    await fetchIocFeed("https://peer.example/ioc.txt", { apiKey: "KEY", fetch: doFetch });
    expect(seen.slice(1).every((s) => s.auth === undefined)).toBe(true);
  });

  it("still refuses a redirect that drops to plaintext", async () => {
    const { doFetch } = responses({ status: 302, location: "http://attacker.example/steal" });
    await expect(fetchIocFeed("https://peer.example/ioc.txt", { apiKey: "KEY", fetch: doFetch })).rejects.toThrow(/https required/);
  });
});
