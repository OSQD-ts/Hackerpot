import { describe, expect, it } from "vitest";
import { IpAllowlist } from "../src/allowlist.js";
import { CompositeBlocklist, MemoryBlocklist } from "../src/blocklist.js";
import { applyIocEntries } from "../src/intel/index.js";
import { computeIoc } from "../src/management/rest.js";
import { HoneypotServer } from "../src/server.js";
import { MemoryStore } from "../src/stores/index.js";

/**
 * The IOC feed must only ever carry what this instance saw first-hand.
 *
 * If an IP ingested from a peer's feed could reappear in our own `/ioc.txt`, one
 * poisoned feed would spread transitively across a whole fleet, each honeypot
 * republishing its neighbour's hearsay as its own observation. That cannot happen
 * today because of how the pieces fit, not because anything checks for it:
 * `/ioc.txt` is computed from the hit store alone, ingested entries are written to a
 * blocklist and never to the store, and a blocked source is answered 403 before
 * evaluation, so it records no hit either. This test pins that composition so a change
 * to any one piece that breaks it fails here.
 */
describe("the IOC feed publishes first-hand observations only", () => {
  it("never republishes an IP it only learned about from a peer feed", async () => {
    const store = new MemoryStore();
    const feed = new MemoryBlocklist();
    const server = new HoneypotServer({
      store,
      blocklist: new CompositeBlocklist(new MemoryBlocklist(), feed),
      trustProxy: true,
      enricher: null,
    });
    await server.listen(0, "127.0.0.1");
    const { port } = server.address() as { port: number };

    try {
      const ingested = "203.0.113.50";
      const observed = "198.51.100.60";
      const result = applyIocEntries([ingested], { blocklist: feed, allowlist: new IpAllowlist([]) });
      expect(result.blocked).toBe(1);

      const probe = (ip: string): Promise<Response> =>
        fetch(`http://127.0.0.1:${port}/.env`, { headers: { "x-forwarded-for": ip } });

      // The ingested IP attacks us: it is refused at the door and leaves no hit.
      expect((await probe(ingested)).status).toBe(403);
      // An IP nobody told us about attacks us: that is a first-hand observation.
      await probe(observed);

      const ips = (await computeIoc(store)).map((entry) => entry.ip);
      expect(ips).toContain(observed);
      expect(ips).not.toContain(ingested);
    } finally {
      await server.close();
    }
  });
});
