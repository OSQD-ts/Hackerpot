import net from "node:net";
import { describe, expect, it } from "vitest";
import { ManagementServer } from "../src/management/server.js";
import { MemoryStore } from "../src/stores/index.js";
import type { HoneypotHit } from "../src/types.js";

const hit = (overrides: Partial<HoneypotHit> = {}): HoneypotHit => ({
  id: "hit-1",
  timestamp: new Date().toISOString(),
  ip: "203.0.113.20",
  method: "POST",
  path: "/login",
  headers: { "user-agent": "curl/8.4.0" },
  detections: [{ detector: "decoy-path", summary: "probe", score: 5 }],
  score: 5,
  totalScore: 5,
  respondedWith: "not-found",
  ...overrides,
});

describe("metrics are counted, not read from the store", () => {
  // Each scrape used to read the whole retained hit log, and its counters fell whenever
  // retention trimmed old hits.
  it("serves /metrics without touching the store, and counters only rise", async () => {
    const store = new MemoryStore();
    store.list = () => {
      throw new Error("a scrape must not read the store");
    };
    const server = new ManagementServer({ store, apiKeys: ["k"], port: 0, host: "127.0.0.1" });
    await server.listen();
    const { port } = server.address() as net.AddressInfo;
    const scrape = async (): Promise<string> => (await fetch(`http://127.0.0.1:${port}/metrics`, { headers: { Authorization: "Bearer k" } })).text();
    try {
      server.publish(hit({ ip: "198.51.100.1", totalScore: 12 }));
      server.publish(hit({ ip: "198.51.100.2", totalScore: 30 }));
      const first = await scrape();
      expect(first).toContain("hackerpot_incidents_total 2");
      expect(first).toContain("hackerpot_unique_ips 2");
      expect(first).toContain("hackerpot_top_offender_score 30");
      expect(first).toContain("hackerpot_stream_dropped_total 0");
      server.publish(hit({ ip: "198.51.100.1" }));
      expect(await scrape()).toContain("hackerpot_incidents_total 3");
    } finally {
      await server.close();
    }
  });
});
