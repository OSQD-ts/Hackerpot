import http from "node:http";
import net from "node:net";
import { describe, expect, it } from "vitest";
import { WebSocket } from "ws";
import { HoneypotEngine } from "../src/core.js";
import { IncidentBroker } from "../src/management/broker.js";
import { REDACTED, redactIncident } from "../src/management/redact.js";
import { ManagementServer } from "../src/management/server.js";
import { WebhookDispatcher } from "../src/management/webhooks.js";
import { MemoryStore } from "../src/stores/index.js";
import type { HoneypotHit } from "../src/types.js";

const hit = (overrides: Partial<HoneypotHit> = {}): HoneypotHit => ({
  id: "hit-1",
  timestamp: new Date().toISOString(),
  ip: "203.0.113.20",
  method: "POST",
  path: "/login",
  headers: { "user-agent": "curl/8.4.0" },
  detections: [{ detectorId: "decoy-path", reason: "probe", score: 5 }],
  score: 5,
  totalScore: 5,
  respondedWith: "not-found",
  ...overrides,
});

async function until(check: () => boolean, ms = 5_000): Promise<void> {
  const started = Date.now();
  while (!check()) {
    if (Date.now() - started > ms) throw new Error("condition not met in time");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

describe("webhook redaction", () => {
  const secretHit = (): HoneypotHit =>
    hit({
      headers: {
        authorization: "Bearer supersecretvalue123",
        cookie: "sid=abcdefgh12345",
        "x-acme-api-key": "key-9999999999",
        "user-agent": "curl/8.4.0",
      },
      body: "user=admin&password=hunter2hunter2",
      detections: [{ detectorId: "payload-injection", reason: "sql-injection payload detected in body", score: 10, metadata: { sample: "user=admin&password=hunter2hunter2" } }],
    });

  it("strips credential headers, secret-named headers and form passwords, including quoted copies", () => {
    const out = redactIncident(secretHit());
    expect(out.headers).toMatchObject({ authorization: REDACTED, cookie: REDACTED, "x-acme-api-key": REDACTED, "user-agent": "curl/8.4.0" });
    expect(out.body).toBe(`user=admin&password=${REDACTED}`);
    expect(JSON.stringify(out.detections)).not.toContain("hunter2hunter2");
  });

  it("strips secret-named JSON body fields at any depth", () => {
    const out = redactIncident(hit({ body: JSON.stringify({ login: { username: "root", password: "toor-toor" }, api_key: "abcd-efgh" }) }));
    expect(out.body).not.toContain("toor-toor");
    expect(out.body).not.toContain("abcd-efgh");
    expect(out.body).toContain("root");
  });

  it("never modifies the incident it was given", () => {
    const original = secretHit();
    redactIncident(original);
    expect(original.headers["authorization"]).toBe("Bearer supersecretvalue123");
  });

  it("is applied to delivered webhooks by default, and skipped with redact: false", async () => {
    const received: Array<{ incident: HoneypotHit }> = [];
    const receiver = http.createServer((req, res) => {
      let data = "";
      req.on("data", (chunk) => (data += chunk));
      req.on("end", () => {
        received.push(JSON.parse(data));
        res.end("ok");
      });
    });
    await new Promise<void>((resolve) => receiver.listen(0, "127.0.0.1", resolve));
    const { port } = receiver.address() as net.AddressInfo;
    try {
      const broker = new IncidentBroker();
      new WebhookDispatcher({ webhooks: [{ url: `http://127.0.0.1:${port}/redacted` }] }).attach(broker);
      new WebhookDispatcher({ webhooks: [{ url: `http://127.0.0.1:${port}/verbatim`, redact: false }] }).attach(broker);
      broker.publish(secretHit());
      await until(() => received.length === 2);
      const values = received.map((payload) => payload.incident.headers["authorization"]).sort();
      expect(values).toEqual(["Bearer supersecretvalue123", REDACTED].sort());
    } finally {
      await new Promise<void>((resolve) => receiver.close(() => resolve()));
    }
  });
});

describe("live feed backpressure", () => {
  // A viewer that stops reading used to make every incident queue in this process.
  it("drops incidents for a viewer that is not reading instead of buffering them all", async () => {
    const server = new ManagementServer({ store: new MemoryStore(), apiKeys: ["k"], port: 0, host: "127.0.0.1" });
    await server.listen();
    const { port } = server.address() as net.AddressInfo;
    const client = new WebSocket(`ws://127.0.0.1:${port}/stream?api_key=k`);
    try {
      await new Promise<void>((resolve, reject) => {
        client.once("message", () => resolve());
        client.once("error", reject);
      });
      (client as unknown as { _socket: net.Socket })._socket.pause();

      const big = "x".repeat(16 * 1024);
      for (let i = 0; i < 2_000; i += 1) server.publish(hit({ id: `hit-${i}`, body: big }));
      expect(server.streamDropped).toBeGreaterThan(0);
    } finally {
      client.terminate();
      await server.close();
    }
  }, 20_000);
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

describe("detector deadline", () => {
  it("skips a detector that never settles, reports it, and still runs the rest", async () => {
    const sources: string[] = [];
    const engine = new HoneypotEngine({
      enricher: null,
      detectorTimeoutMs: 50,
      extraDetectors: [{ id: "stuck", inspect: () => new Promise(() => undefined) }],
      onError: (_error, context) => void sources.push(context.source),
    });
    const started = Date.now();
    const result = await engine.evaluate({ method: "GET", path: "/.env", query: {}, headers: { host: "x", "user-agent": "curl/8" }, ip: "203.0.113.30" });
    expect(Date.now() - started).toBeLessThan(1_000);
    expect(result.detections.map((d) => d.detectorId)).toContain("decoy-path");
    expect(sources).toContain("stuck");
  });
});
