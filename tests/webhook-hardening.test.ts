import { createHmac } from "node:crypto";
import http from "node:http";
import type net from "node:net";
import { describe, expect, it } from "vitest";
import { parseConfig } from "../src/config/schema.js";
import { IncidentBroker } from "../src/management/broker.js";
import { WebhookDispatcher, type WebhookDispatcherOptions } from "../src/management/webhooks.js";
import type { HoneypotHit } from "../src/types.js";

let counter = 0;
const hit = (ip = "203.0.113.70"): HoneypotHit => ({
  id: `hit-${(counter += 1)}`,
  timestamp: new Date().toISOString(),
  ip,
  method: "GET",
  path: "/.env",
  headers: {},
  detections: [{ detectorId: "decoy-path", reason: "probe", score: 10 }],
  score: 10,
  totalScore: 10,
  respondedWith: "decoy-content",
});

interface Received {
  headers: http.IncomingHttpHeaders;
  body: string;
}

async function receiver(status: (request: number) => number) {
  const received: Received[] = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      received.push({ headers: req.headers, body });
      res.statusCode = status(received.length);
      res.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as net.AddressInfo;
  return { url: `http://127.0.0.1:${port}/hook`, received, close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
}

async function until(check: () => boolean, ms = 5_000): Promise<void> {
  const started = Date.now();
  while (!check()) {
    if (Date.now() - started > ms) throw new Error("condition not met in time");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

function attached(options: WebhookDispatcherOptions): { broker: IncidentBroker; dispatcher: WebhookDispatcher } {
  const broker = new IncidentBroker();
  const dispatcher = new WebhookDispatcher(options);
  dispatcher.attach(broker);
  return { broker, dispatcher };
}

describe("webhook signatures", () => {
  it("adds a timestamped signature that can be checked for freshness, and keeps the original", async () => {
    const rx = await receiver(() => 200);
    const { broker, dispatcher } = attached({ webhooks: [{ url: rx.url, secret: "s3cret" }] });
    try {
      broker.publish(hit());
      await until(() => rx.received.length === 1);
      const { headers, body } = rx.received[0]!;
      const timestamp = String(headers["x-hackerpot-timestamp"]);
      expect(Math.abs(Number(timestamp) - Date.now() / 1000)).toBeLessThan(60);
      expect(headers["x-hackerpot-signature-v2"]).toBe(`sha256=${createHmac("sha256", "s3cret").update(`${timestamp}.${body}`).digest("hex")}`);
      expect(headers["x-hackerpot-signature"]).toBe(`sha256=${createHmac("sha256", "s3cret").update(body).digest("hex")}`);
    } finally {
      dispatcher.detach();
      await rx.close();
    }
  });
});

describe("webhook retries", () => {
  // A refusal fails the same way on every attempt, so retrying only delays the report.
  it("does not retry a delivery the receiver refused", async () => {
    const rx = await receiver(() => 403);
    const errors: string[] = [];
    const { broker, dispatcher } = attached({ webhooks: [{ url: rx.url, maxRetries: 3 }], onError: (_url, error) => void errors.push(error.message) });
    try {
      broker.publish(hit());
      await until(() => errors.length === 1);
      await new Promise((resolve) => setTimeout(resolve, 700));
      expect(rx.received).toHaveLength(1);
      expect(errors[0]).toMatch(/403, not retried/);
    } finally {
      dispatcher.detach();
      await rx.close();
    }
  });

  it("still retries a server error and a 429", async () => {
    const rx = await receiver((request) => (request === 1 ? 503 : request === 2 ? 429 : 200));
    const { broker, dispatcher } = attached({ webhooks: [{ url: rx.url, maxRetries: 3 }] });
    try {
      broker.publish(hit());
      await until(() => rx.received.length === 3, 8_000);
    } finally {
      dispatcher.detach();
      await rx.close();
    }
  }, 15_000);
});

describe("suppressed alerts are summarised", () => {
  it("reports how many alerts de-duplication held back", async () => {
    const rx = await receiver(() => 200);
    const { broker, dispatcher } = attached({ webhooks: [{ url: rx.url, dedupeWindowSeconds: 3600 }], summaryIntervalMs: 150 });
    try {
      for (let i = 0; i < 3; i++) broker.publish(hit("203.0.113.71"));
      await until(() => rx.received.length === 2);
      expect(JSON.parse(rx.received[0]!.body).type).toBe("incident");
      expect(JSON.parse(rx.received[1]!.body)).toMatchObject({ type: "suppressed", count: 2 });
    } finally {
      dispatcher.detach();
      await rx.close();
    }
  });

  it("counts deliveries over the per-minute cap shared by all webhooks", async () => {
    const first = await receiver(() => 200);
    const second = await receiver(() => 200);
    const { broker, dispatcher } = attached({ webhooks: [{ url: first.url }, { url: second.url }], globalMaxPerMinute: 1, summaryIntervalMs: 150 });
    try {
      broker.publish(hit());
      await until(() => first.received.length + second.received.length === 2);
      expect(JSON.parse(first.received[0]!.body).type).toBe("incident");
      expect(JSON.parse(second.received[0]!.body)).toMatchObject({ type: "suppressed", count: 1 });
    } finally {
      dispatcher.detach();
      await first.close();
      await second.close();
    }
  });

  it("reads the shared cap from [management]", () => {
    expect(parseConfig({ management: { webhook_global_max_per_minute: 30 } }, "<test>").management.webhookGlobalMaxPerMinute).toBe(30);
    expect(parseConfig({}, "<test>").management.webhookGlobalMaxPerMinute).toBe(0);
  });
});
