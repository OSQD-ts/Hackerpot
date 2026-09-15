import { describe, expect, it } from "vitest";
import { fetchHoneypot, withFetchHoneypot } from "../src/adapters/fetch.js";
import { HoneypotEngine } from "../src/core.js";
import { dripFeedAction, notFoundAction, tarpitAction } from "../src/responses/index.js";
import type { HoneypotHit } from "../src/types.js";

const BROWSER = {
  "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
  accept: "text/html,*/*",
  "accept-language": "en-US,en;q=0.9",
  "accept-encoding": "gzip, deflate, br",
};

const request = (path: string, init: RequestInit = {}): Request => new Request(`http://shop.example${path}`, { headers: BROWSER, ...init });

describe("fetchHoneypot", () => {
  it("answers a probe with the honeypot's Response", async () => {
    const response = await fetchHoneypot(new HoneypotEngine({ enricher: null }))(request("/.env"), { ip: "203.0.113.90" });
    expect(response?.status).toBe(200);
    expect(await response?.text()).toContain("APP_ENV=production");
  });

  // A body read eagerly would lock the stream and break the app's handler.
  it("passes ordinary traffic on with its body still readable", async () => {
    const original = request("/api/orders", { method: "POST", body: "item=42" });
    const response = await fetchHoneypot(new HoneypotEngine({ enricher: null }))(original, { ip: "203.0.113.91" });
    expect(response).toBeUndefined();
    expect(await original.text()).toBe("item=42");
  });

  it("streams a response the action writes over time", async () => {
    const engine = new HoneypotEngine({
      enricher: null,
      responseActions: [dripFeedAction({ chunkBytes: 4, intervalMs: 10, maxDurationMs: 60 })],
      policy: () => "drip-feed",
    });
    const response = await fetchHoneypot(engine)(request("/.env"), { ip: "203.0.113.92" });
    const body = await response!.text();
    expect(body.startsWith("<!doctype html><html><body>")).toBe(true);
    expect(body.endsWith("</body></html>")).toBe(true);
  });

  // Tarpit waits on `close`; an aborted Fetch request has to deliver one.
  it("releases a tarpit as soon as the client aborts", async () => {
    const engine = new HoneypotEngine({ enricher: null, responseActions: [tarpitAction({ delayMs: 5_000, escalate: false })], policy: () => "tarpit" });
    const controller = new AbortController();
    const started = Date.now();
    const pending = fetchHoneypot(engine)(request("/.env", { signal: controller.signal }), { ip: "203.0.113.93" });
    setTimeout(() => controller.abort(), 50);
    await pending;
    expect(Date.now() - started).toBeLessThan(1_000);
  });
});

describe("withFetchHoneypot", () => {
  it("serves the app's response for passed traffic and the honeypot's for probes", async () => {
    const handler = withFetchHoneypot(new HoneypotEngine({ enricher: null }), () => new Response("app", { status: 200 }));
    expect(await (await handler(request("/pricing"), { ip: "203.0.113.94" })).text()).toBe("app");
    expect(await (await handler(request("/.env"), { ip: "203.0.113.94" })).text()).toContain("APP_ENV=production");
  });

  // The 404 gating needs the app's status, which only the wrapper can report.
  it("reports the handler's status, so a 404 walk trips path-bruteforce and a page load does not", async () => {
    const run = async (status: number, ip: string): Promise<boolean> => {
      const hits: HoneypotHit[] = [];
      const engine = new HoneypotEngine({ enricher: null, responseActions: [notFoundAction()], policy: () => "not-found", onHit: (hit) => void hits.push(hit) });
      const handler = withFetchHoneypot(engine, () => new Response(null, { status }));
      for (let i = 0; i < 20; i++) await handler(request(`/section-${i}/overview`), { ip });
      return hits.some((hit) => hit.detections.some((d) => d.detectorId === "path-bruteforce"));
    };
    expect(await run(404, "203.0.113.95")).toBe(true);
    expect(await run(200, "203.0.113.96")).toBe(false);
  });
});
