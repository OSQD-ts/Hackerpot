import http from "node:http";
import { createHmac } from "node:crypto";
import { once } from "node:events";
import { afterEach, describe, expect, it } from "vitest";
import { WebSocket } from "ws";
import { ManagementServer, MemoryStore } from "../src/index.js";
import type { HoneypotHit } from "../src/index.js";

function hit(overrides: Partial<HoneypotHit> = {}): HoneypotHit {
  return {
    id: overrides.id ?? Math.random().toString(36).slice(2),
    timestamp: overrides.timestamp ?? new Date().toISOString(),
    ip: overrides.ip ?? "203.0.113.7",
    method: "GET",
    path: overrides.path ?? "/.env",
    headers: {},
    ...(overrides.fingerprint ? { fingerprint: overrides.fingerprint } : {}),
    ...(overrides.body !== undefined ? { body: overrides.body } : {}),
    detections: overrides.detections ?? [{ detectorId: "decoy-path", reason: "probe", score: 10 }],
    score: overrides.score ?? 10,
    totalScore: overrides.totalScore ?? 10,
    respondedWith: overrides.respondedWith ?? "decoy-content",
  };
}

async function json(port: number, path: string, headers: Record<string, string> = {}): Promise<{ status: number; body: any }> {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, { headers });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : undefined };
}

describe("ManagementServer", () => {
  let server: ManagementServer | undefined;
  afterEach(async () => {
    await server?.close();
    server = undefined;
  });

  async function start(store: MemoryStore, opts: Partial<ConstructorParameters<typeof ManagementServer>[0]> = {}): Promise<number> {
    server = new ManagementServer({ store, host: "127.0.0.1", port: 0, apiKeys: ["secret-key"], ...opts });
    await server.listen();
    return (server.address() as { port: number }).port;
  }

  it("serves health without auth and rejects unauthenticated API calls", async () => {
    const port = await start(new MemoryStore());
    expect((await json(port, "/health")).status).toBe(200);
    expect((await json(port, "/incidents")).status).toBe(401);
    expect((await json(port, "/incidents", { "X-API-Key": "wrong" })).status).toBe(401);
  });

  it("rate-limits API-key brute force per peer IP with a 429", async () => {
    const port = await start(new MemoryStore());
    // Hammer with wrong keys from the same peer (127.0.0.1). After the failure budget
    // (20/min) the endpoint stops answering 401 and returns 429 — a brute-force wall.
    let sawTooMany = false;
    for (let i = 0; i < 25; i++) {
      const res = await json(port, "/incidents", { "X-API-Key": "wrong" });
      if (res.status === 429) { sawTooMany = true; break; }
      expect(res.status).toBe(401);
    }
    expect(sawTooMany).toBe(true);
  });

  it("serves Prometheus metrics (authenticated) including injected gauges", async () => {
    const port = await start(new MemoryStore(), { metrics: () => ({ active_blocks: 3 }) });
    // Counted as incidents are published, not read back from the store on every scrape.
    server!.publish(hit({ ip: "1.1.1.1", path: "/.env" }));

    expect((await fetch(`http://127.0.0.1:${port}/metrics`)).status).toBe(401); // needs auth
    const res = await fetch(`http://127.0.0.1:${port}/metrics`, { headers: { Authorization: "Bearer secret-key" } });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/plain");
    const body = await res.text();
    expect(body).toContain("hackerpot_incidents_total 1");
    expect(body).toContain('hackerpot_incidents_by_detector{detector="decoy-path"} 1');
    expect(body).toContain("hackerpot_active_blocks 3");
  });

  it("lists, filters, fetches, and summarizes incidents with a valid key", async () => {
    const store = new MemoryStore();
    store.record(hit({ id: "a", ip: "1.1.1.1", path: "/.env" }));
    store.record(hit({ id: "b", ip: "2.2.2.2", path: "/wp-login.php", detections: [{ detectorId: "credential-bruteforce", reason: "x", score: 9 }] }));
    const port = await start(store);
    const auth = { Authorization: "Bearer secret-key" };

    const all = await json(port, "/incidents", auth);
    expect(all.status).toBe(200);
    expect(all.body.incidents).toHaveLength(2);

    const filtered = await json(port, "/incidents?ip=1.1.1.1", auth);
    expect(filtered.body.incidents).toHaveLength(1);
    expect(filtered.body.incidents[0].id).toBe("a");

    const byDetector = await json(port, "/incidents?detector=credential-bruteforce", auth);
    expect(byDetector.body.incidents[0].id).toBe("b");

    const one = await json(port, "/incidents/a", auth);
    expect(one.status).toBe(200);
    expect(one.body.incident.ip).toBe("1.1.1.1");
    expect((await json(port, "/incidents/missing", auth)).status).toBe(404);

    const stats = await json(port, "/stats", auth);
    expect(stats.body.totalIncidents).toBe(2);
    expect(stats.body.uniqueIps).toBe(2);
    expect(stats.body.byDetector["decoy-path"]).toBe(1);
  });

  it("serves an IOC feed as JSON and as a plain IP list for firewalls", async () => {
    const store = new MemoryStore();
    store.record(hit({ ip: "9.9.9.9", score: 10, totalScore: 10, detections: [{ detectorId: "web-shell", reason: "x", score: 10 }] }));
    store.record(hit({ ip: "9.9.9.9", score: 8, totalScore: 18, detections: [{ detectorId: "sensitive-file", reason: "y", score: 8 }] }));
    store.record(hit({ ip: "5.5.5.5", score: 3, totalScore: 3 }));
    const port = await start(store);
    const auth = { Authorization: "Bearer secret-key" };

    expect((await json(port, "/ioc")).status).toBe(401); // needs auth
    const ioc = await json(port, "/ioc", auth);
    expect(ioc.status).toBe(200);
    expect(ioc.body.indicators[0].ip).toBe("9.9.9.9"); // highest cumulative score first
    expect(ioc.body.indicators[0].score).toBe(18);
    expect(ioc.body.indicators[0].incidents).toBe(2);
    expect(ioc.body.indicators[0].detectors).toEqual(["sensitive-file", "web-shell"]);

    const filtered = await json(port, "/ioc?min_score=10", auth);
    expect(filtered.body.indicators.map((i: any) => i.ip)).toEqual(["9.9.9.9"]);

    const txtRes = await fetch(`http://127.0.0.1:${port}/ioc.txt`, { headers: auth });
    expect(txtRes.headers.get("content-type")).toContain("text/plain");
    expect((await txtRes.text()).trim().split("\n")).toEqual(["9.9.9.9", "5.5.5.5"]);
  });

  it("groups incidents by actor fingerprint across rotating IPs", async () => {
    const store = new MemoryStore();
    // One actor (same fingerprint) from three IPs, plus a different actor.
    store.record(hit({ ip: "1.1.1.1", fingerprint: "aaaa", score: 10 }));
    store.record(hit({ ip: "2.2.2.2", fingerprint: "aaaa", score: 8 }));
    store.record(hit({ ip: "3.3.3.3", fingerprint: "aaaa", score: 5 }));
    store.record(hit({ ip: "9.9.9.9", fingerprint: "bbbb", score: 4 }));
    const port = await start(store);
    const auth = { Authorization: "Bearer secret-key" };

    expect((await json(port, "/actors")).status).toBe(401); // needs auth
    const actors = await json(port, "/actors", auth);
    expect(actors.status).toBe(200);
    expect(actors.body.actors[0].fingerprint).toBe("aaaa"); // most IPs first
    expect(actors.body.actors[0].ips).toEqual(["1.1.1.1", "2.2.2.2", "3.3.3.3"]);
    expect(actors.body.actors[0].score).toBe(23);

    const one = await json(port, "/actors/aaaa", auth);
    expect(one.body.actor.incidents).toBe(3);
    expect((await json(port, "/actors/zzzz", auth)).status).toBe(404);
  });

  it("correlates an IP's incidents into an attack session timeline", async () => {
    const store = new MemoryStore();
    store.record(hit({ ip: "7.7.7.7", path: "/a", timestamp: "2026-08-27T10:00:00.000Z", detections: [{ detectorId: "scanner-signature", reason: "x", score: 2 }] }));
    store.record(hit({ ip: "7.7.7.7", path: "/.env", timestamp: "2026-08-27T10:00:05.000Z", detections: [{ detectorId: "sensitive-file", reason: "y", score: 8 }] }));
    store.record(hit({ ip: "8.8.8.8", path: "/", timestamp: "2026-08-27T09:00:00.000Z" }));
    const port = await start(store);
    const auth = { Authorization: "Bearer secret-key" };

    const all = await json(port, "/sessions", auth);
    expect(all.status).toBe(200);
    expect(all.body.sessions[0].ip).toBe("7.7.7.7"); // most recent activity first

    const one = await json(port, "/sessions/7.7.7.7", auth);
    expect(one.body.session.incidents).toBe(2);
    expect(one.body.session.detectors).toEqual(["scanner-signature", "sensitive-file"]);
    expect(one.body.session.timeline.map((t: any) => t.path)).toEqual(["/a", "/.env"]); // chronological
    expect((await json(port, "/sessions/1.2.3.4", auth)).status).toBe(404);
  });

  it("pushes new incidents over the WebSocket live feed", async () => {
    const port = await start(new MemoryStore());
    const ws = new WebSocket(`ws://127.0.0.1:${port}/stream?api_key=secret-key`);
    await once(ws, "open");

    const messages: any[] = [];
    ws.on("message", (data) => messages.push(JSON.parse(data.toString())));

    server!.publish(hit({ id: "live-1", path: "/actuator/env" }));
    // give the event loop a tick to deliver
    await new Promise((r) => setTimeout(r, 50));

    ws.close();
    const incident = messages.find((m) => m.type === "incident");
    expect(incident?.incident.id).toBe("live-1");
  });

  it("rejects a WebSocket upgrade without a valid key", async () => {
    const port = await start(new MemoryStore());
    const ws = new WebSocket(`ws://127.0.0.1:${port}/stream`);
    const [err] = (await once(ws, "error")) as [Error];
    expect(err).toBeTruthy(); // handshake refused (401)
  });

  it("delivers incidents to a webhook with an HMAC signature", async () => {
    const received: Array<{ signature: string | undefined; body: any }> = [];
    const receiver = http.createServer((req, res) => {
      let data = "";
      req.on("data", (c) => (data += c));
      req.on("end", () => {
        received.push({ signature: req.headers["x-hackerpot-signature"] as string | undefined, body: JSON.parse(data) });
        res.statusCode = 200;
        res.end("ok");
      });
    });
    await new Promise<void>((r) => receiver.listen(0, "127.0.0.1", r));
    const hookPort = (receiver.address() as { port: number }).port;

    const secret = "sign-me";
    // Started for its side effect only — these assertions drive the broker directly
    // via `server.publish`, so the honeypot port is never dialled.
    await start(new MemoryStore(), { webhooks: [{ url: `http://127.0.0.1:${hookPort}/hook`, secret }] });

    server!.publish(hit({ id: "hook-1" }));
    await new Promise((r) => setTimeout(r, 100));

    expect(received).toHaveLength(1);
    expect(received[0]!.body.incident.id).toBe("hook-1");
    const expected = `sha256=${createHmac("sha256", secret).update(JSON.stringify(received[0]!.body)).digest("hex")}`;
    expect(received[0]!.signature).toBe(expected);

    await new Promise<void>((r) => receiver.close(() => r()));
  });

  it("gates alert webhooks by score, de-dupes per IP, and can omit the body", async () => {
    const bodies: any[] = [];
    const receiver = http.createServer((req, res) => {
      let data = "";
      req.on("data", (c) => (data += c));
      req.on("end", () => { bodies.push(JSON.parse(data).incident); res.statusCode = 200; res.end("ok"); });
    });
    await new Promise<void>((r) => receiver.listen(0, "127.0.0.1", r));
    const hookPort = (receiver.address() as { port: number }).port;

    await start(new MemoryStore(), {
      webhooks: [{ url: `http://127.0.0.1:${hookPort}/alert`, minScore: 40, dedupeWindowSeconds: 60, omitBody: true }],
    });

    server!.publish(hit({ id: "low", ip: "5.5.5.5", totalScore: 10 }));      // below minScore → dropped
    server!.publish(hit({ id: "hi-1", ip: "6.6.6.6", totalScore: 50, body: "<script>evil</script>" }));
    server!.publish(hit({ id: "hi-2", ip: "6.6.6.6", totalScore: 60, body: "again" })); // same IP → deduped
    server!.publish(hit({ id: "hi-3", ip: "7.7.7.7", totalScore: 45 }));      // different IP → delivered
    await new Promise((r) => setTimeout(r, 150));

    const ids = bodies.map((b) => b.id).sort();
    expect(ids).toEqual(["hi-1", "hi-3"]); // low dropped, hi-2 deduped
    expect(bodies.find((b) => b.id === "hi-1").body).toBeUndefined(); // omitBody stripped the payload

    await new Promise<void>((r) => receiver.close(() => r()));
  });
});
