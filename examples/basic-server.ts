/**
 * A minimal real-world integration: hackerpot mounted in front of an app's own
 * routes. Run it with `npm run example`, then try a normal request and a probe:
 *
 *   curl localhost:3000/                          → the real app (localhost is allowlisted)
 *   curl localhost:3000/robots.txt                → decoy paths advertised as Disallow
 *   curl -H "X-Forwarded-For: 203.0.113.5" localhost:3000/.env
 *                                                 → a "remote" attacker: fake bait + a logged hit
 *
 * We allowlist localhost so your own local requests reach the real app, and use
 * X-Forwarded-For to play the part of a remote attacker (trustProxy reads it). In
 * your own project you'd import from "@osqd/hackerpot"; here we import from ../src so the
 * example runs against the working tree. With Express it's the same middleware:
 *   app.use(createMiddleware(engine));   // mount ahead of your routes
 */
import http from "node:http";
import { HoneypotEngine, createMiddleware, generateRobotsTxt, hardenHttpServer, honeytokenDetector } from "../src/index.js";

const PORT = Number(process.env.PORT ?? 3000);

// A honeytoken you'd also plant in a decoy .env / config, so replaying it flags a breach.
const SEEDED_TOKEN = "AKIA_EXAMPLE_SEEDED_TOKEN_DO_NOT_USE";

const engine = new HoneypotEngine({
  trustProxy: true,
  // Exempt localhost so your own local testing reaches the real app; a remote IP
  // (via X-Forwarded-For here) is treated as a potential attacker.
  allowlist: ["127.0.0.1", "::1"],
  extraDetectors: [honeytokenDetector({ tokens: [{ value: SEEDED_TOKEN, label: "example-seed" }] })],
  onHit: (hit) => {
    console.warn(`[honeypot] ${hit.ip} ${hit.method} ${hit.path} -> ${hit.respondedWith} (${hit.detections.map((d) => d.detectorId).join(", ")})`);
  },
});

const honeypot = createMiddleware(engine);
const robotsTxt = generateRobotsTxt({ sitemap: "https://example.com/sitemap.xml" });

const server = http.createServer((req, res) => {
  // 1. hackerpot first: it handles anything a detector flags and calls next() otherwise.
  //    If the honeypot's own machinery fails (e.g. an unreachable blocklist backend) it
  //    reports the error through `onError` and calls next() anyway, so the app is still
  //    served: a honeypot being down must not take the application with it. `err` is
  //    only ever set with `createMiddleware(engine, { failOpen: false })`.
  void honeypot(req, res, (err) => {
    if (err) console.error("[honeypot] degraded, serving the app anyway:", (err as Error).message);
    // 2. Your real application below — reached only for traffic the honeypot didn't flag.
    const path = (req.url ?? "/").split("?")[0];

    if (path === "/robots.txt") {
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end(robotsTxt);
      return;
    }
    if (path === "/") {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.end("<!doctype html><h1>Hello from the real app</h1><p>Nothing to see here.</p>");
      return;
    }
    if (path === "/api/users") {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify([{ id: 1, name: "Alice" }, { id: 2, name: "Bob" }]));
      return;
    }
    res.statusCode = 404;
    res.end("Not Found");
  });
});

// Node's listener defaults are permissive (no connection cap, a 5-minute request
// timeout). In middleware mode the server is yours, so the hardening is your call —
// this is the same one HoneypotServer applies to itself.
hardenHttpServer(server);

server.listen(PORT, () => {
  console.log(`example app + hackerpot on http://localhost:${PORT}`);
  console.log(`try:  curl localhost:${PORT}/   |   curl localhost:${PORT}/robots.txt   |   curl localhost:${PORT}/.env\n`);
});
