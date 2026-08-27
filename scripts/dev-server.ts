import { HoneypotServer, PortScanSentinel, SmtpHoneypot, SshHoneypot, honeytokenDetector, defaultResponsePolicy, ManagementServer, MemoryStore } from "../src/index.js";
import type { HoneypotHit, ResponsePolicy } from "../src/index.js";

const port = Number(process.env.PORT ?? 4004);
const scanPorts = (process.env.SCAN_PORTS ?? "8022,9200,7001").split(",").map((p) => Number(p.trim())); // decoy TCP ports — nothing legitimate should touch these
const mgmtPort = Number(process.env.MGMT_PORT ?? 9500);
const smtpPort = Number(process.env.SMTP_PORT ?? 2525);
const sshPort = Number(process.env.SSH_PORT ?? 2222);
const apiKey = process.env.MGMT_API_KEY ?? "dev-key";

// A demo policy that showcases the newer response actions: still blocks confirmed
// attackers first, but routes specific probes to the fancier retaliations so you
// can see them in the dashboard.
const base = defaultResponsePolicy();
const demoPolicy: ResponsePolicy = (ctx) => {
  const chosen = base(ctx);
  if (chosen === "block") return "block";
  const ids = new Set(ctx.detections.map((d) => d.detectorId));
  if (ids.has("web-shell")) return "fake-success"; // pretend the shell works — sticky decoy
  if (ids.has("ssrf-probe")) return "gzip-bomb"; // hand a scraper 10 MB of nothing
  if (ids.has("open-redirect")) return "rate-limit"; // 429 the phisher
  if (ids.has("crlf-injection")) return "chaos"; // confuse the tooling
  return chosen;
};

// The value the attack simulator's `honeytoken` scenario replays. In a real
// deployment you'd plant this exact string in a decoy .env / config / page.
export const DEMO_HONEYTOKEN = "AKIA_HACKERPOT_HONEYTOKEN_DEMO";

// One store shared by the honeypot (writes hits) and the management API (reads them).
const store = new MemoryStore();

// The onHit handler feeds the live feed, so it closes over `management`, which is
// created just after the engine (the engine copies onHit in its constructor).
let management: ManagementServer | undefined;

const logHit = (hit: HoneypotHit): void => {
  const reasons = hit.detections.map((d) => `${d.detectorId}(${d.reason})`).join(", ");
  console.log(
    `[hit] ${hit.timestamp} ip=${hit.ip} ${hit.method} ${hit.path} ` +
      `score=+${hit.score} total=${hit.totalScore} -> ${hit.respondedWith}`,
  );
  console.log(`      detections: ${reasons}`);
  if (hit.body) console.log(`      body: ${hit.body.slice(0, 160)}`);
  management?.publish(hit);
};

const server = new HoneypotServer({
  trustProxy: true,
  store,
  policy: demoPolicy,
  extraDetectors: [honeytokenDetector({ tokens: [{ value: DEMO_HONEYTOKEN, label: "demo-aws-key" }] })],
  onHit: async (hit) => logHit(hit),
});

// The SMTP honeypot shares the store, so SMTP incidents contribute to per-IP
// scoring and appear in the management API / dashboard next to HTTP ones.
const smtp = new SmtpHoneypot({
  port: smtpPort,
  banner: "Postfix",
  localDomains: ["hackerpot.test"],
  store,
  onHit: (hit) => logHit(hit),
});

// The SSH honeypot also shares the store, so brute-force attempts contribute to
// the same per-IP reputation and appear in the management API / dashboard.
const ssh = new SshHoneypot({
  port: sshPort,
  ident: "OpenSSH_8.4",
  store,
  onHit: (hit) => logHit(hit),
});

management = new ManagementServer({
  store,
  host: "127.0.0.1",
  port: mgmtPort,
  apiKeys: [apiKey],
  websocket: true,
  onError: (err) => console.error(`[mgmt] ${err.message}`),
  // Live gauges the store can't provide, exposed on GET /metrics. Awaited because a
  // Blocklist's size() may be async (or absent) — an unawaited Promise would render
  // as [object Promise] in the metric.
  metrics: async () => ({ active_blocks: (await server.engine.blocklist.size?.()) ?? 0, tracked_ips: server.engine.registry.size }),
});

const sentinel = new PortScanSentinel({
  ports: scanPorts,
  banner: "SSH-2.0-OpenSSH_8.4",
  onEvent: (event) => {
    const tag = event.isScan ? "PORT-SCAN" : "port-touch";
    console.log(`[${tag}] ip=${event.ip} port=${event.port} portsTouched=${event.portsTouched}${event.banner ? ` banner=${JSON.stringify(event.banner)}` : ""}`);
  },
});

/**
 * Start one listener, reporting a port conflict cleanly instead of crashing the whole
 * dev server. A taken port on one honeypot shouldn't stop you testing the others — it
 * logs how to change the port and carries on. Returns whether it started.
 */
async function tryListen(name: string, envVar: string, portNum: number, start: () => Promise<void>): Promise<boolean> {
  try {
    await start();
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "EADDRINUSE") {
      console.error(`⚠ ${name} not started — TCP ${portNum} is already in use. Set ${envVar}=<free port> (e.g. ${envVar}=${portNum + 1} npm run dev) or free the port.`);
      return false;
    }
    throw err; // anything other than a port clash is a real error worth surfacing
  }
}

const started = {
  http: await tryListen("HTTP honeypot", "PORT", port, () => server.listen(port)),
  sentinel: await tryListen("port-scan sentinel", "SCAN_PORTS", scanPorts[0]!, () => sentinel.listen()),
  management: await tryListen("management API", "MGMT_PORT", mgmtPort, () => management!.listen()),
  smtp: await tryListen("SMTP honeypot", "SMTP_PORT", smtpPort, () => smtp.listen()),
  ssh: await tryListen("SSH honeypot", "SSH_PORT", sshPort, () => ssh.listen()),
};

if (started.http) console.log(`hackerpot dev server listening on http://localhost:${port}`);
if (started.sentinel) console.log(`port-scan sentinel listening on TCP ${scanPorts.join(", ")}`);
if (started.smtp) console.log(`SMTP honeypot listening on TCP ${smtpPort}`);
if (started.ssh) console.log(`SSH honeypot listening on TCP ${sshPort}`);
if (started.management) console.log(`management API on http://127.0.0.1:${mgmtPort}  (API key: "${apiKey}")`);
console.log(`${server.engine.detectors.length} detectors active, ${server.engine.actions.size} response actions registered.`);
console.log(`\nGenerate traffic:  npm run attack:all`);
console.log(`Open the dashboard: npm run dashboard   (then enter the API key above)\n`);
