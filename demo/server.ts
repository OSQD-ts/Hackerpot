#!/usr/bin/env tsx
/**
 * The demo. One command, every listener:
 *
 *   npm run demo
 *
 *   :4004  the HTTP honeypot — the thing attackers actually hit
 *   :9501  the dashboard, showing every incident as it happens
 *   :9500  the management API (REST, live WebSocket, /metrics)
 *   :2222 SSH · :2525 SMTP · :2121 FTP · :2323 Telnet · :8022,9200,7001 port-scan sentinels
 *
 * Then, in a second terminal:
 *
 *   npm run simulate           # every scenario
 *   npm run simulate:corpus    # the traffic corpus, over real sockets
 *
 * The dashboard is the one the library ships (`startDashboard`), not a demo-only page, so
 * what you see here is what you get in your own deployment. It reads this process's engine
 * directly. The same page served beside a running stack, reading its management API, is
 * `hackerpot dashboard`; mounted inside an admin page of yours, `npm run demo:embedded`.
 *
 * The honeypot trusts `X-Forwarded-For` here, which the shipped service does not: the
 * simulator gives every scenario its own address that way, so one scenario's score cannot
 * get the next one blocked before its detector is seen.
 */
import {
  FtpHoneypot,
  HoneypotServer,
  ManagementServer,
  MemoryStore,
  PortScanSentinel,
  SmtpHoneypot,
  SshHoneypot,
  TelnetHoneypot,
  defaultResponsePolicy,
  engineSource,
  honeytokenDetector,
  startDashboard,
  trapDetector,
} from "../src/index.js";
import type { HoneypotHit, ResponsePolicy } from "../src/index.js";
import { CORPUS_HONEYTOKEN, CORPUS_TRAP_FIELD, CORPUS_TRAP_PATH } from "../src/corpus/index.js";

const port = Number(process.env.PORT ?? 4004);
const scanPorts = (process.env.SCAN_PORTS ?? "8022,9200,7001").split(",").map((p) => Number(p.trim()));
const mgmtPort = Number(process.env.MGMT_PORT ?? 9500);
const guiPort = Number(process.env.GUI_PORT ?? 9501);
const smtpPort = Number(process.env.SMTP_PORT ?? 2525);
const sshPort = Number(process.env.SSH_PORT ?? 2222);
const ftpPort = Number(process.env.FTP_PORT ?? 2121);
const telnetPort = Number(process.env.TELNET_PORT ?? 2323);
const apiKey = process.env.MGMT_API_KEY ?? "dev-key";

/** The value the simulator's `honeytoken` scenario replays. Plant the real thing in a decoy `.env`. */
export const DEMO_HONEYTOKEN = "AKIA_HACKERPOT_HONEYTOKEN_DEMO";
/** The trap path the simulator and the corpus request. A real site links it from hidden markup. */
export const DEMO_TRAP_PATH = "/internal/export.csv";

// A policy that still blocks confirmed attackers first, but routes a few probes to the
// showier responses so they can be seen working.
const base = defaultResponsePolicy();
const demoPolicy: ResponsePolicy = (ctx) => {
  const chosen = base(ctx);
  if (chosen === "block") return "block";
  const ids = new Set(ctx.detections.map((d) => d.detectorId));
  if (ids.has("web-shell")) return "fake-success";
  if (ids.has("ssrf-probe")) return "gzip-bomb";
  if (ids.has("open-redirect")) return "rate-limit";
  if (ids.has("crlf-injection")) return "chaos";
  return chosen;
};

// One store for everything: the HTTP engine and every protocol honeypot write to it, so an
// address brute-forcing SSH and probing HTTP accrues one score, and the dashboard shows both.
const store = new MemoryStore();
let management: ManagementServer | undefined;

const logHit = (hit: HoneypotHit): void => {
  console.log(`[hit] ${hit.timestamp} ip=${hit.ip} ${hit.method} ${hit.path} score=+${hit.score} total=${hit.totalScore} -> ${hit.respondedWith}`);
  console.log(`      detections: ${hit.detections.map((d) => `${d.detectorId}(${d.reason})`).join(", ")}`);
  management?.publish(hit);
};

const server = new HoneypotServer({
  trustProxy: true,
  store,
  policy: demoPolicy,
  // The corpus's seeds too, so `npm run simulate:corpus` exercises the same honeytoken and
  // trap the in-process corpus run does.
  extraDetectors: [
    honeytokenDetector({ tokens: [{ value: DEMO_HONEYTOKEN, label: "demo-aws-key" }, { value: CORPUS_HONEYTOKEN, label: "corpus" }] }),
    trapDetector({ paths: [...new Set([DEMO_TRAP_PATH, CORPUS_TRAP_PATH])], formFields: [CORPUS_TRAP_FIELD] }),
  ],
  onHit: (hit) => logHit(hit),
});

/** Protocol honeypots record into the store themselves; this makes their hits visible live too. */
const onProtocolHit = (hit: HoneypotHit): void => {
  logHit(hit);
  server.engine.publish(hit);
};

const smtp = new SmtpHoneypot({ port: smtpPort, banner: "Postfix", localDomains: ["hackerpot.test"], store, onHit: onProtocolHit });
const ssh = new SshHoneypot({ port: sshPort, ident: "OpenSSH_8.4", store, onHit: onProtocolHit });
// Interactive here, unlike the shipped default: locally you want to see what gets typed after login.
const ftp = new FtpHoneypot({ port: ftpPort, banner: "(vsFTPd 3.0.3)", interactive: true, store, onHit: onProtocolHit });
const telnet = new TelnetHoneypot({ port: telnetPort, hostname: "srv01", interactive: true, store, onHit: onProtocolHit });

management = new ManagementServer({
  store,
  host: "127.0.0.1",
  port: mgmtPort,
  apiKeys: [apiKey],
  onError: (err) => console.error(`[mgmt] ${err.message}`),
  metrics: async () => ({ active_blocks: (await server.engine.blocklist.size?.()) ?? 0, tracked_ips: server.engine.registry.size }),
  detectorFailures: () => server.engine.detectorFailures,
});

const sentinel = new PortScanSentinel({
  ports: scanPorts,
  banner: "SSH-2.0-OpenSSH_8.4",
  onEvent: (event) => console.log(`[${event.isScan ? "PORT-SCAN" : "port-touch"}] ip=${event.ip} port=${event.port} portsTouched=${event.portsTouched}`),
});

/** Starts one listener, reporting a taken port and carrying on rather than stopping the demo. */
async function tryListen(name: string, envVar: string, portNum: number, start: () => Promise<unknown>): Promise<boolean> {
  try {
    await start();
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "EADDRINUSE" || /in use/.test((err as Error).message)) {
      console.error(`${name} not started: TCP ${portNum} is in use. Set ${envVar}=<free port>.`);
      return false;
    }
    throw err;
  }
}

let dashboardUrl: string | undefined;
const started = {
  http: await tryListen("HTTP honeypot", "PORT", port, () => server.listen(port)),
  sentinel: await tryListen("port-scan sentinel", "SCAN_PORTS", scanPorts[0]!, () => sentinel.listen()),
  management: await tryListen("management API", "MGMT_PORT", mgmtPort, () => management!.listen()),
  // Loopback and no auth: the operating system is the access control on 127.0.0.1.
  dashboard: await tryListen("dashboard", "GUI_PORT", guiPort, async () => {
    dashboardUrl = (await startDashboard(engineSource(server.engine), { port: guiPort, title: "hackerpot demo", instance: "demo" })).url;
  }),
  smtp: await tryListen("SMTP honeypot", "SMTP_PORT", smtpPort, () => smtp.listen()),
  ssh: await tryListen("SSH honeypot", "SSH_PORT", sshPort, () => ssh.listen()),
  ftp: await tryListen("FTP honeypot", "FTP_PORT", ftpPort, () => ftp.listen()),
  telnet: await tryListen("Telnet honeypot", "TELNET_PORT", telnetPort, () => telnet.listen()),
};

if (started.http) console.log(`honeypot         http://localhost:${port}`);
if (started.dashboard) console.log(`dashboard        ${dashboardUrl}`);
if (started.management) console.log(`management API   http://127.0.0.1:${mgmtPort}  (API key "${apiKey}")`);
if (started.sentinel) console.log(`port sentinels   TCP ${scanPorts.join(", ")}`);
if (started.ssh) console.log(`SSH ${sshPort} · SMTP ${smtpPort} · FTP ${ftpPort} · Telnet ${telnetPort}`);
console.log(`${server.engine.detectors.length} detectors, ${server.engine.actions.size} response actions.`);
console.log("\nGenerate traffic:  npm run simulate      (or npm run simulate:corpus)\n");
