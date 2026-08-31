import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import http from "node:http";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

/**
 * Starts the honeypot and the web dashboard as one foreground command.
 *
 * Running them separately means two terminals, remembering which port the management
 * API landed on, and pasting an API key by hand before the GUI shows anything. This
 * owns all of that: it starts both, waits for the management API to actually answer
 * before telling you the dashboard is ready, hands the key to the GUI, and shuts the
 * pair down together so neither is left orphaned holding a port.
 *
 *   node --import tsx scripts/launch.ts dev     honeypot from source + dashboard
 *   node --import tsx scripts/launch.ts start   built honeypot + dashboard
 *
 * Children are spawned as plain `node` processes (never through a package-runner
 * wrapper), so the signal a terminal sends on Ctrl-C reaches the real process rather
 * than a launcher that would exit and leave the honeypot running.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");

type Mode = "dev" | "start";

const mode = (process.argv[2] ?? "dev") as Mode;
if (mode !== "dev" && mode !== "start") {
  console.error(`launch: unknown mode "${mode}" — expected "dev" or "start"`);
  process.exit(2);
}

const mgmtPort = Number(process.env.MGMT_PORT ?? process.env.MANAGEMENT_PORT ?? 9500);
const mgmtHost = process.env.MANAGEMENT_HOST ?? "127.0.0.1";
const dashboardPort = Number(process.env.DASHBOARD_PORT ?? 8080);
const dashboardHost = process.env.DASHBOARD_HOST ?? "127.0.0.1";
const honeypotPort = Number(process.env.PORT ?? 4004);

/**
 * The management API key the dashboard authenticates with.
 *
 * `dev` keeps the dev server's well-known "dev-key" so the two entry points agree.
 * `start` runs the real service, so an absent key is generated rather than defaulted:
 * a predictable key on a production listener is a credential an attacker already has.
 * Setting MANAGEMENT_API_KEYS yourself always wins.
 */
const apiKey =
  process.env.MGMT_API_KEY ??
  process.env.MANAGEMENT_API_KEYS?.split(",")[0]?.trim() ??
  (mode === "dev" ? "dev-key" : randomBytes(24).toString("hex"));

if (mode === "start" && !existsSync(join(ROOT, "dist", "standalone.js"))) {
  console.error(`launch: dist/standalone.js is missing — run \`npm run build\` first, or use \`npm run build:gui\` to do both.`);
  process.exit(2);
}

interface Child {
  label: string;
  proc: ChildProcess;
}

const children: Child[] = [];
let shuttingDown = false;

/** Spawn a child, tagging each of its output lines so two streams stay readable. */
function start(label: string, args: string[], env: NodeJS.ProcessEnv): ChildProcess {
  const proc = spawn(process.execPath, args, {
    cwd: ROOT,
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const tag = `[${label}]`.padEnd(11);
  const pipe = (stream: NodeJS.ReadableStream | null, to: NodeJS.WriteStream): void => {
    let carry = "";
    stream?.on("data", (chunk: Buffer) => {
      const lines = (carry + chunk.toString()).split("\n");
      carry = lines.pop() ?? "";
      for (const line of lines) to.write(`${tag} ${line}\n`);
    });
    stream?.on("end", () => {
      if (carry) to.write(`${tag} ${carry}\n`);
    });
  };
  pipe(proc.stdout, process.stdout);
  pipe(proc.stderr, process.stderr);

  proc.on("exit", (code, signal) => {
    if (shuttingDown) return;
    // One half dying leaves the other useless — a dashboard with nothing behind it, or
    // a honeypot nobody can see. Take the pair down and report why.
    console.error(`\nlaunch: ${label} exited (${signal ?? `code ${code}`}) — stopping the rest.`);
    shutdown(typeof code === "number" && code !== 0 ? code : 1);
  });

  children.push({ label, proc });
  return proc;
}

function shutdown(code: number): void {
  if (shuttingDown) return;
  shuttingDown = true;
  for (const { proc } of children) if (proc.exitCode === null && proc.signalCode === null) proc.kill("SIGTERM");
  // Give them a moment to close listeners, then insist.
  const deadline = setTimeout(() => {
    for (const { proc } of children) if (proc.exitCode === null && proc.signalCode === null) proc.kill("SIGKILL");
    process.exit(code);
  }, 3000);
  deadline.unref();
  void Promise.all(
    children.map(({ proc }) => (proc.exitCode !== null || proc.signalCode !== null ? Promise.resolve() : new Promise<void>((r) => proc.once("exit", () => r())))),
  ).then(() => {
    clearTimeout(deadline);
    process.exit(code);
  });
}

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    process.stdout.write("\n");
    shutdown(0);
  });
}

/** Resolves once the management API answers its unauthenticated /health probe. */
function waitForManagement(timeoutMs = 30_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve) => {
    const attempt = (): void => {
      if (shuttingDown) return resolve(false);
      const req = http.request({ host: mgmtHost, port: mgmtPort, path: "/health", timeout: 1000 }, (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode === 200));
      });
      req.on("error", () => (Date.now() < deadline ? setTimeout(attempt, 200) : resolve(false)));
      req.on("timeout", () => req.destroy());
      req.end();
    };
    attempt();
  });
}

const serverArgs =
  mode === "dev"
    ? ["--import", "tsx", join(ROOT, "scripts", "dev-server.ts")]
    : [join(ROOT, "dist", "standalone.js")];

start("honeypot", serverArgs, {
  MGMT_PORT: String(mgmtPort),
  MGMT_API_KEY: apiKey,
  // The standalone entry point reads these; MANAGEMENT_API_KEYS is also what switches
  // the management API on, which hackerpot.toml leaves off by default.
  MANAGEMENT_API_KEYS: apiKey,
  MANAGEMENT_HOST: mgmtHost,
  MANAGEMENT_PORT: String(mgmtPort),
});

start("dashboard", ["--import", "tsx", join(ROOT, "scripts", "dashboard.ts")], {
  MGMT_URL: `http://${mgmtHost}:${mgmtPort}`,
  DASHBOARD_HOST: dashboardHost,
  DASHBOARD_PORT: String(dashboardPort),
  // Pre-fills the key field so the GUI is usable without a copy/paste step. The
  // dashboard itself refuses to serve it unless it is bound to loopback.
  DASHBOARD_API_KEY: apiKey,
});

const ready = await waitForManagement();
if (shuttingDown) {
  // A child already failed; its own error has been printed.
} else if (!ready) {
  console.error(`\nlaunch: the management API never came up on ${mgmtHost}:${mgmtPort} — see the [honeypot] output above.`);
  shutdown(1);
} else {
  const line = (label: string, value: string): string => `  ${label.padEnd(12)}${value}`;
  console.log(
    [
      "",
      "  hackerpot is up",
      "",
      line("dashboard", `http://${dashboardHost}:${dashboardPort}`),
      line("honeypot", `http://localhost:${honeypotPort}`),
      line("management", `http://${mgmtHost}:${mgmtPort}`),
      line("API key", apiKey === "dev-key" ? `${apiKey}  (pre-filled)` : `${apiKey}  (generated, pre-filled)`),
      "",
      line("traffic", "npm run attack:all"),
      // `start` runs the real standalone service, which leaves trust_proxy off (as it
      // should). The simulator spoofs a source IP per scenario to keep their scores
      // apart, so against this target every scenario lands on one address, that address
      // is blocked during the first one, and the rest of the run is 403s. Flag it here
      // rather than letting a demo look broken; the simulator also says so if it happens.
      ...(mode === "start"
        ? [line("", "for per-scenario source IPs, restart with TRUST_PROXY=true (local demo only)")]
        : []),
      line("stop", "Ctrl-C"),
      "",
    ].join("\n"),
  );
}
