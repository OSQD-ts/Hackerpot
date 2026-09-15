import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { applyEnvOverrides, buildDashboardOptions, buildDashboardSource, parseConfigText } from "../src/config/index.js";
import { HoneypotEngine } from "../src/core.js";
import { ManagementServer } from "../src/management/index.js";
import { MemoryStore } from "../src/stores/index.js";

const run = (args: string[], options: { input?: string; env?: NodeJS.ProcessEnv } = {}): { status: number; stdout: string; stderr: string } => {
  try {
    const stdout = execFileSync(process.execPath, ["--import", "tsx", "src/standalone.ts", ...args], {
      encoding: "utf8",
      timeout: 60_000,
      stdio: ["pipe", "pipe", "pipe"],
      ...(options.input !== undefined ? { input: options.input } : {}),
      env: { ...process.env, ...options.env },
    });
    return { status: 0, stdout, stderr: "" };
  } catch (err) {
    const failure = err as { status: number; stdout: string; stderr: string };
    return { status: failure.status, stdout: failure.stdout, stderr: failure.stderr };
  }
};

const freePort = (): Promise<number> =>
  new Promise((resolve) => {
    const server = createServer();
    server.listen(0, "127.0.0.1", () => {
      const port = (server.address() as AddressInfo).port;
      server.close(() => resolve(port));
    });
  });

describe("hackerpot command line", () => {
  it("prints its version and usage", () => {
    expect(run(["--version"]).stdout).toMatch(/^hackerpot \d+\.\d+\.\d+/);
    const help = run(["--help"]).stdout;
    for (const command of ["serve", "dashboard", "check", "config", "replay", "explain", "detectors", "robots"]) expect(help).toContain(`hackerpot ${command}`);
  }, 90_000);

  it("lists detectors and writes a robots.txt from the config", () => {
    expect(run(["detectors", "--config", "hackerpot.toml"]).stdout).toMatch(/decoy-path[\s\S]*detectors installed/);
    const robots = run(["robots", "--config", "hackerpot.toml", "--sitemap", "https://shop.example/sitemap.xml"]).stdout;
    expect(robots).toContain("Disallow: /.env");
    expect(robots).toContain("Sitemap: https://shop.example/sitemap.xml");
  }, 90_000);

  it("accepts commands and the flags they replaced", () => {
    expect(JSON.parse(run(["config", "--config", "hackerpot.toml"]).stdout).server.port).toBe(4004);
    expect(JSON.parse(run(["--print-config", "--config", "hackerpot.toml"]).stdout).server.port).toBe(4004);
    expect(run(["explain", "nikto/2.5.0", "--url", "/.git/config"]).stdout).toContain("decoy-path");
  }, 90_000);

  it("rejects an unknown command, and exits 2 on a config mistake", () => {
    expect(run(["frobnicate"]).status).toBe(1);
    const dir = mkdtempSync(join(tmpdir(), "hackerpot-cli-"));
    writeFileSync(join(dir, "bad.toml"), "[dashboard]\nenabled = true\nhost = \"0.0.0.0\"\n");
    const bad = run(["config", "--config", join(dir, "bad.toml")]);
    expect(bad.status).toBe(2);
    expect(bad.stderr).toMatch(/\[dashboard\.auth\] is required when the dashboard binds 0\.0\.0\.0/);
  }, 90_000);
});

describe("[dashboard] configuration", () => {
  it("parses auth, sections and the management source, and lets the environment supply secrets", () => {
    const config = parseConfigText(
      `[dashboard]\nenabled = true\nhost = "0.0.0.0"\nusername = "ops"\npassword = "from-file"\nhide = ["intel"]\nmask_ip = true\n`,
      "test.toml",
    );
    const options = buildDashboardOptions(config);
    expect(options).toMatchObject({ host: "0.0.0.0", auth: { username: "ops", password: "from-file" }, sections: { intel: false }, redact: { credentials: true, maskIp: true } });

    applyEnvOverrides(config, { DASHBOARD_TOKEN: "env-token-0123456789", DASHBOARD_ALLOWED_HOSTS: "ops.example, dash.example", DASHBOARD_MANAGEMENT_URL: "http://honeypot:9500", DASHBOARD_MANAGEMENT_API_KEY: "k" });
    expect(buildDashboardOptions(config)).toMatchObject({ auth: { token: "env-token-0123456789" }, allowedHosts: ["ops.example", "dash.example"] });
    expect(buildDashboardSource(config).description).toBe("management API at honeypot:9500");
  });

  it("refuses what could not work", () => {
    expect(() => parseConfigText(`[dashboard]\nhide = ["policy"]\n`, "t.toml")).toThrow(/not a section/);
    expect(() => parseConfigText(`[dashboard]\ntoken = "short"\n`, "t.toml")).toThrow(/at least 16/);
    expect(() => parseConfigText(`[dashboard]\nusername = "ops"\npassword = "x"\nrefusal = "not-found"\n`, "t.toml")).toThrow(/basic auth/);
    expect(() => buildDashboardSource(parseConfigText("", "t.toml"))).toThrow(/no management API/);
  });

  it("checks the dashboard again after environment overrides, before anything binds", () => {
    const config = parseConfigText("[dashboard]\nenabled = true\n", "t.toml");
    expect(() => applyEnvOverrides(config, { DASHBOARD_HOST: "0.0.0.0" })).toThrow(/DASHBOARD_HOST.*needs authentication/);
    const withRefusal = parseConfigText('[dashboard]\nrefusal = "not-found"\n', "t.toml");
    expect(() => applyEnvOverrides(withRefusal, { DASHBOARD_USERNAME: "ops", DASHBOARD_PASSWORD: "pw" })).toThrow(/basic auth cannot work/);
  });

  it("falls back to this config's own management listener and its first key", () => {
    const config = parseConfigText(`[management]\nenabled = true\nhost = "0.0.0.0"\nport = 9600\napi_keys = ["first-key", "second"]\n`, "t.toml");
    expect(buildDashboardSource(config).description).toBe("management API at 127.0.0.1:9600");
  });
});

describe("hackerpot dashboard", () => {
  const cleanups: Array<() => Promise<void> | void> = [];
  afterEach(async () => {
    while (cleanups.length > 0) await cleanups.pop()!();
  });

  it("runs the dashboard as its own process, reading a running management API", async () => {
    const store = new MemoryStore();
    const management = new ManagementServer({ store, host: "127.0.0.1", port: 0, apiKeys: ["management-key-0123456789"] });
    await management.listen();
    cleanups.push(() => management.close());
    const engine = new HoneypotEngine({ enricher: null, store, onHit: (hit) => management.publish(hit) });
    await engine.evaluate({ method: "GET", path: "/.env", query: {}, headers: { host: "x", "user-agent": "sqlmap/1.7" }, ip: "203.0.113.70" });

    const port = await freePort();
    const child = spawn(
      process.execPath,
      ["--import", "tsx", "src/standalone.ts", "dashboard", "--config", "hackerpot.toml", "--port", String(port), "--management-url", `http://127.0.0.1:${(management.address() as AddressInfo).port}`],
      { env: { ...process.env, DASHBOARD_MANAGEMENT_API_KEY: "management-key-0123456789", DASHBOARD_TOKEN: "dashboard-token-0123456789" }, stdio: ["ignore", "pipe", "pipe"] },
    );
    cleanups.push(() => void child.kill("SIGTERM"));
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("dashboard did not start")), 60_000);
      child.stdout.on("data", (chunk: Buffer) => {
        if (String(chunk).includes('"service":"dashboard"')) {
          clearTimeout(timer);
          resolve();
        }
      });
      child.on("exit", (code) => reject(new Error(`dashboard exited with ${code}`)));
    });

    const base = `http://127.0.0.1:${port}`;
    expect((await fetch(`${base}/api/stats`)).status).toBe(401);
    const stats = (await (await fetch(`${base}/api/stats`, { headers: { authorization: "Bearer dashboard-token-0123456789" } })).json()) as { totalIncidents: number };
    expect(stats.totalIncidents).toBe(1);
    const boot = (await (await fetch(`${base}/api/bootstrap?token=dashboard-token-0123456789`)).json()) as { source: string };
    expect(boot.source).toMatch(/^management API at 127\.0\.0\.1:/);
  }, 90_000);
});
