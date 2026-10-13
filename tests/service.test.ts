import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

describe("a SIGHUP reload applies all of [logging], not half of it", () => {
  it("applies include_headers, not only format", () => {
    // `format` lived in a module-level binding and reloaded; include_headers/include_body
    // were read from a config object captured in the hit closure and did not. The reload
    // still reported `applied: ["logging"], requiresRestart: []`, so the operator was
    // told the whole section took effect. Half-applied is worse than not applied: seeing
    // format change is what convinces you the rest did too.
    //
    // The child runs the entrypoint FROM SOURCE via `node --import tsx`, not from
    // `dist/`: CI runs `npm test` before `npm run build`, so a test that reached for a
    // build artifact failed there while passing locally off a stale dist. It must also
    // be a single `node` process — `npx tsx` wraps the real process in a launcher that
    // does not forward SIGHUP, so the reload under test would never fire.
    const dir = mkdtempSync(join(tmpdir(), "hackerpot-reload-"));
    const configPath = join(dir, "hackerpot.toml");
    const port = 4655;
    const config = (includeHeaders: boolean): string =>
      `[server]\nhost = "127.0.0.1"\nport = ${port}\n\n[policy]\nblock_threshold = 1000000\ntarpit_threshold = 999999\n\n[logging]\nstartup = false\nformat = "json"\ninclude_headers = ${includeHeaders}\n`;
    writeFileSync(configPath, config(false));

    const runner = join(dir, "runner.cjs");
    writeFileSync(
      runner,
      `
      const { spawn } = require("node:child_process");
      const { writeFileSync } = require("node:fs");
      const http = require("node:http");
      const [entry, cfg, port, reloaded] = process.argv.slice(2);
      const child = spawn(process.execPath, ["--import", "tsx", entry, "-c", cfg], { stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      let err = "";
      let exited = null;
      child.stdout.on("data", (d) => (out += d));
      child.stderr.on("data", (d) => (err += d));
      child.on("exit", (code) => (exited = code));
      const hit = (path) => new Promise((res) => {
        const req = http.request({ host: "127.0.0.1", port: Number(port), path, headers: { "user-agent": "sqlmap/1.7" } }, (r) => { r.resume(); r.on("end", res); });
        req.on("error", res);
        req.end();
      });
      (async () => {
        // Wait for the listener rather than a fixed sleep: tsx compiles on first run,
        // and a CI runner is slower and noisier than a laptop.
        for (let i = 0; i < 100 && exited === null; i++) {
          const up = await new Promise((res) => {
            const r = http.request({ host: "127.0.0.1", port: Number(port), path: "/__probe" }, (x) => { x.resume(); res(true); });
            r.on("error", () => res(false));
            r.end();
          });
          if (up) break;
          await new Promise((r) => setTimeout(r, 100));
        }
        await hit("/.env");
        await new Promise((r) => setTimeout(r, 300));
        const before = out.includes('"headers"');
        writeFileSync(cfg, reloaded);
        child.kill("SIGHUP");
        for (let i = 0; i < 50 && !/"kind":"reload"/.test(out); i++) await new Promise((r) => setTimeout(r, 100));
        await hit("/.env?after=1");
        await new Promise((r) => setTimeout(r, 300));
        const after = out.includes('"headers"');
        child.kill();
        console.log("RESULT" + JSON.stringify({ before, after, sawReload: /"applied":\\["logging"\\]/.test(out), exited, err: err.slice(0, 400) }));
      })();
    `,
    );

    const stdout = execFileSync("node", [runner, "src/standalone.ts", configPath, String(port), config(true)], {
      encoding: "utf8",
      timeout: 60_000,
    });
    const line = stdout.split("\n").find((l) => l.startsWith("RESULT"));
    expect(line, `runner produced no result:\n${stdout}`).toBeDefined();
    const { before, after, sawReload, exited, err } = JSON.parse(line!.slice("RESULT".length));

    // Diagnose a dead child as a dead child, rather than as a reload that misbehaved.
    expect(exited, `the service exited early (code ${exited}):\n${err}`).toBeNull();
    expect(before, "headers were logged before the reload asked for them").toBe(false);
    expect(sawReload, `the service never reported [logging] as reloaded:\n${err}`).toBe(true);
    expect(after, "include_headers was reported applied but had no effect").toBe(true);
  }, 90_000);
});
