import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import { parseLogLine, replayLog } from "../src/replay.js";
import { MemoryStore } from "../src/stores/index.js";

const CHROME = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";

/** `30/Aug/2026:HH:MM:SS +0000`, `seconds` after 09:00. */
const at = (seconds: number): string => {
  const date = new Date(Date.UTC(2026, 7, 30, 9, 0, seconds));
  const pad = (n: number): string => String(n).padStart(2, "0");
  return `${pad(date.getUTCDate())}/Aug/2026:${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())} +0000`;
};

const line = (ip: string, seconds: number, target: string, status: number, userAgent: string, method = "GET"): string =>
  `${ip} - - [${at(seconds)}] "${method} ${target} HTTP/1.1" ${status} 512 "-" "${userAgent}"`;

const engine = (): HoneypotEngine => new HoneypotEngine({ enricher: null, store: new MemoryStore() });

describe("parseLogLine", () => {
  it("reads a combined log format line, time zone included", () => {
    const request = parseLogLine('203.0.113.5 - - [30/Aug/2026:09:00:00 +0200] "GET /search?q=x HTTP/1.1" 200 512 "https://shop.example/" "curl/8.4.0"');
    expect(request).toMatchObject({ ip: "203.0.113.5", method: "GET", target: "/search?q=x", status: 200, headers: { "user-agent": "curl/8.4.0", referer: "https://shop.example/" } });
    expect(request!.timestamp.toISOString()).toBe("2026-08-30T07:00:00.000Z");
  });

  it("reads a JSON line", () => {
    const request = parseLogLine(JSON.stringify({ remote_addr: "198.51.100.1", method: "post", uri: "/login", time: "2026-08-30T09:00:00Z", status: 401, user_agent: "okhttp/4" }));
    expect(request).toMatchObject({ ip: "198.51.100.1", method: "POST", target: "/login", status: 401, headers: { "user-agent": "okhttp/4" } });
  });

  it("skips what it does not recognise", () => {
    expect(parseLogLine("not a log line")).toBeUndefined();
    expect(parseLogLine('{"message":"no request fields"}')).toBeUndefined();
  });
});

describe("replayLog", () => {
  // A log records a User-Agent and a Referer at most; everything else is absent from every line.
  it("does not argue from headers a log never records", async () => {
    const lines = [line("198.51.100.2", 0, "/pricing", 200, CHROME), '198.51.100.3 - - [30/Aug/2026:09:00:01 +0000] "GET / HTTP/1.1" 200 12'];
    expect((await replayLog(engine(), lines)).flagged).toBe(0);
  });

  it("summarises what the detectors would have done", async () => {
    const lines = [line("203.0.113.7", 0, "/.env", 404, CHROME), line("203.0.113.8", 1, "/", 200, "sqlmap/1.7"), "not a log line"];
    const summary = await replayLog(engine(), lines);
    expect(summary).toMatchObject({ lines: 3, parsed: 2, skipped: 1, flagged: 2 });
    expect(summary.byDetector).toMatchObject({ "decoy-path": 1, "scanner-signature": 1 });
    expect(summary.topSources.map((source) => source.ip).sort()).toEqual(["203.0.113.7", "203.0.113.8"]);
  });

  // Replayed at the logged times, an afternoon's browsing from one address is not a flood.
  it("uses the logged timestamps, so traffic spread over time does not trip rate-spike", async () => {
    const spread = Array.from({ length: 100 }, (_, i) => line("198.51.100.4", i * 30, "/", 200, CHROME));
    expect((await replayLog(engine(), spread)).byDetector["rate-spike"]).toBeUndefined();
    const burst = Array.from({ length: 100 }, () => line("198.51.100.5", 0, "/", 200, CHROME));
    expect((await replayLog(engine(), burst)).byDetector["rate-spike"]).toBeGreaterThan(0);
  });

  it("counts a path toward path-bruteforce only when the log shows a 404", async () => {
    const walk = (status: number, ip: string): string[] => Array.from({ length: 30 }, (_, i) => line(ip, i, `/page-${i}`, status, CHROME));
    expect((await replayLog(engine(), walk(200, "198.51.100.6"))).byDetector["path-bruteforce"]).toBeUndefined();
    expect((await replayLog(engine(), walk(404, "198.51.100.7"))).byDetector["path-bruteforce"]).toBeGreaterThan(0);
  });

  it("runs from the command line", () => {
    const dir = mkdtempSync(join(tmpdir(), "hackerpot-replay-"));
    const log = join(dir, "access.log");
    const config = join(dir, "hackerpot.toml");
    writeFileSync(log, `${line("203.0.113.9", 0, "/.git/config", 404, "curl/8.4.0")}\n`);
    writeFileSync(config, "");
    const out = execFileSync(process.execPath, ["--import", "tsx", "src/standalone.ts", "--config", config, "--replay", log, "--json"], { encoding: "utf8", timeout: 60_000 });
    const summary = JSON.parse(out);
    expect(summary).toMatchObject({ parsed: 1, flagged: 1 });
    expect(summary.byDetector["decoy-path"]).toBe(1);
  }, 90_000);
});
