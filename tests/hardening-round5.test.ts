import net from "node:net";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { applyEnvOverrides } from "../src/config/env.js";
import { parseConfig } from "../src/config/schema.js";
import { MAX_BODY_BYTES } from "../src/http-request.js";
import { FtpHoneypot } from "../src/ftp/index.js";
import { HoneypotServer } from "../src/server.js";
import type { Blocklist } from "../src/blocklist.js";
import type { FtpIncident } from "../src/ftp/types.js";

/** Runs one FTP command against a fresh connection and returns the incidents it produced. */
async function ftpCommand(command: string): Promise<FtpIncident[]> {
  const incidents: FtpIncident[] = [];
  const honeypot = new FtpHoneypot({ host: "127.0.0.1", port: 0, onIncident: (incident) => void incidents.push(incident) });
  await honeypot.listen();
  const port = (honeypot.address() as net.AddressInfo).port;

  const socket = net.connect(port, "127.0.0.1");
  await new Promise((resolve) => socket.once("connect", resolve));
  await new Promise((resolve) => socket.once("data", resolve)); // the 220 banner
  socket.write(`${command}\r\n`);
  await new Promise((resolve) => setTimeout(resolve, 120));
  socket.destroy();
  await new Promise((resolve) => setTimeout(resolve, 80));
  await honeypot.close();
  return incidents;
}

describe("an FTP bounce is only reported for a PORT command that actually names one", () => {
  // `Number()` accepted far more than the protocol's decimal grammar. `Number("")` is 0,
  // so `PORT ,,,,,` — six empty fields, no address at all — parsed as `0.0.0.0:0` and was
  // reported as an `ftp-bounce`: the highest-scored FTP finding, 12 points, naming a
  // third party the client never mentioned. `0x10` and `1e2` were coerced the same way.
  // A honeypot's output is evidence, and an /ioc.txt consumer downstream cannot tell an
  // invented victim address from a real one.
  it("does not invent a bounce from a malformed PORT", async () => {
    for (const command of ["PORT ,,,,,", "PORT  , , , , , ", "PORT 0x10,0,0,1,0,80", "PORT 1e2,0,0,1,0,80", "PORT 1,2,3,4,5"]) {
      const bounces = (await ftpCommand(command)).filter((incident) => incident.finding === "ftp-bounce");
      expect(bounces, command).toHaveLength(0);
    }
  }, 20_000);

  it("still reports a genuine bounce", async () => {
    const bounces = (await ftpCommand("PORT 1,2,3,4,5,6")).filter((incident) => incident.finding === "ftp-bounce");
    expect(bounces).toHaveLength(1);
    expect(bounces[0]!.reason).toContain("1.2.3.4:1286");
  });
});

describe("a blocklist backend that is down does not change what the attacker sees", () => {
  // `blockAction` awaited `blocklist.block()` and let a rejection propagate. That call
  // reaches a live backend whenever the blocklist is Redis-backed or wraps an external
  // enforcer, so it fails for reasons unrelated to the request — and the result was a
  // 500, which is a honeypot tell: every other response here is a plausible one, so an
  // outage turned every flagged request into a distinctive "you broke something" signal.
  // The failure was also reported nowhere, so blocking could stop working entirely with
  // no signal to the operator.
  const brokenBlocklist: Blocklist = {
    block: async () => {
      throw new Error("backend unreachable");
    },
    isBlocked: () => false,
  };

  it("still answers 403 and reports the failure", async () => {
    const errors: Array<{ source: string; message: string }> = [];
    const server = new HoneypotServer({
      blocklist: brokenBlocklist,
      policy: () => "block",
      onError: (error, context) => errors.push({ source: context.source, message: (error as Error).message }),
    });
    await server.listen(0, "127.0.0.1");
    const port = (server.address() as net.AddressInfo).port;

    const response = await fetch(`http://127.0.0.1:${port}/.env`);
    expect(response.status).toBe(403);
    // Not a 500 — nothing about the response distinguishes a broken backend.
    expect(await response.text()).toBe("Forbidden");
    expect(errors).toEqual([{ source: "blocklist", message: "backend unreachable" }]);

    await server.close();
  });

  it("a working blocklist is unaffected", async () => {
    const blocked: string[] = [];
    const server = new HoneypotServer({
      blocklist: { block: (ip) => void blocked.push(ip), isBlocked: () => false },
      policy: () => "block",
    });
    await server.listen(0, "127.0.0.1");
    const port = (server.address() as net.AddressInfo).port;

    expect((await fetch(`http://127.0.0.1:${port}/.env`)).status).toBe(403);
    expect(blocked).toHaveLength(1);

    await server.close();
  });
});

describe("Redis hit retention is bounded by what the deployment can hold", () => {
  // The Redis hit log is one list holding whole incidents, captured body included, so
  // its worst case is max_hits x the 64 KB body cap — ~630 MB at the 10000 default,
  // against the 256 MB the shipped compose file gives Redis. An attacker reaches that by
  // doing the thing a honeypot invites, and the container is OOM-killed and restarted
  // empty: every accrued score and active block gone. A maxmemory-policy is no help
  // because the list is a single key, so LRU drops the small score/block keys first.
  it("exposes retention as an environment override", () => {
    const config = applyEnvOverrides(parseConfig({}, "<defaults>"), { REDIS_URL: "redis://r:6379", REDIS_MAX_HITS: "1500" });
    expect(config.store.redis.maxHits).toBe(1500);
    expect(config.store.redis.enabled).toBe(true);
  });

  it("the shipped compose file sets a retention that fits its own memory limit", () => {
    const compose = readFileSync(new URL("../docker-compose.yml", import.meta.url), "utf8");
    const retention = /REDIS_MAX_HITS:\s*"(\d+)"/.exec(compose);
    const memLimit = /redis:[\s\S]*?mem_limit:\s*(\d+)m/.exec(compose);
    expect(retention, "docker-compose.yml must pin REDIS_MAX_HITS").not.toBeNull();
    expect(memLimit, "the redis service must keep a mem_limit").not.toBeNull();

    const worstCaseBytes = Number(retention![1]) * MAX_BODY_BYTES;
    const limitBytes = Number(memLimit![1]) * 1024 * 1024;
    // Leave headroom for the score and block keys living beside the list.
    expect(worstCaseBytes).toBeLessThan(limitBytes * 0.6);
  });
});
