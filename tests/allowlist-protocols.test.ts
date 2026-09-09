import net from "node:net";
import { describe, expect, it } from "vitest";
import { IpAllowlist } from "../src/allowlist.js";
import { MemoryStore } from "../src/stores/index.js";
import { SmtpHoneypot } from "../src/smtp/index.js";
import { TelnetHoneypot } from "../src/telnet/index.js";
import { FtpHoneypot } from "../src/ftp/index.js";
import { PortScanSentinel } from "../src/detectors/port-scan.js";
import { computeIoc } from "../src/management/rest.js";

/** Drives a short line-protocol session against a listener and waits for it to settle. */
async function session(honeypot: { listen(): Promise<void>; address(): unknown; close(): Promise<void> }, lines: string[]): Promise<void> {
  await honeypot.listen();
  const { port } = honeypot.address() as net.AddressInfo;
  await new Promise<void>((resolve) => {
    const socket = net.connect(port, "127.0.0.1", async () => {
      await new Promise((banner) => socket.once("data", banner));
      for (const line of lines) {
        socket.write(`${line}\r\n`);
        await new Promise((tick) => setTimeout(tick, 60));
      }
      socket.end();
    });
    socket.on("data", () => {});
    socket.on("error", () => resolve());
    socket.on("close", () => resolve());
    setTimeout(() => {
      socket.destroy();
      resolve();
    }, 2_500);
  });
  await new Promise((settle) => setTimeout(settle, 200));
  await honeypot.close();
}

describe("the allowlist exempts a source from the protocol emulators too", () => {
  // `[allowlist] ips` is documented as exempting a source from ALL detection — "never
  // scored, never blocked, no incident recorded". Only the HTTP front ends honoured it.
  // An allowlisted host that touched SSH/FTP/Telnet/SMTP or a sentinel port was scored,
  // stored, and published on /ioc.txt — which peer honeypots ingest and block. An
  // uptime checker or internal scanner, exactly what an operator allowlists, could be
  // propagated into a fleet-wide blocklist by the instance told to exempt it.
  const exempt = new IpAllowlist(["127.0.0.1", "::1"]);
  const isAllowlisted = (ip: string): boolean => exempt.allows(ip);

  it("records nothing for an allowlisted source, and publishes nothing", async () => {
    const store = new MemoryStore();
    await session(new SmtpHoneypot({ host: "127.0.0.1", port: 0, store, isAllowlisted }), ["EHLO x", "VRFY root", "VRFY admin", "QUIT"]);
    await session(new TelnetHoneypot({ host: "127.0.0.1", port: 0, store, isAllowlisted }), ["root", "admin123"]);
    await session(new FtpHoneypot({ host: "127.0.0.1", port: 0, store, isAllowlisted }), ["USER admin", "PASS admin", "QUIT"]);

    expect(await store.list()).toHaveLength(0);
    expect(await store.scoreFor("127.0.0.1")).toBe(0);
    expect(await computeIoc(store, 0)).toHaveLength(0);
  }, 20_000);

  it("still detects a source that is NOT allowlisted", async () => {
    // Same traffic, an allowlist that does not cover the client.
    const other = new IpAllowlist(["10.0.0.1"]);
    const store = new MemoryStore();
    const notExempt = (ip: string): boolean => other.allows(ip);

    await session(new SmtpHoneypot({ host: "127.0.0.1", port: 0, store, isAllowlisted: notExempt }), ["EHLO x", "VRFY root", "QUIT"]);
    await session(new TelnetHoneypot({ host: "127.0.0.1", port: 0, store, isAllowlisted: notExempt }), ["root", "admin123"]);

    const hits = await store.list();
    expect(hits.length).toBeGreaterThan(0);
    expect(await store.scoreFor("127.0.0.1")).toBeGreaterThan(0);
    expect(hits.map((h) => h.detections[0]!.detectorId)).toEqual(expect.arrayContaining(["smtp-user-enumeration", "telnet-auth-bruteforce"]));
  }, 20_000);

  it("omitting the predicate leaves behaviour unchanged", async () => {
    const store = new MemoryStore();
    await session(new SmtpHoneypot({ host: "127.0.0.1", port: 0, store }), ["EHLO x", "VRFY root", "QUIT"]);
    expect((await store.list()).length).toBeGreaterThan(0);
  }, 20_000);

  it("the port-scan sentinel ignores an allowlisted prober", async () => {
    const events: unknown[] = [];
    const sentinel = new PortScanSentinel({ ports: [0], host: "127.0.0.1", isAllowlisted, onEvent: (event) => void events.push(event) });
    await sentinel.listen();
    const { port } = (sentinel as unknown as { servers: net.Server[] }).servers[0]!.address() as net.AddressInfo;
    await new Promise<void>((resolve) => {
      const socket = net.connect(port, "127.0.0.1", () => socket.end());
      socket.on("error", () => resolve());
      socket.on("close", () => resolve());
      setTimeout(() => {
        socket.destroy();
        resolve();
      }, 800);
    });
    await new Promise((settle) => setTimeout(settle, 200));
    await sentinel.close();

    expect(events).toHaveLength(0);
    expect(sentinel.trackedIps).toBe(0);
  }, 15_000);
});
