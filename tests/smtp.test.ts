import net from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { MemoryStore, SmtpHoneypot, type HoneypotHit } from "../src/index.js";
import { parseConfig } from "../src/config/schema.js";
import { portOf } from "./helpers.js";

describe("SMTP honeypot", () => {
  let smtp: SmtpHoneypot | undefined;
  afterEach(async () => { await smtp?.close(); smtp = undefined; });

  function session(port: number, lines: string[]): Promise<{ transcript: string }> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ port }, () => {});
      let transcript = "";
      let i = 0;
      socket.setTimeout(3000, () => socket.destroy());
      socket.on("data", (d) => {
        transcript += d.toString();
        if (i < lines.length) socket.write(lines[i++] + "\r\n");
        else socket.end();
      });
      socket.on("close", () => resolve({ transcript }));
      socket.on("error", reject);
    });
  }

  it("captures an AUTH LOGIN brute-force attempt as a hit", async () => {
    const hits: HoneypotHit[] = [];
    smtp = new SmtpHoneypot({ port: 0, store: new MemoryStore(), onHit: (h) => { hits.push(h); } });
    await smtp.listen();
    const port = (smtp.address() as { port: number }).port;

    // greeting → EHLO → AUTH LOGIN → base64 user → base64 pass → QUIT
    await session(port, ["EHLO attacker", "AUTH LOGIN", Buffer.from("admin").toString("base64"), Buffer.from("hunter2").toString("base64"), "QUIT"]);
    await new Promise((r) => setTimeout(r, 50));

    const auth = hits.find((h) => h.detections[0]?.detector === "smtp-auth-bruteforce");
    expect(auth).toBeTruthy();
    expect(auth?.method).toBe("SMTP");
    expect(auth?.headers["smtp-auth-user"]).toBe("admin");
  });

  it("flags an open-relay attempt to an external domain", async () => {
    const hits: HoneypotHit[] = [];
    smtp = new SmtpHoneypot({ port: 0, localDomains: ["mycorp.test"], onHit: (h) => { hits.push(h); } });
    await smtp.listen();
    const port = (smtp.address() as { port: number }).port;

    await session(port, ["HELO attacker", "MAIL FROM:<spammer@evil.example>", "RCPT TO:<victim@somewhere-else.example>", "QUIT"]);
    await new Promise((r) => setTimeout(r, 50));

    expect(hits.some((h) => h.detections[0]?.detector === "smtp-open-relay")).toBe(true);
  });

  // The message-body phase gets no per-line reply, so drive it with one write.
  function sendAll(port: number, lines: string[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ port }, () => socket.write(lines.join("\r\n") + "\r\n"));
      socket.setTimeout(2000, () => socket.destroy());
      socket.on("data", () => {});
      socket.on("error", reject);
      setTimeout(() => { socket.end(); resolve(); }, 250);
    });
  }

  it("captures the DATA subject and byte count while honoring captureBody=false", async () => {
    const hits: HoneypotHit[] = [];
    smtp = new SmtpHoneypot({ port: 0, captureBody: false, onHit: (h) => { hits.push(h); } });
    await smtp.listen();
    const port = (smtp.address() as { port: number }).port;

    await sendAll(port, ["HELO x", "MAIL FROM:<s@evil.example>", "RCPT TO:<v@evil.example>", "DATA", "Subject: Cheap meds now", "", "Buy http://spam.example", ".", "QUIT"]);
    await new Promise((r) => setTimeout(r, 50));

    const spam = hits.find((h) => h.detections[0]?.detector === "smtp-spam");
    expect(spam).toBeTruthy();
    expect(spam?.headers["smtp-subject"]).toBe("Cheap meds now");
    expect(Number(spam?.headers["smtp-message-bytes"])).toBeGreaterThan(0);
    expect(spam?.body).toBeUndefined(); // captureBody:false → raw body not stored
  });

  it("stores the raw body when captureBody is on (default)", async () => {
    const hits: HoneypotHit[] = [];
    smtp = new SmtpHoneypot({ port: 0, onHit: (h) => { hits.push(h); } });
    await smtp.listen();
    const port = (smtp.address() as { port: number }).port;

    await sendAll(port, ["HELO x", "MAIL FROM:<s@evil.example>", "RCPT TO:<v@evil.example>", "DATA", "Subject: hi", "", "malware-payload-marker", ".", "QUIT"]);
    await new Promise((r) => setTimeout(r, 50));

    const spam = hits.find((h) => h.detections[0]?.detector === "smtp-spam");
    expect(spam?.body).toContain("malware-payload-marker");
  });
});

describe("SMTP connection cap", () => {
  it("refuses connections past maxConnections", async () => {
    const smtp = new SmtpHoneypot({ port: 0, maxConnections: 1 });
    await smtp.listen();
    const port = (smtp.address() as { port: number }).port;

    // First connection: read the greeting and hold it open.
    const c1 = net.createConnection(port);
    await new Promise<void>((resolve) => c1.once("data", () => resolve()));

    // Second connection while the first is still open: must be refused.
    const c2 = net.createConnection(port);
    const banner = await new Promise<string>((resolve) => c2.once("data", (d) => resolve(d.toString())));
    expect(banner).toContain("421");

    c1.destroy();
    c2.destroy();
    await smtp.close();
  });
});

describe("the SMTP emulator caps a session's total lifetime", () => {
  // SSH, FTP and Telnet all carry this cap and document why; SMTP had only the 30s idle
  // timeout, which every byte resets. A client dripping one character every 20 seconds
  // held its slot forever, and with 256 slots a few hundred of them take the SMTP
  // honeypot offline without ever completing a transaction.
  it("drops a connection that stays busy past max_session_ms", async () => {
    const honeypot = new SmtpHoneypot({ host: "127.0.0.1", port: 0, maxSessionMs: 300 });
    await honeypot.listen();
    const port = (honeypot.address() as net.AddressInfo).port;

    const socket = net.connect(port, "127.0.0.1");
    await new Promise((resolve) => socket.once("connect", resolve));
    await new Promise((resolve) => socket.once("data", resolve)); // the 220 greeting
    // Drip well inside the idle timeout: only a lifetime cap can end this.
    const drip = setInterval(() => {
      if (!socket.destroyed) socket.write("X");
    }, 50);

    const outcome = await Promise.race([
      new Promise<string>((resolve) => socket.once("close", () => resolve("closed by server"))),
      new Promise<string>((resolve) => setTimeout(() => resolve("held open"), 2_500)),
    ]);
    clearInterval(drip);
    socket.destroy();
    await honeypot.close();

    expect(outcome).toBe("closed by server");
  });

  it("refuses an uncapped session in config, as its siblings already do", () => {
    expect(parseConfig({}, "<defaults>").smtp.maxSessionMs).toBeGreaterThan(0);
    expect(() => parseConfig({ smtp: { max_session_ms: 0 } }, "<test>")).toThrow(/max_session_ms/);
  });
});

describe("the SMTP honeypot survives a client that resets mid-handshake", () => {
  const captured: Error[] = [];
  const onUncaught = (err: Error): void => void captured.push(err);

  afterEach(() => process.off("uncaughtException", onUncaught));

  it("does not throw an unhandled socket error while awaiting the store", async () => {
    // `handleConnection` used to attach `socket.on("error")` only at the very end —
    // below two `socket.write()` early returns and below `await store.scoreFor(ip)`.
    // A net.Socket rethrows an 'error' with no listener as an uncaughtException, so a
    // client that connected and reset during that await killed the whole process: the
    // HTTP honeypot, the SSH honeypot and the management API all share it. And the
    // window only opened once the operator enabled `drop_above_score`, so switching on
    // a hardening option was what made the service remotely killable.
    process.on("uncaughtException", onUncaught);

    const store = {
      record: async () => undefined,
      list: async () => [],
      // A real store is a network round-trip; that is the window.
      scoreFor: async () => {
        await new Promise((r) => setTimeout(r, 60));
        return 0;
      },
    };
    const honeypot = new SmtpHoneypot({ port: 0, host: "127.0.0.1", store, dropAboveScore: 100, onHit: () => undefined });
    await honeypot.listen();
    const port = portOf(honeypot);

    for (let i = 0; i < 8; i += 1) {
      const socket = net.connect({ port, host: "127.0.0.1" });
      socket.on("error", () => undefined);
      socket.on("connect", () => socket.resetAndDestroy());
    }
    await new Promise((r) => setTimeout(r, 400));
    await honeypot.close();

    expect(captured.map((e) => e.message)).toEqual([]);
  });

  it("still serves the greeting to a well-behaved client", async () => {
    const honeypot = new SmtpHoneypot({ port: 0, host: "127.0.0.1", onHit: () => undefined });
    await honeypot.listen();
    const port = portOf(honeypot);
    const greeting = await new Promise<string>((resolve) => {
      const socket = net.connect({ port, host: "127.0.0.1" });
      socket.on("error", () => resolve(""));
      socket.once("data", (chunk: Buffer) => {
        resolve(chunk.toString());
        socket.destroy();
      });
    });
    await honeypot.close();
    expect(greeting).toMatch(/^220 /);
  });
});
