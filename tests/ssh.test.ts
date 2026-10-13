import { afterEach, describe, expect, it } from "vitest";
import { Client } from "ssh2";
import { MemoryStore, SshHoneypot, type HoneypotHit } from "../src/index.js";

describe("SSH honeypot", () => {
  let ssh: SshHoneypot | undefined;
  afterEach(async () => { await ssh?.close(); ssh = undefined; });

  it("captures a password brute-force attempt (username + password) as a hit", async () => {
    const hits: HoneypotHit[] = [];
    ssh = new SshHoneypot({ port: 0, store: new MemoryStore(), onHit: (h) => { hits.push(h); } });
    await ssh.listen();
    const port = (ssh.address() as { port: number }).port;

    // ssh2 client attempts password auth; the honeypot rejects it, so the client errors out.
    await new Promise<void>((resolve) => {
      const conn = new Client();
      conn.on("ready", () => { conn.end(); resolve(); }); // should never happen
      conn.on("error", () => resolve());                  // expected: auth rejected
      conn.connect({ host: "127.0.0.1", port, username: "root", password: "hunter2", hostVerifier: () => true, readyTimeout: 4000 });
    });
    await new Promise((r) => setTimeout(r, 80));

    const auth = hits.find((h) => h.detections[0]?.detector === "ssh-auth-bruteforce");
    expect(auth).toBeTruthy();
    expect(auth?.method).toBe("SSH");
    expect(auth?.headers["ssh-user"]).toBe("root");
    expect(auth?.body).toBe("hunter2"); // the captured password
  }, 15000);

  it("in interactive mode, accepts the login and captures shell commands", async () => {
    const hits: HoneypotHit[] = [];
    ssh = new SshHoneypot({ port: 0, interactive: true, acceptOnAttempt: 1, store: new MemoryStore(), onHit: (h) => { hits.push(h); } });
    await ssh.listen();
    const port = (ssh.address() as { port: number }).port;

    await new Promise<void>((resolve, reject) => {
      const conn = new Client();
      // Self-pace off the shell prompt so writes never race the channel setup.
      const cmds = ["whoami", "cat /etc/passwd", "exit"];
      let idx = 0;
      conn.on("ready", () => {
        conn.shell((err, stream) => {
          if (err) return reject(err);
          stream.on("close", () => { conn.end(); resolve(); });
          let buf = "";
          stream.on("data", (d: Buffer) => {
            buf += d.toString();
            if (buf.endsWith("# ") && idx < cmds.length) {
              buf = "";
              stream.write(cmds[idx++] + "\n");
            }
          });
        });
      });
      conn.on("error", reject);
      conn.connect({ host: "127.0.0.1", port, username: "root", password: "letmein", hostVerifier: () => true, readyTimeout: 4000 });
    });
    await new Promise((r) => setTimeout(r, 100));

    const commands = hits.filter((h) => h.detections[0]?.detector === "ssh-shell-command").map((h) => h.body);
    expect(commands).toContain("whoami");
    expect(commands).toContain("cat /etc/passwd");
    const summary = hits.find((h) => h.detections[0]?.detector === "ssh-shell-session");
    expect(summary).toBeTruthy();
    expect(Number(summary?.headers["ssh-command-count"])).toBeGreaterThanOrEqual(2);
  }, 15000);

  it("closes a held-open connection after maxSessionMs (slow connection-hold DoS defense)", async () => {
    ssh = new SshHoneypot({ port: 0, interactive: true, acceptOnAttempt: 1, maxSessionMs: 400 });
    await ssh.listen();
    const port = (ssh.address() as { port: number }).port;

    const start = Date.now();
    await new Promise<void>((resolve, reject) => {
      const conn = new Client();
      // Open a shell and then sit idle — without the lifetime cap this would hold forever.
      conn.on("ready", () => conn.shell((err, stream) => { if (err) reject(err); else stream.on("data", () => {}); }));
      conn.on("close", () => resolve());          // the honeypot's timer ends the connection
      conn.on("error", () => resolve());          // either way the socket is gone
      conn.connect({ host: "127.0.0.1", port, username: "root", password: "x", hostVerifier: () => true, readyTimeout: 4000 });
    });
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(3000);   // closed by the ~400ms timer, not held open
  }, 15000);
});
