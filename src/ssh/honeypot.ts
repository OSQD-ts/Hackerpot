import { createHash, randomUUID } from "node:crypto";
// ssh2 is CJS: Node's ESM loader cannot statically detect `Server`/`utils`, so
// take the default export and destructure at runtime.
import ssh2 from "ssh2";
import type { Connection, Server as ServerType } from "ssh2";

const { Server, utils } = ssh2;
import type { HoneypotHit } from "../types.js";
import type { SshFinding, SshHoneypotOptions, SshIncident } from "./types.js";

const SCORES: Record<SshFinding, number> = {
  "ssh-auth-bruteforce": 8,
  "ssh-publickey-probe": 5,
  "ssh-scan": 3,
  // Running commands in the (fake) shell is the highest-signal SSH event: the attacker
  // believes they have a foothold and is showing their hand.
  "ssh-shell-command": 9,
  "ssh-shell-session": 4,
};

function fingerprint(keyData: Buffer): string {
  return `SHA256:${createHash("sha256").update(keyData).digest("base64").replace(/=+$/, "")}`;
}

/**
 * A medium-interaction SSH honeypot. It completes the real SSH transport
 * handshake (via the `ssh2` library, so the crypto is battle-tested) and then
 * captures what attackers actually send at the auth layer — brute-forced
 * username/password pairs, offered public keys, and bare version-grab scans —
 * while rejecting every attempt. Nothing is ever authenticated and no shell is
 * ever granted. Incidents map into the same HoneypotHit shape as HTTP hits, so
 * they share per-IP scoring and appear in the management API and dashboard.
 */
export class SshHoneypot {
  private server?: ServerType;
  private readonly opts: SshHoneypotOptions;
  private readonly ident: string;
  private hostKeys: string[];
  private readonly maxAttempts: number;
  private readonly maxConnections: number;
  private readonly interactive: boolean;
  private readonly acceptOnAttempt: number;
  private readonly shellHostname: string;
  private readonly maxCommands: number;
  private readonly maxCommandLength: number;
  private readonly maxSessionMs: number;
  private activeConnections = 0;

  constructor(options: SshHoneypotOptions) {
    this.opts = options;
    this.ident = options.ident ?? "OpenSSH_8.4";
    this.hostKeys = options.hostKeys ?? [];
    this.maxAttempts = options.maxAuthAttempts ?? 6;
    this.maxConnections = options.maxConnections ?? 256;
    this.interactive = options.interactive ?? false;
    this.acceptOnAttempt = Math.max(1, options.acceptOnAttempt ?? 1);
    this.shellHostname = options.shellHostname ?? "srv01";
    this.maxCommands = options.maxCommands ?? 100;
    this.maxCommandLength = options.maxCommandLength ?? 4096;
    this.maxSessionMs = options.maxSessionMs ?? 120_000;
  }

  listen(): Promise<void> {
    if (this.hostKeys.length === 0) {
      // Ephemeral host key — a honeypot doesn't need a stable identity.
      this.hostKeys = [utils.generateKeyPairSync("rsa", { bits: 2048 }).private];
    }
    this.server = new Server({ hostKeys: this.hostKeys, ident: this.ident }, (client, info) => this.handleClient(client, info.ip, info.header?.identRaw));
    return new Promise((resolve, reject) => {
      this.server!.on("error", reject);
      this.server!.listen(this.opts.port, this.opts.host, () => {
        this.server!.removeListener("error", reject);
        resolve();
      });
    });
  }

  close(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.server) return resolve();
      this.server.close(() => resolve());
    });
  }

  address(): ReturnType<ServerType["address"]> {
    return this.server?.address() ?? null;
  }

  private async handleClient(client: Connection, ip: string, clientVersion?: string): Promise<void> {
    // Attach the error handler first: ssh2's Connection is an EventEmitter, and an
    // unhandled 'error' (malformed input, abrupt disconnect) would otherwise throw —
    // including during the dropAboveScore early-out below.
    client.on("error", () => undefined);

    // Bound our own resource use: a connection flood must not exhaust our sockets.
    if (this.activeConnections >= this.maxConnections) {
      client.end();
      return;
    }
    this.activeConnections += 1;
    client.once("close", () => (this.activeConnections -= 1));

    // Bound how long any one connection can be held open. Without this, an attacker can
    // open a connection (or an interactive shell) and simply sit on it, tying up a slot
    // toward maxConnections indefinitely — a slow connection-exhaustion DoS. The timer is
    // unref'd so it never keeps the process alive, and cleared when the client closes.
    const lifetimeTimer = setTimeout(() => client.end(), this.maxSessionMs);
    lifetimeTimer.unref?.();
    client.once("close", () => clearTimeout(lifetimeTimer));

    if (this.opts.dropAboveScore !== undefined && this.opts.store) {
      const score = await this.opts.store.scoreFor(ip);
      if (score >= this.opts.dropAboveScore) {
        client.end();
        return;
      }
    }

    let attempts = 0;
    let credentialSeen = false;
    let shellUser: string | undefined;

    client.on("authentication", (ctx) => {
      if (ctx.method === "none") {
        // The client is asking what methods are available — prompt for the real attempt.
        ctx.reject(["password", "publickey"]);
        return;
      }

      credentialSeen = true;
      attempts += 1;

      if (ctx.method === "password") {
        void this.report("ssh-auth-bruteforce", `SSH password attempt user="${ctx.username}"`, { clientVersion, username: ctx.username, password: ctx.password }, ip);
        // Interactive mode: let them "in" after the configured attempt, into a fake shell.
        if (this.interactive && attempts >= this.acceptOnAttempt) {
          shellUser = ctx.username;
          ctx.accept();
          return;
        }
      } else if (ctx.method === "publickey") {
        const fp = fingerprint(ctx.key.data);
        void this.report("ssh-publickey-probe", `SSH public-key attempt user="${ctx.username}" (${ctx.key.algo})`, { clientVersion, username: ctx.username, keyType: ctx.key.algo, keyFingerprint: fp }, ip);
      } else {
        // keyboard-interactive / hostbased — steer to password.
        ctx.reject(["password"]);
        return;
      }

      if (attempts >= this.maxAttempts) {
        ctx.reject();
        client.end();
      } else {
        ctx.reject(["password", "publickey"]);
      }
    });

    if (this.interactive) {
      client.on("ready", () => this.handleShellSession(client, ip, clientVersion, shellUser));
    }

    // A connection that handshook but never tried a credential is a scanner / banner grab.
    client.on("close", () => {
      if (!credentialSeen) void this.report("ssh-scan", `SSH scan / banner grab${clientVersion ? ` (${clientVersion})` : ""}`, { clientVersion }, ip);
    });
  }

  /**
   * Presents a fake interactive shell over an accepted SSH session and captures the
   * commands the attacker runs. Nothing executes — the channel is a stream we write
   * scripted output to — so there is no path from a typed command to the host. Both
   * an interactive `shell` and a one-shot `exec` are handled; each command is reported
   * and the full transcript is emitted when the session closes.
   */
  private handleShellSession(client: Connection, ip: string, clientVersion: string | undefined, user: string | undefined): void {
    const prompt = `${user ?? "root"}@${this.shellHostname}:~# `;
    const transcript: string[] = [];

    const capture = (raw: string): void => {
      const command = raw.slice(0, this.maxCommandLength).trim();
      if (!command) return;
      if (transcript.length >= this.maxCommands) return;
      transcript.push(command);
      void this.report("ssh-shell-command", `SSH shell command: ${command.slice(0, 200)}`, { clientVersion, username: user, command }, ip);
    };

    client.on("session", (accept) => {
      const session = accept();
      // Accept a PTY request so a real client believes it has a terminal.
      session.on("pty", (a) => a && a());
      session.on("window-change", (a) => a && a());

      session.on("shell", (acceptShell) => {
        const stream = acceptShell();
        stream.write(`Welcome to Ubuntu 22.04.3 LTS\r\n\r\n${prompt}`);
        let line = "";
        stream.on("data", (chunk: Buffer) => {
          for (const ch of chunk.toString("utf8")) {
            if (ch === "\r" || ch === "\n") {
              stream.write("\r\n");
              if (line.trim() === "exit" || line.trim() === "logout") {
                capture(line);
                line = "";
                this.emitSession(transcript, clientVersion, user, ip);
                stream.end();
                return;
              }
              capture(line);
              stream.write(this.fakeOutput(line) + prompt);
              line = "";
              if (transcript.length >= this.maxCommands) {
                stream.end();
                return;
              }
            } else if (ch === "\x7f" || ch === "\b") {
              line = line.slice(0, -1);
            } else {
              if (line.length < this.maxCommandLength) line += ch;
              stream.write(ch); // echo, so an interactive client shows typing
            }
          }
        });
        stream.on("close", () => this.emitSession(transcript, clientVersion, user, ip));
      });

      session.on("exec", (acceptExec, _reject, info) => {
        const stream = acceptExec();
        capture(info.command);
        stream.write(this.fakeOutput(info.command));
        this.emitSession(transcript, clientVersion, user, ip);
        stream.exit(0);
        stream.end();
      });
    });
  }

  /** A plausible-but-empty response to a shell command — enough to keep an attacker typing. */
  private fakeOutput(command: string): string {
    const cmd = command.trim().split(/\s+/)[0] ?? "";
    if (cmd === "") return "";
    if (cmd === "whoami") return "root\r\n";
    if (cmd === "id") return "uid=0(root) gid=0(root) groups=0(root)\r\n";
    if (cmd === "pwd") return "/root\r\n";
    if (cmd === "uname") return "Linux srv01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n";
    if (cmd === "ls" || cmd === "dir") return "\r\n";
    if (cmd === "cd" || cmd === "export" || cmd === "cat" || cmd === "echo") return "\r\n";
    return `${cmd}: command not found\r\n`;
  }

  private emittedSessions = new WeakSet<string[]>();
  /** Emit the session-transcript incident exactly once per session. */
  private emitSession(transcript: string[], clientVersion: string | undefined, user: string | undefined, ip: string): void {
    if (transcript.length === 0 || this.emittedSessions.has(transcript)) return;
    this.emittedSessions.add(transcript);
    void this.report("ssh-shell-session", `SSH shell session: ${transcript.length} command(s)`, { clientVersion, username: user, commands: [...transcript] }, ip);
  }

  private async report(finding: SshFinding, reason: string, session: SshIncident["session"], ip: string): Promise<void> {
    // Every call site is `void this.report(...)`, so this must never reject: a rejecting
    // async store/onHit (e.g. Redis down) would otherwise become an unhandled rejection —
    // a remote kill switch an attacker triggers just by connecting. Swallow + surface.
    try {
      const score = SCORES[finding];
      const incident: SshIncident = { ip, finding, reason, score, session, at: new Date() };
      await this.opts.onIncident?.(incident);

      if (this.opts.store || this.opts.onHit) {
        const prior = this.opts.store ? await this.opts.store.scoreFor(ip) : 0;
        const hit = this.toHit(incident, prior);
        await this.opts.store?.record(hit);
        await this.opts.onHit?.(hit);
      }
    } catch (err) {
      this.opts.onError?.(err);
    }
  }

  /** Map an SSH incident into the shared HoneypotHit shape used by the HTTP engine. */
  private toHit(incident: SshIncident, priorScore: number): HoneypotHit {
    const s = incident.session;
    const headers: Record<string, string> = { "x-protocol": "ssh" };
    if (s.clientVersion) headers["ssh-client"] = s.clientVersion;
    if (s.username !== undefined) headers["ssh-user"] = s.username;
    if (s.keyType) headers["ssh-key-type"] = s.keyType;
    if (s.keyFingerprint) headers["ssh-key-fingerprint"] = s.keyFingerprint;
    if (s.commands) headers["ssh-command-count"] = String(s.commands.length);

    // Body carries the most analysis-worthy captured content for this finding: the
    // command(s) run in the fake shell, else the brute-forced password.
    const body = s.command ?? (s.commands ? s.commands.join("\n") : s.password);

    return {
      id: randomUUID(),
      timestamp: incident.at.toISOString(),
      ip: incident.ip,
      method: "SSH",
      path: incident.reason,
      headers,
      body,
      detections: [{ detectorId: incident.finding, reason: incident.reason, score: incident.score }],
      score: incident.score,
      totalScore: priorScore + incident.score,
      respondedWith: "ssh-capture",
    };
  }
}
