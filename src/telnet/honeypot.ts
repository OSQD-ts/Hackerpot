import net from "node:net";
import { randomUUID } from "node:crypto";
import { StringDecoder } from "node:string_decoder";
import type { HoneypotHit } from "../types.js";
import { FAKE_MOTD, fakeShellOutput } from "../shell.js";
import { TelnetCodec } from "./codec.js";
import type { TelnetFinding, TelnetHoneypotOptions, TelnetIncident } from "./types.js";

const IDLE_MS = 60_000;
/** Ceiling on lines accepted from one connection, credential retries included. */
const MAX_LINES = 300;

const SCORES: Record<TelnetFinding, number> = {
  "telnet-auth-bruteforce": 8,
  // Running commands in the (fake) shell is the highest-signal Telnet event: the
  // attacker believes they own the device and is showing their hand. Same as SSH.
  "telnet-command": 9,
  "telnet-session": 4,
  "telnet-scan": 3,
};

interface Session {
  username?: string | undefined;
  password?: string | undefined;
  terminal?: string | undefined;
  commands: string[];
}

/**
 * A medium-interaction Telnet honeypot.
 *
 * Telnet is the most-attacked service on the internet that nobody admits to running.
 * It has no transport security, so the credentials arrive in the clear, and the IoT
 * botnet families (Mirai and everything descended from it) sweep ports 23 and 2323
 * continuously with a hard-coded list of vendor defaults. A fake Telnet server is
 * therefore about the highest-yield trap available: it collects the live default-
 * credential list being sprayed at your netblock, and — in interactive mode — the
 * staging URLs the dropper reaches for the moment it believes it is in.
 *
 * The protocol is handled properly rather than approximated: {@link TelnetCodec}
 * strips and answers IAC option negotiation, so captured credentials do not have
 * 0xFF sequences embedded in them and a hostile client cannot drive us into a
 * negotiation loop. Nothing executes — the shell is a scripted stream (`src/shell.ts`)
 * shared with the SSH honeypot, which faces the same botnets. Incidents map into the
 * same HoneypotHit shape as HTTP hits, so they share per-IP scoring and appear in the
 * management API and dashboard.
 */
export class TelnetHoneypot {
  private server: net.Server | undefined;
  /** Live connections, so `close()` can end them instead of waiting on them. */
  private readonly sockets = new Set<net.Socket>();
  private readonly opts: TelnetHoneypotOptions;
  private readonly banner: string;
  private readonly hostname: string;
  private readonly maxAttempts: number;
  private readonly maxConnections: number;
  private readonly interactive: boolean;
  private readonly acceptOnAttempt: number;
  private readonly maxCommands: number;
  private readonly maxCommandLength: number;
  private readonly maxSessionMs: number;
  private activeConnections = 0;

  constructor(options: TelnetHoneypotOptions) {
    this.opts = options;
    this.banner = options.banner ?? FAKE_MOTD;
    this.hostname = options.hostname ?? "srv01";
    this.maxAttempts = options.maxAuthAttempts ?? 3;
    this.maxConnections = options.maxConnections ?? 256;
    this.interactive = options.interactive ?? false;
    this.acceptOnAttempt = Math.max(1, options.acceptOnAttempt ?? 1);
    this.maxCommands = options.maxCommands ?? 100;
    this.maxCommandLength = options.maxCommandLength ?? 4096;
    this.maxSessionMs = options.maxSessionMs ?? 120_000;
  }

  /**
   * Binds the listener, **rejecting** if the bind fails — an EADDRINUSE or the EACCES
   * from port 23 arrives as an `error` event, which with no listener is rethrown as an
   * uncaughtException past the caller's `await`.
   */
  listen(): Promise<void> {
    const server = net.createServer((socket) => void this.handleConnection(socket));
    this.server = server;
    return new Promise((resolve, reject) => {
      const onError = (err: Error): void => {
        this.server = undefined;
        reject(err);
      };
      server.once("error", onError);
      server.listen(this.opts.port, this.opts.host, () => {
        server.removeListener("error", onError);
        resolve();
      });
    });
  }

  /**
   * Stops the listener and ends any connection still open.
   *
   * `server.close()` alone stops accepting but waits for every live connection to end,
   * and this listener's only per-socket bound is an *idle* timeout — which every byte
   * resets. A client dripping one character a second therefore kept shutdown blocked
   * indefinitely, and it is an attacker who decides whether to do that. Shutting down
   * means shutting down: the sockets are destroyed rather than waited on.
   */
  close(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.server) return resolve();
      this.server.close(() => resolve());
      for (const socket of this.sockets) socket.destroy();
      this.sockets.clear();
    });
  }

  address(): ReturnType<net.Server["address"]> {
    return this.server?.address() ?? null;
  }

  private async handleConnection(socket: net.Socket): Promise<void> {
    // FIRST, before anything can write to or await on this socket: an 'error' with no
    // listener is rethrown as an uncaughtException and takes the whole process — every
    // other honeypot and the management API with it. The `scoreFor` await below is a
    // network round-trip when the store is Redis, and a client that connects and resets
    // during it delivers ECONNRESET into exactly that window.
    socket.on("error", () => undefined);
    this.sockets.add(socket);
    socket.once("close", () => this.sockets.delete(socket));

    const ip = socket.remoteAddress ?? "unknown";

    // Allowlisted sources are exempt from all detection — the same rail the HTTP front
    // ends apply, and what `[allowlist] ips` documents. Bail before anything is tracked,
    // scored, or reported, so an exempt host can never reach the store or `/ioc.txt`.
    if (this.opts.isAllowlisted?.(ip)) {
      socket.destroy();
      return;
    }

    // Bound our own resource use: a connection flood must not exhaust our sockets.
    if (this.activeConnections >= this.maxConnections) {
      socket.destroy();
      return;
    }
    this.activeConnections += 1;
    socket.once("close", () => (this.activeConnections -= 1));

    // Bound how long one connection may be held open, or an attacker parks sockets on
    // us and exhausts `maxConnections` without ever sending a byte.
    const lifetimeTimer = setTimeout(() => socket.destroy(), this.maxSessionMs);
    lifetimeTimer.unref?.();
    socket.once("close", () => clearTimeout(lifetimeTimer));

    if (this.opts.dropAboveScore !== undefined && this.opts.store) {
      const score = await this.opts.store.scoreFor(ip);
      if (score >= this.opts.dropAboveScore) {
        socket.destroy();
        return;
      }
    }

    const session: Session = { commands: [] };
    const codec = new TelnetCodec();
    // Decode the *filtered* stream: IAC bytes must come out before this, or a 0xFF
    // command byte is decoded as a character and lands inside a captured credential.
    const decoder = new StringDecoder("utf8");

    let mode: "login" | "password" | "shell" = "login";
    let line = "";
    let attempts = 0;
    let credentialSeen = false;
    let lineCount = 0;
    /** Set by a CR, so the LF or NUL that conventionally follows isn't a second line. */
    let afterCarriageReturn = false;

    const write = (text: string): void => void socket.write(text);
    const prompt = (): string => `${session.username || "root"}@${this.hostname}:~# `;

    socket.setTimeout(IDLE_MS, () => socket.destroy());

    // Announce that we drive the echo and suppress go-ahead, exactly as telnetd does:
    // it is what lets us withhold the echo while a password is being typed.
    socket.write(TelnetCodec.greeting());
    write(`\r\n${this.banner}\r\n\r\n${this.hostname} login: `);

    const submit = (): void => {
      const value = line;
      line = "";
      if (++lineCount > MAX_LINES) {
        socket.destroy();
        return;
      }

      if (mode === "login") {
        write("\r\n");
        if (value.trim() === "") {
          write(`${this.hostname} login: `);
          return;
        }
        session.username = value.trim().slice(0, this.maxCommandLength);
        mode = "password";
        write("Password: ");
        return;
      }

      if (mode === "password") {
        credentialSeen = true;
        attempts += 1;
        session.password = value.slice(0, this.maxCommandLength);
        write("\r\n");
        void this.report("telnet-auth-bruteforce", `Telnet login attempt user="${session.username ?? ""}"`, session, ip);

        if (this.interactive && attempts >= this.acceptOnAttempt) {
          mode = "shell";
          write(`\r\n${FAKE_MOTD}\r\n\r\n${prompt()}`);
          return;
        }
        if (attempts >= this.maxAttempts) {
          write("\r\nLogin incorrect\r\n");
          socket.end();
          return;
        }
        // Real telnetd re-prompts, and each retry is another credential pair for us.
        mode = "login";
        write(`\r\nLogin incorrect\r\n${this.hostname} login: `);
        return;
      }

      // --- shell ---
      write("\r\n");
      const command = value.slice(0, this.maxCommandLength).trim();
      if (command === "exit" || command === "logout" || command === "quit") {
        this.capture(command, session, ip);
        write("logout\r\n");
        this.emitSession(session, ip);
        socket.end();
        return;
      }
      this.capture(command, session, ip);
      write(fakeShellOutput(command, { hostname: this.hostname, user: session.username || "root" }) + prompt());
      if (session.commands.length >= this.maxCommands) {
        this.emitSession(session, ip);
        socket.end();
      }
    };

    socket.on("data", (chunk: Buffer) => {
      const { data, reply, terminal } = codec.feed(chunk);
      if (reply.length > 0) socket.write(reply);
      if (terminal !== undefined) session.terminal = terminal;

      for (const ch of decoder.write(data)) {
        // CR, CR LF and CR NUL all end one line, and so does a bare LF — every telnet
        // client picks a different one of the four. Consuming the byte that follows a
        // CR here is what keeps `\r\n` from reading as two separate submissions.
        if (afterCarriageReturn) {
          afterCarriageReturn = false;
          if (ch === "\n" || ch === "\0") continue;
        }
        if (ch === "\r" || ch === "\n") {
          if (ch === "\r") afterCarriageReturn = true;
          submit();
          // submit() ends the session on `exit`, on the command cap and on the line
          // cap. Keep reading past that and every remaining byte is written to a
          // socket that is already gone.
          if (socket.destroyed || socket.writableEnded) return;
          continue;
        }
        if (ch === "\x7f" || ch === "\b") {
          if (line.length > 0) {
            line = line.slice(0, -1);
            // Erase on the client's display too, but only where it is echoing.
            if (mode !== "password") write("\b \b");
          }
          continue;
        }
        // Drop the remaining control characters rather than storing them: they carry
        // nothing, and they are what corrupts a captured credential in a log line.
        if (ch < " ") continue;
        if (line.length < this.maxCommandLength) {
          line += ch;
          // We announced WILL ECHO, so the client is showing nothing on its own — and
          // a password is precisely what we do not echo back.
          if (mode !== "password") write(ch);
        }
      }
    });

    socket.once("close", () => {
      // A connection that took the banner and left without ever submitting a password
      // is a scanner or a banner grab, not a login attempt.
      if (!credentialSeen) void this.report("telnet-scan", "Telnet banner grab / scan (no credentials offered)", session, ip);
      else this.emitSession(session, ip);
    });
  }

  /** Records one command from the fake shell, both as an incident and in the transcript. */
  private capture(command: string, session: Session, ip: string): void {
    if (command === "") return;
    if (session.commands.length >= this.maxCommands) return;
    session.commands.push(command);
    void this.report("telnet-command", `Telnet shell command: ${command.slice(0, 200)}`, { ...session, command }, ip);
  }

  private emittedSessions = new WeakSet<Session>();
  /** Emit the session-transcript incident exactly once per session. */
  private emitSession(session: Session, ip: string): void {
    if (session.commands.length === 0 || this.emittedSessions.has(session)) return;
    this.emittedSessions.add(session);
    void this.report("telnet-session", `Telnet shell session: ${session.commands.length} command(s)`, session, ip);
  }

  private async report(finding: TelnetFinding, reason: string, session: Session & { command?: string }, ip: string): Promise<void> {
    // Every call site is `void this.report(...)`; this must never reject, or a rejecting
    // async store/onHit becomes an unhandled rejection an attacker can trigger at will.
    try {
      await this.doReport(finding, reason, session, ip);
    } catch (err) {
      this.opts.onError?.(err);
    }
  }

  private async doReport(finding: TelnetFinding, reason: string, session: Session & { command?: string }, ip: string): Promise<void> {
    const score = SCORES[finding];
    const incident: TelnetIncident = {
      ip,
      finding,
      reason,
      score,
      session: {
        ...(session.username !== undefined ? { username: session.username } : {}),
        ...(session.password !== undefined ? { password: session.password } : {}),
        ...(session.terminal !== undefined ? { terminal: session.terminal } : {}),
        ...(session.command !== undefined ? { command: session.command } : {}),
        ...(session.commands.length ? { commands: [...session.commands] } : {}),
      },
      at: new Date(),
    };
    await this.opts.onIncident?.(incident);

    if (this.opts.store || this.opts.onHit) {
      const prior = this.opts.store ? await this.opts.store.scoreFor(ip) : 0;
      const hit = this.toHit(incident, prior);
      await this.opts.store?.record(hit);
      await this.opts.onHit?.(hit);
    }
  }

  /** Map a Telnet incident into the shared HoneypotHit shape used by the HTTP engine. */
  private toHit(incident: TelnetIncident, priorScore: number): HoneypotHit {
    const s = incident.session;
    const headers: Record<string, string> = { "x-protocol": "telnet" };
    if (s.username !== undefined) headers["telnet-user"] = s.username;
    if (s.terminal !== undefined) headers["telnet-terminal"] = s.terminal;
    if (s.commands?.length) headers["telnet-command-count"] = String(s.commands.length);

    // Body carries the most analysis-worthy captured content for this finding: the
    // command(s) run in the fake shell, else the credential that was tried.
    const body = s.command ?? (s.commands ? s.commands.join("\n") : s.password);

    return {
      id: randomUUID(),
      timestamp: incident.at.toISOString(),
      ip: incident.ip,
      method: "TELNET",
      path: incident.reason,
      headers,
      ...(body !== undefined ? { body } : {}),
      detections: [{ detectorId: incident.finding, reason: incident.reason, score: incident.score }],
      score: incident.score,
      totalScore: priorScore + incident.score,
      respondedWith: "telnet-capture",
    };
  }
}
