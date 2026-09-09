import net from "node:net";
import { randomUUID } from "node:crypto";
import { StringDecoder } from "node:string_decoder";
import type { HoneypotHit } from "../types.js";
import type { FtpFinding, FtpHoneypotOptions, FtpIncident } from "./types.js";

const MAX_LINE = 4096;
const MAX_LINES = 300;
const IDLE_MS = 30_000;

const SCORES: Record<FtpFinding, number> = {
  "ftp-auth-bruteforce": 8,
  // Lower than a brute-force attempt: anonymous FTP is a real (if dated) configuration,
  // so the attempt says "someone is looking" more than "someone is attacking".
  "ftp-anonymous-login": 5,
  // The FTP analogue of an open mail relay — the client is asking us to open a
  // connection to a THIRD party on its behalf. Scored like `smtp-open-relay`.
  "ftp-bounce": 12,
  "ftp-traversal": 9,
  // Post-authentication intent, the same reasoning as `ssh-shell-command`.
  "ftp-command": 9,
  "ftp-scan": 3,
};

/** Commands that need no login, so issuing them isn't itself evidence of anything. */
const PRE_AUTH_COMMANDS = new Set(["USER", "PASS", "QUIT", "SYST", "FEAT", "HELP", "NOOP", "AUTH", "CLNT", "OPTS", "ABOR", "REIN"]);

/** Commands whose argument is a path, and therefore worth traversal-checking. */
const PATH_COMMANDS = new Set(["CWD", "RETR", "STOR", "STOU", "APPE", "DELE", "MKD", "RMD", "XMKD", "XRMD", "SIZE", "MDTM", "RNFR", "RNTO", "LIST", "NLST", "MLSD", "MLST", "STAT"]);

/** Usernames that mean "no credential offered" rather than a guessed one. */
const ANONYMOUS_USERS = new Set(["anonymous", "ftp", "anonymous@", "guest"]);

/**
 * Traversal and sensitive-target patterns in a path argument.
 *
 * Encoded forms are included because the FTP command channel is plain text with no
 * canonicalization step of its own — an attacker probing a real server has no reason
 * to percent-encode, so seeing it at all is a sign of tooling built to slip past a
 * filter rather than of a client fetching a file.
 */
const TRAVERSAL = /\.\.[/\\]|\.\.%2f|%2e%2e|%00|\0|^\/etc\/|^\/proc\/|^\/root\/|\\windows\\|\/windows\/win\.ini/i;

/** Normalizes an IPv4-mapped IPv6 address, so `::ffff:10.0.0.1` compares equal to `10.0.0.1`. */
function normalizeIp(ip: string): string {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  return (mapped?.[1] ?? ip).toLowerCase();
}

/**
 * Parses `PORT h1,h2,h3,h4,p1,p2` into an `ip:port` string, or undefined if malformed.
 *
 * Each field must be plain decimal digits. `Number()` alone was far too permissive for
 * a value this decides a *detection* on: `Number("")` is 0, so `PORT ,,,,,` — six empty
 * fields, no address at all — parsed as the perfectly valid-looking `0.0.0.0:0` and was
 * then reported as an `ftp-bounce`, the highest-scored FTP finding at 12 points, naming
 * a third party the client never mentioned. `Number()` also accepts `0x10` and `1e2`,
 * neither of which is an octet in a protocol whose grammar is decimal-only, so both
 * silently became some other address.
 *
 * A honeypot's output is evidence, and evidence invented from a malformed command is
 * worse than a missed detection: the reason string names a specific victim address, and
 * an `/ioc.txt` consumer downstream cannot tell it from a real one. `\d+` here matches
 * the rail `IpAllowlist` already applies to the same problem.
 */
function parsePortCommand(arg: string): string | undefined {
  const parts = arg.trim().split(",");
  if (parts.length !== 6) return undefined;
  const octets: number[] = [];
  for (const part of parts) {
    const field = part.trim();
    if (!/^\d{1,3}$/.test(field)) return undefined;
    const value = Number(field);
    if (value < 0 || value > 255) return undefined;
    octets.push(value);
  }
  const port = octets[4]! * 256 + octets[5]!;
  return `${octets.slice(0, 4).join(".")}:${port}`;
}

/** Parses `EPRT |1|address|port|` into an `ip:port` string, or undefined if malformed. */
function parseEprtCommand(arg: string): string | undefined {
  const trimmed = arg.trim();
  const delimiter = trimmed[0];
  if (!delimiter) return undefined;
  const fields = trimmed.split(delimiter);
  // "|1|10.0.0.1|4711|" splits to ["", "1", "10.0.0.1", "4711", ""].
  const address = fields[2];
  const port = Number(fields[3]);
  if (!address || !Number.isInteger(port) || port < 1 || port > 65535) return undefined;
  if (net.isIP(address) === 0) return undefined;
  return `${address}:${port}`;
}

interface Session {
  username?: string | undefined;
  password?: string | undefined;
  client?: string | undefined;
  commands: string[];
  /** The pending RNFR target, until the RNTO that completes (or fails) the pair. */
  renameFrom?: string | undefined;
}

/**
 * A low-interaction FTP honeypot.
 *
 * FTP is still swept constantly — it is old, it is frequently left on an appliance
 * nobody administers, and its credentials cross the wire in the clear, which is
 * exactly why a fake one is worth running. This speaks enough of RFC 959 to keep a
 * client talking and to recognize the things that only ever come from abuse:
 *
 * - **Credential brute-force** (USER/PASS), captured in plaintext, which is the
 *   whole point — the pairs an attacker tries here are the pairs they are trying
 *   everywhere else.
 * - **Anonymous login** attempts, the oldest reconnaissance question there is.
 * - **FTP bounce** (PORT/EPRT naming an address that is not the client's), where the
 *   attacker asks us to open a connection to a third party — port-scanning or
 *   attacking someone else from our address. We parse it, we report it, and we never
 *   open the connection.
 * - **Path traversal** in any command that takes a filename.
 * - **Post-login commands**, in interactive mode.
 *
 * No data connection is ever opened in either direction, no file is ever served or
 * accepted, and there is no filesystem behind the fake directory listing. Incidents
 * map into the same HoneypotHit shape as HTTP hits, so they share per-IP scoring and
 * appear in the management API and dashboard.
 */
export class FtpHoneypot {
  private server: net.Server | undefined;
  /** Live connections, so `close()` can end them instead of waiting on them. */
  private readonly sockets = new Set<net.Socket>();
  private readonly opts: FtpHoneypotOptions;
  private readonly banner: string;
  private readonly maxAttempts: number;
  private readonly maxConnections: number;
  private readonly interactive: boolean;
  private readonly acceptOnAttempt: number;
  private readonly maxCommands: number;
  private readonly maxCommandLength: number;
  private readonly maxSessionMs: number;
  private activeConnections = 0;

  constructor(options: FtpHoneypotOptions) {
    this.opts = options;
    this.banner = options.banner ?? "(vsFTPd 3.0.3)";
    this.maxAttempts = options.maxAuthAttempts ?? 6;
    this.maxConnections = options.maxConnections ?? 256;
    this.interactive = options.interactive ?? false;
    this.acceptOnAttempt = Math.max(1, options.acceptOnAttempt ?? 1);
    this.maxCommands = options.maxCommands ?? 100;
    this.maxCommandLength = options.maxCommandLength ?? 512;
    this.maxSessionMs = options.maxSessionMs ?? 120_000;
  }

  /**
   * Binds the listener, **rejecting** if the bind fails — `listen()`'s callback only
   * fires on success, and an EADDRINUSE/EACCES arrives as an `error` event that would
   * otherwise be rethrown as an uncaughtException past the caller's `await`. Port 21
   * needs privileges, so a failed bind here is a routine misconfiguration rather than
   * an exotic one.
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
    // listener is rethrown as an uncaughtException and kills the whole process — taking
    // the HTTP, SSH, SMTP and Telnet honeypots and the management API with it. A client
    // that connects and resets during the `scoreFor` await below (a network round-trip
    // when the store is Redis) delivers ECONNRESET into exactly that gap.
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
      socket.write("421 Too many connections, try again later.\r\n");
      socket.destroy();
      return;
    }
    this.activeConnections += 1;
    socket.once("close", () => (this.activeConnections -= 1));

    // Bound how long one connection may be held: without it an attacker opens sockets
    // and sits on them, exhausting `maxConnections` without ever sending a byte.
    const lifetimeTimer = setTimeout(() => socket.destroy(), this.maxSessionMs);
    lifetimeTimer.unref?.();
    socket.once("close", () => clearTimeout(lifetimeTimer));

    if (this.opts.dropAboveScore !== undefined && this.opts.store) {
      const score = await this.opts.store.scoreFor(ip);
      if (score >= this.opts.dropAboveScore) {
        socket.write("421 Service not available, closing control connection.\r\n");
        socket.destroy();
        return;
      }
    }

    const session: Session = { commands: [] };
    let attempts = 0;
    let loggedIn = false;
    let credentialSeen = false;
    let buffer = "";
    let lineCount = 0;
    const write = (line: string): void => void socket.write(`${line}\r\n`);

    socket.setTimeout(IDLE_MS, () => socket.destroy());
    write(`220 ${this.banner}`);

    // Incremental decode: a UTF-8 character split across TCP segments would otherwise
    // decode to replacement characters, corrupting the very credential text this
    // honeypot exists to capture.
    const decoder = new StringDecoder("utf8");
    socket.on("data", (chunk: Buffer) => {
      buffer += decoder.write(chunk);
      let idx: number;
      while ((idx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, idx).replace(/\r$/, "");
        buffer = buffer.slice(idx + 1);
        if (++lineCount > MAX_LINES) {
          write("421 Too many commands.");
          socket.destroy();
          return;
        }

        const spaceAt = line.trim().indexOf(" ");
        const trimmed = line.trim();
        const cmd = (spaceAt === -1 ? trimmed : trimmed.slice(0, spaceAt)).toUpperCase();
        const arg = spaceAt === -1 ? "" : trimmed.slice(spaceAt + 1).trim();

        // --- credentials ---
        if (cmd === "USER") {
          session.username = arg.slice(0, this.maxCommandLength);
          write(`331 Please specify the password for ${arg || "the user"}.`);
          continue;
        }
        if (cmd === "PASS") {
          credentialSeen = true;
          attempts += 1;
          session.password = arg.slice(0, this.maxCommandLength);
          const anonymous = ANONYMOUS_USERS.has((session.username ?? "").toLowerCase());
          if (anonymous) {
            void this.report("ftp-anonymous-login", `FTP anonymous login attempt (password "${session.password}")`, session, ip);
          } else {
            void this.report("ftp-auth-bruteforce", `FTP password attempt user="${session.username ?? ""}"`, session, ip);
          }
          if (this.interactive && attempts >= this.acceptOnAttempt) {
            loggedIn = true;
            write("230 Login successful.");
          } else if (attempts >= this.maxAttempts) {
            write("530 Login incorrect.");
            write("421 Too many failed login attempts.");
            socket.end();
            return;
          } else {
            write("530 Login incorrect.");
          }
          continue;
        }
        if (cmd === "QUIT") {
          write("221 Goodbye.");
          socket.end();
          return;
        }

        // Report intent before the login gate. A `PORT` naming a third party or a
        // `RETR ../../etc/passwd` is evidence of what the client came to do regardless
        // of whether we then refuse it for want of a login — and in the default
        // (non-interactive) configuration we always do refuse, so gating the detection
        // on a successful login would mean never reporting either one.
        this.inspect(cmd, arg, session, ip);

        // --- everything else needs a login we only grant in interactive mode ---
        if (!loggedIn && !PRE_AUTH_COMMANDS.has(cmd)) {
          write("530 Please login with USER and PASS.");
          continue;
        }

        this.handleCommand(cmd, arg, session, ip, write);

        if (loggedIn && session.commands.length >= this.maxCommands) {
          write("421 Session limit reached.");
          socket.end();
          return;
        }
      }

      // Whatever is left has no newline in it, so it is one unterminated command. THIS
      // is the buffer that can grow without bound; the lines already drained above
      // cannot. Checking before the drain would instead have killed a client that
      // pipelined several perfectly ordinary commands into a single segment.
      if (buffer.length > MAX_LINE) {
        write("500 Line too long.");
        socket.destroy();
      }
    });

    socket.once("close", () => {
      // A connection that opened, took the banner and left without ever offering a
      // credential is a scanner or a banner grab, not a login attempt.
      if (!credentialSeen) void this.report("ftp-scan", "FTP banner grab / scan (no credentials offered)", session, ip);
    });
  }

  /**
   * Handles one post-greeting command. Replies are chosen to keep the client working
   * through its script: plausible success for the cheap metadata commands, and a data
   * connection that is always "unavailable" for anything that would need one — which
   * is honest, since we never open one.
   */
  /**
   * The detections that do not depend on the session having a login: a path that is
   * trying to escape the directory tree, and a data-channel address that belongs to
   * somebody other than the client.
   */
  private inspect(cmd: string, arg: string, session: Session, ip: string): void {
    if (PATH_COMMANDS.has(cmd) && arg && TRAVERSAL.test(arg)) {
      void this.report("ftp-traversal", `FTP path traversal: ${cmd} ${arg.slice(0, 200)}`, { ...session, command: `${cmd} ${arg}` }, ip);
    }
    if (cmd !== "PORT" && cmd !== "EPRT") return;
    const target = cmd === "PORT" ? parsePortCommand(arg) : parseEprtCommand(arg);
    if (target === undefined) return;
    const targetIp = normalizeIp(target.slice(0, target.lastIndexOf(":")));
    // The bounce: the client is asking us to open a connection to a THIRD party, to
    // port-scan or attack them from our address. We report it and we never dial it —
    // there is no code path from here to a connect().
    if (targetIp !== normalizeIp(ip)) {
      void this.report("ftp-bounce", `FTP bounce: ${cmd} names third party ${target} (client is ${ip})`, { ...session, bounceTarget: target }, ip);
    }
  }

  private handleCommand(cmd: string, arg: string, session: Session, ip: string, write: (line: string) => void): void {
    switch (cmd) {
      // Already inspected above; all that is left is a reply that keeps them talking.
      case "PORT":
      case "EPRT": {
        const target = cmd === "PORT" ? parsePortCommand(arg) : parseEprtCommand(arg);
        if (target === undefined) {
          write("501 Illegal PORT command.");
          return;
        }
        write(cmd === "PORT" ? "200 PORT command successful. Consider using PASV." : "200 EPRT command successful.");
        return;
      }

      // We advertise no passive port because we have none to advertise.
      case "PASV":
      case "EPSV":
        this.capture(cmd, arg, session, ip);
        write("425 Can't open data connection.");
        return;

      // Anything that would move bytes: captured, then refused for want of a channel.
      case "LIST":
      case "NLST":
      case "MLSD":
      case "RETR":
      case "STOR":
      case "STOU":
      case "APPE":
        this.capture(cmd, arg, session, ip);
        write("425 Use PORT or PASV first.");
        return;

      case "CWD":
      case "XCWD":
        this.capture(cmd, arg, session, ip);
        write("250 Directory successfully changed.");
        return;
      case "CDUP":
        this.capture(cmd, arg, session, ip);
        write("250 Directory successfully changed.");
        return;
      case "DELE":
      case "MKD":
      case "XMKD":
      case "RMD":
      case "XRMD":
        // Captured and acknowledged. Nothing exists to create or destroy.
        this.capture(cmd, arg, session, ip);
        write(cmd === "MKD" || cmd === "XMKD" ? `257 "${arg}" created.` : "250 Requested file action okay, completed.");
        return;
      case "RNFR":
        this.capture(cmd, arg, session, ip);
        session.renameFrom = arg;
        write("350 Ready for RNTO.");
        return;
      case "RNTO":
        this.capture(cmd, arg, session, ip);
        write(session.renameFrom === undefined ? "503 RNFR required first." : "250 Rename successful.");
        session.renameFrom = undefined;
        return;
      case "SITE":
        // `SITE EXEC` is the wu-ftpd remote-execution probe and still shows up in
        // scanner kits decades later; it is worth capturing verbatim.
        this.capture(cmd, arg, session, ip);
        write("500 Unknown SITE command.");
        return;
      case "SIZE":
        this.capture(cmd, arg, session, ip);
        write("213 4096");
        return;
      case "MDTM":
        this.capture(cmd, arg, session, ip);
        write("213 20240115093000");
        return;
      case "STAT":
        this.capture(cmd, arg, session, ip);
        write("211-FTP server status:");
        write("     Connected to the server");
        write("211 End of status");
        return;

      // --- metadata, answered plausibly and not treated as intent ---
      case "SYST":
        write("215 UNIX Type: L8");
        return;
      case "PWD":
      case "XPWD":
        write('257 "/" is the current directory');
        return;
      case "TYPE":
        write(`200 Switching to ${/^a/i.test(arg) ? "ASCII" : "Binary"} mode.`);
        return;
      case "MODE":
        write("200 Mode set to S.");
        return;
      case "STRU":
        write("200 Structure set to F.");
        return;
      case "NOOP":
        write("200 NOOP ok.");
        return;
      case "CLNT":
        session.client = arg.slice(0, this.maxCommandLength);
        write("200 Don't care.");
        return;
      case "OPTS":
        write("200 Always in UTF8 mode.");
        return;
      case "ABOR":
        write("226 Closing data connection.");
        return;
      case "REIN":
        write("220 Service ready for new user.");
        return;
      case "FEAT":
        write("211-Features:");
        write(" EPRT");
        write(" EPSV");
        write(" MDTM");
        write(" PASV");
        write(" SIZE");
        write(" UTF8");
        write("211 End");
        return;
      case "HELP":
        write("214 Help OK.");
        return;
      case "AUTH":
        // No TLS. Refusing it keeps the credentials in the clear, which is the point.
        write("500 AUTH not understood.");
        return;
      default:
        write("500 Unknown command.");
        return;
    }
  }

  /** Records one command from a logged-in session, both as an incident and in the transcript. */
  private capture(cmd: string, arg: string, session: Session, ip: string): void {
    const command = `${cmd}${arg ? ` ${arg}` : ""}`.slice(0, this.maxCommandLength);
    if (session.commands.length >= this.maxCommands) return;
    session.commands.push(command);
    void this.report("ftp-command", `FTP command: ${command.slice(0, 200)}`, { ...session, command }, ip);
  }

  private async report(finding: FtpFinding, reason: string, session: Session & { command?: string; bounceTarget?: string }, ip: string): Promise<void> {
    // Every call site is `void this.report(...)`; this must never reject, or a rejecting
    // async store/onHit becomes an unhandled rejection an attacker can trigger at will.
    try {
      await this.doReport(finding, reason, session, ip);
    } catch (err) {
      this.opts.onError?.(err);
    }
  }

  private async doReport(finding: FtpFinding, reason: string, session: Session & { command?: string; bounceTarget?: string }, ip: string): Promise<void> {
    const score = SCORES[finding];
    const incident: FtpIncident = {
      ip,
      finding,
      reason,
      score,
      session: {
        ...(session.username !== undefined ? { username: session.username } : {}),
        ...(session.password !== undefined ? { password: session.password } : {}),
        ...(session.client !== undefined ? { client: session.client } : {}),
        ...(session.command !== undefined ? { command: session.command } : {}),
        ...(session.commands.length ? { commands: [...session.commands] } : {}),
        ...(session.bounceTarget !== undefined ? { bounceTarget: session.bounceTarget } : {}),
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

  /** Map an FTP incident into the shared HoneypotHit shape used by the HTTP engine. */
  private toHit(incident: FtpIncident, priorScore: number): HoneypotHit {
    const s = incident.session;
    const headers: Record<string, string> = { "x-protocol": "ftp" };
    if (s.username !== undefined) headers["ftp-user"] = s.username;
    if (s.client !== undefined) headers["ftp-client"] = s.client;
    if (s.bounceTarget !== undefined) headers["ftp-bounce-target"] = s.bounceTarget;
    if (s.commands?.length) headers["ftp-command-count"] = String(s.commands.length);

    // Body carries the most analysis-worthy captured content for this finding: the
    // command issued, else the credential that was tried.
    const body = s.command ?? s.password;

    return {
      id: randomUUID(),
      timestamp: incident.at.toISOString(),
      ip: incident.ip,
      method: "FTP",
      path: incident.reason,
      headers,
      ...(body !== undefined ? { body } : {}),
      detections: [{ detectorId: incident.finding, reason: incident.reason, score: incident.score }],
      score: incident.score,
      totalScore: priorScore + incident.score,
      respondedWith: "ftp-capture",
    };
  }
}
