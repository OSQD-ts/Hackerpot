import net from "node:net";
import { randomUUID } from "node:crypto";
import type { HoneypotHit } from "../types.js";
import type { SmtpFinding, SmtpHoneypotOptions, SmtpIncident } from "./types.js";

const MAX_LINE = 4096;
const MAX_LINES = 200;
const MAX_MESSAGE = 64 * 1024;
const IDLE_MS = 30_000;

const SCORES: Record<SmtpFinding, number> = {
  "smtp-auth-bruteforce": 8,
  "smtp-open-relay": 12,
  "smtp-spam": 10,
  "smtp-user-enumeration": 6,
};

interface Session {
  helo?: string | undefined;
  mailFrom?: string | undefined;
  rcptTo: string[];
  authUser?: string | undefined;
  authPass?: string | undefined;
  message?: string | undefined;
  messageBytes?: number | undefined;
  subject?: string | undefined;
}

type Mode = "commands" | "data" | "auth-user" | "auth-pass";

function addrDomain(addr: string | undefined): string | undefined {
  const at = addr?.lastIndexOf("@");
  return at !== undefined && at >= 0 ? addr!.slice(at + 1).replace(/>$/, "").toLowerCase() : undefined;
}

function b64decode(s: string): string {
  try {
    return Buffer.from(s.trim(), "base64").toString("utf8");
  } catch {
    return s;
  }
}

/**
 * A low-interaction SMTP honeypot. It speaks just enough of the protocol to keep
 * an attacker talking and to recognize the four things that only ever come from
 * abuse: credential brute-force (AUTH), open-relay attempts (MAIL/RCPT to an
 * external domain), spam delivery (DATA), and VRFY/EXPN user enumeration. Nothing
 * is ever actually relayed or authenticated. Incidents are mapped into the same
 * HoneypotHit shape as HTTP hits, so they share per-IP scoring and show up in the
 * management API and dashboard.
 */
export class SmtpHoneypot {
  private server?: net.Server;
  private readonly opts: SmtpHoneypotOptions;
  private readonly hostname: string;
  private readonly localDomains: Set<string>;
  private readonly maxConnections: number;
  private readonly captureBody: boolean;
  private readonly maxBodyChars: number;
  private activeConnections = 0;

  constructor(options: SmtpHoneypotOptions) {
    this.opts = options;
    this.hostname = options.hostname ?? "mail";
    this.localDomains = new Set((options.localDomains ?? []).map((d) => d.toLowerCase()));
    this.maxConnections = options.maxConnections ?? 256;
    this.captureBody = options.captureBody ?? true;
    this.maxBodyChars = options.maxBodyChars ?? 2000;
  }

  listen(): Promise<void> {
    this.server = net.createServer((socket) => this.handleConnection(socket));
    return new Promise((resolve) => this.server!.listen(this.opts.port, this.opts.host, resolve));
  }

  close(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.server) return resolve();
      this.server.close(() => resolve());
    });
  }

  address(): ReturnType<net.Server["address"]> {
    return this.server?.address() ?? null;
  }

  private async handleConnection(socket: net.Socket): Promise<void> {
    // FIRST, before anything can write to or await on this socket. A net.Socket is an
    // EventEmitter: an 'error' with no listener is rethrown as an uncaughtException and
    // kills the process — and this is one process, so the HTTP honeypot, the SSH
    // honeypot and the management API all die with it.
    //
    // This used to sit at the bottom of the function, below two `socket.write()` early
    // returns and below `await store.scoreFor(ip)`. A client that connects and resets
    // during that await (the store is a network round-trip when it is Redis) delivers
    // ECONNRESET into the gap: an unauthenticated remote kill, and one that only exists
    // once the operator turns ON `drop_above_score`, so the hardening option was the
    // thing that opened it. The SSH honeypot documents this exact hazard and attaches
    // its handler first; this is the same fix.
    socket.on("error", () => undefined);

    const ip = socket.remoteAddress ?? "unknown";

    // Bound our own resource use: a connection flood must not exhaust our sockets.
    if (this.activeConnections >= this.maxConnections) {
      socket.write("421 Too many connections, try again later\r\n");
      socket.destroy();
      return;
    }
    this.activeConnections += 1;
    socket.once("close", () => (this.activeConnections -= 1));

    if (this.opts.dropAboveScore !== undefined && this.opts.store) {
      const score = await this.opts.store.scoreFor(ip);
      if (score >= this.opts.dropAboveScore) {
        socket.write("421 Service not available, closing transmission channel\r\n");
        socket.destroy();
        return;
      }
    }

    const session: Session = { rcptTo: [] };
    let mode: Mode = "commands";
    let buffer = "";
    let lineCount = 0;
    const write = (line: string): void => void socket.write(line + "\r\n");

    socket.setTimeout(IDLE_MS, () => socket.destroy());

    write(`220 ${this.hostname} ESMTP ${this.opts.banner ?? "Postfix"}`);

    socket.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      if (buffer.length > MAX_LINE + MAX_MESSAGE) {
        socket.destroy();
        return;
      }
      let idx: number;
      while ((idx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, idx).replace(/\r$/, "");
        buffer = buffer.slice(idx + 1);
        if (++lineCount > MAX_LINES) {
          write("421 Too many commands");
          socket.destroy();
          return;
        }
        mode = this.handleLine(line, mode, session, ip, write, socket);
      }
    });
  }

  private handleLine(line: string, mode: Mode, session: Session, ip: string, write: (l: string) => void, socket: net.Socket): Mode {
    // --- DATA capture mode: accumulate until a lone dot ---
    if (mode === "data") {
      if (line === ".") {
        write("250 2.0.0 Ok: queued");
        void this.report("smtp-spam", `Message delivered via DATA (${session.rcptTo.length} recipient(s))`, session, ip);
        session.message = undefined;
        session.messageBytes = undefined;
        session.subject = undefined;
        session.mailFrom = undefined;
        session.rcptTo = [];
        return "commands";
      }
      session.messageBytes = (session.messageBytes ?? 0) + line.length + 1;
      // Parse Subject from the message headers even when the body itself isn't stored.
      if (session.subject === undefined && /^subject:/i.test(line)) session.subject = line.replace(/^subject:\s*/i, "").trim().slice(0, 200);
      // Storing the raw body is opt-out (it may carry malware / sensitive content).
      if (this.captureBody) session.message = ((session.message ?? "") + line + "\n").slice(0, MAX_MESSAGE);
      return "data";
    }

    // --- AUTH LOGIN follow-ups ---
    if (mode === "auth-user") {
      session.authUser = b64decode(line);
      write("334 UGFzc3dvcmQ6"); // "Password:"
      return "auth-pass";
    }
    if (mode === "auth-pass") {
      session.authPass = b64decode(line);
      write("535 5.7.8 Error: authentication failed");
      void this.report("smtp-auth-bruteforce", `AUTH LOGIN attempt as "${session.authUser ?? ""}"`, session, ip);
      return "commands";
    }

    const [rawCmd, ...rest] = line.trim().split(/\s+/);
    const cmd = (rawCmd ?? "").toUpperCase();
    const arg = rest.join(" ");

    switch (cmd) {
      case "HELO":
        session.helo = arg;
        write(`250 ${this.hostname}`);
        return "commands";
      case "EHLO":
        session.helo = arg;
        write(`250-${this.hostname}`);
        write("250-AUTH LOGIN PLAIN");
        write("250-SIZE 10485760");
        write("250 8BITMIME");
        return "commands";
      case "AUTH": {
        const sub = (rest[0] ?? "").toUpperCase();
        if (sub === "PLAIN") {
          const token = rest[1];
          if (token) {
            // base64 of \0user\0pass
            const parts = b64decode(token).split("\0");
            session.authUser = parts[1] ?? "";
            session.authPass = parts[2] ?? "";
            write("535 5.7.8 Error: authentication failed");
            void this.report("smtp-auth-bruteforce", `AUTH PLAIN attempt as "${session.authUser}"`, session, ip);
            return "commands";
          }
          write("334 ");
          return "auth-user"; // next line is the base64 token; treat like a user line
        }
        if (sub === "LOGIN") {
          write("334 VXNlcm5hbWU6"); // "Username:"
          return "auth-user";
        }
        write("504 5.7.4 Unrecognized authentication type");
        return "commands";
      }
      case "MAIL":
        session.mailFrom = /from:\s*(.*)/i.exec(arg)?.[1]?.trim();
        session.rcptTo = [];
        write("250 2.1.0 Ok");
        return "commands";
      case "RCPT": {
        const to = /to:\s*(.*)/i.exec(arg)?.[1]?.trim();
        if (to) session.rcptTo.push(to);
        const rcptDomain = addrDomain(to);
        const fromDomain = addrDomain(session.mailFrom);
        const external = rcptDomain !== undefined && !this.localDomains.has(rcptDomain);
        const fromExternal = fromDomain === undefined || !this.localDomains.has(fromDomain);
        if (external && fromExternal) {
          // Accept it (250) so they proceed to DATA — then we capture the message — but flag the relay attempt.
          void this.report("smtp-open-relay", `Relay attempt: MAIL FROM ${session.mailFrom} → RCPT TO ${to}`, session, ip);
        }
        write("250 2.1.5 Ok");
        return "commands";
      }
      case "DATA":
        if (session.rcptTo.length === 0) {
          write("503 5.5.1 Error: need RCPT command");
          return "commands";
        }
        write("354 End data with <CR><LF>.<CR><LF>");
        return "data";
      case "VRFY":
        write("252 2.0.0 Cannot VRFY user, but will accept message");
        void this.report("smtp-user-enumeration", `VRFY ${arg}`, session, ip);
        return "commands";
      case "EXPN":
        write("252 2.0.0 Cannot expand");
        void this.report("smtp-user-enumeration", `EXPN ${arg}`, session, ip);
        return "commands";
      case "RSET":
        session.mailFrom = undefined;
        session.rcptTo = [];
        session.message = undefined;
        session.messageBytes = undefined;
        session.subject = undefined;
        write("250 2.0.0 Ok");
        return "commands";
      case "NOOP":
        write("250 2.0.0 Ok");
        return "commands";
      case "STARTTLS":
        write("454 4.7.0 TLS not available");
        return "commands";
      case "QUIT":
        write("221 2.0.0 Bye");
        socket.end();
        return "commands";
      default:
        write("500 5.5.2 Error: command not recognized");
        return "commands";
    }
  }

  private async report(finding: SmtpFinding, reason: string, session: Session, ip: string): Promise<void> {
    // Every call site is `void this.report(...)`; this must never reject, or a rejecting
    // async store/onHit becomes an unhandled rejection an attacker can trigger at will.
    try {
      await this.doReport(finding, reason, session, ip);
    } catch (err) {
      this.opts.onError?.(err);
    }
  }

  private async doReport(finding: SmtpFinding, reason: string, session: Session, ip: string): Promise<void> {
    const score = SCORES[finding];
    const incident: SmtpIncident = {
      ip,
      finding,
      reason,
      score,
      session: {
        ...(session.helo !== undefined ? { helo: session.helo } : {}),
        ...(session.mailFrom !== undefined ? { mailFrom: session.mailFrom } : {}),
        ...(session.rcptTo.length ? { rcptTo: [...session.rcptTo] } : {}),
        ...(session.authUser !== undefined ? { authUser: session.authUser } : {}),
        ...(session.authPass !== undefined ? { authPass: session.authPass } : {}),
        ...(session.message !== undefined ? { message: session.message.slice(0, this.maxBodyChars) } : {}),
        ...(session.messageBytes !== undefined ? { messageBytes: session.messageBytes } : {}),
        ...(session.subject !== undefined ? { subject: session.subject } : {}),
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

  /** Map an SMTP incident into the shared HoneypotHit shape used by the HTTP engine. */
  private toHit(incident: SmtpIncident, priorScore: number): HoneypotHit {
    const s = incident.session;
    const headers: Record<string, string> = { "x-protocol": "smtp" };
    if (s.helo) headers["smtp-helo"] = s.helo;
    if (s.mailFrom) headers["smtp-mail-from"] = s.mailFrom;
    if (s.rcptTo?.length) headers["smtp-rcpt-to"] = s.rcptTo.join(", ");
    if (s.authUser !== undefined) headers["smtp-auth-user"] = s.authUser;
    if (s.subject !== undefined) headers["smtp-subject"] = s.subject;
    if (s.messageBytes !== undefined) headers["smtp-message-bytes"] = String(s.messageBytes);

    return {
      id: randomUUID(),
      timestamp: incident.at.toISOString(),
      ip: incident.ip,
      method: "SMTP",
      path: incident.reason,
      headers,
      body: s.message,
      detections: [{ detectorId: incident.finding, reason: incident.reason, score: incident.score }],
      score: incident.score,
      totalScore: priorScore + incident.score,
      respondedWith: "smtp-capture",
    };
  }
}
