import type { HitStore, HoneypotHit } from "../types.js";

export type FtpFinding =
  | "ftp-auth-bruteforce"
  | "ftp-anonymous-login"
  | "ftp-bounce"
  | "ftp-traversal"
  | "ftp-command"
  | "ftp-scan";

export interface FtpIncident {
  ip: string;
  finding: FtpFinding;
  reason: string;
  score: number;
  /** Session context captured so far. */
  session: {
    /** Username from USER — the half of the credential pair that arrives first. */
    username?: string;
    /** Password from PASS. The point of an FTP honeypot: real credentials, in the clear. */
    password?: string;
    /** The client's own advertised software, when it sends CLNT. */
    client?: string;
    /** A single command issued after the honeypot let them "in". */
    command?: string;
    /** The ordered command transcript of a logged-in session, on session close. */
    commands?: string[];
    /** For `ftp-bounce`: the third-party address the client asked us to connect to. */
    bounceTarget?: string;
  };
  at: Date;
}

export interface FtpHoneypotOptions {
  /** Port to listen on. 21 is the real FTP port (needs privileges); 2121 is the usual unprivileged stand-in. */
  port: number;
  host?: string;
  /** Greeting banner shown after the 220 code. A realistic one draws more interaction. */
  banner?: string;
  /** Close the connection after this many credential attempts. Default 6. */
  maxAuthAttempts?: number;
  /**
   * Medium-interaction: after {@link acceptOnAttempt} credential attempts, ACCEPT the
   * login (230) and capture the commands the attacker issues against the fake
   * filesystem. Nothing is ever served, stored, or deleted — there is no filesystem
   * behind it and no data connection is ever opened. Default false (auth-only capture).
   */
  interactive?: boolean;
  /** In interactive mode, accept the login on this attempt number. Default 1. */
  acceptOnAttempt?: number;
  /** Max commands captured per logged-in session before it's closed. Default 100. */
  maxCommands?: number;
  /** Max characters retained per command (longer is truncated). Default 512. */
  maxCommandLength?: number;
  /** Store FTP incidents alongside HTTP ones so they share per-IP scoring + the management API. */
  store?: HitStore;
  /** Called for every FTP incident, mapped into the same HoneypotHit shape as HTTP hits. */
  onHit?: (hit: HoneypotHit) => void | Promise<void>;
  /** Protocol-native callback, if you want the raw FTP incident too. */
  onIncident?: (incident: FtpIncident) => void | Promise<void>;
  /** Surfaces an error from recording an incident (a failing store/onHit) — reporting never throws regardless. */
  onError?: (error: unknown) => void;
  /** Refuse and drop connections from IPs whose cumulative score is at least this (needs `store`). */
  dropAboveScore?: number;
  /** Cap on simultaneous open connections, so a flood can't exhaust our sockets. Default 256. */
  maxConnections?: number;
  /**
   * Reports whether a source IP is allowlisted. Wired to the engine's allowlist by the
   * standalone builder; omit it for no exemption.
   *
   * The HTTP front ends have always consulted the allowlist, and `[allowlist] ips` is
   * documented as exempting a source from **all** detection — "never scored, never
   * blocked, no incident recorded". The protocol emulators did not consult it, so an
   * allowlisted host that touched one was scored, stored, and published on `/ioc.txt`,
   * which peer honeypots ingest and block. An uptime checker or an internal scanner —
   * exactly what an operator allowlists — could therefore be propagated into a
   * fleet-wide blocklist by the very instance that was told to exempt it.
   *
   * Passed as a predicate rather than an `IpAllowlist` so a SIGHUP that reloads the
   * allowlist is honoured live: these listeners are not rebuilt on reload, so a
   * captured instance would go stale.
   */
  isAllowlisted?: (ip: string) => boolean;
  /** Hard cap on how long one connection may stay open, in ms — bounds a slow connection-hold DoS. Default 120000. */
  maxSessionMs?: number;
}
