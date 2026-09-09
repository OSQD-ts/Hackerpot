import type { HitStore, HoneypotHit } from "../types.js";

export type TelnetFinding = "telnet-auth-bruteforce" | "telnet-command" | "telnet-session" | "telnet-scan";

export interface TelnetIncident {
  ip: string;
  finding: TelnetFinding;
  reason: string;
  score: number;
  session: {
    username?: string | undefined;
    /** Captured password. Telnet carries it in the clear, which is why this works. */
    password?: string | undefined;
    /** A single command the attacker ran in the fake shell. */
    command?: string | undefined;
    /** The full ordered command transcript, emitted when the session closes. */
    commands?: string[] | undefined;
    /** Terminal type the client announced during option negotiation, when it sent one. */
    terminal?: string | undefined;
  };
  at: Date;
}

export interface TelnetHoneypotOptions {
  /** Port to listen on. 23 is the real Telnet port (needs privileges); 2323 is the common unprivileged stand-in — and is itself heavily swept, since so many IoT devices expose Telnet there. */
  port: number;
  host?: string;
  /** Banner printed before the login prompt. A device-shaped one draws the IoT botnets. */
  banner?: string;
  /** Hostname in the login and shell prompts. Default "srv01". */
  hostname?: string;
  /** Close the connection after this many credential attempts. Default 3 — what telnetd does. */
  maxAuthAttempts?: number;
  /**
   * Medium→high interaction: after {@link acceptOnAttempt} credential attempts, ACCEPT
   * the login and drop the attacker into a **fake shell** that captures the commands
   * they run. Nothing executes — the shell is a scripted stream. This is where a Telnet
   * honeypot earns its keep: the IoT droppers that sweep port 23 reveal their staging
   * URLs and payload names in the first three commands. Default false (auth-only capture).
   */
  interactive?: boolean;
  /** In interactive mode, accept the login on this attempt number. Default 1. */
  acceptOnAttempt?: number;
  /** Max commands captured per interactive session before it's closed. Default 100. */
  maxCommands?: number;
  /** Max characters retained per command line (longer is truncated). Default 4096. */
  maxCommandLength?: number;
  /** Store Telnet incidents alongside HTTP ones so they share per-IP scoring + the management API. */
  store?: HitStore;
  /** Called for every Telnet incident, mapped into the same HoneypotHit shape as HTTP hits. */
  onHit?: (hit: HoneypotHit) => void | Promise<void>;
  /** Protocol-native callback, if you want the raw Telnet incident too. */
  onIncident?: (incident: TelnetIncident) => void | Promise<void>;
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
