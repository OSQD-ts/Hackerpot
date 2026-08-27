import type { HitStore, HoneypotHit } from "../types.js";

export type SshFinding =
  | "ssh-auth-bruteforce"
  | "ssh-publickey-probe"
  | "ssh-scan"
  | "ssh-shell-command"
  | "ssh-shell-session";

export interface SshIncident {
  ip: string;
  finding: SshFinding;
  reason: string;
  score: number;
  session: {
    /** The client's SSH identification string, e.g. "SSH-2.0-libssh2_1.9.0". */
    clientVersion?: string | undefined;
    username?: string | undefined;
    /** Captured password (password auth) — the whole point of an SSH honeypot. */
    password?: string | undefined;
    /** Public-key algorithm (publickey auth), e.g. "ssh-rsa", "ssh-ed25519". */
    keyType?: string | undefined;
    /** SHA256 fingerprint of the offered public key. */
    keyFingerprint?: string | undefined;
    /** A single command the attacker ran in the fake shell (interactive mode). */
    command?: string | undefined;
    /** The full ordered command transcript of an interactive session, on session close. */
    commands?: string[] | undefined;
  };
  at: Date;
}

export interface SshHoneypotOptions {
  /** Port to listen on. 22 is the real SSH port (needs privileges); 2222 is the common unprivileged stand-in. */
  port: number;
  host?: string;
  /**
   * Server software identifier. The client sees "SSH-2.0-<ident>". A realistic
   * value like "OpenSSH_8.4" draws more brute-force interaction. Default "OpenSSH_8.4".
   */
  ident?: string;
  /**
   * Host private key(s) in PEM/OpenSSH format. If omitted, an ephemeral RSA key
   * is generated at startup (fine for a honeypot — a stable key isn't needed).
   */
  hostKeys?: string[];
  /** Close the connection after this many credential attempts. Default 6. */
  maxAuthAttempts?: number;
  /**
   * Medium→high interaction: after {@link acceptOnAttempt} credential attempts, ACCEPT
   * the login and drop the attacker into a **fake shell** that captures the commands
   * they run (never a real shell — the channel is a script we control, nothing executes).
   * This records what an attacker actually *does*, not just that they knocked. Default
   * false (auth-only capture).
   */
  interactive?: boolean;
  /** In interactive mode, accept the login on this attempt number (earlier ones are captured + rejected). Default 1. */
  acceptOnAttempt?: number;
  /** Fake hostname shown in the shell prompt. Default "srv01". */
  shellHostname?: string;
  /** Max commands captured per interactive session before it's closed. Default 100. */
  maxCommands?: number;
  /** Max bytes captured per command line (longer is truncated) — bounds a flood of giant input. Default 4096. */
  maxCommandLength?: number;
  /** Store SSH incidents alongside HTTP ones so they share per-IP scoring + the management API. */
  store?: HitStore;
  /** Called for every SSH incident, mapped into the same HoneypotHit shape as HTTP hits. */
  onHit?: (hit: HoneypotHit) => void | Promise<void>;
  /** Protocol-native callback, if you want the raw SSH incident too. */
  onIncident?: (incident: SshIncident) => void | Promise<void>;
  /** Surfaces an error from recording an incident (a failing store/onHit) — reporting never throws regardless. */
  onError?: (error: unknown) => void;
  /** Refuse connections from IPs whose cumulative score is at least this (needs `store`). */
  dropAboveScore?: number;
  /** Cap on simultaneous open connections, so a flood can't exhaust our sockets. Default 256. */
  maxConnections?: number;
  /** Hard cap on how long one connection may stay open, in ms — bounds a slow connection-hold DoS. Default 120000. */
  maxSessionMs?: number;
}
