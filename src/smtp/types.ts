import type { HitStore, HoneypotHit } from "../types.js";

export type SmtpFinding = "smtp-auth-bruteforce" | "smtp-open-relay" | "smtp-spam" | "smtp-user-enumeration";

export interface SmtpIncident {
  ip: string;
  finding: SmtpFinding;
  reason: string;
  score: number;
  /** Session context captured so far. */
  session: {
    helo?: string;
    mailFrom?: string;
    rcptTo?: string[];
    authUser?: string;
    authPass?: string;
    /** Captured DATA body, size-capped. Omitted when `captureBody` is false. */
    message?: string;
    /** Byte length of the DATA body seen — recorded even when the body itself isn't stored. */
    messageBytes?: number;
    /** Subject line parsed from the DATA headers, for quick triage. */
    subject?: string;
  };
  at: Date;
}

export interface SmtpHoneypotOptions {
  /** Port to listen on. 25 is the real SMTP port (needs privileges); 2525 is a common unprivileged stand-in. */
  port: number;
  host?: string;
  /** Greeting banner. A realistic one draws more interaction. */
  banner?: string;
  /** Hostname advertised in EHLO/HELO responses. Default "mail". */
  hostname?: string;
  /**
   * Domains this server would legitimately accept mail for. A RCPT TO outside
   * these (with an external MAIL FROM) is an open-relay attempt. Empty means
   * "accept nothing as local", so any external recipient looks like relay abuse.
   */
  localDomains?: string[];
  /** Store SMTP incidents alongside HTTP ones so they share per-IP scoring + the management API. */
  store?: HitStore;
  /** Called for every SMTP incident, mapped into the same HoneypotHit shape as HTTP hits. */
  onHit?: (hit: HoneypotHit) => void | Promise<void>;
  /** Protocol-native callback, if you want the raw SMTP incident too. */
  onIncident?: (incident: SmtpIncident) => void | Promise<void>;
  /** Surfaces an error from recording an incident (a failing store/onHit) — reporting never throws regardless. */
  onError?: (error: unknown) => void;
  /**
   * Capture the DATA-phase message body (the spam/phishing payload itself). Default
   * true. Set false for privacy/safety — the message length and parsed Subject are
   * still recorded, but the raw body (which may carry malware or sensitive content)
   * is not stored.
   */
  captureBody?: boolean;
  /** Max bytes of the DATA body retained on the incident when captured. Default 2000. */
  maxBodyChars?: number;
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
