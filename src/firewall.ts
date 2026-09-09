import { execFile } from "node:child_process";
import { createHmac } from "node:crypto";
import net from "node:net";
import type { Blocklist } from "./blocklist.js";

/**
 * Called whenever an IP is blocked, to enforce the block outside the process —
 * at the OS firewall, a cloud WAF, a fail2ban jail, etc. `blockedUntilEpochMs`
 * is when the in-process block expires; an external enforcer may honor it or use
 * its own expiry.
 */
export type BlockEnforcer = (ip: string, blockedUntilEpochMs: number) => void | Promise<void>;

/**
 * Wraps any `Blocklist` so that every block also fires an external enforcer. Since
 * all blocking flows through the `Blocklist` interface, this catches every block
 * uniformly — not just the ones from the `block` response action. Enforcement
 * errors are reported, never thrown, so a failing firewall call can't break the
 * honeypot's own response.
 *
 * ⚠️ The enforcer acts on the *resolved* client IP. Behind a proxy that means the
 * `X-Forwarded-For` value — so only enable external enforcement with `trustProxy`
 * set correctly and a trusted proxy in front, or an attacker who can spoof
 * `X-Forwarded-For` could get you to firewall-block an arbitrary victim IP.
 */
export class EnforcingBlocklist implements Blocklist {
  constructor(
    private readonly base: Blocklist,
    private readonly enforce: BlockEnforcer,
    private readonly onError?: (error: Error) => void,
  ) {}

  async block(ip: string, untilEpochMs: number): Promise<void> {
    await this.base.block(ip, untilEpochMs);
    // Validate centrally: the library owns IP semantics, so no enforcer (built-in
    // or custom) is ever handed a non-IP source — closing argument-injection and
    // "block the string 'unknown'" surfaces once, for everyone.
    if (net.isIP(ip) === 0) {
      this.onError?.(new Error(`not enforcing a block for a non-IP source: ${JSON.stringify(ip).slice(0, 60)}`));
      return;
    }
    try {
      await this.enforce(ip, untilEpochMs);
    } catch (err) {
      this.onError?.(err as Error);
    }
  }

  isBlocked(ip: string, now?: number): boolean | Promise<boolean> {
    return this.base.isBlocked(ip, now);
  }

  size(): number | Promise<number> | undefined {
    return this.base.size?.();
  }
}

/**
 * A fixed-window rate limiter. Returns a function that reports whether another action
 * is allowed in the current window (and counts it if so). Used to bound how fast the
 * enforcers spawn processes / fire requests.
 */
function rateLimiter(maxPerWindow: number, windowMs: number): () => boolean {
  let windowStart = Date.now();
  let count = 0;
  return () => {
    const now = Date.now();
    if (now - windowStart >= windowMs) {
      windowStart = now;
      count = 0;
    }
    if (count >= maxPerWindow) return false;
    count += 1;
    return true;
  };
}

export interface CommandEnforcerOptions {
  /**
   * The command and arguments to run, with the token `{ip}` replaced by the
   * validated client IP. Run via `execFile` (no shell), so there is no command
   * injection even though the IP is substituted. Example:
   * `["iptables", "-w", "-A", "INPUT", "-s", "{ip}", "-j", "DROP"]`.
   */
  argv: string[];
  /** Milliseconds before the command is killed. Default 5000. */
  timeoutMs?: number;
  /**
   * Max processes spawned per `windowMs` — a spawn-rate ceiling. This is the fork-bomb
   * guard: with `trustProxy` on, one attacker can mint unlimited distinct source IPs via
   * `X-Forwarded-For`, and each IP crossing the block threshold would otherwise spawn an
   * `iptables` process (~3 requests per spawn), no botnet needed. Beyond the cap, blocks
   * are DROPPED from *external* enforcement (not queued) and reported via `onError` — the
   * in-process block still holds, so the honeypot stays protected; only the firewall rule
   * is skipped. Default 50.
   */
  maxPerWindow?: number;
  /** Window for `maxPerWindow`, in ms. Default 1000. */
  windowMs?: number;
  onError?: (error: Error) => void;
}

/**
 * A `BlockEnforcer` that runs a local command to enforce the block — e.g. adding
 * an `iptables`/`nft` DROP rule. The IP is validated (must be a real IPv4/IPv6
 * address) before substitution, and the command runs through `execFile` with an
 * argument array, so a hostile IP string cannot inject a shell command. Requires
 * whatever privileges the command needs (e.g. CAP_NET_ADMIN / root for iptables).
 */
export function commandEnforcer(options: CommandEnforcerOptions): BlockEnforcer {
  const timeout = options.timeoutMs ?? 5000;
  const allow = rateLimiter(options.maxPerWindow ?? 50, options.windowMs ?? 1000);
  return (ip: string) =>
    new Promise<void>((resolve) => {
      if (net.isIP(ip) === 0) {
        options.onError?.(new Error(`refusing to enforce a block for a non-IP source: ${JSON.stringify(ip).slice(0, 60)}`));
        return resolve();
      }
      // Fork-bomb guard: beyond the spawn ceiling, skip the external command (the
      // in-process block already holds) rather than fork the host to death.
      if (!allow()) {
        options.onError?.(new Error(`enforcement rate limit hit — skipping firewall spawn for ${ip} (in-process block still applied)`));
        return resolve();
      }
      const [cmd, ...rest] = options.argv;
      if (!cmd) return resolve();
      const args = rest.map((arg) => arg.replaceAll("{ip}", ip));
      execFile(cmd, args, { timeout }, (err) => {
        if (err) options.onError?.(err);
        resolve();
      });
    });
}

export interface WebhookEnforcerOptions {
  /** URL that receives a JSON POST `{ ip, blockedUntil }` per block. */
  url: string;
  /** HMAC-SHA256 signing secret; when set, the body is signed in `X-Hackerpot-Signature`. */
  secret?: string;
  headers?: Record<string, string>;
  /**
   * Max POSTs per `windowMs`. The same one-attacker-mints-distinct-IPs vector (see
   * `CommandEnforcerOptions.maxPerWindow`) would otherwise fire an unbounded burst of
   * concurrent fetches at your WAF endpoint. Beyond the cap, blocks are dropped from
   * external enforcement (in-process block still holds) and reported via `onError`.
   * Default 100.
   */
  maxPerWindow?: number;
  /** Window for `maxPerWindow`, in ms. Default 1000. */
  windowMs?: number;
  /**
   * Per-request deadline, in ms. Default 10000 — the same budget, for the same reason,
   * that `WebhookDispatcher` applies to management webhooks: `fetch` has no useful
   * timeout of its own (undici's header timeout is measured in minutes), so a WAF
   * endpoint that accepts the connection and then goes quiet holds the request open
   * essentially indefinitely.
   *
   * Without it the spawn-rate ceiling below did not bound anything real. `maxPerWindow`
   * caps how many requests are *started* per window; it does not cap how many are in
   * flight, so against a silently-stalled endpoint every window contributed another 100
   * hung fetches — sockets, TLS sessions and retained closures accumulating for as long
   * as the attack ran, on a path an attacker drives directly by crossing the block
   * threshold from distinct source IPs.
   */
  timeoutMs?: number;
  onError?: (error: Error) => void;
}

/**
 * A `BlockEnforcer` that POSTs each block to an HTTP endpoint — for pushing to a
 * cloud WAF/firewall API or your own automation. Optionally HMAC-signed, the same
 * way management webhooks are.
 */
export function webhookEnforcer(options: WebhookEnforcerOptions): BlockEnforcer {
  const allow = rateLimiter(options.maxPerWindow ?? 100, options.windowMs ?? 1000);
  const timeoutMs = options.timeoutMs ?? 10_000;
  return async (ip, blockedUntilEpochMs) => {
    if (!allow()) {
      options.onError?.(new Error(`enforcement rate limit hit — skipping firewall webhook for ${ip} (in-process block still applied)`));
      return;
    }
    const body = JSON.stringify({ type: "block", ip, blockedUntil: new Date(blockedUntilEpochMs).toISOString() });
    const headers: Record<string, string> = { "Content-Type": "application/json", "User-Agent": "hackerpot-firewall", ...options.headers };
    if (options.secret) headers["X-Hackerpot-Signature"] = `sha256=${createHmac("sha256", options.secret).update(body).digest("hex")}`;
    try {
      const res = await fetch(options.url, { method: "POST", headers, body, signal: AbortSignal.timeout(timeoutMs) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
    } catch (err) {
      options.onError?.(err as Error);
    }
  };
}
