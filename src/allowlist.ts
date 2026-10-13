import net from "node:net";
import { normalizeAddress, v4ToInt, v6ToBigInt } from "./internal/ip.js";

// Re-exported where it always was, for anything that imported it from here.
export { sameAddress } from "./internal/ip.js";

/**
 * Matches an IP against a set of exact addresses and CIDR ranges (both IPv4 and
 * IPv6). Used to exempt known-good sources — uptime monitors, health checkers,
 * office/VPC ranges — from detection entirely, so they never score or get blocked.
 */
export class IpAllowlist {
  private readonly exact = new Set<string>();
  /**
   * Exact IPv6 entries, held as their 128-bit value rather than as text.
   *
   * They used to sit in `exact` alongside the v4 ones and be matched by string equality,
   * which for IPv6 is not an equality test at all: one address has many valid spellings
   * (`2001:db8::1`, `2001:0db8:0:0:0:0:0:1`, `2001:DB8::0:1`), and which one arrives is
   * decided by the peer's stack and Node's formatting, not by whatever the operator
   * typed in the config. So an allowlisted IPv6 monitor matched only by coincidence —
   * and when it did not match, it was not merely un-exempted, it was scored, blocked and
   * (with external enforcement wired) firewalled, silently, as if it were an attacker.
   * Comparing the parsed value makes every spelling of one address one entry, exactly as
   * the v6 CIDR ranges below already do.
   */
  private readonly exactV6 = new Set<bigint>();
  private readonly v4: Array<{ base: number; mask: number }> = [];
  private readonly v6: Array<{ base: bigint; mask: bigint }> = [];
  readonly size: number;
  /**
   * Entries that could not be parsed as an IP or CIDR range. They match nothing —
   * inspect this to fail loudly on a typo (`10.0.0.0/8x`) rather than silently
   * exempting no one. The config loader already rejects these at parse time; this
   * is the guard for direct library use.
   */
  readonly invalid: string[] = [];

  constructor(entries: string[] = []) {
    for (const raw of entries) {
      const entry = raw.trim();
      if (!entry) continue;
      const slash = entry.indexOf("/");
      if (slash === -1) {
        const normalized = normalizeAddress(entry);
        if (net.isIPv6(normalized)) {
          const big = v6ToBigInt(normalized);
          if (big === undefined) this.invalid.push(raw);
          else this.exactV6.add(big);
        } else if (net.isIPv4(normalized)) {
          this.exact.add(normalized);
        } else {
          this.invalid.push(raw);
        }
        continue;
      }
      const base = normalizeAddress(entry.slice(0, slash));
      const prefixPart = entry.slice(slash + 1);
      const prefix = Number(prefixPart);
      const validPrefix = /^\d+$/.test(prefixPart) && Number.isInteger(prefix);
      if (net.isIPv4(base) && validPrefix && prefix >= 0 && prefix <= 32) {
        const int = v4ToInt(base)!;
        const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
        this.v4.push({ base: (int & mask) >>> 0, mask });
      } else if (net.isIPv6(base) && validPrefix && prefix >= 0 && prefix <= 128) {
        const big = v6ToBigInt(base);
        if (big === undefined) {
          this.invalid.push(raw);
          continue;
        }
        const full = (1n << 128n) - 1n;
        const mask = prefix === 0 ? 0n : (full ^ ((1n << BigInt(128 - prefix)) - 1n)) & full;
        this.v6.push({ base: big & mask, mask });
      } else {
        this.invalid.push(raw);
      }
    }
    this.size = this.exact.size + this.exactV6.size + this.v4.length + this.v6.length;
  }

  allows(ip: string): boolean {
    if (this.size === 0) return false;
    const n = normalizeAddress(ip);
    if (this.exact.has(n)) return true;
    if (net.isIPv4(n)) {
      const int = v4ToInt(n);
      if (int === undefined) return false;
      return this.v4.some(({ base, mask }) => ((int & mask) >>> 0) === base);
    }
    const big = v6ToBigInt(n);
    if (big === undefined) return false;
    if (this.exactV6.has(big)) return true;
    return this.v6.some(({ base, mask }) => (big & mask) === base);
  }
}
