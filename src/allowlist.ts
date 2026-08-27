import net from "node:net";

/** Strip an IPv4-mapped IPv6 prefix and a zone id, lowercase. Node reports "::ffff:127.0.0.1" for v4 clients. */
function normalize(ip: string): string {
  let s = ip.trim().toLowerCase();
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  const zone = s.indexOf("%");
  if (zone !== -1) s = s.slice(0, zone);
  if (s.startsWith("::ffff:") && net.isIPv4(s.slice(7))) s = s.slice(7);
  return s;
}

function v4ToInt(ip: string): number | undefined {
  const parts = ip.split(".");
  if (parts.length !== 4) return undefined;
  let n = 0;
  for (const part of parts) {
    const v = Number(part);
    if (!Number.isInteger(v) || v < 0 || v > 255 || !/^\d+$/.test(part)) return undefined;
    n = (n * 256 + v) >>> 0;
  }
  return n >>> 0;
}

/** Expand a (possibly compressed / v4-embedded) IPv6 address to a 128-bit BigInt. */
function v6ToBigInt(ip: string): bigint | undefined {
  let s = ip;
  const v4 = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(s);
  if (v4) {
    const int = v4ToInt(v4[1]!);
    if (int === undefined) return undefined;
    s = s.slice(0, v4.index) + `${(int >>> 16).toString(16)}:${(int & 0xffff).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return undefined;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 ? (halves[1] ? halves[1].split(":") : []) : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? head.length !== 8 : missing < 0) return undefined;
  const groups = [...head, ...Array(Math.max(0, missing)).fill("0"), ...tail];
  if (groups.length !== 8) return undefined;
  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return undefined;
    n = (n << 16n) | BigInt(parseInt(g, 16));
  }
  return n;
}

/**
 * Matches an IP against a set of exact addresses and CIDR ranges (both IPv4 and
 * IPv6). Used to exempt known-good sources — uptime monitors, health checkers,
 * office/VPC ranges — from detection entirely, so they never score or get blocked.
 */
export class IpAllowlist {
  private readonly exact = new Set<string>();
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
        const normalized = normalize(entry);
        if (net.isIP(normalized) === 0) this.invalid.push(raw);
        else this.exact.add(normalized);
        continue;
      }
      const base = normalize(entry.slice(0, slash));
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
    this.size = this.exact.size + this.v4.length + this.v6.length;
  }

  allows(ip: string): boolean {
    if (this.size === 0) return false;
    const n = normalize(ip);
    if (this.exact.has(n)) return true;
    if (net.isIPv4(n)) {
      const int = v4ToInt(n);
      if (int === undefined) return false;
      return this.v4.some(({ base, mask }) => ((int & mask) >>> 0) === base);
    }
    const big = v6ToBigInt(n);
    if (big === undefined) return false;
    return this.v6.some(({ base, mask }) => (big & mask) === base);
  }
}
