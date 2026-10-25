import net from "node:net";

/**
 * Address comparison without a parser dependency: what the allowlist matches with, and the
 * `sameAddress` the shared DNS module asks every host library to provide from this file.
 */

/** Strip an IPv4-mapped IPv6 prefix and a zone id, lowercase. Node reports "::ffff:127.0.0.1" for v4 clients. */
export function normalizeAddress(ip: string): string {
  let s = ip.trim().toLowerCase();
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  const zone = s.indexOf("%");
  if (zone !== -1) s = s.slice(0, zone);
  if (s.startsWith("::ffff:") && net.isIPv4(s.slice(7))) s = s.slice(7);
  return s;
}

export function v4ToInt(ip: string): number | undefined {
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
export function v6ToBigInt(ip: string): bigint | undefined {
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
 * Whether two strings name the same IP address, however each is spelled: an IPv4-mapped
 * IPv6 address and its IPv4 form, zero-compressed and expanded IPv6, and letter case.
 */
export function sameAddress(a: string, b: string): boolean {
  const left = normalizeAddress(a);
  const right = normalizeAddress(b);
  if (left === right) return true;
  if (!net.isIPv6(left) || !net.isIPv6(right)) return false;
  const value = v6ToBigInt(left);
  return value !== undefined && value === v6ToBigInt(right);
}

/**
 * An address with its source port removed, when it carried one. Adapted from bothandlerjs.
 *
 * Forwarded headers are not consistent about this. Most proxies write a bare address,
 * but some load balancers write `1.2.3.4:5678`, and the bracketed `[2001:db8::1]:5678` is
 * the form RFC 7239 defines for IPv6. An entry that carries a port is not an address, and
 * the consequence is not that one entry is skipped: every entry in the chain looks the
 * same way, the chain empties, and the whole internet collapses onto the proxy's own
 * address — one actor, scored and blocked for everybody at once.
 *
 * The rule has to be narrow, because a bare IPv6 address is *made of* colons and must
 * never be mistaken for a host and port. Only two shapes are a port: a bracketed host,
 * which is unambiguous, and a single colon whose left side is an IPv4 address. Anything
 * with more colons and no brackets is IPv6 and is returned untouched.
 */
export function stripPort(value: string): string {
  const input = value.trim();
  if (input.startsWith("[")) {
    const close = input.indexOf("]");
    if (close > 0) return input.slice(1, close);
    return input;
  }
  const colon = input.indexOf(":");
  // Exactly one colon: IPv6 always has at least two, so this can only be host:port.
  if (colon === -1 || input.indexOf(":", colon + 1) !== -1) return input;
  const host = input.slice(0, colon);
  return net.isIPv4(host) ? host : input;
}
