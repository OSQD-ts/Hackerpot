import { promises as dnsPromises } from "node:dns";
import { sameAddress } from "../allowlist.js";

/**
 * DNS access for crawler identity verification. Adapted from bothandlerjs.
 *
 * The distinction this module exists to keep is between *disproof* and *no answer*. A
 * reverse lookup that returns `crawl-66-249-66-1.googlebot.com` for a client claiming to
 * be Googlebot confirms the claim; one that returns `some-vps.example.net` disproves it.
 * One that times out, hits SERVFAIL, or finds no resolver proves nothing, and must never
 * look like disproof, or "our resolver was briefly unhappy" becomes "we flagged Googlebot".
 */

/** The subset of DNS this module uses. Inject your own for tests or a custom resolver. */
export interface DnsResolver {
  /** PTR names for an address. Rejects on NXDOMAIN. */
  reverse(ip: string): Promise<string[]>;
  /** A and AAAA records for a name. Rejects on NXDOMAIN. */
  resolveAddresses(hostname: string): Promise<string[]>;
}

export type DnsVerification =
  /** DNS confirmed the claimed identity. */
  | { status: "verified"; hostname: string }
  /** DNS answered, and the answer contradicts the claim. */
  | { status: "contradicted"; cause: "no-ptr" | "wrong-domain" | "no-forward-record" | "address-mismatch"; reason: string; hostname?: string }
  /** No usable answer. Proves nothing either way. */
  | { status: "indeterminate"; reason: string };

class DnsTimeoutError extends Error {
  override readonly name = "DnsTimeoutError";
  /** Not a definitive absence: a lookup that ran out of time said nothing about whether the name exists. */
  readonly code = "ETIMEDOUT";
  constructor() {
    super("DNS lookup timed out");
  }
}

/** DNS error codes that mean "this name definitively does not exist". */
const DEFINITIVE_ABSENCE = new Set(["ENOTFOUND", "ENODATA", "NXDOMAIN"]);

/** True when a DNS rejection is an authoritative "no such record", as opposed to no answer at all. */
export function isDefinitiveAbsence(error: unknown): boolean {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" && DEFINITIVE_ABSENCE.has(code);
}

function errorCode(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" ? code : "unknown";
}

/** Node's resolver, with a per-lookup deadline on top of its own retry behaviour. */
export function nodeDnsResolver(timeoutMs = 1500): DnsResolver {
  const guard = async <T>(work: Promise<T>): Promise<T> => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        work,
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new DnsTimeoutError()), timeoutMs);
          timer.unref();
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  };

  return {
    reverse: (ip) => guard(dnsPromises.reverse(ip)),
    async resolveAddresses(hostname) {
      const [v4, v6] = await Promise.allSettled([guard(dnsPromises.resolve4(hostname)), guard(dnsPromises.resolve6(hostname))]);
      const addresses = [...(v4.status === "fulfilled" ? v4.value : []), ...(v6.status === "fulfilled" ? v6.value : [])];
      if (addresses.length > 0) return addresses;
      // Nothing came back, and why decides a crawler's fate. A timeout swallowed into an
      // empty answer would read as a failed forward confirmation and brand the real
      // crawler an impersonator, so anything short of an authoritative absence is re-raised.
      const rejections = [v4, v6].filter((result) => result.status === "rejected").map((result) => (result as PromiseRejectedResult).reason as unknown);
      const inconclusive = rejections.find((reason) => !isDefinitiveAbsence(reason));
      if (inconclusive !== undefined) throw inconclusive;
      return addresses;
    },
  };
}

/** True when `hostname` is `domain` itself or a subdomain of it, on label boundaries. Never a substring match. */
export function isUnderDomain(hostname: string, domain: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  const suffix = domain.toLowerCase().replace(/^\.|\.$/g, "");
  return host === suffix || host.endsWith(`.${suffix}`);
}

/**
 * Forward-confirmed reverse DNS.
 *
 * 1. PTR the client IP.
 * 2. Require a name under one of `domains`, matched on label boundaries, so
 *    `googlebot.com.evil.net` does not pass.
 * 3. Forward-resolve that name and require the original IP back, which stops anyone who
 *    controls the PTR record for their own address from claiming to be Googlebot.
 */
export async function forwardConfirmedReverseDns(resolver: DnsResolver, ip: string, domains: readonly string[]): Promise<DnsVerification> {
  const noPtr = { status: "contradicted", cause: "no-ptr", reason: "the address has no PTR record, which every operator of a verifiable crawler publishes" } as const;

  let names: string[];
  try {
    names = await resolver.reverse(ip);
  } catch (error) {
    if (isDefinitiveAbsence(error)) return noPtr;
    return { status: "indeterminate", reason: `reverse lookup failed: ${errorCode(error)}` };
  }
  if (names.length === 0) return noPtr;

  const candidate = names.find((name) => domains.some((domain) => isUnderDomain(name, domain)));
  if (candidate === undefined) {
    return { status: "contradicted", cause: "wrong-domain", reason: `PTR record ${names[0]!} is not under ${domains.join(", ")}` };
  }

  let addresses: string[];
  try {
    addresses = await resolver.resolveAddresses(candidate);
  } catch (error) {
    if (isDefinitiveAbsence(error)) {
      return { status: "contradicted", cause: "no-forward-record", reason: `PTR name ${candidate} does not resolve forward`, hostname: candidate };
    }
    return { status: "indeterminate", reason: `forward lookup failed: ${errorCode(error)}` };
  }
  if (addresses.length === 0) {
    return { status: "contradicted", cause: "no-forward-record", reason: `PTR name ${candidate} does not resolve forward`, hostname: candidate };
  }

  // Compared as addresses, not strings: the forward answer may spell an IPv6 address
  // differently from the way the socket reported it.
  if (!addresses.some((address) => sameAddress(address, ip))) {
    return { status: "contradicted", cause: "address-mismatch", reason: `PTR name ${candidate} resolves to ${addresses.slice(0, 3).join(", ")}, not ${ip}`, hostname: candidate };
  }
  return { status: "verified", hostname: candidate };
}

/** A remembered failure, replayed with the code it had, so a cached "no such name" stays an absence. */
class CachedDnsError extends Error {
  override readonly name = "CachedDnsError";
  constructor(readonly code: string) {
    super(`cached DNS failure (${code})`);
  }
}

type CacheEntry = { expiresAt: number } & ({ ok: true; value: string[] } | { ok: false; code: string });

export interface CachingResolverOptions {
  /** How long a successful answer is reused, ms. Default 3600000 (1h). */
  ttlMs?: number;
  /** How long a failure that is not a definitive absence is remembered, ms. Default 60000. */
  errorTtlMs?: number;
  /** Most names and addresses cached. Default 10000. */
  max?: number;
  /** How long an unanswered lookup is shared with later callers before they start their own, ms. Default 30000. */
  inFlightTtlMs?: number;
}

/**
 * Memoises lookups, including lookups already in flight.
 *
 * A crawler's requests arrive in bursts, so without in-flight sharing a hundred
 * simultaneous requests from Googlebot cost a hundred lookups before the first answer
 * lands. A shared lookup is released after `inFlightTtlMs` even if it never settles, so
 * one hung query cannot make a crawler unverifiable for the life of the process.
 */
export function cachingResolver(inner: DnsResolver, options: CachingResolverOptions = {}): DnsResolver {
  const ttlMs = options.ttlMs ?? 3_600_000;
  const errorTtlMs = options.errorTtlMs ?? 60_000;
  const max = options.max ?? 10_000;
  const inFlightTtlMs = options.inFlightTtlMs ?? 30_000;
  const cache = new Map<string, CacheEntry>();
  const inFlight = new Map<string, Promise<string[]>>();

  const store = (key: string, entry: CacheEntry): void => {
    cache.set(key, entry);
    if (cache.size <= max) return;
    const oldest = cache.keys().next();
    if (oldest.done !== true) cache.delete(oldest.value);
  };

  const lookup = (key: string, work: () => Promise<string[]>): Promise<string[]> => {
    const now = Date.now();
    const hit = cache.get(key);
    if (hit !== undefined && hit.expiresAt > now) {
      return hit.ok ? Promise.resolve(hit.value) : Promise.reject(new CachedDnsError(hit.code));
    }
    const pending = inFlight.get(key);
    if (pending !== undefined) return pending;

    const query = work().then(
      (value) => {
        store(key, { ok: true, value, expiresAt: now + ttlMs });
        inFlight.delete(key);
        return value;
      },
      (error: unknown) => {
        // A definitive absence is cached like an answer, so a forged claim does not cost a lookup per request.
        store(key, { ok: false, code: errorCode(error), expiresAt: now + (isDefinitiveAbsence(error) ? ttlMs : errorTtlMs) });
        inFlight.delete(key);
        throw error;
      },
    );
    inFlight.set(key, query);
    const release = setTimeout(() => {
      if (inFlight.get(key) === query) inFlight.delete(key);
    }, inFlightTtlMs);
    release.unref();
    void query.catch(() => undefined).finally(() => clearTimeout(release));
    return query;
  };

  return {
    reverse: (ip) => lookup(`r:${ip}`, () => inner.reverse(ip)),
    resolveAddresses: (hostname) => lookup(`f:${hostname}`, () => inner.resolveAddresses(hostname)),
  };
}
