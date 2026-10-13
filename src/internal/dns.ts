// Kept identical in hackerpot and bothandlerjs. Change both, or neither.

import { systemClock, type Clock } from "./clock.js";
import { sameAddress } from "./ip.js";
import { TtlLru } from "./lru.js";

/**
 * DNS access for crawler identity verification.
 *
 * The distinction this module exists to keep is between *disproof* and *no answer*, and it is
 * the load-bearing detail of the whole no-false-positive design.
 *
 * A reverse lookup that returns `crawl-66-249-66-1.googlebot.com` for a client claiming to be
 * Googlebot **confirms** the claim. One that returns `some-vps.example.net` **disproves** it.
 * One that times out, hits SERVFAIL, or finds no resolver at all proves nothing — and must
 * never be allowed to look like disproof, because "our resolver was briefly unhappy" would
 * otherwise become "we flagged Googlebot".
 */

/** The subset of DNS this module uses. Inject your own for tests or a custom resolver. */
export interface DnsResolver {
  /** PTR names for an address. Rejects on NXDOMAIN. */
  reverse(ip: string): Promise<string[]>;
  /** A and AAAA records for a name. Rejects on NXDOMAIN. */
  resolveAddresses(hostname: string): Promise<string[]>;
}

export type VerificationOutcome =
  /** DNS confirmed the claimed identity. Deterministic. */
  | { status: "verified"; hostname: string }
  /**
   * DNS answered, and the answer contradicts the claim. Deterministic.
   *
   * `cause` is what callers branch on, never `reason`: an option to stop treating a missing
   * PTR as forgery was once implemented by searching `reason` for "no PTR record", so
   * rewording a human-readable sentence silently turned an operator's opt-out into a no-op.
   * `hostname` is the PTR name the contradiction is about, when there was one.
   */
  | { status: "contradicted"; cause: "no-ptr" | "wrong-domain" | "no-forward-record" | "address-mismatch"; reason: string; hostname?: string | undefined }
  /** No usable answer. Proves nothing; produces no evidence in either direction. */
  | { status: "indeterminate"; reason: string };

export class DnsTimeoutError extends Error {
  override readonly name = "DnsTimeoutError";
  /**
   * Carried so a timeout reads as a timeout everywhere a DNS error's code is inspected — the
   * cache's replay, and the reason an operator sees when a crawler could not be verified.
   * Deliberately not a definitive absence: a lookup that ran out of time has said nothing
   * about whether the name exists.
   */
  readonly code = "ETIMEDOUT";
  constructor() {
    super("DNS lookup timed out");
  }
}

/** DNS error codes that mean "this name definitively does not exist". */
const DEFINITIVE_ABSENCE = new Set(["ENOTFOUND", "ENODATA", "NXDOMAIN"]);

/**
 * Classifies a DNS rejection. `true` means the negative answer is authoritative and may be
 * treated as a contradiction; `false` means there was simply no answer.
 */
export function isDefinitiveAbsence(error: unknown): boolean {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" && DEFINITIVE_ABSENCE.has(code);
}

function errorCode(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" ? code : "unknown";
}

/**
 * Node's resolver, with a per-lookup deadline on top of its own retry behaviour, which can
 * outlive a single lookup's usefulness. `node:dns` is imported on first use, so a library that
 * contains this still loads on a runtime that has no DNS module.
 */
export function nodeDnsResolver(timeoutMs = 1500): DnsResolver {
  let promised: Promise<typeof import("node:dns/promises")> | undefined;
  const load = (): Promise<typeof import("node:dns/promises")> => (promised ??= import("node:dns/promises"));

  const guard = async <T>(work: Promise<T>): Promise<T> => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        work,
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new DnsTimeoutError()), timeoutMs);
          (timer as { unref?: () => void }).unref?.();
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  };

  return {
    async reverse(ip) {
      const dns = await load();
      return guard(dns.reverse(ip));
    },
    async resolveAddresses(hostname) {
      const dns = await load();
      const [v4, v6] = await Promise.allSettled([guard(dns.resolve4(hostname)), guard(dns.resolve6(hostname))]);
      const addresses = [...(v4.status === "fulfilled" ? v4.value : []), ...(v6.status === "fulfilled" ? v6.value : [])];
      if (addresses.length > 0) return addresses;

      // Nothing came back, and *why* decides a crawler's fate. Swallowing both rejections into
      // an empty array makes a resolver timeout indistinguishable from a name with no address
      // records, and an empty forward answer reads as a failed forward confirmation — so a
      // thirty-second DNS blip would prove Googlebot an impersonator. A rejection that cannot
      // be interpreted is re-raised, to degrade to `indeterminate`; only an authoritative
      // "no such record" comes back as an empty answer.
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
 * 2. Require a name under one of `domains` — a suffix match on label boundaries, so
 *    `googlebot.com.evil.net` does not pass.
 * 3. Forward-resolve that name and require the original IP back, which stops anyone who
 *    controls the PTR record for their own address from claiming to be Googlebot.
 */
export async function forwardConfirmedReverseDns(resolver: DnsResolver, ip: string, domains: readonly string[]): Promise<VerificationOutcome> {
  const noPtr = { status: "contradicted", cause: "no-ptr", reason: "address has no PTR record, which every operator of a verifiable crawler publishes" } as const;

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

  // An authoritative empty answer: the PTR name exists but publishes no address, so it cannot
  // forward-confirm. Stated apart from a mismatch because "resolves to nothing" and "resolves
  // to somewhere else" are different accusations, and the reason ends up in an operator's logs.
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

/**
 * A remembered failure, replayed with the code the original carried.
 *
 * The code is the whole point. Caching failures as an undifferentiated sentinel erased the one
 * bit that matters — whether the resolver said "no such name" or said nothing — so a forged
 * crawler was proven an impersonator on its first request and downgraded to `indeterminate`
 * for every request after it, for as long as the entry lived.
 */
class CachedDnsError extends Error {
  override readonly name = "CachedDnsError";
  constructor(readonly code: string) {
    super(`cached DNS failure (${code})`);
  }
}

type CacheEntry = { expiresAt: number } & ({ ok: true; value: string[] } | { ok: false; code: string });

export interface CachingResolverOptions {
  /** Where "now" comes from. Default the system clock. */
  clock?: Clock;
  /** How long a successful answer is reused, ms. Default 3600000 (1h). */
  ttlMs?: number;
  /**
   * How long a failure that is not a definitive absence is remembered, ms. Default 60000.
   *
   * Much shorter than the success lifetime on purpose: caching a failure for an hour would turn
   * a one-minute resolver blip into an hour of unverifiable crawlers, and retrying costs one lookup.
   */
  errorTtlMs?: number;
  /** Most names and addresses cached. Default 10000. */
  max?: number;
  /**
   * How long an unanswered lookup is shared with later callers before they start their own, ms.
   * Default 30000. Not a timeout on the lookup — nothing can cancel one — but a bound on how long
   * a query that has not answered keeps being handed to everybody who asks.
   */
  inFlightTtlMs?: number;
}

/**
 * Memoises lookups, including lookups already in flight.
 *
 * Verification would otherwise resolve DNS twice for every request from a crawler, thousands of
 * lookups an hour for an answer that changes approximately never. And a crawler's requests
 * arrive in bursts, so without in-flight sharing a hundred simultaneous requests cost a hundred
 * lookups before the first answer lands.
 *
 * A shared lookup is released after `inFlightTtlMs` even if it never settles. Sharing a promise
 * means sharing its fate, and one hung query would otherwise make a crawler unverifiable for the
 * life of the process — which, wherever an unverifiable claim is refused, means refusing a real
 * crawler for ever. A custom resolver is an extension point, so that is not a hypothetical about
 * Node's own timeouts. If the released query does eventually answer, the answer is still cached.
 */
export function cachingResolver(inner: DnsResolver, options: CachingResolverOptions = {}): DnsResolver {
  const ttlMs = options.ttlMs ?? 3_600_000;
  const errorTtlMs = options.errorTtlMs ?? 60_000;
  const max = options.max ?? 10_000;
  const inFlightTtlMs = options.inFlightTtlMs ?? 30_000;
  const clock = options.clock ?? systemClock;
  // The cache owns the ceiling and the eviction; each entry still carries its own expiry,
  // because an answer and a failure are remembered for different lengths of time.
  const cache = new TtlLru<CacheEntry>(max, Math.max(ttlMs, errorTtlMs), clock);
  const inFlight = new Map<string, Promise<string[]>>();

  const lookup = (key: string, work: () => Promise<string[]>): Promise<string[]> => {
    const now = clock.now();
    const hit = cache.get(key);
    if (hit !== undefined && hit.expiresAt > now) {
      return hit.ok ? Promise.resolve(hit.value) : Promise.reject(new CachedDnsError(hit.code));
    }
    const pending = inFlight.get(key);
    if (pending !== undefined) return pending;

    const query = work().then(
      (value) => {
        cache.set(key, { ok: true, value, expiresAt: now + ttlMs });
        inFlight.delete(key);
        return value;
      },
      (error: unknown) => {
        // A definitive absence is cached like an answer, so a forged claim does not cost a
        // lookup per request; the code is kept so the replay is still an absence.
        cache.set(key, { ok: false, code: errorCode(error), expiresAt: now + (isDefinitiveAbsence(error) ? ttlMs : errorTtlMs) });
        inFlight.delete(key);
        throw error;
      },
    );
    inFlight.set(key, query);
    // `unref` where the runtime has it: a pending DNS query must never be what keeps a process alive.
    const release = setTimeout(() => {
      if (inFlight.get(key) === query) inFlight.delete(key);
    }, inFlightTtlMs);
    (release as { unref?: () => void }).unref?.();
    void query.catch(() => undefined).finally(() => clearTimeout(release));
    return query;
  };

  return {
    reverse: (ip) => lookup(`r:${ip}`, () => inner.reverse(ip)),
    resolveAddresses: (hostname) => lookup(`f:${hostname}`, () => inner.resolveAddresses(hostname)),
  };
}
