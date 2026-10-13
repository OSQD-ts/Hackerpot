import { IpAllowlist } from "./allowlist.js";
import type { IpEnrichment } from "./enrichment.js";
import { systemClock, type Clock } from "./internal/clock.js";
import type { DnsResolver } from "./internal/dns.js";
import { TtlLru } from "./internal/lru.js";
import { statelessPattern } from "./internal/pattern.js";

/**
 * Names for sources you already know.
 *
 * An incident log is a list of addresses, and an operator's first question about any of them
 * is "who is that?" — usually answered by pasting it into a lookup tool. Some of the answers
 * are known in advance: your own uptime checker, a partner's integration, a security
 * vendor's scanner, the office. Labelling them once turns a wall of addresses into a feed
 * where the unfamiliar ones stand out, which is the only thing that makes a busy feed
 * readable.
 *
 * **A label names; it never exempts.** A labelled actor is still detected, still scored,
 * still answered exactly as it would be otherwise. Exemption is the allowlist's job (or a
 * service token's), and the two are deliberately separate: naming a scanner so you can see
 * what it does is the opposite of trusting it. The only thing a label can change is whether
 * an actor is shown in a live feed by default — `hideFromFeed` mutes the noise of a known,
 * constant source without hiding a single thing from the record it is written to.
 *
 * Adapted from bothandlerjs.
 */

/** What identifies an actor. Every field present must match. */
export interface ActorLabelMatch {
  /** Addresses or CIDR ranges. */
  ip?: readonly string[];
  /** Autonomous system numbers, when a data-backed enricher supplies them. */
  asn?: readonly number[];
  /** Owning organisation, as the enricher reports it. A string matches case-insensitively as a substring. */
  org?: string | RegExp;
  /** The User-Agent. A string matches case-insensitively as a substring. */
  userAgent?: string | RegExp;
  /**
   * The source's reverse-DNS name. Requires a `resolver`, and matches only once the lookup
   * has completed — see the note on resolution below.
   */
  hostname?: string | RegExp;
}

export interface ActorLabel {
  /** What to call this actor, shown wherever the address would be. */
  name: string;
  match: ActorLabelMatch;
  /** A sentence for whoever reads the incident later ("our uptime checker, every 30s"). */
  note?: string;
  /**
   * Keep this actor out of live feeds by default. It is still detected, scored, recorded and
   * counted — this hides constant, known noise from the pane an operator watches, nothing else.
   */
  hideFromFeed?: boolean;
}

/** A label that matched, as recorded on the incident. */
export interface LabelledActor {
  name: string;
  note?: string;
  /** Which part of the request identified it. */
  matchedOn: "ip" | "asn" | "org" | "user-agent" | "hostname";
  /** True when this actor is muted in live feeds. Never affects detection or recording. */
  hidden?: boolean;
}

export interface ActorLabelsOptions {
  labels: readonly ActorLabel[];
  /**
   * Resolver for `hostname` matching. Reverse DNS on the request path would put a network
   * round trip in front of every response, so it is never awaited there — see `labelFor`.
   */
  resolver?: DnsResolver;
  /** How long a resolved name is reused. Default 1h. */
  cacheTtlMs?: number;
  /** Addresses whose names are cached. Default 5000. */
  maxCached?: number;
  clock?: Clock;
  /** Where a failed lookup is reported. Failures are otherwise silent by design. */
  onError?: (error: unknown) => void;
}

/** What a label is matched against. Everything but the address is optional. */
export interface LabelSubject {
  ip: string;
  enrichment?: IpEnrichment | undefined;
  headers?: Record<string, string | string[] | undefined> | undefined;
}

interface CompiledLabel {
  label: ActorLabel;
  ip: IpAllowlist | undefined;
  asn: Set<number> | undefined;
  org: ((value: string) => boolean) | undefined;
  userAgent: ((value: string) => boolean) | undefined;
  hostname: ((value: string) => boolean) | undefined;
  needsHostname: boolean;
}

/** A pattern or a case-insensitive substring — the two ways an operator writes "this one". */
function textMatcher(value: string | RegExp | undefined): ((subject: string) => boolean) | undefined {
  if (value === undefined) return undefined;
  const pattern = statelessPattern(value);
  if (typeof pattern !== "string") return (subject: string) => pattern.test(subject);
  const needle = pattern.toLowerCase();
  return (subject: string) => subject.toLowerCase().includes(needle);
}

function headerValue(headers: LabelSubject["headers"], name: string): string | undefined {
  const value = headers?.[name];
  if (value === undefined) return undefined;
  return Array.isArray(value) ? value.join(", ") : value;
}

export class ActorLabels {
  private readonly compiled: CompiledLabel[];
  private readonly resolver: DnsResolver | undefined;
  private readonly onError: ((error: unknown) => void) | undefined;
  /** Resolved PTR names per address. An empty array means "looked up, nothing usable". */
  private readonly hostnames: TtlLru<string[]>;
  /** Lookups in flight, so a burst from one address triggers one query rather than hundreds. */
  private readonly pending = new Set<string>();

  constructor(options: ActorLabelsOptions) {
    this.resolver = options.resolver;
    this.onError = options.onError;
    this.hostnames = new TtlLru<string[]>(options.maxCached ?? 5_000, options.cacheTtlMs ?? 3_600_000, options.clock ?? systemClock);
    this.compiled = options.labels.map((label) => {
      if (label.name.trim() === "") throw new Error("an actor label needs a name: it is what replaces the address in the feed");
      const match = label.match;
      return {
        label,
        ip: match.ip !== undefined && match.ip.length > 0 ? new IpAllowlist([...match.ip]) : undefined,
        asn: match.asn !== undefined && match.asn.length > 0 ? new Set(match.asn) : undefined,
        org: textMatcher(match.org),
        userAgent: textMatcher(match.userAgent),
        hostname: textMatcher(match.hostname),
        needsHostname: match.hostname !== undefined,
      };
    });
  }

  get size(): number {
    return this.compiled.length;
  }

  /** Every configured name, for a startup log or a dashboard legend. */
  names(): string[] {
    return this.compiled.map((entry) => entry.label.name);
  }

  /**
   * The label for this source, or undefined.
   *
   * Synchronous and cheap: it runs on every recorded incident. When a label matches on
   * `hostname`, the reverse lookup is **started, not awaited** — the current request is
   * labelled only if the answer is already cached, and the next one from that address gets
   * the name. A honeypot that waits on DNS before answering has handed the attacker a way to
   * slow it down by probing from addresses that resolve slowly.
   */
  labelFor(subject: LabelSubject): LabelledActor | undefined {
    const userAgent = headerValue(subject.headers, "user-agent");
    for (const entry of this.compiled) {
      if (entry.needsHostname) this.prime(subject.ip);
      const matched = this.matchOf(entry, subject, userAgent);
      if (matched === undefined) continue;
      const { label } = entry;
      return {
        name: label.name,
        ...(label.note !== undefined ? { note: label.note } : {}),
        matchedOn: matched,
        ...(label.hideFromFeed === true ? { hidden: true } : {}),
      };
    }
    return undefined;
  }

  /** Which field identified the actor, or undefined when this label does not apply. */
  private matchOf(entry: CompiledLabel, subject: LabelSubject, userAgent: string | undefined): LabelledActor["matchedOn"] | undefined {
    // Every configured field has to hold; the one reported is the most specific that did.
    let matched: LabelledActor["matchedOn"] | undefined;
    if (entry.ip !== undefined) {
      if (!entry.ip.allows(subject.ip)) return undefined;
      matched = "ip";
    }
    if (entry.asn !== undefined) {
      const asn = subject.enrichment?.asn;
      if (asn === undefined || !entry.asn.has(asn)) return undefined;
      matched ??= "asn";
    }
    if (entry.org !== undefined) {
      const org = subject.enrichment?.org;
      if (org === undefined || !entry.org(org)) return undefined;
      matched ??= "org";
    }
    if (entry.userAgent !== undefined) {
      if (userAgent === undefined || !entry.userAgent(userAgent)) return undefined;
      matched ??= "user-agent";
    }
    if (entry.hostname !== undefined) {
      const names = this.hostnames.get(subject.ip);
      // Not resolved yet. The lookup is already running; this request is simply not labelled.
      if (names === undefined || !names.some((name) => entry.hostname!(name))) return undefined;
      matched ??= "hostname";
    }
    return matched;
  }

  /** Reverse-resolves an address in the background, at most once per cache lifetime. */
  private prime(ip: string): void {
    if (this.resolver === undefined || this.pending.has(ip) || this.hostnames.peek(ip) !== undefined) return;
    this.pending.add(ip);
    // Deliberately floating: nothing awaits this, and its failure is not the request's problem.
    void this.resolver
      .reverse(ip)
      .then((names) => this.hostnames.set(ip, names))
      .catch((error: unknown) => {
        // Cached as "nothing usable" so a source that never resolves is not looked up on
        // every single request it makes.
        this.hostnames.set(ip, []);
        this.onError?.(error);
      })
      .finally(() => this.pending.delete(ip));
  }
}
