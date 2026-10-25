import type { TrafficAudit } from "./audit.js";
import type { SiteProfile } from "./site/index.js";
import type { Clock } from "./internal/clock.js";
import type { Blocklist } from "./blocklist.js";
import type { ServiceTokenOptions, ServiceTokens } from "./service-tokens.js";
import type { Detection, Detector } from "./detectors/types.js";
import type { IpEnricher, IpEnrichment } from "./enrichment.js";
import type { ActorLabels, LabelledActor } from "./labels.js";
import type { MarkerCookie } from "./marker.js";
import type { ResponseAction } from "./actions/types.js";
import type { ResponsePolicy } from "./policy/types.js";

export interface HoneypotHit {
  id: string;
  timestamp: string;
  ip: string;
  method: string;
  path: string;
  /** The request target as sent, when it differs from the normalised `path` (e.g. `//.env`, `/%2eenv`). */
  rawPath?: string | undefined;
  headers: Record<string, string | string[] | undefined>;
  body?: string | undefined;
  /** Actor fingerprint (header order + UA family) — correlates one actor across rotating IPs. See `computeFingerprint`. */
  fingerprint?: string | undefined;
  /** Source-IP annotation (special-use category, and geo/ASN if a data-backed enricher is configured). */
  enrichment?: IpEnrichment | undefined;
  /** The name this source is known by, when one is configured. See `ActorLabels` — a label never exempts. */
  actor?: LabelledActor | undefined;
  /** The verified marker this client presented. See `MarkerCookie` — a marker correlates, it never accuses. */
  marker?: string | undefined;
  /** How strong this request's evidence was, in [0, 1]. Only proof reaches 1. See `confidenceOf`. */
  confidence?: number | undefined;
  /** Every detector that fired on this request. */
  detections: Detection[];
  /** Findings from shadowed detectors, which added nothing to the score. See `HoneypotConfig.shadowDetectors`. */
  shadowDetections?: Detection[] | undefined;
  /** Points added to this IP by this request. */
  score: number;
  /** This IP's cumulative score after this request. */
  totalScore: number;
  /** Id of the response action that ran. */
  respondedWith: string;
  /** Id of the policy rule that chose it. `"default"` when the shipped ladder decided. */
  rule?: string | undefined;
  /** One sentence saying why, when the policy gave one. */
  reason?: string | undefined;
  /** `"block"` when the policy chose a block that a proof requirement refused. See `EvaluateOptions.blockRequiresProof`. */
  downgradedFrom?: string | undefined;
}

/**
 * A bounded, filtered read of the hit log.
 *
 * Every management read used to go through `list()`, which returns the whole retained
 * corpus — so `/incidents?ip=X&limit=10` pulled every record the backend held (for the
 * file store, a multi-megabyte read and parse; for Elasticsearch, a thousand documents
 * over HTTP) to answer with ten. A store that can push these down implements `query()`;
 * one that cannot omits it, and the caller falls back to `list()` with identical
 * semantics.
 */
export interface HitQuery {
  /** Only hits from this source IP. */
  ip?: string;
  /** Only hits where this detector fired. */
  detector?: string;
  /** Only hits carrying this actor fingerprint. */
  fingerprint?: string;
  /** Only hits at or after this epoch-ms timestamp. */
  sinceMs?: number;
  /** At most this many hits — the **most recent** ones. */
  limit?: number;
}

export interface HitStore {
  record(hit: HoneypotHit): void | Promise<void>;
  /**
   * The retained hits, **oldest first**, across every backend.
   *
   * The order is part of the contract: a caller reading a store directly should not
   * have to know which backend is behind it. `ElasticStore` still *queries* newest-first
   * — with `size`, that is what selects which documents come back — and reverses before
   * returning; the others are naturally in append order.
   *
   * The result is **bounded** by each backend's retention cap, so this is the recent
   * window, not necessarily the full history.
   */
  list(): HoneypotHit[] | Promise<HoneypotHit[]>;
  scoreFor(ip: string): number | Promise<number>;
  /**
   * Optional bounded/filtered read — same ordering contract as `list()`.
   *
   * Implement it when the backend can do better than materializing everything;
   * omit it and callers fall back to `list()` + the shared filter, which produces
   * the same answer. Aggregate endpoints (`/stats`, `/metrics`, `/ioc`) still read
   * `list()`: they summarize the whole corpus, so there is nothing to push down.
   */
  query?(query: HitQuery): HoneypotHit[] | Promise<HoneypotHit[]>;
}

/**
 * How the client address is recovered from behind a proxy. Adapted from bothandlerjs.
 *
 * This is the highest-consequence configuration in the library and the easiest to get
 * wrong, so it has no convenient default: `trustProxy` is off, and with it off the
 * socket address is used and `X-Forwarded-For` is ignored entirely.
 *
 * The reason is that `X-Forwarded-For` is a *client-supplied header*. Trust it without
 * knowing which proxies actually sit in front of you, and anyone can write a fake hop
 * and choose the address the allowlist exempts, the blocklist blocks and the firewall
 * enforcer acts on — spoof an allowlisted source to skip detection entirely, or get an
 * arbitrary victim firewalled. The failure is silent. Configure `trustedProxies` if you
 * can: it is the only variant that does not depend on getting a number right.
 */
export interface ProxyConfig {
  /** Read the forwarded header at all. Default false. */
  trustProxy?: boolean;
  /**
   * Addresses and CIDRs of the proxies you operate. The header is walked from the right,
   * discarding addresses inside these ranges, and the first address outside them is the
   * client. Robust against an extra hop appearing, and the recommended setting.
   *
   * The connecting peer counts as the first hop and is checked the same way. A request
   * that arrives from outside these ranges did not come through your proxies, so its
   * forwarded header is not evidence of anything and the socket address is used instead —
   * which is what makes this safe on a server reachable both through the load balancer
   * and directly. An entry that is not an address or CIDR throws at construction.
   */
  trustedProxies?: readonly string[];
  /**
   * How many proxies sit in front of this process, when you cannot enumerate them. The
   * Nth address from the right is taken. Default 1. Ignored when `trustedProxies` is set.
   *
   * If the chain is shorter than this, the socket address is used instead: a short chain
   * means the request did not come through the expected topology, and every entry in it
   * is then client-controlled. Prefer `trustedProxies`, which does not depend on a count.
   */
  hops?: number;
  /** Header carrying the chain. Default `"x-forwarded-for"`. */
  header?: string;
}

export interface HoneypotConfig {
  /** Detectors to run, in order. Defaults to the full built-in set. */
  detectors?: Detector[];
  /** Extra detectors appended to the defaults (ignored if `detectors` is set). */
  extraDetectors?: Detector[];
  /** Response actions available to run, keyed by their id. Defaults to the full built-in set. */
  responseActions?: ResponseAction[];
  /** Extra response actions appended to the defaults (ignored if `responseActions` is set). */
  extraResponseActions?: ResponseAction[];
  /** Chooses which action id runs for a request. Defaults to the built-in escalation policy. */
  policy?: ResponsePolicy;
  /** Where hits are recorded. Defaults to an in-memory store. */
  store?: HitStore;
  /** Called every time one or more detectors fire — wire up your own logging/alerting. */
  onHit?: (hit: HoneypotHit) => void | Promise<void>;
  /**
   * Called if any internal step throws/rejects — a detector's `inspect()`, or the
   * store/`onHit` when recording a hit. The engine isolates each so a crafted input or
   * a flaky store backend can't crash evaluation, bypass other detectors, or take down a
   * host app in middleware mode. `context.source` is the detector id, `"store"`, or
   * `"onHit"`. Wire this to your logs to see a misbehaving detector or a failing store.
   */
  onError?: (error: unknown, context: { source: string }) => void;
  /** Sliding-window length for the stateful detectors, in ms. Default 60000. */
  activityWindowMs?: number;
  /**
   * How long an actor fingerprint remembers the IPs it was seen attacking from, in ms
   * (bounds `repeat-actor` correlation and the registry's memory). Default 3600000 (1h).
   */
  fingerprintWindowMs?: number;
  /**
   * Annotates each recorded hit's source IP with an `enrichment`. Defaults to the
   * dependency-free `defaultIpEnricher()` (special-use classification only). Pass your
   * own `IpEnricher` — e.g. one backed by a GeoLite2 database — to add ASN/geo. Set to
   * `null` to disable enrichment entirely.
   */
  enricher?: IpEnricher | null;
  /**
   * Shorthand for `proxy: { trustProxy }`. Default false. Kept for configurations written before
   * `proxy` existed; when both are given, `proxy` wins. See `ProxyConfig` before turning it on.
   */
  trustProxy?: boolean;
  /** How the client address is recovered from behind a proxy. See `ProxyConfig`. */
  proxy?: ProxyConfig;
  /**
   * Paths the honeypot skips entirely: no detection, no block check, no record, no count.
   * For health checks, your own polling endpoints and static assets — anything a real
   * client requests so often that watching it only costs time. Adapted from bothandlerjs,
   * with the same matching: a string ending in `/` is a prefix (`"/assets/"`), any other
   * string is the exact path (`"/healthz"`), a RegExp is tested as written. Matched against
   * the normalised path (decoded, dot-segments resolved), so `/assets/../.env` is not
   * under `/assets/`. A string that does not start with `/` can never match a path, so it
   * throws at construction rather than exempting nothing.
   */
  ignorePaths?: readonly (string | RegExp)[];
  /**
   * IPs and CIDR ranges (IPv4/IPv6) that are exempt from all detection — known-good
   * sources like uptime monitors, health checkers, and office/VPC ranges. They never
   * score, never get blocked, and leave no incident. E.g. ["127.0.0.1", "10.0.0.0/8", "2001:db8::/32"].
   */
  allowlist?: string[];
  /**
   * Where "this IP is blocked" state lives. Defaults to an in-memory, per-instance
   * blocklist. Provide a `RedisBlocklist` to make blocks survive restarts and be
   * shared across replicas (opt-in — the default keeps everything self-contained).
   */
  blocklist?: Blocklist;
  /**
   * Longest a detector's asynchronous `inspect()` may take, in ms. Past it that detector
   * is skipped for the request and the timeout is reported through `onError`. Every
   * built-in detector is synchronous and unaffected; this bounds custom `extraDetectors`
   * that call out to something slow. Default 2000; 0 disables the limit.
   */
  detectorTimeoutMs?: number;
  /**
   * Ids of detectors that run in shadow: they inspect every request as usual, but what they
   * find is reported and never acted on. A shadowed finding adds no score, chooses no
   * response, triggers no body read, and records no hit of its own; it is attached to a
   * hit that live detectors caused (`shadowDetections`) and passed to `onShadow`. Use it
   * to trial a new or retuned detector against real traffic before it can block anyone.
   */
  shadowDetectors?: string[];
  /** Called for every request a shadowed detector fired on. */
  onShadow?: (event: ShadowEvent) => void;
  /**
   * Shared secrets your own services present in a header (default `x-hackerpot-token`). A
   * request carrying a valid one is exempt like an allowlisted address: no detection, no
   * block check, no record. For monitors whose address you cannot pin. See `ServiceTokens`.
   */
  serviceTokens?: ServiceTokenOptions | ServiceTokens;
  /** Counts every evaluated request so it can watch for anomalies. See `TrafficAudit`. */
  audit?: TrafficAudit;
  /**
   * What this site serves, learned from `reportOutcome()` — see `SiteProfile`. One is
   * created by default and stays empty (so nothing reads it) until outcomes are reported.
   * Pass your own to share it, or `null` to disable it entirely.
   */
  site?: SiteProfile | null;
  /** @deprecated Renamed `site`, bothandlerjs's option name. Read when `site` is not given. */
  baseline?: SiteProfile | null;
  /**
   * Names for sources you already know — your uptime checker, a partner's integration, a
   * vendor's scanner. A label is shown wherever the address would be and may mute the actor
   * in live feeds; it never exempts it from detection, scoring or a response. Exemption is
   * `allowlist` and `serviceTokens`.
   */
  labels?: ActorLabels;
  /**
   * Hands a signed marker to whoever the honeypot answers, so one client can be correlated
   * across changing addresses even when its fingerprint shifts. Middleware mode only, since
   * it needs a client that keeps cookies. It never exempts and is never proof.
   */
  markers?: MarkerCookie;
  /**
   * Where the engine reads the time: activity windows, the fingerprint registry, block expiry
   * and hit timestamps. Default the system clock; pass a `ManualClock` to make time-dependent
   * behaviour testable without sleeping.
   */
  clock?: Clock;
}

/** A request a shadowed detector fired on. See `HoneypotConfig.shadowDetectors`. */
export interface ShadowEvent {
  timestamp: string;
  ip: string;
  method: string;
  path: string;
  /** What the shadowed detectors found. */
  detections: Detection[];
  /** Whether live detectors fired too, so the request was recorded as a hit anyway. */
  alsoHit: boolean;
}
