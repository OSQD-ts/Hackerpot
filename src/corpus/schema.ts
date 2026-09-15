/**
 * The traffic corpus schema.
 *
 * This is a body of *realistic HTTP traffic* — real User-Agent strings, real header
 * sets in the order real clients send them, real attack payloads — paired with what the
 * honeypot's detectors ought to conclude about each. It exists to answer the one
 * question no unit test can:
 *
 *   > If I mount this configuration in front of a real application, who gets caught who
 *   > should not have?
 *
 * The corpus is deliberately separate from the configuration it tests. `runCorpus` takes
 * a factory that builds *your* `HoneypotEngine`, so the scorecard describes the policy
 * you actually run, not the defaults. The idea, the provenance discipline, and the
 * controlled-DNS apparatus are adapted from bothandlerjs's traffic corpus.
 *
 * ## Two things this schema is strict about
 *
 * **Header order is a fingerprint, so the profiles reproduce it.** `python-requests`
 * sending `Accept-Encoding` before `Accept`, Chromium leading with `Host, Connection,
 * sec-ch-ua…`, Firefox closing with the Fetch Metadata block — these are signals that
 * only exist if the corpus gets the order right, which is why headers are an ordered
 * tuple list and never an object literal whose key order is too easy to disturb.
 *
 * **Provenance is required.** A fixture nobody can trace is a fixture nobody can update
 * when the world moves, and this is a corpus about a world that moves.
 */

/**
 * Who is behind the request — and, more to the point, what it costs to be wrong.
 *
 * The corpus's central assertion is expressed in terms of this axis: **no case marked
 * `human` may have anything fire on it.** For `benign-bot` and `infrastructure` the bar
 * is lower but still real — nothing `certain`, nothing blocked, nothing the case names
 * in `neverDetectors` — because those are traffic an operator wants served, and a
 * honeypot that stops them is a honeypot that costs its owner search ranking, share
 * previews, health checks and webhooks.
 */
export type Audience =
  /** A person. Anything firing here is a customer the honeypot would have caught in a decoy. */
  | "human"
  /** Automation almost every site wants: search crawlers, link unfurlers, uptime monitors, feeds. */
  | "benign-bot"
  /** Automation most sites would rather not serve, but which is not an attack: aggressive SEO, bulk scraping. */
  | "unwanted-bot"
  /** Something in the middle of the path: a health probe, a CDN origin pull, a webhook, a load balancer. */
  | "infrastructure"
  /** Scanners, exploitation payloads, forged identities, credential attacks. Catching these is the point. */
  | "hostile";

/**
 * One HTTP request, as a client would actually put it on the wire.
 */
export interface CaseRequest {
  method?: string;
  /** Path plus query string, exactly as written on the request line. Default `"/"`. */
  path?: string;
  /**
   * Headers **in the order the client sends them**.
   *
   * A tuple list, not an object: order is itself a fingerprint, and an object literal's
   * key order is too easy to disturb by accident. A name may repeat (a duplicated `Host`
   * is a real attack shape), and the runner preserves that in `rawHeaders`.
   */
  headers: ReadonlyArray<readonly [name: string, value: string]>;
  /** Request body, for the POST/PUT payloads the body-inspecting detectors read. */
  body?: string;
  /**
   * Which of the case's source addresses sends this request. Default 0. The runner turns
   * `(caseIndex, from)` into a stable, distinct address (see `addressFor`), so the same
   * `from` is one client and a different `from` is another — which is what the
   * distributed-attacker and rotating-address cases are built on.
   */
  from?: number;
  /**
   * A fixed source address for this request, overriding `addressFor`. Only the crawler
   * cases need it: forward-confirmed reverse DNS and published-range checks are about a
   * *specific* address, so those cases pin one and key their `dns` map on it.
   */
  ip?: string;
  /** Milliseconds after the case's start time. Drives the rate and cadence detectors deterministically. */
  atMs?: number;
  /**
   * What the application answered, reported back the way an adapter would.
   *
   * The engine decides before a response exists, so this arrives afterwards. Only the
   * path-enumeration case needs it: in middleware mode a path the app served normally is
   * not enumeration, so `path-bruteforce` counts a path only once the app answered `404`.
   */
  status?: number;
  /** HTTP version from the request line (`"1.1"`, `"2"`). Default `"1.1"`. */
  httpVersion?: string;
  /**
   * The source could not supply the full header set — facts rebuilt from an access log
   * carry a User-Agent and a Referer at most. Detectors that reason from an *absent*
   * header skip such a request. See `RequestFacts.partialHeaders`.
   */
  partialHeaders?: boolean;
}

/** What the detectors should conclude. Every field is optional; absent means "don't care". */
export interface CaseExpectation {
  /**
   * Detector ids that must each fire on at least one request in the case. The core
   * assertion for a hostile case: the attack it models is actually caught.
   */
  detectors?: readonly string[];
  /** Whether the conclusion must rest on proof (`Detection.certain`) somewhere in the case. */
  certain?: boolean;
  /**
   * Detectors that must not fire on any request. The per-case false-positive guard, and
   * for a `benign-bot`/`infrastructure` case one of the three things that makes a false
   * positive.
   */
  neverDetectors?: readonly string[];
}

/**
 * Answers the controlled resolver should give while a case runs.
 *
 * Forward-confirmed reverse DNS is the only mechanism that can confirm a `verified`
 * crawler or prove an impersonator, so a corpus that cannot control DNS cannot test the
 * two most consequential verdicts `crawler-verification` reaches. A name absent from the
 * map resolves to NXDOMAIN, which is a *definitive* negative — the runner never presents
 * a timeout unless `unavailable` is set, because "no answer" and "the wrong answer" must
 * lead to different verdicts.
 */
export interface CaseDns {
  /** Address → PTR names. */
  reverse?: Readonly<Record<string, readonly string[]>>;
  /** PTR name → addresses, for the forward-confirmation step. */
  forward?: Readonly<Record<string, readonly string[]>>;
  /** Make every lookup time out, to exercise the indeterminate path (a DNS blip is not disproof). */
  unavailable?: boolean;
}

export interface TrafficCase {
  /** Stable, unique, kebab-case. Appears in every report; treat it as an identifier. */
  id: string;
  title: string;
  audience: Audience;
  /** Finer grouping within an audience, e.g. `"desktop-browser"`, `"scanner"`, `"exploit"`. */
  category: string;
  /**
   * Where this shape came from: a specification, a vendor's documentation, a CVE, a
   * tool's source or default User-Agent, an observed log line. Required and enforced.
   */
  provenance: string;
  /** Anything a reader needs in order to judge whether the expectation is right. */
  notes?: string;
  /** A single request, or an ordered sequence from one or more actors. */
  requests: readonly CaseRequest[];
  expect?: CaseExpectation;
  tags?: readonly string[];
  /**
   * Capabilities this case depends on, as free-text names matched against what the engine
   * under test provides. A case that needs `honeytoken`, `trap`, `crawler-verification`
   * or `published-ranges` and finds the handler is not configured for it is **skipped and
   * reported**, never failed — because "we did not check" and "it passed" must not look
   * the same.
   */
  requires?: readonly string[];
  /** Controlled DNS answers, for the crawler-verification cases. */
  dns?: CaseDns;
}

/** Capability names a case may declare in `requires`, and the runner may be told it provides. */
export type Capability = "honeytoken" | "trap" | "crawler-verification" | "published-ranges";

/**
 * The seeded honeytoken value the corpus plants and replays. No legitimate client is ever
 * given it, so a request carrying it is proof of a breach. The engine under test must be
 * configured to watch for exactly this value (`honeytokenDetector({ tokens: [...] })`).
 */
export const CORPUS_HONEYTOKEN = "AKIA_HACKERPOT_HONEYTOKEN_CORPUS";

/**
 * The trap path the corpus links only from hidden markup. It is one of `trapDetector`'s
 * default paths, so even an unconfigured trap catches it — but a case that touches it
 * still declares `requires: ["trap"]`, so a handler running without the trap detector
 * skips it rather than silently passing.
 */
export const CORPUS_TRAP_PATH = "/internal/export.csv";

/** The hidden form field the corpus fills. Must be listed in `trapDetector({ formFields })`. */
export const CORPUS_TRAP_FIELD = "company_url";

/**
 * Declares a case involving a person. Anything firing on one of these is caught by the
 * runner as a false positive — the guarantee cannot be forgotten, because the audience
 * rule is applied by the harness regardless of what the case's own `expect` says.
 */
export function human(input: Omit<TrafficCase, "audience">): TrafficCase {
  return { ...input, audience: "human" };
}

/** Declares a case involving automation an operator wants served. */
export function benign(input: Omit<TrafficCase, "audience">): TrafficCase {
  return { ...input, audience: "benign-bot" };
}

/** Declares a case involving infrastructure in the request path. */
export function infrastructure(input: Omit<TrafficCase, "audience">): TrafficCase {
  return { ...input, audience: "infrastructure" };
}

/** Declares a hostile case: a scan, an exploit payload, a forgery, a credential attack. */
export function hostile(input: Omit<TrafficCase, "audience">): TrafficCase {
  return { ...input, audience: "hostile" };
}

/** Declares an unwanted-but-not-hostile automation case. */
export function unwanted(input: Omit<TrafficCase, "audience">): TrafficCase {
  return { ...input, audience: "unwanted-bot" };
}

/**
 * Repeats a request `count` times at a fixed interval, optionally varying the path. For
 * the rate, cadence and enumeration shapes.
 */
export function repeat(template: CaseRequest, count: number, everyMs: number, pathAt?: (index: number) => string): CaseRequest[] {
  return Array.from({ length: count }, (_, index) => ({
    ...template,
    ...(pathAt ? { path: pathAt(index) } : {}),
    atMs: index * everyMs,
  }));
}
