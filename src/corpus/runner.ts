import type { HoneypotEngine } from "../core.js";
import type { DnsResolver } from "../internal/dns.js";
import type { Detection, RequestFacts } from "../detectors/types.js";
import { mayHaveBody, parseQuery, pathOf } from "../http-request.js";
import type { Audience, CaseDns, CaseRequest, TrafficCase } from "./schema.js";

/**
 * The harness.
 *
 * It takes a factory rather than an engine because the corpus tests **your** detector
 * configuration, not the defaults. Hand it whatever you run in production and it reports
 * what that configuration does to every shape of traffic in here — including, and this is
 * the part worth reading, which of them are people the honeypot would have caught.
 *
 * Two things it controls that a real deployment does not:
 *
 * - **DNS.** No lookup leaves the process. Each case declares the answers it wants, so
 *   the difference between "the operator's DNS disproves this claim" (an impersonator)
 *   and "our resolver was briefly unhappy" (Googlebot during a blip) can actually be
 *   tested. Those must reach different verdicts, and only a controlled resolver can prove
 *   it. The runner builds one per case from `case.dns` and hands it to `create`.
 * - **Time.** Each request is evaluated with an explicit `now` of `start + atMs`, so the
 *   sliding-window detectors (`rate-spike`, `path-bruteforce`, `credential-bruteforce`,
 *   `repeat-actor`) are exercised deterministically. A corpus that slept would take hours
 *   and still be flaky. Because each case gets a fresh engine — and so a fresh store,
 *   activity registry and fingerprint registry — no case can inherit another's history.
 */

export interface RunnerOptions {
  /** Builds the engine under test. The runner supplies the controlled resolver. */
  create: (dependencies: { resolver: DnsResolver }) => HoneypotEngine;
  /** The cases to run. Default: the whole corpus. */
  cases?: readonly TrafficCase[];
  /**
   * Capability names the engine under test provides, matched against a case's `requires`.
   * A case naming something absent here is skipped and reported, never failed.
   */
  provides?: readonly string[];
  /**
   * Evaluate the way `createMiddleware` does. Default true.
   *
   * On: two-pass body handling, `blockRequiresProof` so an unproven block becomes a
   * tarpit and nothing is blocklisted, activity marked `passed`, and a path confirmed
   * toward `path-bruteforce` only when the app answered `404` or the honeypot answered it
   * — exactly `src/middleware.ts`. Off: standalone evaluation, every path counted and a
   * block allowed on score alone. The two must catch the same attacks; the difference is
   * only in what an unproven guess is allowed to do.
   */
  middleware?: boolean;
  /** Epoch ms the first request of every case is stamped with. */
  startedAt?: number;
}

export interface RequestResult {
  detections: Detection[];
  actionId: string;
  /** Set to `"block"` when a block was refused for want of proof. */
  downgradedFrom?: string;
}

export interface CaseResult {
  case: TrafficCase;
  /** Every request in the case, in order. */
  requests: RequestResult[];
  /** Every detector id that fired anywhere in the case. */
  fired: string[];
  /** Human-readable expectation violations. Empty means the case met its expectations. */
  failures: string[];
  /** Set when the case denies the corpus's audience guarantee: something fired that must not have. */
  falsePositive: boolean;
  /** A human case that fires as a documented, accepted cost rather than a bug. */
  knownCost: boolean;
  /** Why the case did not run, when it did not. Never counted as a pass. */
  skipped?: string;
  durationMs: number;
}

export interface AudienceTally {
  total: number;
  passed: number;
  failed: number;
  /** How many cases in this audience received each response action. */
  actions: Record<string, number>;
}

export interface Scorecard {
  results: CaseResult[];
  total: number;
  passed: number;
  failed: number;
  skipped: CaseResult[];
  /**
   * The section to read first: traffic that should have been served but was not.
   *
   * For a human case, anything firing at all. For a benign-bot or infrastructure case, a
   * `certain` detection, a block, or a detector the case named in `neverDetectors`. These
   * are the honeypot's own false alarms, and there must be none.
   */
  falsePositives: CaseResult[];
  /**
   * Human traffic the design knowingly cannot serve cleanly — a WordPress author at
   * `/wp-login.php`, which is a decoy path. Reported rather than failed, and honest about
   * the cost rather than pretending it away.
   */
  knownCosts: CaseResult[];
  byAudience: Record<Audience, AudienceTally>;
  byCategory: Record<string, { total: number; failed: number }>;
  /** How many cases each detector produced evidence on. */
  detectorCoverage: Record<string, number>;
  /**
   * Detectors installed in the engine that no case exercised. A gap in the corpus, not
   * the library: an untested detector is one whose next regression nobody notices.
   */
  unexercisedDetectors: string[];
  durationMs: number;
}

const DEFAULT_START = Date.UTC(2026, 8, 15, 9, 0, 0);

/**
 * A stable, distinct source address for a `(caseIndex, from)` pair.
 *
 * Distinct per case so no case inherits another's per-IP history, distinct per `from` so
 * a case can model several clients, and stable across runs so a failure reproduces.
 * Drawn from 198.18.0.0/15, which RFC 2544 reserves for benchmarking — it collides with
 * nothing real and its meaning is exactly this.
 */
export function addressFor(caseIndex: number, from = 0): string {
  const block = 18 + Math.floor(caseIndex / 256);
  return `198.${block}.${caseIndex % 256}.${(from % 254) + 1}`;
}

/** A controlled resolver answering only from the case's own map; absent names are NXDOMAIN. */
export function caseResolver(dns: CaseDns | undefined): DnsResolver {
  const notFound = (): never => {
    throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
  };
  const timedOut = (): never => {
    throw Object.assign(new Error("timed out"), { code: "ETIMEDOUT" });
  };
  return {
    async reverse(ip: string) {
      if (dns === undefined) return notFound();
      if (dns.unavailable === true) return timedOut();
      const names = dns.reverse?.[ip];
      return names === undefined ? notFound() : [...names];
    },
    async resolveAddresses(hostname: string) {
      if (dns === undefined) return notFound();
      if (dns.unavailable === true) return timedOut();
      const addresses = dns.forward?.[hostname];
      return addresses === undefined ? notFound() : [...addresses];
    },
  };
}

/** Turns a case request into the `RequestFacts` the engine evaluates. Exposed for the wire simulator. */
export function factsFor(testCase: TrafficCase, request: CaseRequest, caseIndex: number): RequestFacts {
  const target = request.path ?? "/";
  const headers: Record<string, string | string[]> = {};
  const order: string[] = [];
  for (const [name, value] of request.headers) {
    const key = name.toLowerCase();
    const existing = headers[key];
    // A repeated header becomes an array, so `header-integrity`'s duplicate check and
    // `host-header-injection`'s duplicate-Host check both see what was actually sent.
    headers[key] = existing === undefined ? value : Array.isArray(existing) ? [...existing, value] : [existing, value];
    order.push(name, value);
  }
  void testCase;
  return {
    method: request.method ?? "GET",
    path: pathOf(target),
    query: parseQuery(target),
    headers,
    ip: request.ip ?? addressFor(caseIndex, request.from ?? 0),
    rawHeaders: order,
    httpVersion: request.httpVersion ?? "1.1",
    ...(request.partialHeaders === true ? { partialHeaders: true } : {}),
    ...(request.body !== undefined ? { body: request.body } : {}),
  };
}

/**
 * Evaluates one request the way the chosen front end would.
 *
 * In middleware mode this reproduces `src/middleware.ts`: a first, body-free pass that
 * defers recording when a body phase is possible, a committing second pass with the body
 * only if the first fired, `blockRequiresProof`, and the confirm-path bookkeeping that
 * makes `path-bruteforce` count only paths the app missed. In standalone mode it is a
 * single pass that counts every path and may block on score alone.
 */
async function evaluateRequest(engine: HoneypotEngine, facts: RequestFacts, request: CaseRequest, now: Date, middleware: boolean): Promise<RequestResult> {
  if (!middleware) {
    const result = await engine.evaluate(facts, { now });
    return { detections: result.detections, actionId: result.actionId, ...(result.downgradedFrom !== undefined ? { downgradedFrom: result.downgradedFrom } : {}) };
  }

  const guard = { blockRequiresProof: true, unprovenBlockFallback: "tarpit", now } as const;
  const bodyPhase = engine.needsBodyPhase && mayHaveBody(facts.method) && facts.body !== undefined;
  // The first pass sees no body, exactly as the middleware evaluates on headers alone.
  const { body: _firstPassBodyOmitted, ...withoutBody } = facts;
  const base: RequestFacts = bodyPhase ? withoutBody : facts;

  let result = await engine.evaluate(base, bodyPhase ? { recordHit: false, activityStatus: "passed", ...guard } : { activityStatus: "passed", ...guard });
  if (bodyPhase && result.detections.length > 0) {
    result = await engine.evaluate(facts, { trackActivity: false, ...guard });
  }

  // The app served the request (nothing fired and it was not a miss) → the path stays
  // `passed` and does not count as enumeration. Anything else — a detection, or a 404 —
  // promotes it, mirroring the middleware's res.finish bookkeeping.
  if (result.detections.length > 0 || request.status === 404) result.tracker.confirmPath(result.path);

  return { detections: result.detections, actionId: result.actionId, ...(result.downgradedFrom !== undefined ? { downgradedFrom: result.downgradedFrom } : {}) };
}

async function runCase(engine: HoneypotEngine, item: TrafficCase, caseIndex: number, startedAt: number, middleware: boolean): Promise<CaseResult> {
  const began = performance.now();
  const requests: RequestResult[] = [];
  const firedSet = new Set<string>();
  let anyCertain = false;
  let anyBlock = false;

  for (const request of item.requests) {
    const facts = factsFor(item, request, caseIndex);
    const now = new Date(startedAt + (request.atMs ?? 0));
    const result = await evaluateRequest(engine, facts, request, now, middleware);
    requests.push(result);
    for (const detection of result.detections) {
      firedSet.add(detection.detectorId);
      if (detection.certain === true) anyCertain = true;
    }
    if (result.actionId === "block" || result.downgradedFrom === "block") anyBlock = true;
  }

  const fired = [...firedSet];
  const expect = item.expect ?? {};
  const failures: string[] = [];

  for (const detector of expect.detectors ?? []) {
    if (!firedSet.has(detector)) failures.push(`expected detector "${detector}" to fire; it did not (fired: ${fired.join(", ") || "nothing"})`);
  }
  for (const detector of expect.neverDetectors ?? []) {
    if (firedSet.has(detector)) failures.push(`detector "${detector}" fired but the case forbids it`);
  }
  if (expect.certain !== undefined && anyCertain !== expect.certain) {
    failures.push(`certain was ${anyCertain}, expected ${expect.certain}`);
  }

  const isKnownCost = item.tags?.includes("known-cost") === true;
  let falsePositive = false;
  let knownCost = false;

  if (item.audience === "human") {
    if (fired.length > 0) {
      if (isKnownCost) {
        knownCost = true;
      } else {
        falsePositive = true;
        failures.push(`FALSE POSITIVE: a person had ${fired.join(", ")} fire (${anyCertain ? "proven" : "on suspicion"})`);
      }
    }
  } else if (item.audience === "benign-bot" || item.audience === "infrastructure") {
    const forbidden = new Set(expect.neverDetectors ?? []);
    const trippedForbidden = fired.filter((id) => forbidden.has(id));
    if (anyCertain || anyBlock || trippedForbidden.length > 0) {
      falsePositive = true;
      const why = [anyCertain ? "a certain detection" : "", anyBlock ? "a block" : "", trippedForbidden.length > 0 ? `forbidden ${trippedForbidden.join(", ")}` : ""].filter(Boolean).join("; ");
      failures.push(`FALSE POSITIVE: wanted traffic was penalised — ${why} (fired: ${fired.join(", ") || "nothing"})`);
    }
  }

  return { case: item, requests, fired, failures, falsePositive, knownCost, durationMs: performance.now() - began };
}

const AUDIENCES: readonly Audience[] = ["human", "benign-bot", "unwanted-bot", "infrastructure", "hostile"];

export async function runCorpus(options: RunnerOptions): Promise<Scorecard> {
  const cases = options.cases ?? (await import("./index.js")).CORPUS;
  assertCorpusIntegrity(cases);

  const middleware = options.middleware ?? true;
  const startedAt = options.startedAt ?? DEFAULT_START;
  const provides = new Set(options.provides ?? []);

  const began = performance.now();
  const results: CaseResult[] = [];
  let installedIds: string[] = [];

  for (const [caseIndex, item] of cases.entries()) {
    const missing = (item.requires ?? []).filter((capability) => !provides.has(capability));
    if (missing.length > 0) {
      results.push({ case: item, requests: [], fired: [], failures: [], falsePositive: false, knownCost: false, skipped: `needs capabilities the engine does not provide: ${missing.join(", ")}`, durationMs: 0 });
      continue;
    }
    // Fresh engine per case: a fresh store, activity registry and fingerprint registry, so
    // no case can influence another. The resolver is the case's own controlled DNS.
    const engine = options.create({ resolver: caseResolver(item.dns) });
    if (installedIds.length === 0) installedIds = engine.detectors.map((detector) => detector.id);
    results.push(await runCase(engine, item, caseIndex, startedAt, middleware));
  }

  const byAudience = Object.fromEntries(AUDIENCES.map((audience) => [audience, { total: 0, passed: 0, failed: 0, actions: {} as Record<string, number> }])) as Record<Audience, AudienceTally>;
  const byCategory: Record<string, { total: number; failed: number }> = {};
  const detectorCoverage: Record<string, number> = {};
  let passed = 0;

  for (const result of results) {
    if (result.skipped !== undefined) continue;
    const tally = byAudience[result.case.audience];
    tally.total++;
    const action = result.requests[result.requests.length - 1]?.actionId || "allow";
    tally.actions[action] = (tally.actions[action] ?? 0) + 1;

    const category = (byCategory[result.case.category] ??= { total: 0, failed: 0 });
    category.total++;

    const ok = result.failures.length === 0 && !result.falsePositive;
    if (ok) {
      passed++;
      tally.passed++;
    } else {
      tally.failed++;
      category.failed++;
    }

    for (const detector of result.fired) detectorCoverage[detector] = (detectorCoverage[detector] ?? 0) + 1;
  }

  const skipped = results.filter((result) => result.skipped !== undefined);
  const total = results.length - skipped.length;

  return {
    results,
    total,
    passed,
    failed: total - passed,
    skipped,
    falsePositives: results.filter((result) => result.falsePositive),
    knownCosts: results.filter((result) => result.knownCost),
    byAudience,
    byCategory,
    detectorCoverage,
    unexercisedDetectors: installedIds.filter((id) => detectorCoverage[id] === undefined),
    durationMs: performance.now() - began,
  };
}

/**
 * Fails fast on a corpus that would produce misleading reports: a duplicate or
 * malformed id, an untraceable case, an empty or ill-formed header tuple.
 */
export function assertCorpusIntegrity(cases: readonly TrafficCase[]): void {
  const seen = new Set<string>();
  const problems: string[] = [];

  for (const item of cases) {
    if (seen.has(item.id)) problems.push(`duplicate id "${item.id}"`);
    seen.add(item.id);
    if (!/^[a-z0-9][a-z0-9-]*$/.test(item.id)) problems.push(`id "${item.id}" is not kebab-case`);
    if (item.provenance.trim().length < 10) problems.push(`case "${item.id}" has no meaningful provenance`);
    if (item.requests.length === 0) problems.push(`case "${item.id}" has no requests`);
    for (const request of item.requests) {
      for (const tuple of request.headers) {
        if (!Array.isArray(tuple) || tuple.length !== 2 || typeof tuple[0] !== "string" || tuple[0].length === 0 || typeof tuple[1] !== "string") {
          problems.push(`case "${item.id}" has a malformed header tuple: ${JSON.stringify(tuple)}`);
        }
      }
    }
  }

  if (problems.length > 0) throw new Error(`Corpus integrity problems:\n  - ${problems.join("\n  - ")}`);
}
