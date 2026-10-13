import type { RequestFacts } from "../src/detectors/types.js";
import type { HoneypotHit } from "../src/types.js";

/**
 * Builders shared across the suites, the way bothandlerjs keeps its own in `tests/helpers.ts`.
 *
 * Only what several files were defining identically lives here. A suite whose fixture means
 * something particular to it — a login POST, a request with a stolen credential in it — keeps
 * its own, named for what it is, because a shared default it silently depends on is a test
 * that breaks when somebody else's changes.
 */

/** A GET from a private address with no headers, overridden by `partial`. */
export function facts(partial: Partial<RequestFacts> & Pick<RequestFacts, "path">): RequestFacts {
  return { method: "GET", query: {}, headers: {}, ip: "10.0.0.1", ...partial };
}

/** A recorded decoy probe of `/.env`, overridden by `overrides`. */
export function hit(overrides: Partial<HoneypotHit> = {}): HoneypotHit {
  return {
    id: Math.random().toString(36).slice(2),
    timestamp: new Date().toISOString(),
    ip: "203.0.113.7",
    method: "GET",
    path: "/.env",
    headers: {},
    detections: [{ detector: "decoy-path", summary: "probe", score: 10 }],
    score: 10,
    totalScore: 10,
    respondedWith: "decoy-content",
    ...overrides,
  };
}

/** The port a listening server, or anything exposing `address()` like one, is bound to. */
export function portOf(server: { address(): unknown }): number {
  const address = server.address();
  return typeof address === "object" && address !== null ? (address as { port: number }).port : 0;
}
