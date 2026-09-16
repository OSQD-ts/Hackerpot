import type { ServerResponse } from "node:http";
import type { Blocklist } from "../blocklist.js";
import type { Detection } from "../detectors/types.js";
import type { IpTracker } from "../state.js";

/** What the policy sees when choosing a response — detections, score, and the IP's activity window. */
export interface PolicyContext {
  /** The detection that selected this action — the highest-scoring one for the request. */
  detection: Detection;
  /** Every detection that fired on this request. */
  detections: Detection[];
  ip: string;
  path: string;
  /**
   * What this request scored on its own, before the address's history. Optional because a
   * caller may build a context by hand; the engine always sets it, and a rule matching on
   * `minScore` reads the running total when it is absent.
   */
  score?: number;
  /** The request method, for rules that match on it. Optional for the same reason. */
  method?: string;
  /**
   * How strong this request's evidence is, in [0, 1] — see `confidenceOf`. Optional for the
   * same reason as `score`; the engine always sets it.
   */
  confidence?: number;
  /** This IP's cumulative suspicion score, including the current request. */
  totalScore: number;
  tracker: IpTracker;
}

/** Everything a response action needs to produce the HTTP response and (for `block`) update state. */
export interface ResponseContext extends PolicyContext {
  res: ServerResponse;
  /** The engine's blocklist — the `block` action writes here so blocking is pluggable. */
  blocklist: Blocklist;
  /**
   * The engine's error channel, so an action can report a side-effect that failed
   * without failing the response. Optional: a directly-constructed context may omit it.
   */
  onError?: ((error: unknown, context: { source: string }) => void) | undefined;
}

export interface ResponseAction {
  id: string;
  description?: string;
  execute(ctx: ResponseContext): Promise<void> | void;
}

/**
 * What a policy decided, and why.
 *
 * A bare action id records what was served and nothing about the reasoning, so an operator
 * reading an incident cannot tell a deliberate rule from a default. A decision names the rule
 * that chose the response and carries a sentence about it; `rulePolicy` produces them, and
 * the engine records both on the hit.
 */
export interface ResponseDecision {
  /** The response action to run. */
  actionId: string;
  /** Id of the rule that chose it, or `"default"`/`"fallback"`. */
  rule: string;
  /** One sentence, safe to log and to show an operator. */
  reason: string;
}

/**
 * Chooses which action runs for a request, given everything that fired on it.
 *
 * Returning a bare action id is still supported and is what the closure form does; returning
 * a {@link ResponseDecision} adds the rule and the reason to the recorded incident.
 */
export type ResponsePolicy = (ctx: PolicyContext) => string | ResponseDecision;
