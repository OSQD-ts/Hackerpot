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
  /** This IP's cumulative suspicion score, including the current request. */
  totalScore: number;
  tracker: IpTracker;
}

/** Everything a response action needs to produce the HTTP response and (for `block`) update state. */
export interface ResponseContext extends PolicyContext {
  res: ServerResponse;
  /** The engine's blocklist — the `block` action writes here so blocking is pluggable. */
  blocklist: Blocklist;
}

export interface ResponseAction {
  id: string;
  description?: string;
  execute(ctx: ResponseContext): Promise<void> | void;
}

/** Chooses which action runs for a request, given everything that fired on it. */
export type ResponsePolicy = (ctx: PolicyContext) => string;
