import type { ServerResponse } from "node:http";
import type { Blocklist } from "../blocklist.js";
import type { PolicyContext } from "../policy/types.js";

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
