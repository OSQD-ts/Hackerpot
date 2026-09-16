import type { TrafficAnomaly } from "../audit.js";
import type { Incident } from "../management/types.js";

/**
 * What a sink is told about, and what it is told.
 *
 * The same shape bothandlerjs uses, so the two libraries describe notification the same way:
 * an event with a type, a sink with one method, and a filter that says which events reach it.
 * A deployment running both should not have to learn two vocabularies for the same job.
 */

/** Why a notification was raised. */
export type NotifyEventType =
  /** An incident: something fired and the honeypot answered it. */
  | "hit"
  /** The proof guard replaced a block with something recoverable. */
  | "downgrade"
  /**
   * The audit noticed the *shape* of traffic change — a spike in flagged requests, a probe
   * campaign, detectors failing. The one type that is not about a single request, which is why
   * {@link NotifyEvent.incident} is optional.
   */
  | "anomaly"
  /** A store, a sink or a detector failed. Operational, not about traffic. */
  | "error";

export interface NotifyEvent {
  type: NotifyEventType;
  /** ISO-8601. */
  at: string;
  /** The request this is about. Absent on `anomaly`, and on an `error` with no request behind it. */
  incident?: Incident | undefined;
  /** Present on `anomaly`. */
  anomaly?: TrafficAnomaly | undefined;
  /** Present on `error`. */
  error?: { source: string; message: string } | undefined;
}

export interface NotifySink {
  /** Short name, used when a failure is reported. */
  id: string;
  /**
   * Delivers an event.
   *
   * Called off the request path — nothing awaits a sink — so taking time here is fine.
   * Throwing is fine too: failures are caught, reported through the hub's `onError`, and never
   * reach the client or the other sinks.
   */
  notify(event: NotifyEvent): void | Promise<void>;
  /** Releases whatever the sink holds open. */
  close?(): void | Promise<void>;
}

/**
 * Which events reach a sink.
 *
 * Note the default, which differs from bothandlerjs on purpose. There, `detection` is excluded
 * by default because most requests are not bots and the interesting event is the *action*.
 * Here every incident already is a detection — the honeypot only records what fired — so
 * excluding them by default would silently stop syslog forwarding the thing it exists to
 * forward. Everything is delivered unless this says otherwise.
 */
export interface NotifyFilter {
  /** Event types to deliver. Default: all of them. */
  types?: readonly NotifyEventType[];
  /** Minimum cumulative score for a `hit`. Default 0. */
  minScore?: number;
  /** Only deliver hits carrying proof (`certain`). Default false. */
  certainOnly?: boolean;
}
