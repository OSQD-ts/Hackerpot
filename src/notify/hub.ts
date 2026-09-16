import { systemClock, type Clock } from "../internal/clock.js";
import { TtlLru } from "../internal/lru.js";
import { IncidentBroker } from "../management/broker.js";
import type { Incident } from "../management/types.js";
import type { TrafficAnomaly } from "../audit.js";
import type { NotifyEvent, NotifyEventType, NotifyFilter, NotifySink } from "./types.js";

/**
 * One place incidents leave the process from.
 *
 * They used to leave from two. Webhooks subscribed to the management server's broker, and
 * syslog was called by hand on the hit path — once for HTTP hits, once for protocol hits —
 * because the broker belongs to the management server, which is optional, so with the REST
 * API switched off there was no hub to attach anything to. That meant every new delivery path
 * was another call site somebody had to remember, and **webhook alerting required enabling the
 * management API**, which means exposing a REST service over captured attacker data to get a
 * message into a chat channel.
 *
 * The hub is the fan-out on its own, with no listener and no API attached to it. Sinks
 * register; the service publishes each incident once; the management server, when it is
 * enabled, shares this broker rather than owning a second one.
 *
 * It also carries the two properties that decide whether notification is an asset or a
 * liability under load, which bothandlerjs learned first and this had none of:
 *
 * **It never blocks a request.** Delivery happens on its own; a wedged webhook slows nothing.
 *
 * **It has a ceiling.** Attack traffic arrives in volumes ordinary alerting was not built for.
 * Repeats of the same address and response collapse into one event per window, a global cap
 * catches distributed traffic where every event is genuinely distinct, and what was suppressed
 * is reported when the window rolls — so a quiet channel is never mistaken for quiet traffic.
 * Until now those bounds lived inside `WebhookDispatcher`, which meant syslog and anybody's
 * own sink had none of them.
 *
 * What the hub deliberately does **not** do is redact centrally. Each sink redacts on the way
 * out, from the one shared implementation (`redactIncident`), because the choice is per
 * destination: a webhook may opt out for a receiver meant to see the raw capture, and the
 * authenticated operator feed is not the same audience as a chat channel.
 */

export interface NotificationHubOptions {
  /**
   * An existing broker to fan out through. Omitted, the hub makes its own — which is the
   * point: delivery must not depend on the management server existing.
   */
  broker?: IncidentBroker;
  /** Which events reach the sinks. Everything, unless narrowed. */
  filter?: NotifyFilter;
  /**
   * Suppress repeats of the same address and response inside this window, in ms. Default
   * 60000. One scanner produces thousands of near-identical incidents a minute, and without
   * this the first thing a honeypot breaks is its own alerting.
   */
  dedupeWindowMs?: number;
  /**
   * Ceiling on events delivered per window across every address. Default 200. The backstop for
   * what dedupe cannot help with — a distributed scan from ten thousand addresses, where every
   * event really is distinct.
   */
  maxPerWindow?: number;
  /** Where a sink's failure is reported. A failing sink never affects a request or its neighbours. */
  onError?: (sink: string, error: unknown) => void;
  clock?: Clock;
}

/** Every type, which is the default: in a honeypot, an incident is the thing worth saying. */
const ALL_TYPES: readonly NotifyEventType[] = ["hit", "downgrade", "anomaly", "error"];

/** Addresses remembered for deduplication. Bounded: the keys are attacker-chosen. */
const MAX_DEDUPE_KEYS = 10_000;

export class NotificationHub {
  /** The fan-out itself, so anything that already knows how to attach to a broker still can. */
  readonly broker: IncidentBroker;
  private readonly sinks: NotifySink[] = [];
  private readonly types: Set<NotifyEventType>;
  private readonly minScore: number;
  private readonly certainOnly: boolean;
  private readonly dedupe: TtlLru<true>;
  private readonly dedupeWindowMs: number;
  private readonly maxPerWindow: number;
  private readonly clock: Clock;
  private readonly onError: ((sink: string, error: unknown) => void) | undefined;
  private unsubscribe: (() => void) | undefined;

  private windowStart: number;
  private windowCount = 0;
  private suppressed = 0;

  constructor(options: NotificationHubOptions = {}) {
    this.onError = options.onError;
    this.clock = options.clock ?? systemClock;
    this.broker = options.broker ?? new IncidentBroker((error) => this.onError?.("broker", error));
    this.types = new Set(options.filter?.types ?? ALL_TYPES);
    this.minScore = options.filter?.minScore ?? 0;
    this.certainOnly = options.filter?.certainOnly ?? false;
    this.dedupeWindowMs = Math.max(0, options.dedupeWindowMs ?? 60_000);
    this.maxPerWindow = Math.max(1, options.maxPerWindow ?? 200);
    this.dedupe = new TtlLru<true>(MAX_DEDUPE_KEYS, Math.max(1, this.dedupeWindowMs), this.clock);
    this.windowStart = this.clock.now();
  }

  get size(): number {
    return this.sinks.length;
  }

  /** Names of the attached sinks, for a startup log. */
  names(): string[] {
    return this.sinks.map((sink) => sink.id);
  }

  /** Registers a sink and returns the way to remove it. */
  add(sink: NotifySink): () => void {
    this.sinks.push(sink);
    // Subscribed once, on the first sink: an idle hub holds no subscription, and a hundred
    // sinks do not mean a hundred trips through the broker.
    this.listen();
    return () => {
      const at = this.sinks.indexOf(sink);
      if (at !== -1) this.sinks.splice(at, 1);
    };
  }

  /**
   * Sends one incident to every sink.
   *
   * On the hit path, so it is synchronous and never throws: a sink's slowness or failure is
   * the sink's problem, not the response's.
   */
  publish(incident: Incident): void {
    this.broker.publish(incident);
  }

  /** Sends a traffic anomaly. Never deduplicated — the audit has a cooldown of its own. */
  announce(anomaly: TrafficAnomaly): void {
    this.emit({ type: "anomaly", at: new Date(this.clock.now()).toISOString(), anomaly });
  }

  /** Reports an operational failure. Never deduplicated: two failures are two problems. */
  reportError(source: string, message: string): void {
    this.emit({ type: "error", at: new Date(this.clock.now()).toISOString(), error: { source, message } });
  }

  /** The one way an event reaches a sink. Filtered and bounded first. */
  emit(event: NotifyEvent): void {
    if (this.sinks.length === 0) return;
    if (!this.shouldDeliver(event)) return;
    this.dispatch(event);
  }

  /** Closes every sink. Failures are reported, never thrown: shutdown must finish. */
  async close(): Promise<void> {
    this.unsubscribe?.();
    this.unsubscribe = undefined;
    for (const sink of [...this.sinks]) {
      try {
        await sink.close?.();
      } catch (error) {
        this.onError?.(sink.id, error);
      }
    }
    this.sinks.length = 0;
  }

  private listen(): void {
    if (this.unsubscribe !== undefined) return;
    this.unsubscribe = this.broker.subscribe((incident) => {
      // A refused block is worth saying on its own: it is the guard reporting that the policy
      // asked for more than the evidence supports, which is a tuning signal rather than a hit.
      const type: NotifyEventType = incident.downgradedFrom === undefined ? "hit" : "downgrade";
      this.emit({ type, at: incident.timestamp, incident });
    });
  }

  private dispatch(event: NotifyEvent): void {
    for (const sink of this.sinks) {
      try {
        const result = sink.notify(event);
        // A sink may be sync or async. Either way its failure is reported and contained, and an
        // async rejection never escapes as an unhandled one.
        if (result !== undefined) void Promise.resolve(result).catch((error: unknown) => this.onError?.(sink.id, error));
      } catch (error) {
        this.onError?.(sink.id, error);
      }
    }
  }

  private shouldDeliver(event: NotifyEvent): boolean {
    if (!this.types.has(event.type)) return false;
    const incident = event.incident;
    if ((event.type === "hit" || event.type === "downgrade") && incident !== undefined) {
      const proven = incident.detections.some((detection) => detection.certain === true);
      if (this.certainOnly && !proven) return false;
      if (!proven && incident.totalScore < this.minScore) return false;
    }

    const now = this.clock.now();
    if (this.dedupeWindowMs > 0 && now - this.windowStart >= this.dedupeWindowMs) {
      const dropped = this.suppressed;
      this.windowStart = now;
      this.windowCount = 0;
      this.suppressed = 0;
      // Report what the window hid, so an operator can tell "nothing happened" from "far too
      // much happened".
      if (dropped > 0) this.summarise(dropped);
    }

    // `error` and `anomaly` bypass deduplication. Two failures with the same shape are two
    // problems, and losing the second is how an outage becomes invisible; the audit's own
    // cooldown already decided an anomaly was worth saying.
    if (this.dedupeWindowMs > 0 && incident !== undefined && event.type !== "error" && event.type !== "anomaly") {
      const key = `${event.type}:${incident.ip}:${incident.respondedWith}:${incident.rule ?? ""}`;
      if (this.dedupe.get(key) !== undefined) {
        this.suppressed += 1;
        return false;
      }
      this.dedupe.set(key, true);
    }

    if (this.windowCount >= this.maxPerWindow) {
      this.suppressed += 1;
      return false;
    }
    this.windowCount += 1;
    return true;
  }

  private summarise(dropped: number): void {
    this.dispatch({
      type: "error",
      at: new Date(this.clock.now()).toISOString(),
      error: {
        source: "notification-hub",
        message: `${dropped} notification(s) were suppressed in the last ${this.dedupeWindowMs}ms by deduplication or the per-window ceiling. Traffic is exceeding what these sinks are configured to report.`,
      },
    });
  }
}
