import { EventEmitter } from "node:events";
import type { Incident } from "./types.js";

/**
 * In-process pub/sub hub for incidents. The engine's `onHit` feeds
 * `publish()`; the management transports (WebSocket, webhooks) subscribe. This
 * decouples "an incident happened" from "how it's delivered", so transports can
 * be added or removed without touching the honeypot.
 */
export class IncidentBroker {
  private readonly emitter = new EventEmitter();
  private readonly onError: ((error: unknown) => void) | undefined;

  constructor(onError?: (error: unknown) => void) {
    // Many subscribers (WS clients + webhooks) are expected.
    this.emitter.setMaxListeners(0);
    this.onError = onError;
  }

  publish(incident: Incident): void {
    this.emitter.emit("incident", incident);
  }

  /**
   * Registers a listener, isolated from its neighbours.
   *
   * `emit()` calls listeners synchronously in registration order, so a listener that
   * throws aborts the loop: every subscriber registered *after* it never sees the
   * incident, and the throw propagates back out of `publish()`. That is not a
   * hypothetical — the WebSocket transport's listener calls `JSON.stringify` and
   * `ws.send`, and either can throw (a `BigInt` in a custom detector's `metadata`, a
   * socket that changed state between the readyState check and the send). One
   * misbehaving WS client would then silently starve the other WS clients and any
   * syslog sink attached to the same broker — a quiet loss of alerting, which for a
   * security tool is the failure that matters most and shows up least.
   *
   * So each listener is wrapped: it can only break itself. This is the rail the engine
   * already applies to a throwing detector and the port-scan sentinel to a throwing
   * `onEvent`, including the `Promise.resolve(...).catch(...)` for a listener that
   * hands back a rejected promise instead of throwing outright.
   */
  subscribe(listener: (incident: Incident) => void): () => void {
    const isolated = (incident: Incident): void => {
      try {
        Promise.resolve(listener(incident)).catch((err: unknown) => this.onError?.(err));
      } catch (err) {
        this.onError?.(err);
      }
    };
    this.emitter.on("incident", isolated);
    return () => this.emitter.off("incident", isolated);
  }
}
