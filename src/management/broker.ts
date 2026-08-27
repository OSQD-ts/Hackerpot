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

  constructor() {
    // Many subscribers (WS clients + webhooks) are expected.
    this.emitter.setMaxListeners(0);
  }

  publish(incident: Incident): void {
    this.emitter.emit("incident", incident);
  }

  subscribe(listener: (incident: Incident) => void): () => void {
    this.emitter.on("incident", listener);
    return () => this.emitter.off("incident", listener);
  }
}
