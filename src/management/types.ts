import type { AlertFormat } from "./alerts.js";
import type { HoneypotHit } from "../types.js";

/** An incident is a recorded honeypot hit — the detections that fired plus the response that was served. */
export type Incident = HoneypotHit;

export interface WebhookConfig {
  /** Destination URL that each incident is POSTed to as JSON. */
  url: string;
  /**
   * How the request body is rendered. `hackerpot` (the default) posts the native
   * incident JSON to your own receiver. `slack` and `discord` render a human-readable
   * alert those platforms accept directly on an incoming-webhook URL — with the
   * attacker-controlled text escaped, mentions neutered and link previews disabled.
   * See `src/management/alerts.ts` for why each of those matters.
   */
  format?: AlertFormat;
  /** Optional HMAC-SHA256 signing secret. When set, each request carries an `X-Hackerpot-Signature` header. */
  secret?: string;
  /** Extra static headers to send (e.g. an auth token the receiver expects). */
  headers?: Record<string, string>;
  /** Delivery attempts before giving up. Default 3. */
  maxRetries?: number;
  /** Only deliver incidents whose total score is at least this — the "danger" gate for alert webhooks. Default 0 (all). */
  minScore?: number;
  /**
   * Suppress repeat alerts for the same source IP within this many seconds — one noisy
   * attacker becomes one alert, not hundreds. 0/unset disables de-duplication.
   */
  dedupeWindowSeconds?: number;
  /**
   * Rate-limit this webhook: at most `maxPerWindow` deliveries per
   * `throttleWindowSeconds`. Beyond that, incidents are dropped (not queued) until the
   * window rolls, so a flood can't hammer a chat channel or page an operator hundreds of
   * times. Both must be set to take effect.
   */
  throttleWindowSeconds?: number;
  maxPerWindow?: number;
  /**
   * Ceiling on deliveries in flight at once for this webhook. Beyond it, incidents are
   * dropped (not queued) and reported. Default 32. Unlike the throttle above this is
   * always on: it bounds *our* resource use rather than the receiver's alert volume.
   */
  maxInFlight?: number;
  /** Per-attempt deadline in ms. Default 10000. */
  timeoutMs?: number;
  /**
   * Omit the attacker-controlled request `body` from the delivered payload. The score,
   * detectors, IP, and path still go through.
   *
   * Defaults to FALSE for the `hackerpot` format (your own receiver asked for the whole
   * incident) and TRUE for `slack`/`discord`, where the body is raw attacker payload
   * being rendered to everyone in a channel. Set it explicitly to override either way.
   */
  omitBody?: boolean;
}

export interface ManagementConfig {
  /** Turn the management API on. Defaults to true when at least one API key is set. */
  enabled?: boolean;
  /**
   * Network interface / address the management API binds to. Defaults to
   * "127.0.0.1" — loopback only. Set to an internal address (e.g. a private
   * VPC/overlay IP) to expose it to your own services, but NEVER to a
   * public interface: this API exposes captured attacker data and must not
   * be reachable by the attackers themselves.
   */
  host?: string;
  /** Port the management API listens on. Default 9500. */
  port?: number;
  /** Accepted API keys. Requests must present one via `Authorization: Bearer` or `X-API-Key`. */
  apiKeys?: string[];
  /** Enable the WebSocket live feed at `/stream`. Default true. */
  websocket?: boolean;
  /** Webhook destinations pushed to on every incident. */
  webhooks?: WebhookConfig[];
}
