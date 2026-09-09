import { createHmac } from "node:crypto";
import { renderAlert } from "./alerts.js";
import type { IncidentBroker } from "./broker.js";
import type { Incident, WebhookConfig } from "./types.js";

const BACKOFF_BASE_MS = 500;

/**
 * Per-attempt deadline. `fetch` has no timeout of its own worth relying on (undici's
 * header timeout is minutes), so a receiver that accepts the connection and then goes
 * quiet pinned a delivery — times `maxRetries` — for as long as it liked.
 */
const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * Ceiling on deliveries in flight at once, per webhook.
 *
 * Deliveries are attacker-driven: one incident, one POST. With no bound, a flood put an
 * unbounded number of concurrent `fetch` calls in the air — sockets, TLS handshakes and
 * retained incident payloads all scaling with the attack rate, against a receiver that
 * is by then certainly rate-limiting or timing out. Optional `throttle_window_seconds` /
 * `max_per_window` did not cover this: they are opt-in, need both halves set, and the
 * schema defaults neither.
 *
 * Beyond the cap a delivery is DROPPED and reported, never queued — the same choice the
 * firewall enforcer makes for the same reason: a queue in front of a slow consumer is
 * just the unbounded growth moved somewhere less visible.
 */
const DEFAULT_MAX_IN_FLIGHT = 32;

export interface WebhookDispatcherOptions {
  webhooks: WebhookConfig[];
  /** Called when a delivery ultimately fails, for logging. */
  onError?: (url: string, error: Error) => void;
}

/**
 * Delivers each incident to the configured webhook URLs as an HTTP POST with a
 * JSON body. When a `secret` is set, the body is signed with HMAC-SHA256 and the
 * hex digest is sent in `X-Hackerpot-Signature` so the receiver can verify
 * authenticity. Failed deliveries retry with exponential backoff.
 */
/** Per-webhook delivery state for de-duplication and throttling. */
interface HookState {
  /** Last-alert time per source IP, for de-duplication. */
  recentByIp: Map<string, number>;
  /** Timestamps of recent deliveries, for the throttle window. */
  sends: number[];
  /** Deliveries currently in flight — bounded by `maxInFlight`. */
  inFlight: number;
  /** Deliveries dropped because `maxInFlight` was reached. */
  dropped: number;
}

export class WebhookDispatcher {
  private readonly webhooks: WebhookConfig[];
  private readonly onError: ((url: string, error: Error) => void) | undefined;
  private readonly state: HookState[];
  private unsubscribe: (() => void) | undefined;

  constructor(options: WebhookDispatcherOptions) {
    this.webhooks = options.webhooks;
    this.onError = options.onError;
    this.state = this.webhooks.map(() => ({ recentByIp: new Map(), sends: [], inFlight: 0, dropped: 0 }));
  }

  attach(broker: IncidentBroker): void {
    // This fires on every incident (attacker-driven), so it must never reject into the
    // void — dispatch() catches its own delivery errors, and this .catch is the backstop.
    this.unsubscribe = broker.subscribe((incident) => {
      this.dispatch(incident).catch((err) => this.onError?.("", err as Error));
    });
  }

  detach(): void {
    this.unsubscribe?.();
    this.unsubscribe = undefined;
  }

  private async dispatch(incident: Incident): Promise<void> {
    const now = Date.now();
    const pending: Array<Promise<void>> = [];
    for (let i = 0; i < this.webhooks.length; i++) {
      const hook = this.webhooks[i]!;
      if (incident.totalScore < (hook.minScore ?? 0)) continue;
      const state = this.state[i]!;
      const maxInFlight = hook.maxInFlight ?? DEFAULT_MAX_IN_FLIGHT;
      if (state.inFlight >= maxInFlight) {
        state.dropped += 1;
        this.onError?.(hook.url, new Error(`delivery dropped — ${maxInFlight} already in flight (${state.dropped} dropped so far)`));
        continue;
      }
      if (!this.shouldSend(hook, state, incident.ip, now)) continue;
      state.inFlight += 1;
      pending.push(this.deliver(hook, incident).finally(() => (state.inFlight -= 1)));
    }
    await Promise.all(pending);
  }

  /**
   * Applies per-webhook de-duplication and throttling, recording the send when allowed.
   * Keeps one noisy attacker to one alert and caps total deliveries per window, so an
   * alert webhook can't flood a chat channel or page an operator hundreds of times.
   */
  private shouldSend(hook: WebhookConfig, state: HookState, ip: string, now: number): boolean {
    const dedupeMs = (hook.dedupeWindowSeconds ?? 0) * 1000;
    if (dedupeMs > 0) {
      const last = state.recentByIp.get(ip);
      if (last !== undefined && now - last < dedupeMs) return false;
    }
    if (hook.throttleWindowSeconds && hook.maxPerWindow) {
      const cutoff = now - hook.throttleWindowSeconds * 1000;
      state.sends = state.sends.filter((t) => t >= cutoff);
      if (state.sends.length >= hook.maxPerWindow) return false;
      state.sends.push(now);
    }
    if (dedupeMs > 0) {
      state.recentByIp.set(ip, now);
      // Bound the dedup map: drop entries older than the dedup window.
      for (const [k, t] of state.recentByIp) if (now - t >= dedupeMs) state.recentByIp.delete(k);
    }
    return true;
  }

  private async deliver(hook: WebhookConfig, incident: Incident): Promise<void> {
    // The renderer owns both the payload shape and the escaping the destination needs:
    // native incident JSON for your own receiver, an escaped and mention-neutered
    // message for a chat platform. It also decides the `omitBody` default per format.
    const { body } = renderAlert(hook.format ?? "hackerpot", incident, hook.omitBody !== undefined ? { omitBody: hook.omitBody } : {});
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "User-Agent": "hackerpot-webhook",
      ...hook.headers,
    };
    if (hook.secret) {
      headers["X-Hackerpot-Signature"] = `sha256=${createHmac("sha256", hook.secret).update(body).digest("hex")}`;
    }

    const maxRetries = hook.maxRetries ?? 3;
    const timeoutMs = hook.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const res = await fetch(hook.url, { method: "POST", headers, body, signal: AbortSignal.timeout(timeoutMs) });
        if (res.ok) return;
        throw new Error(`HTTP ${res.status}`);
      } catch (err) {
        if (attempt === maxRetries) {
          this.onError?.(hook.url, err as Error);
          return;
        }
        await new Promise((resolve) => setTimeout(resolve, BACKOFF_BASE_MS * 2 ** (attempt - 1)));
      }
    }
  }
}
