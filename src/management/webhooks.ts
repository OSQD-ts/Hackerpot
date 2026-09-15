import { createHmac } from "node:crypto";
import { renderAlert, renderAnomaly, renderSuppressedSummary } from "./alerts.js";
import type { TrafficAnomaly } from "../audit.js";
import type { IncidentBroker } from "./broker.js";
import { redactIncident } from "./redact.js";
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

/**
 * Client errors worth retrying: the receiver timed out, asked to be retried later, or is
 * rate-limiting. Any other 4xx is a refusal (a wrong URL, a revoked token, a payload the
 * receiver rejects) that fails the same way on every attempt, so retrying it only delays
 * the error report and holds an in-flight slot through the backoff.
 */
const RETRYABLE_CLIENT_ERRORS = new Set([408, 425, 429]);

/** Shortest interval between two suppression summaries for one webhook. */
const MIN_SUMMARY_INTERVAL_MS = 60_000;

export interface WebhookDispatcherOptions {
  webhooks: WebhookConfig[];
  /** Called when a delivery ultimately fails, for logging. */
  onError?: (url: string, error: Error) => void;
  /**
   * Cap on deliveries started per minute across every webhook together. Default:
   * unlimited. Per-hook throttles bound each channel; this bounds the total when several
   * hooks fire on the same flood.
   */
  globalMaxPerMinute?: number;
  /** Overrides how long suppressed alerts are counted before the summary is sent. Mainly for tests. */
  summaryIntervalMs?: number;
}

/** Per-webhook delivery state for de-duplication, throttling and suppression summaries. */
interface HookState {
  /** Last-alert time per source IP, for de-duplication. */
  recentByIp: Map<string, number>;
  /** Timestamps of recent deliveries, for the throttle window. */
  sends: number[];
  /** Deliveries currently in flight — bounded by `maxInFlight`. */
  inFlight: number;
  /** Deliveries dropped because `maxInFlight` was reached. */
  dropped: number;
  /** Alerts held back since the last summary: deduplicated, throttled, over the global cap or over the in-flight cap. */
  suppressed: number;
  summaryTimer: ReturnType<typeof setTimeout> | undefined;
}

/**
 * Delivers each incident to the configured webhook URLs as an HTTP POST with a JSON body.
 *
 * With a `secret`, each delivery carries two signatures. `X-Hackerpot-Signature` is
 * HMAC-SHA256 over the body alone, unchanged for existing receivers; a captured delivery
 * signed that way can be replayed indefinitely, because nothing in it expires.
 * `X-Hackerpot-Signature-V2` covers `<timestamp>.<body>`, with the timestamp (Unix seconds)
 * in `X-Hackerpot-Timestamp`, so a receiver that verifies it and rejects old timestamps is
 * not open to replay. Failed deliveries retry with exponential backoff, except refusals.
 */
export class WebhookDispatcher {
  private readonly webhooks: WebhookConfig[];
  private readonly onError: ((url: string, error: Error) => void) | undefined;
  private readonly state: HookState[];
  private readonly globalMaxPerMinute: number | undefined;
  private readonly summaryIntervalMs: number | undefined;
  private globalSends: number[] = [];
  private unsubscribe: (() => void) | undefined;

  constructor(options: WebhookDispatcherOptions) {
    this.webhooks = options.webhooks;
    this.onError = options.onError;
    this.globalMaxPerMinute = options.globalMaxPerMinute;
    this.summaryIntervalMs = options.summaryIntervalMs;
    this.state = this.webhooks.map(() => ({ recentByIp: new Map(), sends: [], inFlight: 0, dropped: 0, suppressed: 0, summaryTimer: undefined }));
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
    for (const state of this.state) {
      if (state.summaryTimer !== undefined) clearTimeout(state.summaryTimer);
      state.summaryTimer = undefined;
    }
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
        this.suppress(hook, state);
        continue;
      }
      if (!this.shouldSend(hook, state, incident.ip, now) || !this.allowGlobal(now)) {
        this.suppress(hook, state);
        continue;
      }
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

  /**
   * Delivers a traffic anomaly to every hook that has not opted out (`anomalies: false`).
   * Anomalies are already rate-limited at the source by the audit's cooldown, so per-hook
   * dedupe, throttle and `minScore` do not apply; the global cap and in-flight cap do.
   */
  announce(anomaly: TrafficAnomaly): void {
    const now = Date.now();
    for (let i = 0; i < this.webhooks.length; i++) {
      const hook = this.webhooks[i]!;
      if (hook.anomalies === false) continue;
      const state = this.state[i]!;
      if (state.inFlight >= (hook.maxInFlight ?? DEFAULT_MAX_IN_FLIGHT) || !this.allowGlobal(now)) {
        this.suppress(hook, state);
        continue;
      }
      state.inFlight += 1;
      this.post(hook, renderAnomaly(hook.format ?? "hackerpot", anomaly))
        .catch((err) => this.onError?.(hook.url, err as Error))
        .finally(() => (state.inFlight -= 1));
    }
  }

  /** Counts a delivery against the per-minute cap shared by every webhook, or refuses it. */
  private allowGlobal(now: number): boolean {
    if (!this.globalMaxPerMinute) return true;
    const cutoff = now - 60_000;
    this.globalSends = this.globalSends.filter((t) => t >= cutoff);
    if (this.globalSends.length >= this.globalMaxPerMinute) return false;
    this.globalSends.push(now);
    return true;
  }

  /**
   * Counts an alert this webhook held back, and makes sure the count gets reported.
   *
   * Dedupe, throttling and the caps keep a channel readable during a flood by staying
   * quiet, and silence is ambiguous: somebody watching the channel cannot tell "nothing
   * happened" from "a lot happened and was held back". So the first suppression in a
   * window schedules one summary delivery at its end, saying how many.
   */
  private suppress(hook: WebhookConfig, state: HookState): void {
    state.suppressed += 1;
    if (state.summaryTimer !== undefined) return;
    const intervalMs =
      this.summaryIntervalMs ?? Math.max(MIN_SUMMARY_INTERVAL_MS, (hook.dedupeWindowSeconds ?? 0) * 1000, (hook.throttleWindowSeconds ?? 0) * 1000);
    state.summaryTimer = setTimeout(() => {
      state.summaryTimer = undefined;
      const count = state.suppressed;
      state.suppressed = 0;
      if (count === 0) return;
      const body = renderSuppressedSummary(hook.format ?? "hackerpot", count, Math.round(intervalMs / 1000));
      this.post(hook, body).catch((err) => this.onError?.(hook.url, err as Error));
    }, intervalMs);
    // A pending summary must never be what keeps the process alive.
    state.summaryTimer.unref();
  }

  private async deliver(hook: WebhookConfig, incident: Incident): Promise<void> {
    // Credentials are stripped from the copy that leaves the process unless the operator
    // opted out for this hook. See `WebhookConfig.redact`.
    const outgoing = hook.redact === false ? incident : redactIncident(incident);
    // The renderer owns both the payload shape and the escaping the destination needs:
    // native incident JSON for your own receiver, an escaped and mention-neutered
    // message for a chat platform. It also decides the `omitBody` default per format.
    const { body } = renderAlert(hook.format ?? "hackerpot", outgoing, hook.omitBody !== undefined ? { omitBody: hook.omitBody } : {});
    await this.post(hook, body);
  }

  /** POSTs one body: signed, retried with backoff, never retried after a refusal. */
  private async post(hook: WebhookConfig, body: string): Promise<void> {
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
      const attemptHeaders = { ...headers };
      if (hook.secret) {
        // Signed per attempt, so a retry after a backoff is not rejected as stale.
        const timestamp = String(Math.floor(Date.now() / 1000));
        attemptHeaders["X-Hackerpot-Timestamp"] = timestamp;
        attemptHeaders["X-Hackerpot-Signature-V2"] = `sha256=${createHmac("sha256", hook.secret).update(`${timestamp}.${body}`).digest("hex")}`;
      }

      let failure: Error;
      try {
        const res = await fetch(hook.url, { method: "POST", headers: attemptHeaders, body, signal: AbortSignal.timeout(timeoutMs) });
        // The response body is never needed; release the connection instead of leaving it half-read.
        await res.body?.cancel().catch(() => undefined);
        if (res.ok) return;
        if (res.status >= 400 && res.status < 500 && !RETRYABLE_CLIENT_ERRORS.has(res.status)) {
          this.onError?.(hook.url, new Error(`HTTP ${res.status}, not retried: the receiver refused the delivery`));
          return;
        }
        failure = new Error(`HTTP ${res.status}`);
      } catch (err) {
        failure = err as Error;
      }
      if (attempt === maxRetries) {
        this.onError?.(hook.url, failure);
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, BACKOFF_BASE_MS * 2 ** (attempt - 1)));
    }
  }
}
