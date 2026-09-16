import type { SyslogSink } from "../syslog.js";
import type { WebhookDispatcher } from "../management/webhooks.js";
import type { NotifyEvent, NotifySink } from "./types.js";

/**
 * The sinks an event can go to.
 *
 * Two of these adapt machinery that already existed — the syslog transport and the webhook
 * dispatcher — and one is the sink bothandlerjs starts everybody with and this had no
 * equivalent of: the console. A deployment that wants to see what its honeypot is saying
 * before wiring a SIEM to it had to write that itself.
 */

/**
 * Syslog as a sink.
 *
 * `send()` never throws and never returns a promise — it sits on the hit path — and the sink
 * applies its own credential redaction and address masking on the way out.
 */
export function syslogNotifySink(sink: SyslogSink): NotifySink {
  return {
    id: "syslog",
    notify: (event) => {
      // A collector receives incidents. An anomaly is about a window and a hub error is about
      // this process; neither is a syslog record of an attack, and inventing one would put a
      // line in the SIEM that no detector produced.
      if (event.incident !== undefined) sink.send(event.incident);
    },
    close: () => sink.close(),
  };
}

/**
 * Webhooks as a sink.
 *
 * The dispatcher keeps its own per-hook dedupe, throttling, in-flight cap, suppression
 * summaries and redaction: those are per destination, and a chat channel's idea of "too many"
 * is not a SIEM's. The hub's bounds sit in front of all of them.
 */
export function webhookNotifySink(dispatcher: WebhookDispatcher): NotifySink {
  return {
    id: "webhooks",
    notify: (event) => {
      if (event.incident !== undefined) return dispatcher.deliverIncident(event.incident);
      if (event.anomaly !== undefined) dispatcher.announce(event.anomaly);
      return undefined;
    },
    close: () => dispatcher.detach(),
  };
}

export interface ConsoleNotifierOptions {
  /** `"pretty"` for a person watching, `"json"` for a log pipeline. Default `"pretty"`. */
  format?: "pretty" | "json";
  /** Where to write. Default `console`. */
  target?: Pick<Console, "log" | "warn" | "error">;
}

/**
 * Writes events to the console. The sink to start with, and the one that needs no account.
 *
 * Deliberately terse: one line for what happened, one for why. The captured request is not
 * printed — it is attacker-written text going to a terminal, and the store already has it.
 */
export function consoleNotifier(options: ConsoleNotifierOptions = {}): NotifySink {
  const format = options.format ?? "pretty";
  const target = options.target ?? console;

  return {
    id: "console",
    notify(event: NotifyEvent): void {
      if (format === "json") {
        target.log(JSON.stringify(event));
        return;
      }
      // An error carries its own account of what went wrong and nothing else on the event
      // describes it, so it is answered first: this is the sink an operator gets by default,
      // and errors are how the library reports a store, a sink or a detector failing.
      if (event.error !== undefined) {
        target.error(`[hackerpot] error ${event.error.source} — ${event.error.message}`);
        return;
      }
      if (event.incident === undefined) {
        // An anomaly is about a window rather than a request. One line, same shape.
        target.warn(`[hackerpot] anomaly ${event.anomaly?.id ?? "unknown"} — ${event.anomaly?.summary ?? ""}`);
        return;
      }
      const incident = event.incident;
      const proven = incident.detections.some((detection) => detection.certain === true) ? " (proof)" : "";
      const detectors = incident.detections.map((detection) => detection.detectorId).join(", ") || "nothing";
      const head = `[hackerpot] ${event.type} ${incident.ip} ${incident.method} ${incident.path} score=${incident.score}/${incident.totalScore}${proven} -> ${incident.respondedWith}`;
      const downgraded = incident.downgradedFrom === undefined ? "" : ` (downgraded from ${incident.downgradedFrom})`;
      const why = incident.reason ?? incident.detections[0]?.reason ?? detectors;
      const write = event.type === "downgrade" ? target.warn : target.log;
      write.call(target, `${head}${downgraded}\n           ${why}`);
    },
  };
}

export interface NotifyJsSinkOptions {
  /** The hub's base URL, e.g. `https://hub.example.com`. */
  url: string;
  /** An ingest token (`njs_…`), minted with `notifyjs token create`. */
  token: string;
  /** Channel to publish under. Default `"hackerpot"`. */
  channel?: string;
  /** Per-request deadline, ms. Default 5000. */
  timeoutMs?: number;
  /** `fetch` implementation. Defaults to the global. */
  fetch?: typeof globalThis.fetch;
}

/** Longest title and body sent. Both carry attacker-chosen text; a phone is not the place for all of it. */
const MAX_TITLE = 120;
const MAX_BODY = 400;

function clip(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}

/**
 * Publishes to a NotifyJS hub, so honeypot alerts arrive on the same devices as the rest of
 * your operational notifications.
 *
 * Written against the hub's HTTP ingest (`POST /api/notify`) rather than importing its client,
 * so this adds no dependency and works whichever version of the hub you run. Ingest is **off by
 * default** on a hub — `notifyjs serve --ingest`, then `notifyjs token create --role oncall` —
 * and a hub that has it switched off answers 404 rather than confirming the feature exists, so
 * that case is reported as what it is instead of as a missing endpoint.
 *
 * What is sent is deliberately thin: who, what, and what the honeypot did. No headers, no
 * captured body, and the path clipped — this lands on a lock screen, and the store already has
 * the request in full.
 */
export function notifyJsSink(options: NotifyJsSinkOptions): NotifySink {
  const endpoint = `${options.url.replace(/\/+$/, "")}/api/notify`;
  const channel = options.channel ?? "hackerpot";
  const timeoutMs = options.timeoutMs ?? 5000;
  const doFetch = options.fetch ?? globalThis.fetch;
  if (typeof doFetch !== "function") throw new Error("notifyJsSink needs a fetch implementation; pass one via `fetch` on a runtime without a global.");

  return {
    id: "notifyjs",
    async notify(event: NotifyEvent): Promise<void> {
      const payload = bodyFor(event, channel);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      (timer as { unref?: () => void }).unref?.();
      try {
        const response = await doFetch(endpoint, {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${options.token}` },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });
        // 202 is the hub's success. Every refusal below is reported as itself, because
        // "the hub rejected it" sends somebody to look at the wrong thing: a disabled
        // feature, a revoked token and a token whose role cannot publish are three
        // different fixes.
        if (response.ok) return;
        throw new Error(refusal(response.status));
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

/** What a refusal from the hub actually means, in the words of its own contract. */
function refusal(status: number): string {
  if (status === 404) return "the NotifyJS hub has HTTP ingest switched off (start it with `notifyjs serve --ingest`); a disabled feature answers 404 rather than confirming it exists";
  if (status === 421) return "the hub refused a bearer token over plain HTTP from off-box; put TLS in front of it, or run the hub on loopback behind a reverse proxy";
  if (status === 401) return "the NotifyJS ingest token is unknown or revoked";
  if (status === 403) return "this ingest token's role cannot publish notifications (`notify.send`)";
  if (status === 429) return "the hub is rate-limiting this ingest token";
  if (status === 413) return "the hub refused the notification as too large";
  return `the NotifyJS hub refused the notification with ${status}`;
}

/** The notification one event becomes. Built field by field: the hub accepts only what it names. */
function bodyFor(event: NotifyEvent, channel: string): Record<string, unknown> {
  const base = { channel, tags: ["hackerpot", event.type] as string[] };

  if (event.error !== undefined) {
    return {
      ...base,
      title: clip(`hackerpot: ${event.error.source} failed`, MAX_TITLE),
      body: clip(event.error.message, MAX_BODY),
      severity: "error",
      // One alert per failing component rather than one per failed delivery.
      dedupeKey: `hackerpot:error:${event.error.source}`,
    };
  }

  const anomaly = event.anomaly;
  if (anomaly !== undefined) {
    return {
      ...base,
      title: clip(`hackerpot: ${anomaly.id}`, MAX_TITLE),
      body: clip(anomaly.summary, MAX_BODY),
      // The audit's own severities are already the hub's vocabulary.
      severity: anomaly.severity,
      dedupeKey: `hackerpot:anomaly:${anomaly.id}`,
      data: { metric: anomaly.metric, value: anomaly.value, baseline: anomaly.baseline },
    };
  }

  const incident = event.incident;
  if (incident === undefined) return { ...base, title: `hackerpot: ${event.type}`, severity: "info" };

  const proven = incident.detections.some((detection) => detection.certain === true);
  const detectors = incident.detections.map((detection) => detection.detectorId);
  return {
    ...base,
    tags: [...base.tags, ...detectors].slice(0, 20),
    title: clip(event.type === "downgrade" ? `hackerpot: refused a block for ${incident.ip}` : `hackerpot: ${detectors[0] ?? "incident"} from ${incident.ip}`, MAX_TITLE),
    // The path is attacker-chosen, so it is clipped and it is all that is sent of the
    // request: no headers, no body. The store has those.
    body: clip(`${incident.method} ${incident.path} → ${incident.respondedWith}${incident.reason === undefined ? "" : ` · ${incident.reason}`}`, MAX_BODY),
    severity: proven ? "error" : event.type === "downgrade" ? "warning" : "info",
    // One alert per address, however many times it probes.
    dedupeKey: `hackerpot:${event.type}:${incident.ip}`,
    data: { id: incident.id, ip: incident.ip, score: incident.score, totalScore: incident.totalScore, respondedWith: incident.respondedWith, proof: proven },
  };
}
