import type { TrafficAnomaly } from "../audit.js";
import type { Incident } from "./types.js";

/**
 * Alert rendering for the chat destinations.
 *
 * The webhook dispatcher already solves delivery — signing, retries, de-duplication,
 * throttling, in-flight caps. What Slack and Discord need on top of that is a
 * different *body*: neither speaks hackerpot's incident JSON, and both render what
 * they are given. That second half is the dangerous one.
 *
 * **Everything interpolated here is attacker-chosen.** The request path, the
 * User-Agent, the detector `reason` strings that quote them back, a captured shell
 * command. Sending that raw into a chat client is a text-injection sink with real
 * consequences, and the two platforms fail differently:
 *
 * - **Discord** turns `@everyone` in a webhook message into a genuine notification
 *   for the whole server. `GET /@everyone` — a path an attacker types in one second —
 *   would page an entire team. Escaping alone is not something to rest on here, so the
 *   payload ALSO carries `allowed_mentions: {parse: []}`, which is the platform's own
 *   guarantee that no mention in the body can ever resolve.
 * - **Slack** builds mentions out of angle brackets (`<!channel>`, `<@U123>`), so
 *   HTML-escaping `&`, `<` and `>` — the escaping Slack documents for exactly this —
 *   defuses them.
 *
 * Both platforms also *fetch* URLs found in a message to build a preview. An attacker
 * who puts a URL in a path they know will be alerted on gets your chat provider to
 * dial it, and learns their probe landed. Both payloads therefore disable unfurling.
 */

/** How a webhook's body is rendered. `hackerpot` is the native incident JSON. */
export type AlertFormat = "hackerpot" | "slack" | "discord";

/** Discord rejects a message over 2000 characters outright; leave room for the wrapper. */
const DISCORD_LIMIT = 1800;
/** Slack accepts more, but a wall of text in a channel is not an alert anybody reads. */
const SLACK_LIMIT = 2800;
/** Per-field caps, so one enormous captured value cannot crowd out the rest. */
const FIELD_LIMIT = 300;
const BODY_LIMIT = 500;

/** Discord's SUPPRESS_EMBEDS message flag — no link previews, no outbound fetch. */
const SUPPRESS_EMBEDS = 1 << 2;

/**
 * Strips control characters and folds every line break into a space.
 *
 * A captured value carrying a newline would otherwise add lines to the alert that
 * look exactly like the ones this module wrote — a forged "score: 0" line under a
 * real detection reads as the truth to whoever is on call.
 */
function flatten(value: string, limit = FIELD_LIMIT): string {
  const collapsed = value.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim();
  return collapsed.length > limit ? `${collapsed.slice(0, limit)}…` : collapsed;
}

/** Slack's documented escaping. Defuses `<!channel>`, `<!here>` and `<@USER>` mentions. */
export function escapeSlack(value: string): string {
  return flatten(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/**
 * Neutralizes Discord markdown so a captured value renders as the literal text it is.
 *
 * Belt and braces with `allowed_mentions`: this stops the formatting tricks (a link
 * whose label lies about its target, a spoiler hiding the actual path), while
 * `allowed_mentions` is what actually guarantees no ping fires.
 */
export function escapeDiscord(value: string): string {
  return flatten(value).replace(/([\\`*_~|<>[\]()@#])/g, "\\$1");
}

/** A glanceable severity marker, on the same scale the policy thresholds use. */
function marker(totalScore: number): string {
  if (totalScore >= 40) return "\u{1F6A8}";
  if (totalScore >= 20) return "⚠️";
  return "\u{1F50E}";
}

/** The lines every chat alert carries, before per-platform escaping. */
function alertLines(incident: Incident, omitBody: boolean): string[] {
  const detectors = incident.detections.map((d) => d.detectorId).join(", ") || "hit";
  const lines = [
    `${marker(incident.totalScore)} hackerpot — ${detectors}`,
    `source: ${incident.ip}  ·  score: ${incident.score} (total ${incident.totalScore})`,
    `request: ${incident.method} ${incident.path}`,
    `response: ${incident.respondedWith}  ·  ${incident.timestamp}`,
  ];
  const reason = incident.detections[0]?.reason;
  if (reason) lines.push(`reason: ${reason}`);
  const ua = incident.headers["user-agent"];
  if (ua) lines.push(`agent: ${ua}`);
  if (!omitBody && incident.body !== undefined && incident.body !== "") {
    lines.push(`body: ${flatten(incident.body, BODY_LIMIT)}`);
  }
  lines.push(`id: ${incident.id}`);
  return lines;
}

function truncate(text: string, limit: number): string {
  return text.length > limit ? `${text.slice(0, limit)}…` : text;
}

export interface RenderedAlert {
  /** The serialized request body. */
  body: string;
  /** Whether the attacker-controlled request body was included, for the caller's logging. */
  includesBody: boolean;
}

/**
 * Renders an incident for one destination.
 *
 * `omitBody` defaults to TRUE for the chat formats: the request body is raw attacker
 * payload — a serialized exploit, someone else's leaked data, a malware stager — and
 * a chat client renders it to every person in the channel. An operator who genuinely
 * wants it can set `omit_body = false`; nobody should get it by accident.
 */
export function renderAlert(format: AlertFormat, incident: Incident, options: { omitBody?: boolean } = {}): RenderedAlert {
  if (format === "hackerpot") {
    const omitBody = options.omitBody ?? false;
    const payload = omitBody && incident.body !== undefined ? { ...incident, body: undefined } : incident;
    return { body: JSON.stringify({ type: "incident", incident: payload }), includesBody: !omitBody && incident.body !== undefined };
  }

  const omitBody = options.omitBody ?? true;
  const lines = alertLines(incident, omitBody);
  const includesBody = !omitBody && incident.body !== undefined && incident.body !== "";

  if (format === "slack") {
    const text = truncate(lines.map(escapeSlack).join("\n"), SLACK_LIMIT);
    // unfurl_* off: no preview means Slack never fetches a URL an attacker planted.
    return { body: JSON.stringify({ text, unfurl_links: false, unfurl_media: false }), includesBody };
  }

  const content = truncate(lines.map(escapeDiscord).join("\n"), DISCORD_LIMIT);
  return {
    body: JSON.stringify({
      content,
      // The actual guarantee that nothing in `content` can ping anyone.
      allowed_mentions: { parse: [] },
      flags: SUPPRESS_EMBEDS,
    }),
    includesBody,
  };
}

/**
 * A traffic anomaly for one destination. The summary is our own sentence, but a campaign
 * anomaly quotes the probed path, which is attacker-chosen, so the chat formats escape it
 * like any alert line.
 */
export function renderAnomaly(format: AlertFormat, anomaly: TrafficAnomaly): string {
  if (format === "hackerpot") return JSON.stringify({ type: "anomaly", anomaly });
  const marker = anomaly.severity === "critical" ? "\u{1F6A8}" : anomaly.severity === "warning" ? "⚠️" : "\u{1F50E}";
  const lines = [`${marker} hackerpot anomaly — ${anomaly.id}`, anomaly.summary, `at ${anomaly.timestamp}`];
  if (format === "slack") return JSON.stringify({ text: truncate(lines.map(escapeSlack).join("\n"), SLACK_LIMIT), unfurl_links: false, unfurl_media: false });
  return JSON.stringify({ content: truncate(lines.map(escapeDiscord).join("\n"), DISCORD_LIMIT), allowed_mentions: { parse: [] }, flags: SUPPRESS_EMBEDS });
}

/**
 * The delivery saying how many alerts a webhook held back, so a quiet channel is not read
 * as quiet traffic. The text is ours, not attacker input, so it needs no escaping.
 */
export function renderSuppressedSummary(format: AlertFormat, count: number, windowSeconds: number): string {
  const text = `hackerpot: ${count} alert${count === 1 ? "" : "s"} held back in the last ${windowSeconds}s (deduplicated, throttled, or over a delivery cap)`;
  if (format === "slack") return JSON.stringify({ text, unfurl_links: false, unfurl_media: false });
  if (format === "discord") return JSON.stringify({ content: text, allowed_mentions: { parse: [] }, flags: SUPPRESS_EMBEDS });
  return JSON.stringify({ type: "suppressed", count, windowSeconds });
}
