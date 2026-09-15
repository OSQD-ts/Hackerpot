import type { Detection } from "../detectors/types.js";
import type { Incident } from "./types.js";

/** What a removed value is replaced with. */
export const REDACTED = "[redacted]";

/** Headers that carry a credential by definition. */
export const CREDENTIAL_HEADERS: readonly string[] = ["cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token", "set-cookie"];

/**
 * Header names that read as a credential whether or not anybody listed them. A fixed list
 * only covers headers this library has heard of, and a deployment's own secret is by
 * definition one it has not (`x-acme-automation-token`). Errs towards hiding.
 */
export const SECRET_HEADER_SHAPE = /secret|token|api[-_]?key|passw|credential/i;

/** Form or JSON field names whose value is a credential. */
const SECRET_FIELD_SHAPE = /pass(word|wd)?|secret|token|api[-_]?key|credential/i;

/** Values shorter than this are not scrubbed out of free text: they would match too much. */
const MIN_SCRUB_LENGTH = 4;

/** Whether a header should be hidden before an incident leaves the process. */
export function isSecretHeader(name: string): boolean {
  const lower = name.toLowerCase();
  return CREDENTIAL_HEADERS.includes(lower) || SECRET_HEADER_SHAPE.test(lower);
}

/**
 * The copy of an incident that is safe to send to a webhook.
 *
 * Runs on the way out, never on the way in: detection and the store keep everything, and
 * only the copy handed to a sink is reduced. Credential headers become `[redacted]` (the
 * name stays, so it is still visible that one was sent), secret-named form or JSON body
 * fields likewise, and every removed value is scrubbed from detection reasons and
 * metadata, because detectors quote what they saw. A body that is neither form-encoded
 * nor valid JSON is sent unchanged. Adapted from bothandlerjs.
 */
export function redactIncident(incident: Incident): Incident {
  const removed: string[] = [];
  const headers: Incident["headers"] = {};
  for (const [name, value] of Object.entries(incident.headers)) {
    if (value === undefined || !isSecretHeader(name)) {
      headers[name] = value;
      continue;
    }
    for (const one of Array.isArray(value) ? value : [value]) if (one) removed.push(one);
    headers[name] = REDACTED;
  }

  const body = incident.body === undefined ? undefined : redactBody(incident.body, removed);
  const detections = removed.length === 0 ? incident.detections : incident.detections.map((detection) => scrubDetection(detection, removed));

  const redacted: Incident = { ...incident, headers, detections };
  if (body !== undefined) redacted.body = scrubText(body, removed);
  return redacted;
}

function redactBody(body: string, removed: string[]): string {
  const trimmed = body.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      return JSON.stringify(redactJson(parsed, removed, 0));
    } catch {
      return body;
    }
  }
  if (!trimmed.includes("=")) return body;
  return body
    .split("&")
    .map((pair) => {
      const eq = pair.indexOf("=");
      if (eq <= 0 || eq === pair.length - 1) return pair;
      if (!SECRET_FIELD_SHAPE.test(decodeFormPart(pair.slice(0, eq)))) return pair;
      removed.push(decodeFormPart(pair.slice(eq + 1)));
      return `${pair.slice(0, eq + 1)}${REDACTED}`;
    })
    .join("&");
}

function redactJson(node: unknown, removed: string[], depth: number): unknown {
  if (depth > 32 || node === null || typeof node !== "object") return node;
  if (Array.isArray(node)) return node.map((item) => redactJson(item, removed, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(node)) {
    if (typeof value === "string" && value !== "" && SECRET_FIELD_SHAPE.test(key)) {
      removed.push(value);
      out[key] = REDACTED;
    } else {
      out[key] = redactJson(value, removed, depth + 1);
    }
  }
  return out;
}

function decodeFormPart(part: string): string {
  try {
    return decodeURIComponent(part.replace(/\+/g, " "));
  } catch {
    return part;
  }
}

function scrubDetection(detection: Detection, removed: readonly string[]): Detection {
  const scrubbed: Detection = { ...detection, reason: scrubText(detection.reason, removed) };
  if (detection.metadata !== undefined) {
    const metadata: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(detection.metadata)) metadata[key] = typeof value === "string" ? scrubText(value, removed) : value;
    scrubbed.metadata = metadata;
  }
  return scrubbed;
}

/**
 * Removes every removed value from `text`, including a truncated quote of one: detectors
 * record excerpts (`value.slice(0, 200)`), and searching an excerpt for the longer value
 * it came from finds nothing, which is exactly when redaction is needed.
 */
function scrubText(text: string, removed: readonly string[]): string {
  let output = text;
  for (const secret of removed) {
    if (secret.length < MIN_SCRUB_LENGTH) continue;
    if (output.includes(secret)) {
      output = output.split(secret).join(REDACTED);
      continue;
    }
    if (output.length >= MIN_SCRUB_LENGTH && secret.includes(output)) return REDACTED;
  }
  return output;
}
