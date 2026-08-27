import type { HoneypotHit } from "./types.js";

const PRODUCT = "hackerpot";
const PRODUCT_VERSION = "0.1.0";

/** CEF severity 0–10, derived from the IP's cumulative score (block ≈ 10, tarpit range ≈ 7). */
function severity(hit: HoneypotHit): number {
  return Math.max(1, Math.min(10, Math.round(hit.totalScore / 5)));
}

function cefEscapeHeader(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/\|/g, "\\|");
}
function cefEscapeExt(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/=/g, "\\=").replace(/\n/g, "\\n");
}

/**
 * Formats an incident as an ArcSight **CEF** (Common Event Format) line — the
 * lingua franca for SIEM ingestion (Splunk, QRadar, ArcSight, Elastic). Pair with
 * `syslogLine` to ship it over syslog, or write it to a file your SIEM tails.
 */
export function cefFormat(hit: HoneypotHit): string {
  const detectorIds = hit.detections.map((d) => d.detectorId).join(",");
  const name = hit.detections[0]?.reason ?? "honeypot hit";
  const ext: Record<string, string> = {
    src: hit.ip,
    requestMethod: hit.method,
    request: hit.path,
    act: hit.respondedWith,
    cs1Label: "detectors",
    cs1: detectorIds,
    cn1Label: "score",
    cn1: String(hit.totalScore),
    externalId: hit.id,
    rt: String(Date.parse(hit.timestamp)),
  };
  const extStr = Object.entries(ext)
    .map(([k, v]) => `${k}=${cefEscapeExt(v)}`)
    .join(" ");
  const header = `CEF:0|${PRODUCT}|${PRODUCT}|${PRODUCT_VERSION}|${cefEscapeHeader(hit.detections[0]?.detectorId ?? "hit")}|${cefEscapeHeader(name)}|${severity(hit)}`;
  return `${header}|${extStr}`;
}

export interface SyslogOptions {
  /** Hostname in the syslog header. Default "hackerpot". */
  host?: string;
  /** Syslog facility (0–23). Default 13 (log audit). */
  facility?: number;
  /** Syslog severity (0–7). Default 4 (warning). */
  severity?: number;
  /** The message to wrap. Defaults to the incident's CEF line. */
  message?: string;
}

/**
 * Wraps a message (a CEF line by default) in an RFC 3164 syslog envelope —
 * `<PRI>TIMESTAMP HOST hackerpot: MESSAGE` — ready to send to a syslog collector
 * over UDP/TCP. Provide your own `message` to ship something other than CEF.
 */
export function syslogLine(hit: HoneypotHit, options: SyslogOptions = {}): string {
  const facility = options.facility ?? 13;
  const sev = options.severity ?? 4;
  const pri = facility * 8 + sev;
  const host = options.host ?? PRODUCT;
  const d = new Date(hit.timestamp);
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const ts = `${months[d.getMonth()]} ${String(d.getDate()).padStart(2, " ")} ${d.toTimeString().slice(0, 8)}`;
  const message = options.message ?? cefFormat(hit);
  return `<${pri}>${ts} ${host} ${PRODUCT}: ${message}`;
}
