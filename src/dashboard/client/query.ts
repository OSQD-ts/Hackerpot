import { compile, defineVocabulary, type UntypedQuery } from "@osqd/jql";
import { parseText, type Suggestions, suggest } from "@osqd/jql/text";
import { classOf, RESPONSE_CLASSES } from "./analysis.js";
import type { Incident, Sections, TabName } from "./types.js";

/**
 * The page's decisions that are not drawing: which screens exist, what a filter asks the
 * API for, what a failure means, how long to wait before reconnecting.
 *
 * Kept free of the document so each one is a unit test rather than something to find out
 * in a browser.
 */

/** The screens in tab-strip order. */
export const TAB_ORDER: readonly TabName[] = ["overview", "incidents", "statistics", "sessions", "actors", "intel", "policy", "reference"];

export const TAB_LABELS: Readonly<Record<TabName, string>> = {
  overview: "Overview",
  incidents: "Incidents",
  statistics: "Statistics",
  sessions: "Sessions",
  actors: "Actors",
  intel: "Threat intel",
  policy: "Policy",
  reference: "Reference",
};

/**
 * The screens this dashboard has. Most exist because their section is on; `policy` because a
 * control was granted; `reference` always, because it explains the library rather than this
 * deployment and needs nothing from the server.
 */
export function availableTabs(sections: Sections, policy = false): TabName[] {
  return TAB_ORDER.filter((tab) => (tab === "policy" ? policy : tab === "reference" ? true : sections[tab] === true));
}

export function isTabName(value: unknown): value is TabName {
  return typeof value === "string" && (TAB_ORDER as readonly string[]).includes(value);
}

/**
 * The tab a `#fragment` names, or the first available one.
 *
 * `#stats` is accepted for `statistics` because that is what the old console wrote, and
 * a bookmark somebody made of it should still land on the screen it meant.
 */
export function tabFromHash(hash: string, available: readonly TabName[]): TabName | undefined {
  const raw = hash.replace(/^#/, "").split("?")[0] ?? "";
  const name = raw === "stats" ? "statistics" : raw;
  if (isTabName(name) && available.includes(name)) return name;
  return available[0];
}

export interface IncidentFilter {
  limit: number;
  detector: string;
  ip: string;
  /** The search box: a filter expression. Applied here, never sent to the API. See `parseQuery`. */
  query: string;
  /** One response class (`decoy`, `time cost`, `block`, …), or empty for all. Applied here, like `query`. */
  outcome?: string;
}

export const LIMITS = [50, 100, 250, 500, 1000] as const;

/** The query string for the Incidents screen. The server clamps `limit` too; this keeps the page honest about what it asked for. */
export function incidentQuery(filter: IncidentFilter): string {
  const params = new URLSearchParams();
  const limit = Number.isFinite(filter.limit) && filter.limit > 0 ? Math.min(Math.floor(filter.limit), 1000) : 100;
  params.set("limit", String(limit));
  if (filter.detector.trim() !== "") params.set("detector", filter.detector.trim());
  if (filter.ip.trim() !== "") params.set("ip", filter.ip.trim());
  return params.toString();
}

/**
 * Whether a live incident belongs on the Incidents screen under its current filter.
 *
 * The detector and address boxes are the server's filter, repeated here so a streamed
 * incident is judged the way a fetched one was. The search box is this page's alone: the API
 * has no grammar, so those two narrow what is *fetched* and the expression refines what is
 * *shown*. Which is which matters, because an expression can only ever search what the server
 * already sent.
 */
export function matchesFilter(incident: Incident, filter: IncidentFilter): boolean {
  const detector = filter.detector.trim();
  const ip = filter.ip.trim();
  if (detector !== "" && !incident.detections.some((d) => d.detector === detector)) return false;
  if (ip !== "" && incident.ip !== ip) return false;
  if (filter.outcome !== undefined && filter.outcome !== "" && classOf(incident.respondedWith) !== filter.outcome) return false;
  if (filter.query.trim() !== "" && !queryMatcher(filter.query)(incident)) return false;
  return true;
}

/**
 * The search box's language, shared by every screen that searches.
 *
 * It is `@osqd/jql`'s text syntax, the same one bothandlerjs's feed takes: fielded terms
 * (`ip:198.51.100`, `detector:decoy-path`, `score:>20`), quoted phrases, `-term` for not,
 * `field:$in(a, b)` for a set, `has:rule`, parentheses, and `$and` / `$or` / `$not`, with
 * adjacent terms an implicit `$and`. The text is parsed into a JQL query and the engine runs
 * that, so there is no matcher here to drift from the one the other projects use.
 *
 * Two decisions worth stating, both JQL's now. The operators carry a `$` because a bare "or"
 * is a word that appears in User-Agents and paths, and a language where an ordinary search
 * word silently becomes an operator is one that lies about what it matched. And **nothing
 * here throws**: this backs a box somebody types into, so half-written input parses to the
 * best available reading rather than blanking the screen between keystrokes.
 */

/** Longest expression parsed. Beyond this the box holds a paste, not a query. JQL reads to 8 KB; this page stops sooner. */
export const MAX_QUERY_CHARS = 512;

/** The fields an incident answers to, how `field:value` reads each value, and what a bare word searches. */
export const INCIDENT_VOCABULARY = defineVocabulary<Incident>()({
  fields: {
    // A whole component, so `ip:203.0.113.4` does not also find `203.0.113.45`; `ip:203.0.113` still finds the network.
    ip: { kind: "word" },
    path: {},
    method: { kind: "exact" },
    detector: { get: (incident) => incident.detections.map((detection) => detection.detector) },
    // `reason` is the name the summary had before it matched bothandlerjs's; a saved filter may still use it.
    summary: { aliases: ["reason"], get: (incident) => incident.detections.map((detection) => detection.summary) },
    action: { path: "respondedWith" },
    // What the chips above the search choose, so a query can say it too and a saved filter keeps it.
    outcome: { kind: "exact", get: (incident) => classOf(incident.respondedWith), values: RESPONSE_CLASSES.map((c) => c.name) },
    rule: {},
    score: { kind: "number" },
    total: { path: "totalScore", kind: "number" },
    ua: {
      get: (incident) => {
        const value = incident.headers["user-agent"];
        return Array.isArray(value) ? value.join(" ") : value;
      },
    },
    actor: { get: (incident) => incident.actor?.name },
  },
  // A bare word searches what somebody scanning the table is already looking at. Not the
  // summary: it quotes attacker text, and a free word matching it would make half the table
  // match half the time.
  text: ["path", "ip", "detector", "action", "ua", "actor"],
});

/**
 * A search-box expression as the JQL query it means. An empty box is `{}`, which lets
 * everything through.
 *
 * Cut to `MAX_QUERY_CHARS` before it is read, so a term past the cap is dropped rather than
 * half-read.
 */
export function parseQuery(text: string): UntypedQuery {
  return parseText(text.slice(0, MAX_QUERY_CHARS), { vocabulary: INCIDENT_VOCABULARY });
}

/** A compiled test for the search box's expression. */
export function queryMatcher(text: string): (incident: Incident) => boolean {
  return compile<Incident>(parseQuery(text), { vocabulary: INCIDENT_VOCABULARY });
}

/**
 * Completion for the search box, the way bothandlerjs's feed completes its own.
 *
 * Field names come from the vocabulary itself, so a field added to the language is offered the day
 * it exists. Values are offered only where the set is closed — the detectors and actions seen, the
 * outcome classes — because guessing values for a path or an address is inventing options rather
 * than completing them. The values seen change as incidents arrive, so they are passed in on each
 * call, after the ones the vocabulary declares. JQL quotes a value with a space in it, and keeps
 * completing inside a quote somebody has opened.
 */
export function suggestFor(input: string, caret: number, values: Readonly<Record<string, readonly string[]>>): Suggestions {
  return suggest(input, caret, INCIDENT_VOCABULARY, { values });
}

/**
 * Whether a value off the event stream is an incident at all.
 *
 * The stream is the server's, but a page that trusted its shape would throw on the first
 * malformed frame from a proxy or a future version and stop drawing for good. A frame
 * that fails this is dropped rather than half-rendered.
 */
/**
 * An incident with its detections in the current shape. A server older than the rename writes
 * `detectorId` and `reason`; an embedded element can be newer than the server it reads, so the
 * page upgrades what it receives rather than rejecting it.
 */
export function upgradeIncident(value: unknown): unknown {
  if (typeof value !== "object" || value === null) return value;
  const v = value as Record<string, unknown>;
  const upgrade = (list: unknown): unknown =>
    Array.isArray(list)
      ? list.map((d) => {
          if (typeof d !== "object" || d === null) return d;
          const r = d as Record<string, unknown>;
          if (typeof r["detector"] === "string" || typeof r["detectorId"] !== "string") return d;
          const { detectorId, reason, ...rest } = r;
          return { ...rest, detector: detectorId, summary: reason };
        })
      : list;
  return { ...v, detections: upgrade(v["detections"]), ...(v["shadowDetections"] !== undefined ? { shadowDetections: upgrade(v["shadowDetections"]) } : {}) };
}

export function isIncident(value: unknown): value is Incident {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v["id"] === "string" &&
    typeof v["timestamp"] === "string" &&
    typeof v["ip"] === "string" &&
    typeof v["method"] === "string" &&
    typeof v["path"] === "string" &&
    typeof v["respondedWith"] === "string" &&
    typeof v["score"] === "number" &&
    typeof v["totalScore"] === "number" &&
    Array.isArray(v["detections"]) &&
    (v["detections"] as unknown[]).every((d) => typeof d === "object" && d !== null && typeof (d as Record<string, unknown>)["detector"] === "string") &&
    typeof v["headers"] === "object" &&
    v["headers"] !== null
  );
}

/**
 * Adds a live incident to the corpus: oldest first, no duplicates, at most `cap` kept.
 *
 * Duplicates are real: a reconnect reloads the corpus while frames are still arriving, so
 * the same incident can come in through both doors. Returns a new array.
 */
export function mergeIncident(list: readonly Incident[], incident: Incident, cap: number): Incident[] {
  if (list.some((existing) => existing.id === incident.id)) return list.slice();
  const t = Date.parse(incident.timestamp);
  const next = list.slice();
  let at = next.length;
  while (at > 0 && Date.parse((next[at - 1] as Incident).timestamp) > t) at--;
  next.splice(at, 0, incident);
  return next.length > cap ? next.slice(next.length - cap) : next;
}

/** `hackerpot_<name> <value>` lines of a Prometheus exposition, unlabelled series only. */
export function parseMetrics(text: string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const line of text.split("\n")) {
    const match = /^hackerpot_([a-zA-Z0-9_]+)\s+([0-9.eE+-]+|NaN|[+-]?Inf)\s*$/.exec(line.trim());
    if (match === null) continue;
    const value = Number(match[2]);
    if (!Number.isNaN(value)) out[match[1] as string] = value;
  }
  return out;
}

/**
 * The path with the token the page was opened with, if any.
 *
 * `auth: { token }` accepts `?token=` so a link can be opened directly. That authenticates
 * the navigation and nothing after it unless the page carries the token on its own
 * requests, which is what this is for. There is no key box: authentication is the server's
 * business, and a page that asked for a key would be asking an operator to paste a secret
 * into a page full of attacker-written text.
 */
export function withToken(path: string, token: string): string {
  if (token === "") return path;
  return `${path}${path.includes("?") ? "&" : "?"}token=${encodeURIComponent(token)}`;
}

/** Only http, https and relative links from the configuration become anchors. */
export function safeHref(href: string): string | undefined {
  const trimmed = href.trim();
  if (trimmed === "") return undefined;
  if (/^[a-z][a-z0-9+.-]*:/i.test(trimmed)) return /^https?:/i.test(trimmed) ? trimmed : undefined;
  // A protocol-relative `//host` is another origin wearing a path's clothes; allowed, it is still http(s).
  return trimmed;
}

/** Exponential backoff for the event stream, capped, with no jitter below a second. */
export function reconnectDelay(attempt: number): number {
  return Math.min(30_000, 1000 * 2 ** Math.max(0, Math.min(attempt, 5)));
}

export interface Failure {
  kind: "auth" | "source" | "off" | "busy" | "network" | "other";
  title: string;
  detail: string;
}

/**
 * What an endpoint's refusal means to the operator reading it.
 *
 * The server says precisely what went wrong in `{ error }`, and the page repeats it; the
 * status decides the framing, because "502" alone sends somebody to look at the
 * dashboard when the thing that is down is the management API behind it.
 */
export function explainFailure(status: number, endpoint: string, message: string): Failure {
  const said = message.trim();
  if (status === 401 || status === 403) {
    return {
      kind: "auth",
      title: status === 401 ? "Not signed in" : "Refused",
      detail: `${endpoint} answered ${status}. This dashboard has authentication configured and this browser's credentials were not accepted${status === 403 ? " for this client or origin" : ""}. Reload the page to sign in again.`,
    };
  }
  if (status === 502) {
    return { kind: "source", title: "The data source could not answer", detail: said !== "" ? said : `${endpoint} answered 502: the store or management API behind this dashboard is unavailable.` };
  }
  if (status === 404 && /switched off/.test(said)) return { kind: "off", title: "Section switched off", detail: said };
  if (status === 503) return { kind: "busy", title: "Live feed unavailable", detail: said !== "" ? said : `${endpoint} answered 503.` };
  if (status === 0) return { kind: "network", title: "Cannot reach the dashboard", detail: `${endpoint} could not be fetched${said !== "" ? `: ${said}` : ""}. The server may have stopped.` };
  return { kind: "other", title: `Request failed (${status})`, detail: said !== "" ? `${endpoint}: ${said}` : `${endpoint} answered ${status}.` };
}

/** The notice shown when the live feed did not deliver everything. `undefined` when it did. */
export function streamNotice(dropped: number, skipped: number): string | undefined {
  const parts: string[] = [];
  if (dropped > 0) parts.push(`${dropped.toLocaleString()} incident${dropped === 1 ? "" : "s"} dropped because this browser fell behind`);
  if (skipped > 0) parts.push(`${skipped.toLocaleString()} skipped by the server's per-viewer rate limit`);
  if (parts.length === 0) return undefined;
  return `The live feed is incomplete: ${parts.join(", and ")}. The charts and lists are missing them until you reload.`;
}

/** The response id as a class-name fragment: the page's own vocabulary, never a selector built from anything else. */
export function responseClass(response: string): string {
  return `resp-${response.toLowerCase().replace(/[^a-z0-9-]/g, "")}`;
}
