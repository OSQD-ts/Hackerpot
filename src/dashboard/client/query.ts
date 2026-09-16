import type { Incident, Sections, TabName } from "./types.js";

/**
 * The page's decisions that are not drawing: which screens exist, what a filter asks the
 * API for, what a failure means, how long to wait before reconnecting.
 *
 * Kept free of the document so each one is a unit test rather than something to find out
 * in a browser.
 */

/** The screens in tab-strip order. */
export const TAB_ORDER: readonly TabName[] = ["overview", "incidents", "statistics", "sessions", "actors", "intel"];

export const TAB_LABELS: Readonly<Record<TabName, string>> = {
  overview: "Overview",
  incidents: "Incidents",
  statistics: "Statistics",
  sessions: "Sessions",
  actors: "Actors",
  intel: "Threat intel",
};

export function availableTabs(sections: Sections): TabName[] {
  return TAB_ORDER.filter((tab) => sections[tab] === true);
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
  /** The search box: a filter expression. Applied here, never sent to the API. See `parseFilter`. */
  query: string;
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
  if (detector !== "" && !incident.detections.some((d) => d.detectorId === detector)) return false;
  if (ip !== "" && incident.ip !== ip) return false;
  if (filter.query.trim() !== "" && !matchesQuery(incident, parseFilter(filter.query, INCIDENT_VOCABULARY), INCIDENT_VOCABULARY)) return false;
  return true;
}

/**
 * A small filter language, shared by every screen that searches.
 *
 * Fielded terms (`ip:198.51.100`, `detector:decoy-path`, `score:>20`), quoted phrases,
 * parentheses, and `$and` / `$or` / `$not`. Adjacent terms are an implicit `$and`.
 *
 * Two decisions worth stating. The operators carry a `$` because a bare "or" is a word that
 * appears in User-Agents and paths, and a language where an ordinary search word silently
 * becomes an operator is one that lies about what it matched. And **nothing here throws**:
 * this backs a box somebody types into, so half-written input parses to the best available
 * reading rather than blanking the screen between keystrokes.
 *
 * The vocabulary is a parameter so a second screen can reuse the grammar over a different
 * shape. Two parsers would be two dialects within a week. Adapted from bothandlerjs.
 */
export type FilterNode =
  | { kind: "all" }
  | { kind: "term"; field: string | undefined; op: "has" | "gt" | "gte" | "lt" | "lte"; value: string; number: number | undefined }
  | { kind: "and"; nodes: FilterNode[] }
  | { kind: "or"; nodes: FilterNode[] }
  | { kind: "not"; node: FilterNode };

/** How a record answers a field, and which fields a bare word searches. */
export interface Vocabulary<T> {
  fields: Record<string, (record: T) => string | number | readonly string[] | undefined>;
  free: readonly string[];
}

/** Longest expression parsed. Beyond this the box holds a paste, not a query. */
export const MAX_QUERY_CHARS = 512;

const OPERATORS = new Set(["$and", "$or", "$not"]);

/** Splits an expression into words, quoted phrases and parentheses. Rejects nothing. */
function tokenize(text: string): string[] {
  const tokens: string[] = [];
  let index = 0;
  while (index < text.length) {
    const char = text[index] as string;
    if (/\s/.test(char)) {
      index += 1;
      continue;
    }
    if (char === "(" || char === ")") {
      tokens.push(char);
      index += 1;
      continue;
    }
    if (char === '"') {
      const end = text.indexOf('"', index + 1);
      // An unclosed quote takes the rest of the line: somebody is still typing it.
      tokens.push(end === -1 ? text.slice(index + 1) : text.slice(index + 1, end));
      index = end === -1 ? text.length : end + 1;
      continue;
    }
    let end = index;
    while (end < text.length && !/[\s()]/.test(text[end] as string)) end += 1;
    tokens.push(text.slice(index, end));
    index = end;
  }
  return tokens;
}

/** One word, read as a field term when its prefix names a field the vocabulary knows. */
function termOf(token: string, vocabulary: Vocabulary<unknown>): FilterNode {
  const colon = token.indexOf(":");
  let field: string | undefined;
  let rest = token;
  if (colon > 0) {
    const name = token.slice(0, colon).toLowerCase();
    // Only a name the vocabulary knows is a field. Anything else is a word that happens to
    // contain a colon — a URL, a timestamp, an IPv6 address.
    if (Object.hasOwn(vocabulary.fields, name)) {
      field = name;
      rest = token.slice(colon + 1);
    }
  }
  const comparison = /^(>=|<=|>|<)(.*)$/.exec(rest);
  const symbol = comparison?.[1];
  const op = symbol === undefined ? "has" : symbol === ">" ? "gt" : symbol === ">=" ? "gte" : symbol === "<" ? "lt" : "lte";
  const value = comparison === null ? rest : (comparison[2] as string);
  const numeric = Number(value);
  return { kind: "term", field, op, value: value.toLowerCase(), number: value.trim() !== "" && Number.isFinite(numeric) ? numeric : undefined };
}

/** Parses an expression. Anything unreadable is skipped rather than refused. */
export function parseFilter<T>(text: string, vocabulary: Vocabulary<T>): FilterNode {
  const tokens = tokenize(text.slice(0, MAX_QUERY_CHARS));
  let at = 0;

  const parsePrimary = (): FilterNode => {
    const token = tokens[at];
    if (token === undefined) return { kind: "all" };
    at += 1;
    if (token === "(") {
      const inner = parseOr();
      // A missing closing parenthesis is somebody mid-expression, not an error.
      if (at < tokens.length && tokens[at] === ")") at += 1;
      return inner;
    }
    if (token === ")") return { kind: "all" };
    if (OPERATORS.has(token.toLowerCase())) return { kind: "all" };
    return termOf(token, vocabulary as Vocabulary<unknown>);
  };

  const parseNot = (): FilterNode => {
    if (at < tokens.length && (tokens[at] as string).toLowerCase() === "$not") {
      at += 1;
      return { kind: "not", node: parseNot() };
    }
    return parsePrimary();
  };

  const parseAnd = (): FilterNode => {
    const nodes: FilterNode[] = [];
    while (at < tokens.length) {
      const token = tokens[at] as string;
      if (token === ")" || token.toLowerCase() === "$or") break;
      if (token.toLowerCase() === "$and") {
        at += 1;
        continue;
      }
      nodes.push(parseNot());
    }
    if (nodes.length === 0) return { kind: "all" };
    return nodes.length === 1 ? (nodes[0] as FilterNode) : { kind: "and", nodes };
  };

  function parseOr(): FilterNode {
    const nodes = [parseAnd()];
    while (at < tokens.length && (tokens[at] as string).toLowerCase() === "$or") {
      at += 1;
      nodes.push(parseAnd());
    }
    return nodes.length === 1 ? (nodes[0] as FilterNode) : { kind: "or", nodes };
  }

  return parseOr();
}

function textOf(value: string | number | readonly string[] | undefined): string[] {
  if (value === undefined) return [];
  if (Array.isArray(value)) return value.map((entry) => String(entry).toLowerCase());
  return [String(value as string | number).toLowerCase()];
}

/** Whether one record satisfies a parsed expression. */
export function matchesQuery<T>(record: T, node: FilterNode, vocabulary: Vocabulary<T>): boolean {
  switch (node.kind) {
    case "all":
      return true;
    case "and":
      return node.nodes.every((child) => matchesQuery(record, child, vocabulary));
    case "or":
      return node.nodes.some((child) => matchesQuery(record, child, vocabulary));
    case "not":
      return !matchesQuery(record, node.node, vocabulary);
    case "term": {
      if (node.value === "" && node.op === "has") return true;
      const names = node.field === undefined ? vocabulary.free : [node.field];
      return names.some((name) => {
        const read = vocabulary.fields[name];
        if (read === undefined) return false;
        const raw = read(record);
        if (node.op === "has") return textOf(raw).some((value) => value.includes(node.value));
        // A comparison only means something against a number, and only against one value.
        const value = Array.isArray(raw) ? Number.NaN : Number(raw);
        if (!Number.isFinite(value) || node.number === undefined) return false;
        return node.op === "gt" ? value > node.number : node.op === "gte" ? value >= node.number : node.op === "lt" ? value < node.number : value <= node.number;
      });
    }
  }
}

/** The fields an incident answers to, and what a bare word searches. */
export const INCIDENT_VOCABULARY: Vocabulary<Incident> = {
  fields: {
    ip: (incident) => incident.ip,
    path: (incident) => incident.path,
    method: (incident) => incident.method,
    detector: (incident) => incident.detections.map((detection) => detection.detectorId),
    reason: (incident) => incident.detections.map((detection) => detection.reason),
    action: (incident) => incident.respondedWith,
    rule: (incident) => incident.rule,
    score: (incident) => incident.score,
    total: (incident) => incident.totalScore,
    ua: (incident) => {
      const value = incident.headers["user-agent"];
      return Array.isArray(value) ? value.join(" ") : value;
    },
    actor: (incident) => incident.actor?.name,
  },
  // A bare word searches what somebody scanning the table is already looking at.
  free: ["path", "ip", "detector", "action", "ua", "actor"],
};

/**
 * Whether a value off the event stream is an incident at all.
 *
 * The stream is the server's, but a page that trusted its shape would throw on the first
 * malformed frame from a proxy or a future version and stop drawing for good. A frame
 * that fails this is dropped rather than half-rendered.
 */
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
    (v["detections"] as unknown[]).every((d) => typeof d === "object" && d !== null && typeof (d as Record<string, unknown>)["detectorId"] === "string") &&
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
