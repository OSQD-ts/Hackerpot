import { readFileSync } from "node:fs";
import type { EvaluationResult, HoneypotEngine } from "./core.js";
import type { RequestFacts } from "./detectors/types.js";
import { parseQuery, pathOf } from "./http-request.js";

/** One request recovered from an access log. */
export interface LogRequest {
  ip: string;
  method: string;
  /** Path and query string, as logged. */
  target: string;
  timestamp: Date;
  /** The status the application answered with, when the log records it. */
  status?: number;
  /** What the log recorded of the headers: usually a User-Agent and a Referer at most. */
  headers: Record<string, string>;
}

/** Common and combined log format: `ip ident user [time] "METHOD target PROTO" status size "referer" "ua"`. */
const COMBINED = /^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Za-z]+) (\S+)(?: [^"]*)?" (\d{3}) \S+(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?/;
const CLF_TIME = /^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/;
const MONTHS: Record<string, number> = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

/** `30/Aug/2026:09:00:00 +0200` → the instant it names. */
function parseClfTime(value: string): Date | undefined {
  const match = CLF_TIME.exec(value);
  if (!match) return undefined;
  const month = MONTHS[match[2]!];
  if (month === undefined) return undefined;
  const utc = Date.UTC(Number(match[3]), month, Number(match[1]), Number(match[4]), Number(match[5]), Number(match[6]));
  const offsetMs = (Number(match[8]) * 60 + Number(match[9])) * 60_000;
  return new Date(match[7] === "+" ? utc - offsetMs : utc + offsetMs);
}

/** A combined or common log format line, or one JSON object per line. Undefined for anything else. */
export function parseLogLine(line: string): LogRequest | undefined {
  const trimmed = line.trim();
  if (trimmed === "") return undefined;
  if (trimmed.startsWith("{")) return parseJsonLine(trimmed);

  const match = COMBINED.exec(trimmed);
  if (!match) return undefined;
  const timestamp = parseClfTime(match[2]!);
  if (!timestamp) return undefined;
  const headers: Record<string, string> = {};
  if (match[6] !== undefined && match[6] !== "-") headers["referer"] = match[6];
  if (match[7] !== undefined && match[7] !== "-") headers["user-agent"] = match[7];
  return { ip: match[1]!, method: match[3]!.toUpperCase(), target: match[4]!, timestamp, status: Number(match[5]), headers };
}

function parseJsonLine(line: string): LogRequest | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return undefined;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const record = parsed as Record<string, unknown>;
  const pick = (...keys: string[]): unknown => keys.map((key) => record[key]).find((value) => value !== undefined);

  const ip = pick("ip", "remote_addr", "client_ip", "remoteAddress");
  const method = pick("method", "request_method");
  const target = pick("url", "uri", "request_uri", "path", "target");
  if (typeof ip !== "string" || typeof method !== "string" || typeof target !== "string") return undefined;

  const time = pick("timestamp", "time", "ts", "@timestamp");
  const timestamp = typeof time === "string" || typeof time === "number" ? new Date(time) : new Date();
  if (Number.isNaN(timestamp.getTime())) return undefined;

  const headers: Record<string, string> = {};
  const logged = pick("headers");
  if (logged !== null && typeof logged === "object") {
    for (const [name, value] of Object.entries(logged as Record<string, unknown>)) if (typeof value === "string") headers[name.toLowerCase()] = value;
  }
  const userAgent = pick("user_agent", "userAgent", "http_user_agent");
  if (typeof userAgent === "string") headers["user-agent"] ??= userAgent;
  const referer = pick("referer", "referrer", "http_referer");
  if (typeof referer === "string") headers["referer"] ??= referer;

  const request: LogRequest = { ip, method: method.toUpperCase(), target, timestamp, headers };
  const status = pick("status", "status_code");
  if (typeof status === "number") request.status = status;
  else if (typeof status === "string" && /^\d{3}$/.test(status)) request.status = Number(status);
  return request;
}

export interface ReplaySummary {
  /** Non-empty lines read. */
  lines: number;
  parsed: number;
  /** Lines in a format this does not recognise. */
  skipped: number;
  /** Requests at least one detector flagged. */
  flagged: number;
  byDetector: Record<string, number>;
  /** The response action each flagged request would have received. */
  byResponse: Record<string, number>;
  /** Blocks refused because no detection was proof. */
  downgraded: number;
  /** The ten sources with the highest cumulative score. */
  topSources: Array<{ ip: string; requests: number; flagged: number; totalScore: number }>;
}

export interface ReplayOptions {
  /** Called for every flagged request, with what the engine decided. */
  onFlagged?: (request: LogRequest, result: EvaluationResult) => void;
}

/**
 * Runs logged requests through the engine in the order and at the times the log recorded,
 * and summarises what it would have done. Nothing is served and nothing is blocked.
 *
 * A log comes from an application serving real users, so this applies middleware rules:
 * a path counts toward `path-bruteforce` only once the log shows the app answered 404 (or a
 * detector flagged it), and a block needs proof. The facts are marked `partialHeaders`, so
 * detectors that reason from a missing header skip: a log records a User-Agent and a
 * Referer at most, and everything else is absent from every line. Use an engine with its
 * own store, so a replay never writes into a live one.
 */
export async function replayLog(engine: HoneypotEngine, lines: Iterable<string>, options: ReplayOptions = {}): Promise<ReplaySummary> {
  const summary: ReplaySummary = { lines: 0, parsed: 0, skipped: 0, flagged: 0, byDetector: {}, byResponse: {}, downgraded: 0, topSources: [] };
  const sources = new Map<string, { requests: number; flagged: number; totalScore: number }>();

  for (const line of lines) {
    if (line.trim() === "") continue;
    summary.lines += 1;
    const request = parseLogLine(line);
    if (!request) {
      summary.skipped += 1;
      continue;
    }
    summary.parsed += 1;

    const facts: RequestFacts = {
      method: request.method,
      path: pathOf(request.target),
      query: parseQuery(request.target),
      headers: request.headers,
      ip: request.ip,
      partialHeaders: true,
    };
    const result = await engine.evaluate(facts, { now: request.timestamp, activityStatus: "passed", blockRequiresProof: true });
    if (result.detections.length > 0 || request.status === 404) result.tracker.confirmPath(result.path);

    const source = sources.get(request.ip) ?? { requests: 0, flagged: 0, totalScore: 0 };
    source.requests += 1;
    if (result.detections.length > 0) {
      summary.flagged += 1;
      source.flagged += 1;
      source.totalScore = Math.max(source.totalScore, result.totalScore);
      for (const detection of result.detections) summary.byDetector[detection.detectorId] = (summary.byDetector[detection.detectorId] ?? 0) + 1;
      summary.byResponse[result.actionId] = (summary.byResponse[result.actionId] ?? 0) + 1;
      if (result.downgradedFrom !== undefined) summary.downgraded += 1;
      options.onFlagged?.(request, result);
    }
    sources.set(request.ip, source);
  }

  summary.topSources = [...sources.entries()]
    .map(([ip, source]) => ({ ip, ...source }))
    .filter((source) => source.flagged > 0)
    .sort((a, b) => b.totalScore - a.totalScore || b.flagged - a.flagged)
    .slice(0, 10);
  return summary;
}

/** A log file's lines. */
export function readLogLines(path: string): string[] {
  return readFileSync(path, "utf8").split(/\r?\n/);
}

/** The summary as text, for a terminal. */
export function formatReplaySummary(summary: ReplaySummary): string {
  const rows = (counts: Record<string, number>): string[] =>
    Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .map(([name, count]) => `  ${name.padEnd(26)} ${count}`);
  const share = summary.parsed === 0 ? "0" : ((summary.flagged / summary.parsed) * 100).toFixed(1);
  const out = [
    `Replayed ${summary.lines} log lines: ${summary.parsed} parsed, ${summary.skipped} skipped (unrecognised format).`,
    `Flagged ${summary.flagged} requests (${share}%).`,
  ];
  if (summary.flagged > 0) {
    out.push("", "By detector:", ...rows(summary.byDetector), "", "Responses it would have sent:", ...rows(summary.byResponse));
    out.push("", `Blocks refused for lack of proof: ${summary.downgraded}`);
    out.push("", "Top sources:");
    for (const source of summary.topSources) {
      out.push(`  ${source.ip.padEnd(26)} ${source.flagged} flagged of ${source.requests} requests, total score ${source.totalScore}`);
    }
  }
  return `${out.join("\n")}\n`;
}
