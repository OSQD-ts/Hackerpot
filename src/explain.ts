import type { EvaluationResult, HoneypotEngine } from "./core.js";
import type { RequestFacts } from "./detectors/types.js";
import { parseQuery, pathOf } from "./http-request.js";

/**
 * One request, and why the detectors decided what they did. Adapted from bothandlerjs.
 *
 * Accepts what people actually have to hand when a question comes up: a User-Agent pasted
 * from a log, a curl command copied from a browser's developer tools, or a block of raw
 * request headers.
 */

export interface ExplainOverrides {
  ip?: string | undefined;
  /** Path and query, e.g. `/login?next=/admin`. Wins over one found in the input. */
  url?: string | undefined;
  method?: string | undefined;
}

/** Shell-style words: single and double quotes group, a backslash escapes, `\`+newline continues. */
function shellWords(input: string): string[] {
  const words: string[] = [];
  let current = "";
  let quote: "'" | '"' | undefined;
  let started = false;
  for (let i = 0; i < input.length; i += 1) {
    const ch = input[i]!;
    if (quote === "'") {
      if (ch === "'") quote = undefined;
      else current += ch;
      continue;
    }
    if (ch === "\\") {
      const next = input[i + 1];
      if (next === "\n") {
        i += 1;
        continue;
      }
      if (next !== undefined) {
        current += next;
        started = true;
        i += 1;
      }
      continue;
    }
    if (quote === '"') {
      if (ch === '"') quote = undefined;
      else current += ch;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      started = true;
      continue;
    }
    if (/\s/.test(ch)) {
      if (started) words.push(current);
      current = "";
      started = false;
      continue;
    }
    current += ch;
    started = true;
  }
  if (started) words.push(current);
  return words;
}

/** Path and query of a URL or a bare target, so a pasted `https://site/x?y` reads as `/x?y`. */
function targetOf(url: string): string {
  if (url.startsWith("/")) return url;
  try {
    const parsed = new URL(url);
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return `/${url}`;
  }
}

interface Parsed {
  method: string;
  target: string;
  headers: Record<string, string>;
  body?: string;
}

function addHeader(headers: Record<string, string>, line: string): void {
  const colon = line.indexOf(":");
  if (colon <= 0) return;
  const name = line.slice(0, colon).trim().toLowerCase();
  if (name === "" || /\s/.test(name)) return;
  headers[name] = headers[name] === undefined ? line.slice(colon + 1).trim() : `${headers[name]}, ${line.slice(colon + 1).trim()}`;
}

function parseCurl(input: string): Parsed {
  const words = shellWords(input).slice(1);
  const parsed: Parsed = { method: "GET", target: "/", headers: {} };
  let explicitMethod = false;
  for (let i = 0; i < words.length; i += 1) {
    const word = words[i]!;
    const value = words[i + 1];
    if ((word === "-H" || word === "--header") && value !== undefined) {
      addHeader(parsed.headers, value);
      i += 1;
    } else if ((word === "-A" || word === "--user-agent") && value !== undefined) {
      parsed.headers["user-agent"] = value;
      i += 1;
    } else if ((word === "-e" || word === "--referer") && value !== undefined) {
      parsed.headers["referer"] = value;
      i += 1;
    } else if ((word === "-b" || word === "--cookie") && value !== undefined) {
      parsed.headers["cookie"] = value;
      i += 1;
    } else if ((word === "-X" || word === "--request") && value !== undefined) {
      parsed.method = value.toUpperCase();
      explicitMethod = true;
      i += 1;
    } else if (["-d", "--data", "--data-raw", "--data-binary", "--data-urlencode"].includes(word) && value !== undefined) {
      parsed.body = parsed.body === undefined ? value : `${parsed.body}&${value}`;
      if (!explicitMethod) parsed.method = "POST";
      i += 1;
    } else if (word === "--url" && value !== undefined) {
      parsed.target = targetOf(value);
      i += 1;
    } else if (word === "-I" || word === "--head") {
      parsed.method = "HEAD";
      explicitMethod = true;
    } else if (!word.startsWith("-")) {
      parsed.target = targetOf(word);
    }
  }
  if (parsed.headers["host"] === undefined) {
    const url = words.find((word) => /^https?:\/\//i.test(word));
    if (url !== undefined) {
      try {
        parsed.headers["host"] = new URL(url).host;
      } catch {
        // No host to take.
      }
    }
  }
  // curl sends these unless told otherwise, and their absence would read as a scripted client.
  parsed.headers["user-agent"] ??= "curl/8.4.0";
  parsed.headers["accept"] ??= "*/*";
  return parsed;
}

/**
 * Turns pasted text into request facts. A curl command, a request line followed by
 * headers, a bare block of `Name: value` lines, or, failing all of those, a User-Agent.
 * Throws on empty input.
 */
export function parseRequestText(text: string, overrides: ExplainOverrides = {}): RequestFacts {
  const input = text.trim();
  if (input === "") throw new Error("nothing to explain: pass a User-Agent, a curl command or a block of request headers");

  let parsed: Parsed;
  if (/^curl\s/i.test(input)) {
    parsed = parseCurl(input);
  } else {
    const lines = input.split(/\r?\n/);
    const requestLine = /^([A-Z]+)\s+(\S+)(?:\s+HTTP\/[\d.]+)?$/.exec(lines[0]!.trim());
    const headerLines = requestLine ? lines.slice(1) : lines;
    const looksLikeHeaders = headerLines.some((line) => /^[A-Za-z0-9-]+:\s/.test(line));
    if (requestLine || looksLikeHeaders) {
      parsed = { method: requestLine?.[1] ?? "GET", target: requestLine ? targetOf(requestLine[2]!) : "/", headers: {} };
      const blank = headerLines.findIndex((line) => line.trim() === "");
      for (const line of blank === -1 ? headerLines : headerLines.slice(0, blank)) addHeader(parsed.headers, line);
      if (blank !== -1) {
        const body = headerLines.slice(blank + 1).join("\n");
        if (body !== "") parsed.body = body;
      }
    } else {
      // One line, no colon-separated headers: a User-Agent, with the headers a browser sends
      // alongside one, so the answer is about the User-Agent rather than their absence.
      parsed = {
        method: "GET",
        target: "/",
        headers: { "user-agent": input, accept: "text/html,*/*;q=0.8", "accept-language": "en-US,en;q=0.9", "accept-encoding": "gzip, deflate, br" },
      };
    }
  }

  const target = overrides.url !== undefined ? targetOf(overrides.url) : parsed.target;
  parsed.headers["host"] ??= "localhost";
  const rawHeaders = Object.entries(parsed.headers).flat();
  return {
    method: (overrides.method ?? parsed.method).toUpperCase(),
    path: pathOf(target),
    query: parseQuery(target),
    headers: parsed.headers,
    rawHeaders,
    ip: overrides.ip ?? "203.0.113.10",
    httpVersion: "1.1",
    ...(parsed.body !== undefined ? { body: parsed.body } : {}),
  };
}

/** The request and the engine's verdict, as text for a terminal. */
export function formatExplanation(facts: RequestFacts, result: EvaluationResult): string {
  const ua = facts.headers["user-agent"];
  const out = [
    `Request   ${facts.method} ${result.path}${Object.keys(facts.query).length > 0 ? ` (${Object.keys(facts.query).length} query parameter(s))` : ""}`,
    `From      ${facts.ip}${ua ? `, User-Agent ${JSON.stringify(Array.isArray(ua) ? ua[0] : ua)}` : ""}`,
    "",
  ];
  if (result.detections.length === 0) {
    out.push("No detector fired. The honeypot would leave this request alone.");
  } else {
    out.push(`${result.detections.length} detector(s) fired, score ${result.score}:`);
    for (const detection of result.detections) {
      const tags = [detection.certain ? "proof" : undefined, detection.family ? `family ${detection.family}` : undefined].filter(Boolean).join(", ");
      out.push(`  +${String(detection.score).padEnd(3)} ${detection.detectorId.padEnd(24)} ${detection.reason}${tags ? `  [${tags}]` : ""}`);
    }
    out.push("", `Response  ${result.actionId || "none"}${result.downgradedFrom ? ` (the policy chose ${result.downgradedFrom}, refused without proof)` : ""}`);
  }
  if (result.shadowDetections.length > 0) {
    out.push("", "Shadowed detectors (reported only):");
    for (const detection of result.shadowDetections) out.push(`  ${detection.detectorId.padEnd(24)} ${detection.reason}`);
  }
  return `${out.join("\n")}\n`;
}

/**
 * Evaluates one request on the given engine as a dry run. Give it an engine of its own
 * (a fresh store, no `onHit`): an explanation must not be recorded as an incident.
 */
export async function explainRequest(engine: HoneypotEngine, facts: RequestFacts): Promise<EvaluationResult> {
  return engine.evaluate(facts);
}
