import type { IncomingMessage } from "node:http";
import { StringDecoder } from "node:string_decoder";

/**
 * Shared request-parsing helpers for the two HTTP front ends.
 *
 * `middleware.ts` and `server.ts` each carried their own byte-identical copy of
 * `readBody`/`parseQuery`. Two copies of the code that decides how much
 * attacker-controlled input we buffer is exactly the thing that drifts: a bound
 * tightened in one entrypoint and not the other is a hole in whichever one was
 * forgotten. There is one copy now.
 */

/** Most bytes of a request body read into memory. Anything past this is dropped and marked. */
export const MAX_BODY_BYTES = 64 * 1024;

const TRUNCATED_SUFFIX = "…[truncated]";

/** Methods that never carry a body worth inspecting — reading one would only stall the request. */
export function mayHaveBody(method: string): boolean {
  const upper = method.toUpperCase();
  return upper !== "GET" && upper !== "HEAD";
}

/**
 * Reads at most `MAX_BODY_BYTES` of the request body as UTF-8.
 *
 * Decoding is incremental through a `StringDecoder` rather than `chunk.toString()`
 * per chunk. A multi-byte character split across a TCP segment boundary — routine
 * for any non-ASCII payload, and trivially forced by an attacker who controls where
 * the split lands — decodes to replacement characters under per-chunk `toString`,
 * silently mutating the bytes every body detector then matches against. The decoder
 * carries the partial sequence across chunks instead.
 *
 * The cap keeps the *prefix*: an oversized chunk is sliced to whatever budget is
 * left rather than discarded whole, so the payload (which is always near the front)
 * survives instead of ending at an arbitrary chunk boundary.
 */
export function readBody(req: IncomingMessage): Promise<string | undefined> {
  if (!mayHaveBody(req.method ?? "GET")) return Promise.resolve(undefined);

  return new Promise((resolve) => {
    const decoder = new StringDecoder("utf8");
    let data = "";
    let bytes = 0;
    let truncated = false;
    let settled = false;

    const finish = (value: string | undefined): void => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    req.on("data", (chunk: Buffer) => {
      if (truncated) return;
      const remaining = MAX_BODY_BYTES - bytes;
      if (chunk.length >= remaining) {
        truncated = true;
        data += decoder.write(chunk.subarray(0, remaining)) + decoder.end();
        bytes = MAX_BODY_BYTES;
        return;
      }
      bytes += chunk.length;
      data += decoder.write(chunk);
    });
    req.on("end", () => finish(truncated ? `${data}${TRUNCATED_SUFFIX}` : data + decoder.end()));
    // A body we could not read in full is not a body we can reason about.
    req.on("error", () => finish(undefined));
    req.on("aborted", () => finish(undefined));
  });
}

/**
 * Parses the query string into a **null-prototype** bag.
 *
 * The null prototype is load-bearing twice over: a literal `?__proto__=…` param
 * becomes an ordinary own key detectors can actually see (a plain object silently
 * swallows it through the `__proto__` setter), and the honeypot itself can never be
 * prototype-polluted by parsing a request.
 */
export function parseQuery(url: string): Record<string, string> {
  const query: Record<string, string> = Object.create(null);
  const queryStart = url.indexOf("?");
  if (queryStart === -1) return query;
  for (const [key, value] of new URLSearchParams(url.slice(queryStart)).entries()) query[key] = value;
  return query;
}

/** Most query parameters any detector inspects. See `boundedQuery`. */
export const MAX_QUERY_PARAMS = 256;

/**
 * The first `MAX_QUERY_PARAMS` parameters of a query bag, and how many were left out.
 *
 * Around ten detectors decode and scan every query value, so a request's cost grew with
 * its parameter count. Measured: 20 parameters cost 0.08 ms to evaluate, and a 16 KB URL
 * of 4 000 tiny ones cost 9.9 ms, about 130 times an ordinary request, from one
 * unauthenticated GET. In middleware mode that CPU comes out of the host app's event
 * loop, and a hundred such requests a second fill a core. Past the cap nothing more is
 * scanned, and the engine records how many were dropped so `header-anomaly` flags the
 * flood itself: a payload hidden behind a thousand junk parameters still arrives on a
 * request no legitimate client sends.
 */
export function boundedQuery(query: Record<string, string>): { query: Record<string, string>; dropped: number } {
  const keys = Object.keys(query);
  if (keys.length <= MAX_QUERY_PARAMS) return { query, dropped: 0 };
  const kept: Record<string, string> = Object.create(null);
  for (const key of keys.slice(0, MAX_QUERY_PARAMS)) kept[key] = query[key]!;
  return { query: kept, dropped: keys.length - MAX_QUERY_PARAMS };
}

/** Longest original request target kept as `rawPath` alongside the normalised path. */
export const MAX_RAW_PATH_CHARS = 2048;

/** `GET http://elsewhere/…`: the form a request addressed to a proxy takes. */
const ABSOLUTE_FORM = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * The path detection matches against: decoded once, `\` and repeated `/` collapsed,
 * `.` and `..` resolved, trailing slash dropped.
 *
 * Detectors used to match the path exactly as sent, so `//.env`, `/./.env`, `/%2eenv`
 * and `/foo/../.env` all scored nothing while `/.env` scored 10. A Node server or static
 * handler in front of a real app resolves every one of those to the same file, so in
 * middleware mode a probe could fetch the real thing while the honeypot recorded nothing.
 *
 * Decoding is single-pass on purpose: decoding until the value stops changing is how
 * `%252e` becomes `.` and how traversal filters are bypassed. That also means this is
 * not idempotent, so it must run exactly once per request; the engine does it. An
 * absolute-form target is returned unchanged, because collapsing its `//` would destroy
 * the evidence `header-anomaly` reads. Adapted from bothandlerjs.
 */
export function normalizePath(rawPath: string): string {
  if (ABSOLUTE_FORM.test(rawPath)) return rawPath;
  let path = rawPath;
  try {
    path = decodeURIComponent(rawPath);
  } catch {
    // Malformed percent-encoding. Keep the raw form rather than guess at a decoding.
  }
  path = path.replace(/\\/g, "/").replace(/\/{2,}/g, "/");
  if (!path.startsWith("/")) path = `/${path}`;

  // `/.` rather than `./`: a target ending in `/..` has no `./` in it and must resolve too.
  if (path.includes("/.")) {
    const resolved: string[] = [];
    for (const segment of path.split("/")) {
      if (segment === "" || segment === ".") continue;
      if (segment === "..") resolved.pop();
      else resolved.push(segment);
    }
    path = `/${resolved.join("/")}`;
  }
  return path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : path;
}

/** The path portion of a request URL, without its query string. */
export function pathOf(url: string): string {
  const queryStart = url.indexOf("?");
  return (queryStart === -1 ? url : url.slice(0, queryStart)) || "/";
}
