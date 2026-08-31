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

/** The path portion of a request URL, without its query string. */
export function pathOf(url: string): string {
  const queryStart = url.indexOf("?");
  return (queryStart === -1 ? url : url.slice(0, queryStart)) || "/";
}
