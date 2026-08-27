import { timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";

/** Extract a presented API key from `Authorization: Bearer <key>`, `X-API-Key`, or a `?api_key=` query param (the last for WebSocket clients that can't set headers). */
export function extractApiKey(req: IncomingMessage): string | undefined {
  const auth = req.headers["authorization"];
  if (typeof auth === "string" && auth.toLowerCase().startsWith("bearer ")) {
    return auth.slice(7).trim();
  }
  const header = req.headers["x-api-key"];
  if (typeof header === "string" && header.trim()) return header.trim();
  if (Array.isArray(header) && header[0]?.trim()) return header[0].trim();

  const url = req.url ?? "";
  const q = url.indexOf("?");
  if (q !== -1) {
    const fromQuery = new URLSearchParams(url.slice(q)).get("api_key");
    if (fromQuery) return fromQuery;
  }
  return undefined;
}

/** Constant-time check of a presented key against the accepted set. */
export function isAuthorized(presented: string | undefined, acceptedKeys: string[]): boolean {
  if (!presented || acceptedKeys.length === 0) return false;
  const presentedBuf = Buffer.from(presented);
  let ok = false;
  for (const key of acceptedKeys) {
    const keyBuf = Buffer.from(key);
    // Compare against a same-length buffer so timingSafeEqual never throws. Compute the
    // content and length comparisons UNCONDITIONALLY (not `length === … && timingSafeEqual`)
    // so a length mismatch never short-circuits the compare and leaks the key's length by
    // timing — the value the code above claims to protect. `ok |=` accumulates without a
    // short-circuit that could reveal which candidate matched.
    const padded = Buffer.alloc(presentedBuf.length);
    keyBuf.copy(padded);
    const contentEqual = timingSafeEqual(presentedBuf, padded);
    const lengthEqual = presentedBuf.length === keyBuf.length;
    ok = Boolean(Number(ok) | Number(contentEqual && lengthEqual));
  }
  return ok;
}
