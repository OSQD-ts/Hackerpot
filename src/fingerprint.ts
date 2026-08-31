import { createHash } from "node:crypto";
import type { RequestFacts } from "./detectors/types.js";

/**
 * Coarse client family from the User-Agent — deliberately broad. It groups an actor's
 * tooling ("all their curl", "all their Chrome") without splitting on version noise,
 * and separates two clients that happen to share a header order but are plainly
 * different software.
 */
export function uaClass(userAgent: string | undefined): string {
  if (!userAgent) return "none";
  const ua = userAgent.toLowerCase();
  if (/\b(curl|wget|libwww|python-requests|python-urllib|go-http-client|java|okhttp|axios|node-fetch|got|httpie|postman)\b/.test(ua)) {
    const m = ua.match(/\b(curl|wget|libwww|python|go-http-client|java|okhttp|axios|node-fetch|got|httpie|postman)\b/);
    return m ? `tool:${m[1]}` : "tool";
  }
  // Grouped, and deliberately without word boundaries. Written as
  // `/\bbot|crawl|…|zgrab\b/`, the alternation bound `\b` to only the FIRST and LAST
  // branch — so `\bbot` demanded a word boundary before "bot" and `zgrab\b` one after,
  // which is exactly backwards for the names this is looking for. Every mainstream
  // crawler ("googlebot", "bingbot", "AhrefsBot") failed the leading boundary and was
  // classified "other", i.e. the branch never matched the traffic it names. These are
  // distinctive substrings; substring matching is the intent.
  if (/(bot|crawl|spider|scan|nikto|sqlmap|nmap|masscan|zgrab)/.test(ua)) return "bot";
  if (ua.includes("edg/")) return "browser:edge";
  if (ua.includes("firefox/")) return "browser:firefox";
  if (ua.includes("chrome/")) return "browser:chrome";
  if (ua.includes("safari/")) return "browser:safari";
  return "other";
}

/**
 * Extracts the ordered list of header *names* a client sent. Node's `rawHeaders`
 * preserves both order and the client's original casing (`[name, value, name, …]`);
 * the order and set of headers is characteristic of the client software and far more
 * stable across IPs than the source address. Falls back to the parsed-headers key
 * order when `rawHeaders` isn't available.
 */
export function headerOrder(facts: RequestFacts): string[] {
  if (facts.rawHeaders && facts.rawHeaders.length >= 2) {
    const names: string[] = [];
    for (let i = 0; i < facts.rawHeaders.length; i += 2) names.push(facts.rawHeaders[i]!.toLowerCase());
    return names;
  }
  return Object.keys(facts.headers);
}

/**
 * Computes an **actor fingerprint** — a short, stable hash of the client's header
 * ordering plus its UA family. Two requests from different IPs that share a
 * fingerprint are very likely the same tool driven by the same actor, which is how
 * the honeypot correlates an attacker across a rotating set of source addresses
 * (something a per-IP view fundamentally can't do). It is a heuristic, not identity:
 * many benign clients of one browser share a fingerprint too, so it's used to
 * *correlate already-suspicious traffic*, never to flag traffic on its own.
 */
export function computeFingerprint(facts: RequestFacts): string {
  const order = headerOrder(facts).join(",");
  const ua = facts.headers["user-agent"];
  const cls = uaClass(Array.isArray(ua) ? ua[0] : ua);
  return createHash("sha256").update(`${order}|${cls}`).digest("hex").slice(0, 16);
}
