import type { Incident } from "./types.js";

/**
 * Payload auto-decode.
 *
 * Attackers hide payloads behind URL-encoding, base64 and hex, often layered. This peels
 * those layers off the request's own strings and surfaces what is inside, so an operator
 * reads the actual intent without decoding by hand.
 *
 * The output is attacker-written text by construction, and frequently text designed to be
 * dangerous when interpreted: `<script>`, `${jndi:...}`, a shell pipeline. It reaches the
 * page through `textContent` like everything else, which is why decoding it here is safe
 * and why nothing in this file ever needs to escape anything.
 */

/** Longest value considered. A multi-megabyte body is not something a person reads as a payload. */
const MAX_VALUE = 8192;
/** Layers peeled at most, so a value that decodes to itself forever cannot spin. */
const MAX_LAYERS = 5;
/** Rows shown per incident. */
export const MAX_DECODED = 12;

export interface DecodedValue {
  /** Where the value was found: `query`, `header user-agent`, `body`, `<detector> sample`. */
  src: string;
  /** The chain applied, outermost first: `url → base64`. */
  encoding: string;
  raw: string;
  decoded: string;
}

function asciiRatio(s: string): number {
  if (s === "") return 0;
  let printable = 0;
  let total = 0;
  for (const c of s) {
    total++;
    const n = c.codePointAt(0) ?? 0;
    if (n === 9 || n === 10 || n === 13 || (n >= 32 && n < 127)) printable++;
  }
  return printable / total;
}

/**
 * A decode only counts if what came out reads like text somebody would send. Without the
 * alphanumeric-run test any sixteen hex digits (an actor fingerprint, a request id)
 * "decode" to high-byte garbage and get reported as a hidden payload.
 */
export function looksInteresting(s: string): boolean {
  return s.length >= 3 && asciiRatio(s) > 0.75 && /[A-Za-z0-9]{3}/.test(s);
}

export function tryUrl(s: string): string | undefined {
  if (!/%[0-9a-fA-F]{2}/.test(s)) return undefined;
  try {
    const d = decodeURIComponent(s.replace(/\+/g, " "));
    return d !== s ? d : undefined;
  } catch {
    return undefined;
  }
}

export function tryBase64(s: string): string | undefined {
  if (!/^[A-Za-z0-9+/]{16,}={0,2}$/.test(s) || s.length % 4 !== 0) return undefined;
  try {
    const d = atob(s);
    return looksInteresting(d) && d !== s ? d : undefined;
  } catch {
    return undefined;
  }
}

export function tryHex(s: string): string | undefined {
  if (!/^(?:[0-9a-fA-F]{2}){8,}$/.test(s)) return undefined;
  let d = "";
  for (let i = 0; i < s.length; i += 2) d += String.fromCharCode(Number.parseInt(s.slice(i, i + 2), 16));
  return looksInteresting(d) ? d : undefined;
}

/** Peels layered encodings off one value: the final decoded form and the chain applied. */
export function peel(value: string): { decoded: string; chain: string[] } | undefined {
  let current = value;
  const chain: string[] = [];
  for (let guard = 0; guard < MAX_LAYERS; guard++) {
    const url = tryUrl(current);
    if (url !== undefined) {
      chain.push("url");
      current = url;
      continue;
    }
    const b64 = tryBase64(current);
    if (b64 !== undefined) {
      chain.push("base64");
      current = b64;
      continue;
    }
    const hex = tryHex(current);
    if (hex !== undefined) {
      chain.push("hex");
      current = hex;
      continue;
    }
    break;
  }
  return chain.length > 0 ? { decoded: current, chain } : undefined;
}

/**
 * The metadata fields that hold attacker-supplied text. A fingerprint or an IP list is not
 * a payload, and feeding those in manufactures decodes.
 */
const METADATA_FIELDS = ["sample", "payload", "target", "param", "path", "userAgent"] as const;

/** Every encoded value in an incident: query values, header values, body chunks, detector samples. */
export function decodeCandidates(incident: Incident): DecodedValue[] {
  const seen = new Set<string>();
  const out: DecodedValue[] = [];
  const consider = (src: string, value: unknown): void => {
    if (out.length >= MAX_DECODED) return;
    if (typeof value !== "string" || value.length < 8 || value.length > MAX_VALUE) return;
    const result = peel(value);
    if (result === undefined || result.decoded === value) return;
    const key = `${src}|${result.decoded}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ src, encoding: result.chain.join(" → "), raw: value, decoded: result.decoded });
  };
  const splitPairs = (src: string, text: string, keysToo: boolean): void => {
    for (const pair of text.split("&")) {
      const eq = pair.indexOf("=");
      if (eq >= 0) consider(src, pair.slice(eq + 1));
      else if (keysToo) consider(src, pair);
    }
  };

  const path = typeof incident.path === "string" ? incident.path : "";
  const q = path.indexOf("?");
  if (q >= 0) splitPairs("query", path.slice(q + 1), true);
  for (const [name, value] of Object.entries(incident.headers ?? {})) {
    for (const one of Array.isArray(value) ? value : [value]) consider(`header ${name}`, one);
  }
  if (typeof incident.body === "string" && incident.body !== "") {
    consider("body", incident.body);
    splitPairs("body", incident.body, false);
  }
  // The recorded incident keeps the path without its query string, so a query-borne
  // payload often survives only in the detector's own metadata.
  for (const detection of incident.detections ?? []) {
    const metadata = detection.metadata ?? {};
    for (const field of METADATA_FIELDS) {
      if (!Object.hasOwn(metadata, field)) continue;
      const value = metadata[field];
      for (const one of Array.isArray(value) ? value : [value]) consider(`${detection.detectorId} ${field}`, one);
    }
  }
  return out;
}
