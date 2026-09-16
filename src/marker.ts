import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * A marker the honeypot hands to whoever probes it.
 *
 * In middleware mode the honeypot sits in front of a real application, where clients keep
 * cookies. An attacker rotating through proxies changes address between requests, and the
 * [actor fingerprint](./fingerprint.ts) only correlates them when their header order and
 * client family stay identical — which a tool run behind different proxies usually manages,
 * and a browser-driven attack usually does not. A marker survives both: it is the same value
 * coming back from wherever the next request is made.
 *
 * The rules it lives under are the same ones the fingerprint lives under, and they matter
 * more here because a cookie is a stronger identifier than a heuristic:
 *
 * - **Only somebody the honeypot already answered gets one.** The marker is set on the
 *   honeypot's own responses to probes, never on a response your application produced. An
 *   ordinary visitor who never trips a detector is never marked, so this is not analytics
 *   attached to your traffic — it is a tag on requests that were already incidents.
 * - **It correlates, it never accuses.** A returning marker says "the same client as that
 *   earlier incident". It adds no score by itself and can never be proof: anybody can copy a
 *   cookie into a request, including copying somebody else's.
 * - **It never exempts.** A marker is not a token and grants nothing.
 * - **It is signed, and carries nothing.** The value is a random id plus an HMAC over it, so
 *   a forged or edited marker is rejected rather than becoming a new phantom actor, and the
 *   cookie holds no address, no timestamp and nothing about the person.
 *
 * Adapted from bothandlerjs.
 */

export interface MarkerCookieOptions {
  /**
   * HMAC secret. Required, with no default: an unsigned marker is one an attacker can mint at
   * will, and a marker anybody can mint correlates nothing — it invents actors.
   */
  secret: string;
  /** Cookie name. Default `"__hp"`. */
  name?: string;
  /** How long a marker is asked to live, in seconds. Default 86400 (a day). */
  maxAgeSeconds?: number;
  /** Add `Secure`. Default true — send it back only over HTTPS. */
  secure?: boolean;
  path?: string;
  /** Default `"Lax"`: it should come back on ordinary navigation, not on somebody else's cross-site request. */
  sameSite?: "Lax" | "Strict" | "None";
}

/** Shortest secret worth calling one. A short secret is a forgeable marker. */
export const MIN_MARKER_SECRET_LENGTH = 16;

const ID_BYTES = 12;
const SIGNATURE_CHARS = 32;

export class MarkerCookie {
  readonly name: string;
  private readonly secret: string;
  private readonly maxAgeSeconds: number;
  private readonly secure: boolean;
  private readonly path: string;
  private readonly sameSite: "Lax" | "Strict" | "None";

  constructor(options: MarkerCookieOptions) {
    if (typeof options.secret !== "string" || options.secret.length === 0) {
      throw new Error("a marker cookie needs a secret: an unsigned marker is one an attacker can mint");
    }
    this.secret = options.secret;
    this.name = options.name ?? "__hp";
    this.maxAgeSeconds = options.maxAgeSeconds ?? 86_400;
    this.secure = options.secure !== false;
    this.path = options.path ?? "/";
    this.sameSite = options.sameSite ?? "Lax";
  }

  /** True when the secret is short enough to be worth warning about. */
  get weakSecret(): boolean {
    return this.secret.length < MIN_MARKER_SECRET_LENGTH;
  }

  /** A fresh marker: random id, signed. */
  issue(): string {
    const id = randomBytes(ID_BYTES).toString("hex");
    return `${id}.${this.sign(id)}`;
  }

  /**
   * The verified id a request carries, or undefined.
   *
   * Undefined covers every failure the same way — no cookie, a name that is not ours, a value
   * that was edited, a signature that does not match — because none of them is more
   * interesting than the others: all of them mean "this request is not carrying a marker we
   * issued", and treating a forgery as a distinct event is how a forgery becomes a signal an
   * attacker can raise at will.
   */
  read(headers: Record<string, string | string[] | undefined>): string | undefined {
    const raw = headers["cookie"];
    const header = Array.isArray(raw) ? raw.join("; ") : raw;
    if (header === undefined || header === "") return undefined;
    const value = readCookie(header, this.name);
    if (value === undefined) return undefined;
    const dot = value.lastIndexOf(".");
    if (dot <= 0) return undefined;
    const id = value.slice(0, dot);
    const signature = value.slice(dot + 1);
    if (!/^[0-9a-f]+$/.test(id) || signature.length !== SIGNATURE_CHARS) return undefined;
    return this.verify(id, signature) ? id : undefined;
  }

  /** The `Set-Cookie` value for a marker. `HttpOnly`, so page script can neither read nor plant it. */
  header(marker: string): string {
    const parts = [`${this.name}=${marker}`, `Path=${this.path}`, `Max-Age=${this.maxAgeSeconds}`, "HttpOnly", `SameSite=${this.sameSite}`];
    if (this.secure) parts.push("Secure");
    return parts.join("; ");
  }

  private sign(id: string): string {
    return createHmac("sha256", this.secret).update(id).digest("hex").slice(0, SIGNATURE_CHARS);
  }

  private verify(id: string, signature: string): boolean {
    const expected = Buffer.from(this.sign(id), "utf8");
    const given = Buffer.from(signature, "utf8");
    // Same length by construction (both are `SIGNATURE_CHARS` hex characters), but a
    // mismatched length would throw rather than compare, so it is checked first.
    return expected.length === given.length && timingSafeEqual(expected, given);
  }
}

/**
 * Reads one cookie out of a `Cookie` header.
 *
 * Deliberately small and forgiving: the header is attacker-controlled, and every malformed
 * shape means the same thing (no marker here). It takes the FIRST match, because a client
 * that sends two cookies of one name is either confused or trying something, and the first is
 * what a browser sends for the most specific path.
 */
function readCookie(header: string, name: string): string | undefined {
  for (const part of header.split(";")) {
    const at = part.indexOf("=");
    if (at === -1) continue;
    if (part.slice(0, at).trim() !== name) continue;
    return part.slice(at + 1).trim();
  }
  return undefined;
}
