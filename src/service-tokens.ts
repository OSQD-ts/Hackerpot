import { createHash, timingSafeEqual } from "node:crypto";

/**
 * Shared secrets that let your own services through. Adapted from bothandlerjs.
 *
 * An uptime monitor is a bare HTTP client: no browser headers, a scripting User-Agent,
 * the same path every minute. In middleware mode that is what `scanner-signature`,
 * `client-anomaly` and `rate-spike` look for, and the allowlist only helps when the
 * monitor has a fixed address, which hosted monitors do not. A token is the answer that
 * does not depend on the address.
 *
 * Handed no help, the check people write compares a header with `===`, which leaks the
 * secret a character at a time to anyone who can time it, and prints the header in full
 * wherever a request is logged. So the comparison happens here, in constant time, and a
 * request that presents a valid token is exempt before any detector runs, so it is never
 * recorded anywhere.
 *
 * A shared secret in a header does not expire and is replayable by anyone who sees it
 * once. It suits a monitor you operate calling an endpoint you operate, not anything a
 * third party holds.
 */
export interface ServiceTokenOptions {
  /** The header the token arrives in. Default `x-hackerpot-token`. */
  header?: string;
  /** Name → secret. The name is what logs show; the secret appears nowhere. */
  tokens: Readonly<Record<string, string>>;
}

/** Shorter secrets than this are reported as weak. Not refused, so a rotation can still start. */
export const MIN_SERVICE_TOKEN_LENGTH = 16;

export const DEFAULT_SERVICE_TOKEN_HEADER = "x-hackerpot-token";

/**
 * Compares two secrets without revealing where they differ. Both are hashed first, so
 * values of different lengths compare in the same time: `timingSafeEqual` throws on a
 * length mismatch, and checking lengths first would itself reveal the secret's length.
 */
function sameSecret(presented: string, expected: string): boolean {
  return timingSafeEqual(createHash("sha256").update(presented, "utf8").digest(), createHash("sha256").update(expected, "utf8").digest());
}

export class ServiceTokens {
  readonly header: string;
  private readonly entries: ReadonlyArray<readonly [string, string]>;

  constructor(options: ServiceTokenOptions) {
    this.header = (options.header ?? DEFAULT_SERVICE_TOKEN_HEADER).toLowerCase();
    this.entries = Object.entries(options.tokens ?? {}).filter(([, secret]) => typeof secret === "string" && secret.length > 0);
  }

  get size(): number {
    return this.entries.length;
  }

  /** Names configured with a secret shorter than `MIN_SERVICE_TOKEN_LENGTH`. */
  get weak(): string[] {
    return this.entries.filter(([, secret]) => secret.length < MIN_SERVICE_TOKEN_LENGTH).map(([name]) => name);
  }

  /**
   * The name of the token this request presented, or undefined. Every configured token is
   * compared even after a match, so the time taken does not say which one matched.
   */
  identify(headers: Readonly<Record<string, string | string[] | undefined>>): string | undefined {
    const raw = headers[this.header];
    const presented = Array.isArray(raw) ? raw[0] : raw;
    if (presented === undefined || presented === "") return undefined;
    let found: string | undefined;
    for (const [name, secret] of this.entries) {
      if (sameSecret(presented, secret) && found === undefined) found = name;
    }
    return found;
  }
}
