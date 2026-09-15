/**
 * Regex patterns supplied by an operator or a library caller, made safe to reuse.
 *
 * `RegExp.test` is stateful when the pattern carries `g` or `y`: it resumes from
 * `lastIndex` and resets only on a failed match, so the same pattern tested against the
 * same path answers `true`, `false`, `true`, `false`. Every detector here tests a value
 * once per request, so neither flag can express anything anyone wanted, but either turns
 * a detector into a coin flip that lets every other probe through. Adapted from
 * bothandlerjs.
 */

/** The pattern with `g` and `y` removed. Returns strings and stateless regexes unchanged. */
export function statelessPattern<T extends string | RegExp>(pattern: T): T {
  if (typeof pattern === "string" || !/[gy]/.test(pattern.flags)) return pattern;
  return new RegExp(pattern.source, pattern.flags.replace(/[gy]/g, "")) as T;
}
