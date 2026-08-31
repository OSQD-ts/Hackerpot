/**
 * The package version, as a single source of truth inside `src`.
 *
 * It cannot be imported from `package.json`: the build's `rootDir` is `src`, so a
 * `../package.json` import would place emitted output outside it. So the constant is
 * declared here and `tests/version.test.ts` asserts it still matches `package.json` —
 * the drift shows up as a failing test at release time rather than as a stale
 * `deviceVersion` in whatever SIEM is ingesting the CEF feed.
 */
export const VERSION = "0.1.0";
