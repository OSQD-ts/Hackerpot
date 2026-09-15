export { HoneypotEngine } from "./core.js";
export type { EvaluateOptions, EvaluationResult } from "./core.js";
export { createMiddleware, dispatch } from "./middleware.js";
export type { HoneypotMiddleware, MiddlewareOptions, NextFn } from "./middleware.js";
export { HoneypotServer } from "./server.js";
export * from "./stores/index.js";
export { ActivityRegistry, FingerprintRegistry, IpTracker } from "./state.js";
export type { RequestEvent } from "./state.js";
export { IpAllowlist } from "./allowlist.js";
export { MemoryBlocklist, RedisBlocklist, CompositeBlocklist } from "./blocklist.js";
export type { Blocklist, MemoryBlocklistOptions, RedisBlocklistOptions } from "./blocklist.js";
export * from "./intel/index.js";
export { EnforcingBlocklist, commandEnforcer, webhookEnforcer } from "./firewall.js";
export type { BlockEnforcer, CommandEnforcerOptions, WebhookEnforcerOptions } from "./firewall.js";
export { hardenHttpServer } from "./http-hardening.js";
export { generateRobotsTxt } from "./robots.js";
export type { RobotsTxtOptions } from "./robots.js";
export { cefFormat, syslogLine } from "./formats.js";
export type { SyslogOptions } from "./formats.js";
// Syslog forwarding, deliberately outside the management API: shipping to a SIEM
// should not require standing up a REST service over the captured data too.
export { SyslogSink, truncateBytes } from "./syslog.js";
export type { SyslogMessageFormat, SyslogSinkOptions } from "./syslog.js";
// The scripted shell the interactive SSH and Telnet honeypots present. Nothing here
// executes anything — see the module for why it is shared between the two.
export { FAKE_MOTD, fakeShellOutput } from "./shell.js";
export type { FakeShellOptions } from "./shell.js";
// Log rendering, so a custom `onHit` can emit the same injection-safe text lines the
// standalone service does rather than re-deriving the escaping rules.
export { formatTextLine, formatValue } from "./logfmt.js";
// Request parsing, for mounting the engine behind a front end that is neither the
// bundled server nor Connect-style middleware. These enforce the body cap and the
// null-prototype query bag the built-in entrypoints rely on.
export { MAX_BODY_BYTES, mayHaveBody, parseQuery, pathOf, readBody } from "./http-request.js";
// Delay helpers, for custom response actions that want the built-in `[min, max]` shape.
export { randomBetween, resolveDelay, sleep } from "./utils.js";
export { VERSION } from "./version.js";
export { computeFingerprint, headerOrder, uaClass } from "./fingerprint.js";
export { defaultIpEnricher } from "./enrichment.js";
export type { IpEnricher, IpEnrichment } from "./enrichment.js";
export type { HitQuery, HitStore, HoneypotConfig, HoneypotHit } from "./types.js";

export * from "./detectors/index.js";
export * from "./responses/index.js";
export * from "./management/index.js";
export * from "./smtp/index.js";
export * from "./ssh/index.js";
export * from "./ftp/index.js";
export * from "./telnet/index.js";
export * from "./config/index.js";
