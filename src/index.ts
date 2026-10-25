export { HoneypotEngine } from "./core.js";
export type { BypassReason, ChangeContext, ChangeEvent, EvaluateOptions, EvaluationResult, HoneypotEngineEvents, Notice } from "./core.js";
export { createMiddleware, dispatch, trapFormGuard } from "./adapters/node.js";
export type { HoneypotMiddleware, MiddlewareOptions, NextFn } from "./adapters/node.js";
export { koaHoneypot } from "./adapters/koa.js";
export type { KoaHoneypotMiddleware, KoaLikeContext } from "./adapters/koa.js";
export { fastifyHoneypot } from "./adapters/fastify.js";
export type { FastifyHoneypotHook, FastifyLikeReply, FastifyLikeRequest } from "./adapters/fastify.js";
export { fetchHoneypot, withFetchHoneypot } from "./adapters/fetch.js";
export { formatReplaySummary, parseLogLine, readLogLines, replayLog } from "./replay.js";
export { explainRequest, formatExplanation, parseRequest, parseRequestText } from "./explain.js";
export type { ExplainOverrides } from "./explain.js";
// Where incidents leave the process: one fan-out, with or without the management API.
export { NotificationHub, consoleNotifier, notifyJsSink, syslogNotifySink, webhookNotifySink } from "./notify/index.js";
export type { ConsoleNotifierOptions, NotifyJsSinkOptions, NotificationHubOptions, NotifyEvent, NotifyEventType, NotifyFilter, NotifySink } from "./notify/index.js";
// Evidence strength, alongside scores: how strong a finding is, not how much it adds up to.
// The same vocabulary as bothandlerjs; the old names stay exported, deprecated, for a release.
export { CERTAINTY_WEIGHT, SUSPICION_CEILING, TIER_WEIGHT, certaintyOf, certaintyOfConfidence, confidenceOf, tierOf, tierOfConfidence } from "./evidence.js";
export type { Certainty, EvidenceTier } from "./evidence.js";
export { MIN_MARKER_SECRET_LENGTH, MarkerCookie } from "./marker.js";
export type { MarkerCookieOptions } from "./marker.js";
export { ActorLabels } from "./labels.js";
export type { ActorLabel, ActorLabelMatch, ActorLabelsOptions, LabelSubject, LabelledActor } from "./labels.js";
export { DEFAULT_MIN_OBSERVATIONS, DEFAULT_MIN_SERVED_PATHS, SiteBaseline, SiteProfile } from "./site/index.js";
export type { BaselineSnapshot, PathStat, RequestOutcome, SiteBaselineOptions, SiteProfileOptions, SiteProfileSnapshot } from "./site/index.js";
export { DEFAULT_AUDIT_CHECKS, TrafficAudit } from "./audit.js";
export type { AnomalySeverity, AuditCheck, AuditContext, AuditRecord, AuditWindow, TrafficAnomaly, TrafficAuditOptions } from "./audit.js";
export { DEFAULT_SERVICE_TOKEN_HEADER, MIN_SERVICE_TOKEN_LENGTH, ServiceTokens } from "./service-tokens.js";
export type { ServiceTokenOptions } from "./service-tokens.js";
export { CrawlerRanges, PUBLISHED_CRAWLER_RANGES, fetchCrawlerRanges, refreshCrawlerRanges, startCrawlerRangeRefresh, validateRanges } from "./crawler-ranges.js";
export type { FetchRangesOptions, PublishedRangeSource, RefreshOptions, RefreshResult, ScheduleOptions } from "./crawler-ranges.js";
export type { LogRequest, ReplayOptions, ReplaySummary } from "./replay.js";
export type { FetchHandler, FetchHoneypot, FetchHoneypotContext } from "./adapters/fetch.js";
export { HoneypotServer } from "./adapters/server.js";
// The operator dashboard: its own listener, a handler to mount, and the data sources behind
// either. The embeddable element is `@osqd/hackerpot/element`.
export * from "./dashboard/index.js";
export * from "./stores/index.js";
// The caps are public so a threshold above one can be refused rather than silently ignored.
export { ActivityRegistry, DEFAULT_MAX_EVENTS, FingerprintRegistry, IpTracker, MAX_IPS_PER_FINGERPRINT, MAX_PATH_CHARS } from "./state.js";
export type { RequestEvent } from "./state.js";
export { IpAllowlist } from "./allowlist.js";
export { MemoryBlocklist, RedisBlocklist, CompositeBlocklist } from "./blocklist.js";
export type { Blocklist, MemoryBlocklistOptions, RedisBlocklistOptions } from "./blocklist.js";
export * from "./intel/index.js";
export { EnforcingBlocklist, commandEnforcer, webhookEnforcer } from "./firewall.js";
export type { BlockEnforcer, CommandEnforcerOptions, WebhookEnforcerOptions } from "./firewall.js";
export { hardenHttpServer } from "./internal/http-hardening.js";
export { generateRobotsTxt } from "./robots.js";
export type { RobotsTxtOptions } from "./robots.js";
export { cefFormat, syslogLine } from "./notify/formats.js";
export type { SyslogOptions } from "./notify/formats.js";
// Syslog forwarding, deliberately outside the management API: shipping to a SIEM
// should not require standing up a REST service over the captured data too.
export { SyslogSink, truncateBytes } from "./notify/syslog.js";
export type { SyslogMessageFormat, SyslogSinkOptions } from "./notify/syslog.js";
// The scripted shell the interactive SSH and Telnet honeypots present. Nothing here
// executes anything — see the module for why it is shared between the two.
export { FAKE_MOTD, fakeShellOutput } from "./protocols/shell.js";
export type { FakeShellOptions } from "./protocols/shell.js";
// Log rendering, so a custom `onHit` can emit the same injection-safe text lines the
// standalone service does rather than re-deriving the escaping rules.
export { formatTextLine, formatValue } from "./internal/logfmt.js";
// Request parsing, for mounting the engine behind a front end that is neither the
// bundled server nor Connect-style middleware. These enforce the body cap and the
// null-prototype query bag the built-in entrypoints rely on.
export { MAX_BODY_BYTES, mayHaveBody, parseQuery, pathOf, readBody } from "./internal/http.js";
// Delay helpers, for custom response actions that want the built-in `[min, max]` shape.
export { randomBetween, resolveDelay, sleep } from "./internal/delay.js";
// Time, injectable. Everything with a window reads a `Clock`, so a test can move time
// rather than wait for it; `ManualClock` is exported for your own detectors and actions.
export { ManualClock, systemClock } from "./internal/clock.js";
export type { Clock } from "./internal/clock.js";
export { VERSION } from "./version.js";
export { computeFingerprint, headerOrder, uaClass } from "./fingerprint.js";
export { defaultIpEnricher } from "./enrichment.js";
export type { IpEnricher, IpEnrichment } from "./enrichment.js";
export type { HitQuery, HitStore, HoneypotConfig, HoneypotHit, ProxyConfig, ShadowEvent } from "./types.js";

export * from "./detectors/index.js";
export * from "./actions/index.js";
export * from "./policy/index.js";
export * from "./management/index.js";
export * from "./protocols/smtp/index.js";
export * from "./protocols/ssh/index.js";
export * from "./protocols/ftp/index.js";
export * from "./protocols/telnet/index.js";
export * from "./config/index.js";
