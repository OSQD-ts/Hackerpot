import { describe, expect, it } from "vitest";
import * as api from "../src/index.js";

/**
 * The package's runtime export surface, pinned.
 *
 * Every module here imports its neighbours by path, so nothing else notices when a name
 * disappears from the entry point (a dropped re-export, a renamed module) or appears
 * without anybody deciding it should. This list is what consumers of `@osqd/hackerpot` can
 * import: adding a name is a feature, removing one is a breaking change, and either way it
 * should be a deliberate edit here. Adapted from bothandlerjs.
 */
const EXPORTS = [
  "ActivityRegistry", "CONFIG_PATH_ENV", "CONFIG_SEARCH_PATHS", "CompositeBlocklist", "CompositeStore", "ConfigError",
  "ElasticStore", "EnforcingBlocklist", "FAKE_MOTD", "FileStore", "FingerprintRegistry", "FtpHoneypot", "HoneypotEngine",
  "HoneypotServer", "IncidentBroker", "IncidentCounters", "IpAllowlist", "IpTracker", "MAX_BODY_BYTES", "ManagementServer",
  "MemoryBlocklist", "MemoryStore", "PortScanSentinel", "REDACTED", "RedisBlocklist", "RedisStore", "RotatingJsonlWriter",
  "SYSTEM_CONFIG_PATH", "ScoreLedger", "Section", "SmtpHoneypot", "SshHoneypot", "SyslogSink", "TelnetCodec",
  "TelnetHoneypot", "VERSION", "WebhookDispatcher", "applyEnvOverrides", "applyIocEntries", "applyQuery",
  "attackToolUserAgentPatterns", "blockAction", "buildDetectors", "buildHoneypotConfig", "buildPolicy",
  "buildResponseActions", "cachingResolver", "cefFormat", "chaosAction", "checkResponseActions", "clientAnomalyDetector",
  "commandEnforcer", "computeActors", "computeFingerprint", "computeIoc", "computeSessions", "computeStats",
  "crawlerVerificationDetector", "createBlocklist", "createFtpHoneypot", "createManagementServer", "createMiddleware",
  "createPortScanSentinel", "createSmtpHoneypot", "createSshHoneypot", "createStore", "createSyslogSink",
  "createTelnetHoneypot", "credentialBruteforceDetector", "crlfInjectionDetector", "decoyContentAction",
  "decoyPathDetector", "defaultConfig", "defaultDecoyPaths", "defaultDetectors", "defaultIpEnricher",
  "defaultResponseActions", "defaultResponsePolicy", "defaultSuspiciousMethods", "describeConfig", "discoverConfigPath",
  "dispatch", "dripFeedAction", "escapeDiscord", "escapeSlack", "extractApiKey", "fakeDataAction", "fakeShellOutput",
  "fakeSuccessAction", "fastifyHoneypot", "fetchHoneypot", "fetchIocFeed", "formatTextLine", "formatValue",
  "forwardConfirmedReverseDns", "generateRobotsTxt", "getIncident", "graphqlAbuseDetector", "gzipBombAction",
  "hardenHttpServer", "headerAnomalyDetector", "headerIntegrityDetector", "headerOrder", "honeytokenDetector",
  "hostHeaderInjectionDetector", "injectionSignatures", "insecureDeserializationDetector", "isAuthorized",
  "isSecretHeader", "jwtWeaknessDetector", "koaHoneypot", "largePayloadAction", "listIncidents", "loadConfig",
  "loadConfigFile", "matchesQuery", "mayHaveBody", "nodeDnsResolver", "nosqlInjectionDetector", "notFoundAction",
  "openRedirectDetector", "parseConfig", "parseConfigText", "parseIps", "parseQuery", "pathBruteforceDetector", "pathOf",
  "payloadInjectionDetector", "planReload", "prototypePollutionDetector", "queryHits", "randomBetween",
  "rateLimitAction", "rateSpikeDetector", "readBody", "redactIncident", "redirectAction", "renderAlert", "renderMetrics",
  "repeatActorDetector", "resolveDelay", "scannerSignatureDetector", "scannerUserAgentPatterns",
  "scriptingClientUserAgentPatterns", "sensitiveFileDetector", "sensitiveFilePatterns", "sleep", "ssrfProbeDetector",
  "suspiciousMethodDetector", "syslogLine", "takeLatest", "targetIntegrityDetector", "tarpitAction", "toRegExp",
  "truncateBytes", "uaClass", "verifiableCrawlers", "webShellDetector", "webShellPatterns", "webhookEnforcer",
  "withFetchHoneypot", "formatReplaySummary", "parseLogLine", "readLogLines", "replayLog",
  "trapFormGuard", "explainRequest", "formatExplanation", "parseRequestText", "DEFAULT_AUDIT_CHECKS", "TrafficAudit",
  "DEFAULT_SERVICE_TOKEN_HEADER", "MIN_SERVICE_TOKEN_LENGTH", "ServiceTokens", "CrawlerRanges", "PUBLISHED_CRAWLER_RANGES",
  "fetchCrawlerRanges", "refreshCrawlerRanges", "startCrawlerRangeRefresh", "validateRanges", "DEFAULT_TRAP_PATHS",
  "renderTrapField", "renderTrapLink", "trapDetector", "trapRobotsEntries", "renderAnomaly", "buildAudit",
  "buildDashboardOptions", "buildDashboardSource", "DashboardConfigError", "createDashboardHandler", "maskIp", "startDashboard",
  "brokerSource", "engineSource", "managementApiSource", "managementServerSource", "storeSource", "toDashboardSource",
  "DASHBOARD_CSS", "DASHBOARD_MARKUP", "renderDashboardPage",
];

describe("the public API", () => {
  it("exports exactly the pinned names", () => {
    const actual = Object.keys(api).sort();
    const missing = EXPORTS.filter((name) => !actual.includes(name));
    const unexpected = actual.filter((name) => !EXPORTS.includes(name));
    expect({ missing, unexpected }).toEqual({ missing: [], unexpected: [] });
  });

  it("every pinned name is defined, not just declared", () => {
    const undefinedNames = EXPORTS.filter((name) => (api as Record<string, unknown>)[name] === undefined);
    expect(undefinedNames).toEqual([]);
  });
});
