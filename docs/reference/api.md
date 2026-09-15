# API reference

Every export, grouped by what it is for, and the package subpaths.

← [Documentation](../index.md)

---

The runtime export list is pinned by `tests/public-api.test.ts`: adding a name is a feature, removing one
is a breaking change, and either is a deliberate edit there. Types are exported beside each value.

## Import paths

| Path | Holds |
| --- | --- |
| `@osqd/hackerpot` | everything below |
| `@osqd/hackerpot/adapters` | `createMiddleware`, `dispatch`, `trapFormGuard`, `koaHoneypot`, `fastifyHoneypot`, `fetchHoneypot`, `withFetchHoneypot`, `createDashboardHandler`, and their types. Also exported from the root |
| `@osqd/hackerpot/cli` | `main(argv): Promise<number>`, `readStdin()` |
| `@osqd/hackerpot/corpus` | the labelled traffic corpus and the harness that runs it against a configuration. See [the corpus](../testing/corpus.md) |
| `@osqd/hackerpot/element` | `<hackerpot-dashboard>`, the dashboard as a custom element. See [embedding](../operations/embedding.md) |

ESM and CommonJS, with declarations. Node 20 or later.

---

## The engine

| Export | |
| --- | --- |
| `HoneypotEngine` | runs detectors, scores, picks a response. See below |
| `HoneypotServer` | a hardened standalone HTTP server around an engine: `new HoneypotServer(config)`, `.engine`, `listen(port, host?)`, `address()`, `close()` |
| `EvaluateOptions`, `EvaluationResult` | types for `engine.evaluate` |
| `HoneypotConfig`, `HoneypotHit`, `HitStore`, `HitQuery`, `ShadowEvent` | the core types |
| `VERSION` | the package version |

### `new HoneypotEngine(config)`

| Option | Default | |
| --- | --- | --- |
| `detectors` | `defaultDetectors()` | the exact detector list, in order |
| `extraDetectors` | `[]` | appended to the defaults; ignored with `detectors` |
| `responseActions` | `defaultResponseActions()` | the actions the policy may name |
| `extraResponseActions` | `[]` | appended |
| `policy` | `defaultResponsePolicy()` | see [writing a policy](../responses/policy.md) |
| `store` | `new MemoryStore()` | see [stores](../operations/stores.md) |
| `blocklist` | `new MemoryBlocklist()` | see [firewall](../operations/firewall.md#the-blocklists) |
| `allowlist` | `[]` | addresses and CIDRs exempt from everything |
| `trustProxy` | `false` | see [the client IP](../integration/client-ip.md) |
| `onHit` | — | every recorded incident |
| `onError` | — | every absorbed failure, with `{ source }`: a detector id, `store`, `onHit`, `enricher`, `middleware`, `blocklist`, `subscriber`, `onShadow` |
| `activityWindowMs` | `60000` | |
| `fingerprintWindowMs` | `3600000` | |
| `detectorTimeoutMs` | `2000` | `0` disables |
| `enricher` | `defaultIpEnricher()` | `null` disables |
| `shadowDetectors` | `[]` | |
| `onShadow` | — | |
| `serviceTokens` | — | `{ header?, tokens }` or a `ServiceTokens` |
| `audit` | — | a `TrafficAudit` |

| Member | |
| --- | --- |
| `evaluate(facts, options?)` | run one request: `{ detections, score, totalScore, tracker, actionId, action, fingerprint, path, downgradedFrom?, shadowDetections, serviceToken? }`. Options: `trackActivity`, `recordHit`, `activityStatus`, `blockRequiresProof`, `unprovenBlockFallback`, `now`, `audit` |
| `reconfigure({ detectors?, responseActions?, policy?, allowlist?, shadowDetectors?, serviceTokens? })` | hot-swap; see [runtime changes](../operations/runtime-changes.md) |
| `resolveIp(remoteAddress, headers)` | the client address |
| `isAllowlisted(ip)`, `isBlocked(ip)`, `serviceTokenFor(headers)` | |
| `subscribe(listener)` | every recorded hit, after `onHit`; returns an unsubscribe |
| `publish(hit)` | tell subscribers about a hit recorded elsewhere (a protocol honeypot) |
| `reportError(error, context)`, `reportShadow(facts, detections, alsoHit)` | for front ends |
| `scoreFor(ip)` | |
| `needsBodyPhase` | whether any detector reads bodies |
| `detectors`, `actions`, `policy`, `shadowed`, `allowlist`, `serviceTokens` | live, swappable |
| `store`, `blocklist`, `registry`, `fingerprints`, `audit`, `detectorFailures` | fixed |

## Front ends

| Export | |
| --- | --- |
| `createMiddleware(engine, options?)` | Express, Connect, `node:http`. Options: `blockRequiresProof`, `unprovenBlockFallback`, `failOpen`, `countOnlyMissedPaths` |
| `koaHoneypot(engine, options?)` | Koa middleware |
| `fastifyHoneypot(engine, options?)` | a Fastify `onRequest` hook |
| `fetchHoneypot(engine, options?)` | `(request, { ip }) => Promise<Response \| undefined>` |
| `withFetchHoneypot(engine, handler, options?)` | wraps a Fetch handler |
| `trapFormGuard(engine, options?)` | checks parsed trap form fields |
| `dispatch(engine, res, result, ip, path)` | run the response for an evaluation |
| `hardenHttpServer(server)` | timeouts and a connection cap |
| `MAX_BODY_BYTES`, `mayHaveBody`, `parseQuery`, `pathOf`, `readBody` | request parsing for a front end of your own |

See [adapters](../integration/adapters.md).

## Detectors

| Export | |
| --- | --- |
| `defaultDetectors()` | the 23-detector default set |
| `decoyPathDetector`, `defaultDecoyPaths` | |
| `payloadInjectionDetector`, `injectionSignatures` | |
| `ssrfProbeDetector`, `nosqlInjectionDetector`, `prototypePollutionDetector`, `insecureDeserializationDetector`, `graphqlAbuseDetector`, `jwtWeaknessDetector`, `crlfInjectionDetector` | |
| `webShellDetector`, `webShellPatterns` | |
| `headerAnomalyDetector`, `headerIntegrityDetector`, `targetIntegrityDetector`, `hostHeaderInjectionDetector` | |
| `sensitiveFileDetector`, `sensitiveFilePatterns` | |
| `openRedirectDetector` | |
| `suspiciousMethodDetector`, `defaultSuspiciousMethods` | |
| `credentialBruteforceDetector`, `pathBruteforceDetector`, `rateSpikeDetector`, `repeatActorDetector` | |
| `scannerSignatureDetector`, `attackToolUserAgentPatterns`, `scriptingClientUserAgentPatterns`, `scannerUserAgentPatterns` | |
| `clientAnomalyDetector` | |
| `honeytokenDetector` | |
| `trapDetector`, `DEFAULT_TRAP_PATHS`, `renderTrapLink`, `renderTrapField`, `trapRobotsEntries` | |
| `crawlerVerificationDetector`, `verifiableCrawlers` | |
| `cachingResolver`, `nodeDnsResolver`, `forwardConfirmedReverseDns` | DNS for verification |
| `CrawlerRanges`, `PUBLISHED_CRAWLER_RANGES`, `fetchCrawlerRanges`, `refreshCrawlerRanges`, `startCrawlerRangeRefresh`, `validateRanges` | published ranges |
| `Detector`, `Detection`, `DetectionContext`, `RequestFacts`, and each `…Options` type | |
| `generateRobotsTxt` | |

See [the detectors](../detection/detectors.md) and [writing a detector](../detection/writing-a-detector.md).

## Responses

| Export | |
| --- | --- |
| `defaultResponseActions()`, `defaultResponsePolicy(block?, tarpit?)` | |
| `decoyContentAction`, `notFoundAction`, `redirectAction`, `blockAction`, `tarpitAction`, `dripFeedAction`, `largePayloadAction`, `fakeSuccessAction`, `fakeDataAction`, `gzipBombAction`, `chaosAction`, `rateLimitAction` | |
| `checkResponseActions(actions, { budgetMs? })` | serve each once over loopback |
| `sleep`, `randomBetween`, `resolveDelay` | helpers for custom actions |
| `ResponseAction`, `ResponseContext`, `ResponsePolicy`, `PolicyContext`, and each `…Options` type | |

See [response actions](../responses/actions.md).

## State and identity

| Export | |
| --- | --- |
| `ActivityRegistry`, `IpTracker` | per-address sliding windows |
| `FingerprintRegistry` | fingerprints → suspicious addresses |
| `computeFingerprint(facts)`, `headerOrder(facts)`, `uaClass(userAgent)` | the actor fingerprint |
| `IpAllowlist` | CIDR matching by value; `.allows(ip)`, `.invalid` |
| `defaultIpEnricher()`, `IpEnricher`, `IpEnrichment` | |
| `ServiceTokens`, `DEFAULT_SERVICE_TOKEN_HEADER`, `MIN_SERVICE_TOKEN_LENGTH` | |

## Stores and blocklists

| Export | |
| --- | --- |
| `MemoryStore`, `FileStore`, `RedisStore`, `ElasticStore`, `CompositeStore` | |
| `RotatingJsonlWriter`, `ScoreLedger` | the file store's writer and score checkpoint |
| `queryHits`, `applyQuery`, `matchesQuery`, `takeLatest` | the shared `HitQuery` semantics |
| `MemoryBlocklist`, `RedisBlocklist`, `CompositeBlocklist` | |
| `EnforcingBlocklist`, `commandEnforcer`, `webhookEnforcer` | firewall enforcement |

## Operations

| Export | |
| --- | --- |
| `ManagementServer` | REST, WebSocket, webhooks; `listen()`, `publish(hit)`, `announce(anomaly)`, `broker`, `close()` |
| `IncidentBroker` | publish and subscribe for incidents |
| `WebhookDispatcher` | webhook delivery on its own |
| `listIncidents`, `getIncident`, `computeStats`, `computeIoc`, `computeSessions`, `computeActors` | the functions behind the endpoints |
| `IncidentCounters`, `renderMetrics` | Prometheus |
| `extractApiKey`, `isAuthorized` | management authentication |
| `redactIncident`, `isSecretHeader`, `REDACTED` | |
| `renderAlert`, `renderAnomaly`, `escapeSlack`, `escapeDiscord` | Slack and Discord |
| `SyslogSink`, `truncateBytes` | syslog |
| `cefFormat`, `syslogLine` | CEF and RFC 3164 |
| `formatTextLine`, `formatValue` | the injection-safe text log |
| `TrafficAudit`, `DEFAULT_AUDIT_CHECKS` | |
| `fetchIocFeed`, `applyIocEntries`, `parseIps` | threat-intel ingest |
| `Incident`, `ManagementConfig`, `WebhookConfig`, `StatsSummary`, `IocEntry`, `AttackSession`, `ActorGroup`, `TrafficAnomaly`, `AuditCheck`, … | |

See [operations](../operations/index.md).

## The dashboard

| Export | |
| --- | --- |
| `startDashboard(source, options?)` | on a listener of its own; resolves to `{ url, port, host, clients, close() }` |
| `createDashboardHandler(source, options)` | a request handler to mount; `auth` required |
| `engineSource`, `managementServerSource`, `brokerSource`, `storeSource`, `managementApiSource`, `toDashboardSource` | where it reads from |
| `DashboardConfigError` | thrown for a refused configuration (no auth on a public bind) |
| `maskIp` | |
| `renderDashboardPage`, `DASHBOARD_CSS`, `DASHBOARD_MARKUP` | the page itself |
| `DashboardOptions`, `DashboardAuth`, `DashboardRefusal`, `DashboardSections`, `DashboardRedaction`, `DashboardSource`, … | |

See [the dashboard](../operations/dashboard.md) and [embedding](../operations/embedding.md).

## Protocol honeypots

| Export | |
| --- | --- |
| `SshHoneypot`, `SmtpHoneypot`, `FtpHoneypot`, `TelnetHoneypot` | `listen()`, `close()` |
| `TelnetCodec` | IAC negotiation |
| `PortScanSentinel` | |
| `FAKE_MOTD`, `fakeShellOutput` | the scripted shell |
| `…HoneypotOptions`, `…Incident`, `…Finding`, `PortScanEvent`, `PortScanSentinelOptions` | |

See [protocols](../protocols/index.md).

## Configuration

| Export | |
| --- | --- |
| `loadConfig`, `loadConfigFile`, `parseConfigText`, `parseConfig`, `defaultConfig`, `describeConfig`, `discoverConfigPath` | |
| `CONFIG_SEARCH_PATHS`, `SYSTEM_CONFIG_PATH`, `CONFIG_PATH_ENV` | |
| `applyEnvOverrides` | |
| `buildHoneypotConfig`, `buildDetectors`, `buildResponseActions`, `buildPolicy`, `buildAudit`, `buildDashboardOptions`, `buildDashboardSource` | |
| `createStore`, `createBlocklist`, `createManagementServer`, `createSyslogSink`, `createPortScanSentinel`, `createSmtpHoneypot`, `createSshHoneypot`, `createFtpHoneypot`, `createTelnetHoneypot` | |
| `planReload` | |
| `ConfigError`, `Section`, `toRegExp` | the reader |
| `HackerpotConfig` and every section type | |

See [configuration](configuration.md#sharing-a-config-with-a-library-deployment).

## Testing

| Export | |
| --- | --- |
| `parseRequestText`, `explainRequest`, `formatExplanation` | `hackerpot explain` |
| `parseLogLine`, `readLogLines`, `replayLog`, `formatReplaySummary` | `hackerpot replay` |

See [the command line](../testing/cli.md) and [replay](../testing/replay.md).

## Related

- [Configuration](configuration.md) · [Data shapes](data-shapes.md)
