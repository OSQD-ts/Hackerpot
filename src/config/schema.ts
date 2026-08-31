import { ConfigError, Section } from "./reader.js";
import { IpAllowlist } from "../allowlist.js";
import { defaultDecoyPaths } from "../detectors/index.js";
import type {
  ClientAnomalyOptions,
  CredentialBruteforceOptions,
  CrlfInjectionOptions,
  DecoyPath,
  GraphqlAbuseOptions,
  HeaderAnomalyOptions,
  HostHeaderInjectionOptions,
  HoneytokenOptions,
  InsecureDeserializationOptions,
  JwtWeaknessOptions,
  NosqlInjectionOptions,
  OpenRedirectOptions,
  PathBruteforceOptions,
  PayloadInjectionOptions,
  PrototypePollutionOptions,
  RateSpikeOptions,
  RepeatActorOptions,
  ScannerSignatureOptions,
  SensitiveFileOptions,
  SsrfProbeOptions,
  SuspiciousMethodOptions,
  WebShellOptions,
} from "../detectors/index.js";
import type {
  BlockOptions,
  ChaosOptions,
  DripFeedOptions,
  FakeDataOptions,
  FakeSuccessOptions,
  GzipBombOptions,
  LargePayloadOptions,
  RateLimitOptions,
  TarpitOptions,
} from "../responses/index.js";
import type { WebhookConfig } from "../management/index.js";

/**
 * The shape of a hackerpot TOML file, after parsing, validation, and defaulting.
 * Everything here is fully populated — there are no "unset" fields — so the
 * resolved config can be printed as-is to show exactly what the process will do.
 */

/** A component that can be switched off without losing its settings. */
export interface Toggle<T> {
  enabled: boolean;
  options: T;
}

export interface ServerConfig {
  host: string;
  port: number;
  /** Resolve the client IP from X-Forwarded-For (only safe behind a trusted proxy). */
  trustProxy: boolean;
}

export interface LoggingConfig {
  format: "json" | "text";
  /** Emit the one-line startup summary. */
  startup: boolean;
  /** Include the request headers of each hit in the log line. */
  includeHeaders: boolean;
  /** Include the (possibly truncated) request body of each hit in the log line. */
  includeBody: boolean;
}

export interface EngineConfig {
  /** Sliding-window length the stateful detectors read, in ms. */
  activityWindowMs: number;
  /** How long the actor registry remembers a fingerprint's IPs — bounds repeat-actor's horizon and its memory. */
  fingerprintWindowMs: number;
}

export interface PolicyConfig {
  /** Cumulative score at which an IP is blocked outright. */
  blockThreshold: number;
  /** Cumulative score at which unclaimed detections are tarpitted. */
  tarpitThreshold: number;
}

export interface FileStoreConfig {
  enabled: boolean;
  path: string;
  loadOnStart: boolean;
  /** Roll the live file into an archive at this size, in bytes. 0 disables rotation. */
  maxBytes: number;
  /** Archives kept alongside the live file. 0 keeps every one. */
  maxArchives: number;
  /** Delete an archive older than this many seconds. 0 disables age pruning. */
  maxArchiveAgeSeconds: number;
  /** gzip rolled segments. */
  compressArchives: boolean;
  /** Cap on per-IP scores held in memory; least-recently-updated are dropped past it. */
  maxScoreEntries: number;
}

export interface RedisStoreConfig {
  enabled: boolean;
  url: string;
  keyPrefix: string;
  /** Seconds; 0 means scores never expire. */
  scoreTtlSeconds: number;
  maxHits: number;
}

export interface ElasticStoreConfig {
  enabled: boolean;
  /** Base URL of the cluster, e.g. "http://localhost:9200". */
  node: string;
  index: string;
  apiKey: string;
  username: string;
  password: string;
  maxHits: number;
  /** Make each write immediately searchable. Slower; leave off in production. */
  refresh: boolean;
}

export interface MemoryStoreConfig {
  /** Retained hits — the store keeps the most recent N. Scores are kept separately. */
  maxHits: number;
  /** Cap on per-IP scores held in memory; least-recently-updated are dropped past it. */
  maxScoreEntries: number;
}

export interface StoreConfig {
  memory: MemoryStoreConfig;
  file: FileStoreConfig;
  redis: RedisStoreConfig;
  elastic: ElasticStoreConfig;
}

export interface EnforcerConfig {
  enabled: boolean;
  /** Program to run — never a shell, so no pipeline or metacharacter is interpreted. */
  command: string;
  /** Arguments; the token `{ip}` is replaced with the validated client IP. */
  args: string[];
  timeoutMs: number;
  /** Ceiling on external enforcement actions per `windowMs` — the fork-bomb guard. */
  maxPerWindow: number;
  windowMs: number;
  /** URL POSTed per block, as an alternative to a local command. */
  webhook: string;
  /** HMAC-SHA256 signing secret for the webhook body. */
  secret: string;
  headers: Record<string, string>;
}

export interface IntelConfig {
  enabled: boolean;
  /** Peer /ioc.txt feed URLs. https, except a loopback host. */
  feeds: string[];
  refreshSeconds: number;
  /** Appended as ?min_score= so only confident offenders are pulled. */
  minScore: number;
  apiKey: string;
  /** How long an ingested block lasts — hearsay expires on its own. */
  ttlSeconds: number;
  maxEntries: number;
  /**
   * Send ingested blocks to the ENFORCING blocklist, so a feed can drive the OS
   * firewall. Off by default and deliberately hard to turn on: a feed you enforce
   * is as trusted as root on this host.
   */
  enforce: boolean;
}

export interface BlocklistConfig {
  /** "memory" (default, per-instance) or "redis" (blocks survive restarts, shared across replicas). */
  backend: "memory" | "redis";
  /** Key namespace for the redis backend. */
  keyPrefix: string;
  /**
   * Hard ceiling on tracked blocks for the memory backend. Expired entries are swept
   * first; past that the soonest-to-expire live blocks are shed. Ignored by redis,
   * where expiry is the server's job.
   */
  maxEntries: number;
  /** Optional external enforcement — an OS firewall command or a webhook. */
  enforcer: EnforcerConfig;
}

export interface DecoyPathConfig {
  enabled: boolean;
  /** Use only the decoys listed in the file, instead of appending them to the built-in set. */
  replaceDefaults: boolean;
  /** Ids of built-in decoys to drop (ignored when `replaceDefaults` is set). */
  disabled: string[];
  decoys: DecoyPath[];
}

export interface DetectorsConfig {
  "decoy-path": DecoyPathConfig;
  "payload-injection": Toggle<PayloadInjectionOptions>;
  "ssrf-probe": Toggle<SsrfProbeOptions>;
  "nosql-injection": Toggle<NosqlInjectionOptions>;
  "prototype-pollution": Toggle<PrototypePollutionOptions>;
  "insecure-deserialization": Toggle<InsecureDeserializationOptions>;
  "graphql-abuse": Toggle<GraphqlAbuseOptions>;
  "jwt-weakness": Toggle<JwtWeaknessOptions>;
  "crlf-injection": Toggle<CrlfInjectionOptions>;
  "web-shell": Toggle<WebShellOptions>;
  "header-anomaly": Toggle<HeaderAnomalyOptions>;
  "host-header-injection": Toggle<HostHeaderInjectionOptions>;
  "sensitive-file": Toggle<SensitiveFileOptions>;
  "open-redirect": Toggle<OpenRedirectOptions>;
  "suspicious-method": Toggle<SuspiciousMethodOptions>;
  "credential-bruteforce": Toggle<CredentialBruteforceOptions>;
  "path-bruteforce": Toggle<PathBruteforceOptions>;
  "scanner-signature": Toggle<ScannerSignatureOptions>;
  "client-anomaly": Toggle<ClientAnomalyOptions>;
  "repeat-actor": Toggle<RepeatActorOptions>;
  "rate-spike": Toggle<RateSpikeOptions>;
  honeytoken: Toggle<HoneytokenOptions>;
}

export interface ResponsesConfig {
  "decoy-content": Toggle<Record<string, never>>;
  "not-found": Toggle<Record<string, never>>;
  redirect: Toggle<Record<string, never>>;
  block: Toggle<BlockOptions>;
  tarpit: Toggle<TarpitOptions>;
  "drip-feed": Toggle<DripFeedOptions>;
  "large-payload": Toggle<LargePayloadOptions>;
  "fake-success": Toggle<FakeSuccessOptions>;
  "fake-data": Toggle<FakeDataOptions>;
  "gzip-bomb": Toggle<GzipBombOptions>;
  chaos: Toggle<ChaosOptions>;
  "rate-limit": Toggle<RateLimitOptions>;
}

export interface SmtpConfig {
  enabled: boolean;
  port: number;
  host: string;
  /** Greeting banner shown after the 220 code; a realistic one draws more interaction. */
  banner: string;
  /** Hostname advertised in EHLO/HELO responses. */
  hostname: string;
  /** Domains this server would legitimately accept mail for; anything else is relay abuse. */
  localDomains: string[];
  /** Drop connections from IPs at or above this cumulative score. 0 = never. */
  dropAboveScore: number;
  /** Cap on simultaneous open connections, so a flood cannot exhaust our sockets. */
  maxConnections: number;
  /** Store the raw DATA body. Off still records the parsed Subject and byte count. */
  captureBody: boolean;
  maxBodyChars: number;
}

export interface SshConfig {
  enabled: boolean;
  port: number;
  host: string;
  /** Server software identifier; the client sees "SSH-2.0-<ident>". */
  ident: string;
  /** Host private keys, inline as PEM. Empty means an ephemeral key at startup. */
  hostKeys: string[];
  /** Paths to PEM host-key files, read at build time and appended to `hostKeys`. */
  hostKeyFiles: string[];
  /** Close the connection after this many credential attempts. */
  maxAuthAttempts: number;
  /** Drop connections from IPs at or above this cumulative score. 0 = never. */
  dropAboveScore: number;
  /** Cap on simultaneous open connections, so a flood cannot exhaust our sockets. */
  maxConnections: number;
  /** Accept the login after `acceptOnAttempt` tries and capture fake-shell commands. */
  interactive: boolean;
  acceptOnAttempt: number;
  /** Hostname shown in the fake shell prompt. Cosmetic. */
  shellHostname: string;
  maxCommands: number;
  maxCommandLength: number;
  /** Hard lifetime for one SSH connection, so a held-open session can't hold a slot forever. */
  maxSessionMs: number;
}

export interface ManagementApiConfig {
  enabled: boolean;
  host: string;
  port: number;
  apiKeys: string[];
  websocket: boolean;
  webhooks: WebhookConfig[];
}

export interface PortScanConfig {
  enabled: boolean;
  ports: number[];
  host: string;
  scanThreshold: number;
  /** Fake service banner sent on connect; empty string stays silent. */
  banner: string;
  /** Max source IPs whose touched-port sets are remembered; least-recently-seen are shed past this. */
  maxTrackedIps: number;
  /** How long an IP's touched-port set is remembered, in ms. */
  retentionMs: number;
}

export interface HackerpotConfig {
  /** Where these settings came from — a file path, or "<defaults>". */
  source: string;
  server: ServerConfig;
  logging: LoggingConfig;
  engine: EngineConfig;
  policy: PolicyConfig;
  store: StoreConfig;
  blocklist: BlocklistConfig;
  intel: IntelConfig;
  /** IPs and CIDR ranges exempt from all detection — never scored, blocked, or recorded. */
  allowlist: string[];
  detectors: DetectorsConfig;
  responses: ResponsesConfig;
  portScan: PortScanConfig;
  smtp: SmtpConfig;
  ssh: SshConfig;
  management: ManagementApiConfig;
}

/** Assigns only when a value was actually supplied, so optional fields stay absent. */
function put<T extends object, K extends keyof T>(target: T, key: K, value: T[K] | undefined): void {
  if (value !== undefined) target[key] = value;
}

/** Section names may be written with either the id's hyphens or underscores. */
function child(parent: Section, id: string): Section {
  const snake = id.replace(/-/g, "_");
  return parent.has(id) || !parent.has(snake) ? parent.section(id) : parent.section(snake);
}

/** Reads the `enabled` flag and the two settings every detector shares. */
function toggle<T extends { score?: number; respondWith?: string }>(section: Section, defaultEnabled: boolean, options: T): Toggle<T> {
  const enabled = section.boolean("enabled", defaultEnabled);
  const shared = options as { score?: number; respondWith?: string };
  put(shared, "score", section.integer("score"));
  put(shared, "respondWith", section.string("respond_with"));
  return { enabled, options };
}

function parseDecoy(section: Section): DecoyPath {
  const id = section.string("id");
  if (id === undefined) section.fail("id", "is required");
  const description = section.string("description", id);
  const exact = section.string("path");
  const pattern = section.regexp("pattern");
  if (exact === undefined && pattern === undefined) section.fail(undefined, 'needs either "path" (exact match) or "pattern" (regular expression)');
  if (exact !== undefined && pattern !== undefined) section.fail(undefined, 'cannot set both "path" and "pattern"');

  const decoy: DecoyPath = { id, description, path: (pattern ?? exact)!, score: section.integer("score", 5) };
  put(decoy, "method", section.string("method"));
  put(decoy, "respondWith", section.string("respond_with"));

  const payload = section.section("payload");
  const body: NonNullable<DecoyPath["payload"]> = {};
  put(body, "status", payload.integer("status"));
  put(body, "contentType", payload.string("content_type"));
  put(body, "body", payload.string("body"));
  put(body, "location", payload.string("location"));
  payload.done();
  if (Object.keys(body).length > 0) decoy.payload = body;

  section.done();
  return decoy;
}

function parseDecoyPaths(section: Section): DecoyPathConfig {
  const config: DecoyPathConfig = {
    enabled: section.boolean("enabled", true),
    replaceDefaults: section.boolean("replace_defaults", false),
    disabled: section.stringArray("disabled", []),
    decoys: (section.sections("decoys") ?? []).map(parseDecoy),
  };
  const known = new Set(defaultDecoyPaths.map((decoy) => decoy.id));
  const unknown = config.disabled.filter((id) => !known.has(id));
  if (unknown.length > 0) section.fail("disabled", `names built-in decoys that do not exist: ${unknown.join(", ")}`);
  section.done();
  return config;
}

function parseHoneytokens(section: Section): Toggle<HoneytokenOptions> {
  const raw = section.value("tokens");
  const tokens: HoneytokenOptions["tokens"] = [];

  if (Array.isArray(raw) && raw.every((entry) => typeof entry === "string")) {
    tokens.push(...(raw as string[]));
  } else if (raw !== undefined) {
    if (!Array.isArray(raw)) section.fail("tokens", "must be an array of strings or an array of tables");
    for (const [index, entry] of raw.entries()) {
      if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
        section.fail("tokens", `entry ${index} must be a string or a table with a "value" key`);
      }
      const token: Section = new Section(section.source, `${section.path}.tokens[${index}]`, entry as Record<string, unknown>);
      const value = token.string("value");
      if (value === undefined) token.fail("value", "is required");
      const label = token.string("label");
      token.done();
      tokens.push(label === undefined ? { value } : { value, label });
    }
  }

  const options: HoneytokenOptions = { tokens };
  const result = toggle(section, tokens.length > 0, options);
  section.done();
  return result;
}

function parseDetectors(section: Section): DetectorsConfig {
  const decoyPath = parseDecoyPaths(child(section, "decoy-path"));

  const injection = child(section, "payload-injection");
  const injectionOptions: PayloadInjectionOptions = {};
  put(injectionOptions, "inspectBody", injection.boolean("inspect_body"));
  put(injectionOptions, "inspectHeaders", injection.stringArray("inspect_headers")?.map((name) => name.toLowerCase()));
  const payloadInjection = toggle(injection, true, injectionOptions);
  injection.done();

  const ssrf = child(section, "ssrf-probe");
  const ssrfOptions: SsrfProbeOptions = {};
  put(ssrfOptions, "inspectBody", ssrf.boolean("inspect_body"));
  put(ssrfOptions, "inspectHeaders", ssrf.stringArray("inspect_headers")?.map((name) => name.toLowerCase()));
  const ssrfProbe = toggle(ssrf, true, ssrfOptions);
  ssrf.done();

  const nosql = child(section, "nosql-injection");
  const nosqlOptions: NosqlInjectionOptions = {};
  put(nosqlOptions, "inspectBody", nosql.boolean("inspect_body"));
  const nosqlInjection = toggle(nosql, true, nosqlOptions);
  nosql.done();

  const proto = child(section, "prototype-pollution");
  const protoOptions: PrototypePollutionOptions = {};
  put(protoOptions, "inspectBody", proto.boolean("inspect_body"));
  const prototypePollution = toggle(proto, true, protoOptions);
  proto.done();

  const deser = child(section, "insecure-deserialization");
  const deserOptions: InsecureDeserializationOptions = {};
  put(deserOptions, "inspectBody", deser.boolean("inspect_body"));
  put(deserOptions, "inspectHeaders", deser.stringArray("inspect_headers")?.map((name) => name.toLowerCase()));
  const insecureDeserialization = toggle(deser, true, deserOptions);
  deser.done();

  const graphql = child(section, "graphql-abuse");
  const graphqlOptions: GraphqlAbuseOptions = {};
  put(graphqlOptions, "maxDepth", graphql.integer("max_depth"));
  put(graphqlOptions, "inspectBody", graphql.boolean("inspect_body"));
  const graphqlAbuse = toggle(graphql, true, graphqlOptions);
  graphql.done();

  const jwt = child(section, "jwt-weakness");
  const jwtOptions: JwtWeaknessOptions = {};
  put(jwtOptions, "inspectHeaders", jwt.stringArray("inspect_headers")?.map((name) => name.toLowerCase()));
  const jwtWeakness = toggle(jwt, true, jwtOptions);
  jwt.done();

  const crlf = child(section, "crlf-injection");
  const crlfOptions: CrlfInjectionOptions = {};
  put(crlfOptions, "inspectHeaders", crlf.stringArray("inspect_headers")?.map((name) => name.toLowerCase()));
  const crlfInjection = toggle(crlf, true, crlfOptions);
  crlf.done();

  const shell = child(section, "web-shell");
  const shellOptions: WebShellOptions = {};
  put(shellOptions, "patterns", shell.regexpArray("patterns"));
  const webShell = toggle(shell, true, shellOptions);
  shell.done();

  const redirect = child(section, "open-redirect");
  const redirectOptions: OpenRedirectOptions = {};
  put(redirectOptions, "params", redirect.stringArray("params")?.map((name) => name.toLowerCase()));
  // Lowercased here so --print-config shows exactly what gets matched; the
  // detector lowercases too, and treats an empty list as "fall back to Host".
  put(redirectOptions, "trustedHosts", redirect.stringArray("trusted_hosts")?.map((host) => host.toLowerCase()));
  const openRedirect = toggle(redirect, true, redirectOptions);
  redirect.done();

  const header = child(section, "header-anomaly");
  const headerOptions: HeaderAnomalyOptions = {};
  put(headerOptions, "flagMissingHost", header.boolean("flag_missing_host"));
  const headerAnomaly = toggle(header, true, headerOptions);
  header.done();

  const hostHeader = child(section, "host-header-injection");
  const hostOptions: HostHeaderInjectionOptions = {};
  const expectedHosts = hostHeader.stringArray("expected_hosts")?.map((host) => host.trim().toLowerCase());
  if (expectedHosts !== undefined) {
    // The detector compares against port-stripped incoming hosts but does NOT
    // strip ports from this list, so an entry like "example.com:8443" could never
    // match — and with a list set, every real request would then be flagged as an
    // unexpected host. Reject it here rather than let that ship silently.
    const withPort = expectedHosts.filter((host) => /:\d+$/.test(host));
    if (withPort.length > 0) {
      hostHeader.fail("expected_hosts", `${withPort.map((h) => `"${h}"`).join(", ")} must not include a port — write just the hostname (the Host header's port is stripped before comparison)`);
    }
    const malformed = expectedHosts.filter((host) => host === "" || /[^a-z0-9.\-_[\]:]/.test(host));
    if (malformed.length > 0) {
      hostHeader.fail("expected_hosts", `${malformed.map((h) => `"${h}"`).join(", ")} is not a valid hostname`);
    }
    put(hostOptions, "expectedHosts", expectedHosts);
  }
  const hostHeaderInjection = toggle(hostHeader, true, hostOptions);
  hostHeader.done();

  const sensitive = child(section, "sensitive-file");
  const sensitiveOptions: SensitiveFileOptions = {};
  put(sensitiveOptions, "patterns", sensitive.regexpArray("patterns"));
  const sensitiveFile = toggle(sensitive, true, sensitiveOptions);
  sensitive.done();

  const method = child(section, "suspicious-method");
  const methodOptions: SuspiciousMethodOptions = {};
  put(methodOptions, "methods", method.stringArray("methods"));
  const suspiciousMethod = toggle(method, true, methodOptions);
  method.done();

  const credential = child(section, "credential-bruteforce");
  const credentialOptions: CredentialBruteforceOptions = {};
  put(credentialOptions, "authPaths", credential.regexp("auth_paths"));
  put(credentialOptions, "windowMs", credential.integer("window_ms"));
  put(credentialOptions, "attemptThreshold", credential.integer("attempt_threshold"));
  const credentialBruteforce = toggle(credential, true, credentialOptions);
  credential.done();

  const pathBrute = child(section, "path-bruteforce");
  const pathOptions: PathBruteforceOptions = {};
  put(pathOptions, "windowMs", pathBrute.integer("window_ms"));
  put(pathOptions, "uniquePathThreshold", pathBrute.integer("unique_path_threshold"));
  const pathBruteforce = toggle(pathBrute, true, pathOptions);
  pathBrute.done();

  const scanner = child(section, "scanner-signature");
  const scannerOptions: ScannerSignatureOptions = {};
  put(scannerOptions, "extraPatterns", scanner.regexpArray("extra_patterns"));
  put(scannerOptions, "flagMissingUserAgent", scanner.boolean("flag_missing_user_agent"));
  const scannerSignature = toggle(scanner, true, scannerOptions);
  scanner.done();

  const client = child(section, "client-anomaly");
  const clientOptions: ClientAnomalyOptions = {};
  put(clientOptions, "requiredBrowserHeaders", client.stringArray("required_browser_headers")?.map((name) => name.toLowerCase()));
  const clientAnomaly = toggle(client, true, clientOptions);
  client.done();

  const actor = child(section, "repeat-actor");
  const actorOptions: RepeatActorOptions = {};
  put(actorOptions, "distinctIpThreshold", actor.integer("distinct_ip_threshold"));
  put(actorOptions, "windowMs", actor.integer("window_ms"));
  const repeatActor = toggle(actor, true, actorOptions);
  actor.done();

  const rate = child(section, "rate-spike");
  const rateOptions: RateSpikeOptions = {};
  put(rateOptions, "windowMs", rate.integer("window_ms"));
  put(rateOptions, "requestThreshold", rate.integer("request_threshold"));
  const rateSpike = toggle(rate, true, rateOptions);
  rate.done();

  const honeytoken = parseHoneytokens(child(section, "honeytoken"));

  section.done();
  return {
    "decoy-path": decoyPath,
    "payload-injection": payloadInjection,
    "ssrf-probe": ssrfProbe,
    "nosql-injection": nosqlInjection,
    "prototype-pollution": prototypePollution,
    "insecure-deserialization": insecureDeserialization,
    "graphql-abuse": graphqlAbuse,
    "jwt-weakness": jwtWeakness,
    "crlf-injection": crlfInjection,
    "web-shell": webShell,
    "header-anomaly": headerAnomaly,
    "host-header-injection": hostHeaderInjection,
    "sensitive-file": sensitiveFile,
    "open-redirect": openRedirect,
    "suspicious-method": suspiciousMethod,
    "credential-bruteforce": credentialBruteforce,
    "path-bruteforce": pathBruteforce,
    "scanner-signature": scannerSignature,
    "client-anomaly": clientAnomaly,
    "repeat-actor": repeatActor,
    "rate-spike": rateSpike,
    honeytoken,
  };
}

/** An action with no settings of its own — only an on/off switch. */
function bareAction(section: Section): Toggle<Record<string, never>> {
  const enabled = section.boolean("enabled", true);
  section.done();
  return { enabled, options: {} };
}

function parseResponses(section: Section): ResponsesConfig {
  const blockSection = child(section, "block");
  const blockOptions: BlockOptions = {};
  put(blockOptions, "durationMs", blockSection.integer("duration_ms"));
  put(blockOptions, "status", blockSection.integer("status"));
  put(blockOptions, "body", blockSection.string("body"));
  put(blockOptions, "sendRetryAfter", blockSection.boolean("send_retry_after"));
  const block = { enabled: blockSection.boolean("enabled", true), options: blockOptions };
  blockSection.done();

  const tarpitSection = child(section, "tarpit");
  const tarpitOptions: TarpitOptions = {};
  put(tarpitOptions, "delayMs", tarpitSection.numberOrRange("delay_ms"));
  put(tarpitOptions, "status", tarpitSection.integer("status"));
  put(tarpitOptions, "body", tarpitSection.string("body"));
  put(tarpitOptions, "escalate", tarpitSection.boolean("escalate"));
  put(tarpitOptions, "maxConcurrent", tarpitSection.integer("max_concurrent"));
  const tarpit = { enabled: tarpitSection.boolean("enabled", true), options: tarpitOptions };
  tarpitSection.done();

  const dripSection = child(section, "drip-feed");
  const dripOptions: DripFeedOptions = {};
  put(dripOptions, "chunkBytes", dripSection.integer("chunk_bytes"));
  put(dripOptions, "intervalMs", dripSection.integer("interval_ms"));
  put(dripOptions, "maxDurationMs", dripSection.integer("max_duration_ms"));
  put(dripOptions, "status", dripSection.integer("status"));
  put(dripOptions, "maxConcurrent", dripSection.integer("max_concurrent"));
  const dripFeed = { enabled: dripSection.boolean("enabled", true), options: dripOptions };
  dripSection.done();

  const largeSection = child(section, "large-payload");
  const largeOptions: LargePayloadOptions = {};
  put(largeOptions, "totalBytes", largeSection.integer("total_bytes"));
  put(largeOptions, "chunkBytes", largeSection.integer("chunk_bytes"));
  put(largeOptions, "throttleMs", largeSection.integer("throttle_ms"));
  put(largeOptions, "contentType", largeSection.string("content_type"));
  put(largeOptions, "maxConcurrent", largeSection.integer("max_concurrent"));
  const largePayload = { enabled: largeSection.boolean("enabled", true), options: largeOptions };
  largeSection.done();

  const successSection = child(section, "fake-success");
  const successOptions: FakeSuccessOptions = {};
  put(successOptions, "status", successSection.integer("status"));
  put(successOptions, "body", successSection.string("body"));
  put(successOptions, "contentType", successSection.string("content_type"));
  put(successOptions, "setSessionCookie", successSection.boolean("set_session_cookie"));
  const fakeSuccess = { enabled: successSection.boolean("enabled", true), options: successOptions };
  successSection.done();

  const fakeDataSection = child(section, "fake-data");
  const fakeDataOptions: FakeDataOptions = {};
  put(fakeDataOptions, "names", fakeDataSection.stringArray("names"));
  put(fakeDataOptions, "domain", fakeDataSection.string("domain"));
  put(fakeDataOptions, "rows", fakeDataSection.integer("rows"));
  const fakeData = { enabled: fakeDataSection.boolean("enabled", true), options: fakeDataOptions };
  fakeDataSection.done();

  const bombSection = child(section, "gzip-bomb");
  const bombOptions: GzipBombOptions = {};
  // Bounded because the bomb is built on OUR side: the action allocates a buffer of
  // exactly this size and gzips it synchronously the first time it is served. An
  // over-large value (a stray zero on `10485760`) is not a bigger bomb for the
  // attacker, it is a multi-gigabyte allocation and a blocked event loop on the first
  // probe that trips it. Failing here means the operator learns at startup instead of
  // during an attack.
  const decompressedBytes = bombSection.integer("decompressed_bytes");
  if (decompressedBytes !== undefined && decompressedBytes > MAX_GZIP_BOMB_BYTES) {
    bombSection.fail(
      "decompressed_bytes",
      `must not exceed ${MAX_GZIP_BOMB_BYTES} (256 MB) — the payload is allocated and compressed in this process, so a larger value stalls the honeypot, not the attacker`,
    );
  }
  put(bombOptions, "decompressedBytes", decompressedBytes);
  put(bombOptions, "contentType", bombSection.string("content_type"));
  const gzipBomb = { enabled: bombSection.boolean("enabled", true), options: bombOptions };
  bombSection.done();

  const chaosSection = child(section, "chaos");
  const chaosOptions: ChaosOptions = {};
  put(chaosOptions, "statuses", chaosSection.integerArray("statuses"));
  const garbageChance = chaosSection.number("garbage_chance");
  if (garbageChance !== undefined && (garbageChance < 0 || garbageChance > 1)) {
    chaosSection.fail("garbage_chance", `must be a probability between 0 and 1, got ${garbageChance}`);
  }
  put(chaosOptions, "garbageChance", garbageChance);
  put(chaosOptions, "maxGarbageBytes", chaosSection.integer("max_garbage_bytes"));
  const chaos = { enabled: chaosSection.boolean("enabled", true), options: chaosOptions };
  chaosSection.done();

  const limitSection = child(section, "rate-limit");
  const limitOptions: RateLimitOptions = {};
  put(limitOptions, "retryAfterSeconds", limitSection.integer("retry_after_seconds"));
  put(limitOptions, "status", limitSection.integer("status"));
  put(limitOptions, "body", limitSection.string("body"));
  const rateLimit = { enabled: limitSection.boolean("enabled", true), options: limitOptions };
  limitSection.done();

  const config: ResponsesConfig = {
    "decoy-content": bareAction(child(section, "decoy-content")),
    "not-found": bareAction(child(section, "not-found")),
    redirect: bareAction(child(section, "redirect")),
    block,
    tarpit,
    "drip-feed": dripFeed,
    "large-payload": largePayload,
    "fake-success": fakeSuccess,
    "fake-data": fakeData,
    "gzip-bomb": gzipBomb,
    chaos,
    "rate-limit": rateLimit,
  };
  section.done();
  return config;
}

function parsePortScan(section: Section): PortScanConfig {
  const ports = section.portArray("ports", []);
  const config: PortScanConfig = {
    enabled: section.boolean("enabled", ports.length > 0),
    ports,
    host: section.string("host", "0.0.0.0"),
    scanThreshold: section.integer("scan_threshold", 2),
    banner: section.string("banner", "SSH-2.0-OpenSSH_8.4"),
    maxTrackedIps: section.integer("max_tracked_ips", 10_000),
    retentionMs: section.integer("retention_ms", 3_600_000),
  };
  if (config.maxTrackedIps === 0) section.fail("max_tracked_ips", "must be greater than 0 — 0 would remember no IP long enough to ever see a second port, so no sweep is ever reported");
  if (config.retentionMs === 0) section.fail("retention_ms", "must be greater than 0 — an IP's touched ports would be forgotten immediately and no sweep could be correlated");
  section.done();
  return config;
}

function parseSmtp(section: Section): SmtpConfig {
  const port = section.port("port", 2525);
  const config: SmtpConfig = {
    // Off unless asked for: binding a mail port is a deliberate choice, and port
    // 25 needs privileges the container deliberately does not have.
    enabled: section.boolean("enabled", false),
    port,
    host: section.string("host", "0.0.0.0"),
    banner: section.string("banner", "Postfix"),
    hostname: section.string("hostname", "mail"),
    localDomains: section.stringArray("local_domains", []).map((domain) => domain.toLowerCase()),
    dropAboveScore: section.integer("drop_above_score", 0),
    maxConnections: section.integer("max_connections", 256),
    captureBody: section.boolean("capture_body", true),
    maxBodyChars: section.integer("max_body_chars", 2_000),
  };
  if (config.enabled && config.port === 0) section.fail("port", "is required when the SMTP honeypot is enabled");
  if (config.captureBody && config.maxBodyChars === 0) {
    section.fail("max_body_chars", 'is 0 while capture_body is true — set capture_body = false to stop storing bodies, rather than capturing an empty one');
  }
  section.done();
  return config;
}

function parseSsh(section: Section): SshConfig {
  const config: SshConfig = {
    // Off unless asked for, like the SMTP honeypot: binding a service port is a
    // deliberate choice, and 22 needs privileges the container does not have.
    enabled: section.boolean("enabled", false),
    port: section.port("port", 2222),
    host: section.string("host", "0.0.0.0"),
    ident: section.string("ident", "OpenSSH_8.4"),
    hostKeys: section.stringArray("host_keys", []),
    hostKeyFiles: section.stringArray("host_key_files", []),
    maxAuthAttempts: section.integer("max_auth_attempts", 6),
    dropAboveScore: section.integer("drop_above_score", 0),
    maxConnections: section.integer("max_connections", 256),
    interactive: section.boolean("interactive", false),
    acceptOnAttempt: section.integer("accept_on_attempt", 1),
    shellHostname: section.string("shell_hostname", "srv01"),
    maxCommands: section.integer("max_commands", 100),
    maxCommandLength: section.integer("max_command_length", 4096),
    maxSessionMs: section.integer("max_session_ms", 120_000),
  };
  if (config.maxSessionMs === 0) {
    section.fail("max_session_ms", "must be greater than 0 — a session with no lifetime cap can be held open forever, which is the exhaustion this bounds");
  }
  if (config.maxAuthAttempts === 0) section.fail("max_auth_attempts", "must be at least 1, or the honeypot captures no credentials");
  if (config.interactive) {
    if (config.acceptOnAttempt === 0) section.fail("accept_on_attempt", "must be at least 1 — attempt numbering starts at 1");
    if (config.acceptOnAttempt > config.maxAuthAttempts) {
      section.fail("accept_on_attempt", `(${config.acceptOnAttempt}) exceeds max_auth_attempts (${config.maxAuthAttempts}) — the connection closes before the login is ever accepted, so no shell is entered`);
    }
    if (config.maxCommands === 0) section.fail("max_commands", "must be at least 1 in interactive mode, or no commands are captured");
    if (config.maxCommandLength === 0) section.fail("max_command_length", "must be greater than 0");
  }
  section.done();
  return config;
}

function parseWebhook(section: Section): WebhookConfig {
  const url = section.string("url");
  if (url === undefined) section.fail("url", "is required");
  if (!/^https?:\/\//i.test(url)) section.fail("url", `must be an http(s) URL, got "${url}"`);

  const webhook: WebhookConfig = { url };
  put(webhook, "secret", section.string("secret"));
  put(webhook, "headers", section.stringTable("headers"));
  put(webhook, "maxRetries", section.integer("max_retries"));
  put(webhook, "minScore", section.integer("min_score"));
  put(webhook, "dedupeWindowSeconds", section.integer("dedupe_window_seconds"));
  put(webhook, "omitBody", section.boolean("omit_body"));

  // Throttling needs both halves; setting one alone silently does nothing, which
  // is the failure an operator would only discover when a flood pages them 400 times.
  const throttleWindow = section.integer("throttle_window_seconds");
  const maxPerWindow = section.integer("max_per_window");
  if ((throttleWindow === undefined) !== (maxPerWindow === undefined)) {
    section.fail(undefined, "sets only one of throttle_window_seconds / max_per_window — throttling needs both to take effect");
  }
  if (throttleWindow === 0) section.fail("throttle_window_seconds", "must be greater than 0");
  if (maxPerWindow === 0) section.fail("max_per_window", "must be greater than 0 — that would drop every alert");
  put(webhook, "throttleWindowSeconds", throttleWindow);
  put(webhook, "maxPerWindow", maxPerWindow);

  const maxInFlight = section.integer("max_in_flight");
  if (maxInFlight === 0) section.fail("max_in_flight", "must be greater than 0 — that would drop every delivery");
  put(webhook, "maxInFlight", maxInFlight);
  const timeoutMs = section.integer("timeout_ms");
  if (timeoutMs === 0) section.fail("timeout_ms", "must be greater than 0 — 0 would abort every delivery immediately");
  put(webhook, "timeoutMs", timeoutMs);
  section.done();
  return webhook;
}

/**
 * Ceiling for `[responses.gzip-bomb] decompressed_bytes`. The buffer is allocated in
 * this process before being compressed, so this bounds our own memory, not theirs.
 */
const MAX_GZIP_BOMB_BYTES = 256 * 1024 * 1024;

function parseManagement(section: Section): ManagementApiConfig {
  const apiKeys = section.stringArray("api_keys", []);
  const config: ManagementApiConfig = {
    enabled: section.boolean("enabled", apiKeys.length > 0),
    host: section.string("host", "127.0.0.1"),
    port: section.port("port", 9500),
    apiKeys,
    websocket: section.boolean("websocket", true),
    webhooks: (section.sections("webhooks") ?? []).map(parseWebhook),
  };
  // The API serves captured attacker data; with no keys every request is denied,
  // so an enabled-but-keyless API is a misconfiguration, not a permissive one.
  if (config.enabled && config.apiKeys.length === 0) section.fail("api_keys", "is required when the management API is enabled");
  section.done();
  return config;
}

/** Validates a parsed TOML document and fills in every default. */
export function parseConfig(raw: Record<string, unknown>, source: string): HackerpotConfig {
  const root = new Section(source, "", raw);

  const server = root.section("server");
  const serverConfig: ServerConfig = {
    host: server.string("host", "0.0.0.0"),
    port: server.port("port", 4004),
    // Defaults to FALSE, and must stay that way. When this is on, the client IP comes
    // from an attacker-supplied header, and that IP is what the allowlist exempts, the
    // blocklist blocks, and the firewall enforcer acts on — so trusting it without a
    // proxy in front hands an attacker a detection bypass (spoof an allowlisted source)
    // and a way to get an arbitrary victim firewalled. Defaulting on made every
    // directly-exposed deployment vulnerable unless the operator knew to turn it off;
    // defaulting off means enabling it is a deliberate act by someone who has a proxy.
    trustProxy: server.boolean("trust_proxy", false),
  };
  server.done();

  const logging = root.section("logging");
  const loggingConfig: LoggingConfig = {
    format: logging.enum("format", ["json", "text"] as const, "json"),
    startup: logging.boolean("startup", true),
    includeHeaders: logging.boolean("include_headers", false),
    includeBody: logging.boolean("include_body", false),
  };
  logging.done();

  const engine = root.section("engine");
  const engineConfig: EngineConfig = {
    activityWindowMs: engine.integer("activity_window_ms", 60_000),
    fingerprintWindowMs: engine.integer("fingerprint_window_ms", 3_600_000),
  };
  engine.done();

  const policy = root.section("policy");
  const policyConfig: PolicyConfig = {
    blockThreshold: policy.integer("block_threshold", 40),
    tarpitThreshold: policy.integer("tarpit_threshold", 15),
  };
  if (policyConfig.tarpitThreshold > policyConfig.blockThreshold) {
    policy.fail("tarpit_threshold", `(${policyConfig.tarpitThreshold}) must not exceed block_threshold (${policyConfig.blockThreshold}); nothing would ever be tarpitted`);
  }
  policy.done();

  const store = root.section("store");
  const memorySection = child(store, "memory");
  const memoryConfig: MemoryStoreConfig = {
    maxHits: memorySection.integer("max_hits", 10_000),
    maxScoreEntries: memorySection.integer("max_score_entries", 100_000),
  };
  // 0 keeps no hits at all: scoring and blocking still work, but the management API,
  // dashboard, and IOC feed all go permanently empty — a config that looks like a
  // retention setting and is actually an off switch for every read path.
  if (memoryConfig.maxHits === 0) memorySection.fail("max_hits", "must be greater than 0 — 0 retains no incidents at all, leaving the API, dashboard, and IOC feed empty");
  if (memoryConfig.maxScoreEntries === 0) {
    memorySection.fail("max_score_entries", "must be greater than 0 — 0 retains no per-IP score at all, so nothing would ever accumulate enough suspicion to be blocked");
  }
  memorySection.done();

  const fileSection = child(store, "file");
  const filePath = fileSection.string("path", "");
  const fileConfig: FileStoreConfig = {
    enabled: fileSection.boolean("enabled", filePath !== ""),
    path: filePath,
    loadOnStart: fileSection.boolean("load_on_start", true),
    maxBytes: fileSection.integer("max_bytes", 128 * 1024 * 1024),
    maxArchives: fileSection.integer("max_archives", 10),
    maxArchiveAgeSeconds: fileSection.integer("max_archive_age_seconds", 0),
    compressArchives: fileSection.boolean("compress_archives", true),
    maxScoreEntries: fileSection.integer("max_score_entries", 100_000),
  };
  if (fileConfig.enabled && fileConfig.path === "") fileSection.fail("path", "is required when the file store is enabled");
  // Rotation off plus archives kept is a contradiction the operator should hear about
  // now rather than discover as a full disk: nothing ever rolls, so nothing is pruned.
  if (fileConfig.enabled && fileConfig.maxBytes === 0 && fileConfig.maxArchives > 0) {
    fileSection.fail("max_bytes", "is 0 (rotation disabled) while max_archives is set — with rotation off the live file grows without limit and no archive is ever created; set max_bytes, or set max_archives = 0 to say the unbounded file is deliberate");
  }
  if (fileConfig.enabled && fileConfig.maxScoreEntries === 0) {
    fileSection.fail("max_score_entries", "must be greater than 0 — 0 retains no per-IP score at all, so nothing would ever accumulate enough suspicion to be blocked");
  }
  fileSection.done();

  const redisSection = child(store, "redis");
  const redisUrl = redisSection.string("url", "");
  const redisConfig: RedisStoreConfig = {
    enabled: redisSection.boolean("enabled", redisUrl !== ""),
    url: redisUrl,
    keyPrefix: redisSection.string("key_prefix", "hackerpot:"),
    scoreTtlSeconds: redisSection.integer("score_ttl_seconds", 0),
    maxHits: redisSection.integer("max_hits", 10_000),
  };
  if (redisConfig.enabled && redisConfig.url === "") redisSection.fail("url", "is required when the redis store is enabled");
  redisSection.done();

  const elasticSection = child(store, "elastic");
  const elasticNode = elasticSection.string("node", "");
  const elasticConfig: ElasticStoreConfig = {
    enabled: elasticSection.boolean("enabled", elasticNode !== ""),
    node: elasticNode,
    index: elasticSection.string("index", "hackerpot-hits"),
    apiKey: elasticSection.string("api_key", ""),
    username: elasticSection.string("username", ""),
    password: elasticSection.string("password", ""),
    maxHits: elasticSection.integer("max_hits", 1_000),
    refresh: elasticSection.boolean("refresh", false),
  };
  if (elasticConfig.enabled) {
    if (elasticConfig.node === "") elasticSection.fail("node", "is required when the elastic store is enabled");
    if (!/^https?:\/\//i.test(elasticConfig.node)) elasticSection.fail("node", `must be an http(s) URL, got "${elasticConfig.node}"`);
    // Half-configured basic auth silently sends no Authorization header at all,
    // so the cluster answers 401 and every write is dropped into onError.
    if ((elasticConfig.username === "") !== (elasticConfig.password === "")) {
      elasticSection.fail(undefined, "sets only one of username/password — basic auth needs both (or use api_key)");
    }
  }
  elasticSection.done();
  store.done();

  const blocklistSection = child(root, "blocklist");
  const enforcerSection = blocklistSection.section("enforcer");
  const enforcer: EnforcerConfig = {
    command: enforcerSection.string("command", ""),
    args: enforcerSection.stringArray("args", []),
    timeoutMs: enforcerSection.integer("timeout_ms", 5_000),
    maxPerWindow: enforcerSection.integer("max_per_window", 0),
    windowMs: enforcerSection.integer("window_ms", 1_000),
    webhook: enforcerSection.string("webhook", ""),
    secret: enforcerSection.string("secret", ""),
    headers: enforcerSection.stringTable("headers") ?? {},
    enabled: false,
  };
  enforcer.enabled = enforcerSection.boolean("enabled", enforcer.command !== "" || enforcer.webhook !== "");

  if (enforcer.enabled) {
    if (enforcer.command === "" && enforcer.webhook === "") {
      enforcerSection.fail(undefined, 'is enabled but sets neither "command" nor "webhook"');
    }
    if (enforcer.command !== "" && enforcer.webhook !== "") {
      enforcerSection.fail(undefined, 'sets both "command" and "webhook" — pick one; a block fires a single enforcer');
    }
    if (enforcer.webhook !== "" && !/^https?:\/\//i.test(enforcer.webhook)) {
      enforcerSection.fail("webhook", `must be an http(s) URL, got "${enforcer.webhook}"`);
    }
    // Without the token the same command runs for every block, so it cannot
    // actually target the offending IP — always a mistake, never a style choice.
    if (enforcer.command !== "" && !enforcer.args.some((arg) => arg.includes("{ip}"))) {
      enforcerSection.fail("args", 'must contain the "{ip}" token, or the command cannot target the blocked address');
    }
  }
  if (enforcer.args.length > 0 && enforcer.command === "") enforcerSection.fail("args", 'requires "command"');
  // 0 reads as "no limit" and means the opposite: the counter is never below the
  // cap, so every enforcement is dropped and the firewall is silently never touched.
  if (enforcerSection.has("max_per_window") && enforcer.maxPerWindow === 0) {
    enforcerSection.fail("max_per_window", "must be greater than 0 — 0 drops every enforcement, silently disabling the firewall rather than removing the limit");
  }
  if (enforcerSection.has("window_ms") && enforcer.windowMs === 0) enforcerSection.fail("window_ms", "must be greater than 0");
  enforcerSection.done();

  const blocklistConfig: BlocklistConfig = {
    backend: blocklistSection.enum("backend", ["memory", "redis"] as const, "memory"),
    keyPrefix: blocklistSection.string("key_prefix", "hackerpot:block:"),
    maxEntries: blocklistSection.integer("max_entries", 100_000),
    enforcer,
  };
  if (blocklistConfig.backend === "redis" && !redisConfig.enabled) {
    blocklistSection.fail("backend", 'is "redis" but no [store.redis] url is configured — the blocklist shares that connection');
  }
  blocklistSection.done();

  // A table rather than a bare top-level key: a bare key placed after any
  // [section] header silently belongs to that section instead of the root, which
  // is a trap in a file this long.
  const intelSection: Section = root.section("intel");
  const feeds = intelSection.stringArray("feeds", []);
  const intel: IntelConfig = {
    enabled: intelSection.boolean("enabled", feeds.length > 0),
    feeds,
    refreshSeconds: intelSection.integer("refresh_seconds", 300),
    minScore: intelSection.integer("min_score", 0),
    apiKey: intelSection.string("api_key", ""),
    ttlSeconds: intelSection.integer("ttl_seconds", 3_600),
    maxEntries: intelSection.integer("max_entries", 10_000),
    enforce: intelSection.boolean("enforce", false),
  };
  if (intel.enabled) {
    if (intel.feeds.length === 0) intelSection.fail("feeds", "is required when intel ingest is enabled");
    for (const feed of intel.feeds) {
      let parsed: URL | undefined;
      try {
        parsed = new URL(feed);
      } catch {
        // Reported just below, so the narrowing stays visible to the compiler.
      }
      if (!parsed) intelSection.fail("feeds", `"${feed}" is not a valid URL`);
      const loopback = ["localhost", "127.0.0.1", "::1", "[::1]"].includes(parsed.hostname.toLowerCase());
      // Matches the library: a feed decides which IPs you block, so it must not be
      // readable or forgeable in transit. Plaintext is allowed only to a local peer.
      if (parsed.protocol !== "https:" && !loopback) {
        intelSection.fail("feeds", `"${feed}" must use https (plaintext is allowed only for a loopback host)`);
      }
    }
    // A typo'd interval shouldn't turn this host into a hammer on a peer.
    if (intel.refreshSeconds < 30) intelSection.fail("refresh_seconds", `must be at least 30, got ${intel.refreshSeconds}`);
    if (intel.ttlSeconds === 0) intelSection.fail("ttl_seconds", "must be greater than 0 — ingested blocks have to expire");
    if (intel.maxEntries === 0) intelSection.fail("max_entries", "must be greater than 0");
  }
  intelSection.done();

  const allowlistSection = root.section("allowlist");
  const allowlist = allowlistSection.ipList("ips", []);
  // IpAllowlist is what actually matches at runtime, so ask it directly rather
  // than trusting the shape check above to agree with it — a second parser that
  // is merely more permissive puts us back to silently exempting nothing. This
  // catches e.g. an IPv4-mapped "::ffff:10.0.0.0/104", which looks like a valid
  // IPv6 CIDR but normalizes to an IPv4 address with an out-of-range prefix.
  const unusable = new IpAllowlist(allowlist).invalid;
  if (unusable.length > 0) {
    allowlistSection.fail("ips", `${unusable.map((entry) => `"${entry}"`).join(", ")} cannot be matched at runtime — write an IPv4 range in plain form (10.0.0.0/8) rather than IPv4-mapped IPv6`);
  }
  allowlistSection.done();

  const detectors = parseDetectors(root.section("detectors"));
  const responses = parseResponses(root.section("responses"));
  const portScan = parsePortScan(child(root, "port-scan"));
  const smtp = parseSmtp(root.section("smtp"));
  const ssh = parseSsh(root.section("ssh"));
  const management = parseManagement(root.section("management"));

  root.done();

  // Every listener binds on the same host by default, so a duplicated port means
  // one of them silently fails to start. Catch it here rather than at bind time.
  const claimed = new Map<number, string>();
  const claim = (port: number, owner: string): void => {
    const existing = claimed.get(port);
    if (existing !== undefined) {
      throw new ConfigError(`${source}: port ${port} is claimed by both ${existing} and ${owner}`);
    }
    claimed.set(port, owner);
  };
  claim(serverConfig.port, "[server]");
  if (portScan.enabled) for (const port of portScan.ports) claim(port, "[port-scan]");
  if (smtp.enabled) claim(smtp.port, "[smtp]");
  if (ssh.enabled) claim(ssh.port, "[ssh]");
  if (management.enabled) claim(management.port, "[management]");

  return {
    source,
    server: serverConfig,
    logging: loggingConfig,
    engine: engineConfig,
    policy: policyConfig,
    store: { memory: memoryConfig, file: fileConfig, redis: redisConfig, elastic: elasticConfig },
    blocklist: blocklistConfig,
    intel,
    allowlist,
    detectors,
    responses,
    portScan,
    smtp,
    ssh,
    management,
  };
}

/** The configuration used when no file is present — identical to hackerpot.toml as shipped. */
export function defaultConfig(source = "<defaults>"): HackerpotConfig {
  return parseConfig({}, source);
}
