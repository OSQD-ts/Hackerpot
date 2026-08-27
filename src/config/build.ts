import { Redis } from "ioredis";
import {
  PortScanSentinel,
  clientAnomalyDetector,
  credentialBruteforceDetector,
  crlfInjectionDetector,
  decoyPathDetector,
  defaultDecoyPaths,
  graphqlAbuseDetector,
  prototypePollutionDetector,
  headerAnomalyDetector,
  honeytokenDetector,
  hostHeaderInjectionDetector,
  insecureDeserializationDetector,
  jwtWeaknessDetector,
  nosqlInjectionDetector,
  openRedirectDetector,
  pathBruteforceDetector,
  payloadInjectionDetector,
  rateSpikeDetector,
  repeatActorDetector,
  scannerSignatureDetector,
  sensitiveFileDetector,
  ssrfProbeDetector,
  suspiciousMethodDetector,
  webShellDetector,
} from "../detectors/index.js";
import type { Detector, PortScanEvent, PortScanSentinelOptions } from "../detectors/index.js";
import {
  blockAction,
  chaosAction,
  decoyContentAction,
  defaultResponsePolicy,
  dripFeedAction,
  fakeDataAction,
  fakeSuccessAction,
  gzipBombAction,
  largePayloadAction,
  notFoundAction,
  rateLimitAction,
  redirectAction,
  tarpitAction,
} from "../responses/index.js";
import type { ResponseAction, ResponsePolicy } from "../responses/index.js";
import { ManagementServer } from "../management/index.js";
import type { ManagementServerOptions } from "../management/index.js";
import { readFileSync } from "node:fs";
import { CompositeBlocklist, MemoryBlocklist, RedisBlocklist, type Blocklist } from "../blocklist.js";
import { EnforcingBlocklist, commandEnforcer, webhookEnforcer, type BlockEnforcer } from "../firewall.js";
import { SmtpHoneypot } from "../smtp/index.js";
import type { SmtpHoneypotOptions } from "../smtp/index.js";
import { SshHoneypot } from "../ssh/index.js";
import type { SshHoneypotOptions } from "../ssh/index.js";
import { ConfigError } from "./reader.js";
import { CompositeStore, ElasticStore, FileStore, MemoryStore, RedisStore } from "../stores/index.js";
import type { HitStore, HoneypotConfig, HoneypotHit } from "../types.js";
import type { HackerpotConfig } from "./schema.js";

/**
 * Turns a validated config file into the live objects the engine runs on. Kept
 * separate from parsing so the config can be inspected (or printed) without
 * opening Redis connections or binding sockets.
 */

/** In the same order as `defaultDetectors()`, minus anything switched off. */
export function buildDetectors(config: HackerpotConfig): Detector[] {
  const d = config.detectors;
  const detectors: Detector[] = [];

  if (d["decoy-path"].enabled) {
    const custom = d["decoy-path"].decoys;
    const base = d["decoy-path"].replaceDefaults ? [] : defaultDecoyPaths.filter((decoy) => !d["decoy-path"].disabled.includes(decoy.id));
    // Custom decoys come first so one sharing an id with a built-in wins the match.
    detectors.push(decoyPathDetector([...custom, ...base]));
  }
  if (d["payload-injection"].enabled) detectors.push(payloadInjectionDetector(d["payload-injection"].options));
  if (d["ssrf-probe"].enabled) detectors.push(ssrfProbeDetector(d["ssrf-probe"].options));
  if (d["nosql-injection"].enabled) detectors.push(nosqlInjectionDetector(d["nosql-injection"].options));
  if (d["prototype-pollution"].enabled) detectors.push(prototypePollutionDetector(d["prototype-pollution"].options));
  if (d["insecure-deserialization"].enabled) detectors.push(insecureDeserializationDetector(d["insecure-deserialization"].options));
  if (d["graphql-abuse"].enabled) detectors.push(graphqlAbuseDetector(d["graphql-abuse"].options));
  if (d["jwt-weakness"].enabled) detectors.push(jwtWeaknessDetector(d["jwt-weakness"].options));
  if (d["crlf-injection"].enabled) detectors.push(crlfInjectionDetector(d["crlf-injection"].options));
  if (d["web-shell"].enabled) detectors.push(webShellDetector(d["web-shell"].options));
  if (d["header-anomaly"].enabled) detectors.push(headerAnomalyDetector(d["header-anomaly"].options));
  if (d["host-header-injection"].enabled) detectors.push(hostHeaderInjectionDetector(d["host-header-injection"].options));
  if (d["sensitive-file"].enabled) detectors.push(sensitiveFileDetector(d["sensitive-file"].options));
  if (d["open-redirect"].enabled) detectors.push(openRedirectDetector(d["open-redirect"].options));
  if (d["suspicious-method"].enabled) detectors.push(suspiciousMethodDetector(d["suspicious-method"].options));
  if (d["credential-bruteforce"].enabled) detectors.push(credentialBruteforceDetector(d["credential-bruteforce"].options));
  if (d["path-bruteforce"].enabled) detectors.push(pathBruteforceDetector(d["path-bruteforce"].options));
  if (d["scanner-signature"].enabled) detectors.push(scannerSignatureDetector(d["scanner-signature"].options));
  if (d["client-anomaly"].enabled) detectors.push(clientAnomalyDetector(d["client-anomaly"].options));
  if (d["rate-spike"].enabled) detectors.push(rateSpikeDetector(d["rate-spike"].options));
  if (d["repeat-actor"].enabled) detectors.push(repeatActorDetector(d["repeat-actor"].options));
  if (d.honeytoken.enabled && d.honeytoken.options.tokens.length > 0) detectors.push(honeytokenDetector(d.honeytoken.options));

  return detectors;
}

export function buildResponseActions(config: HackerpotConfig): ResponseAction[] {
  const r = config.responses;
  const actions: ResponseAction[] = [];
  if (r["decoy-content"].enabled) actions.push(decoyContentAction());
  if (r["not-found"].enabled) actions.push(notFoundAction());
  if (r.redirect.enabled) actions.push(redirectAction());
  if (r.block.enabled) actions.push(blockAction(r.block.options));
  if (r.tarpit.enabled) actions.push(tarpitAction(r.tarpit.options));
  if (r["drip-feed"].enabled) actions.push(dripFeedAction(r["drip-feed"].options));
  if (r["large-payload"].enabled) actions.push(largePayloadAction(r["large-payload"].options));
  if (r["fake-success"].enabled) actions.push(fakeSuccessAction(r["fake-success"].options));
  if (r["fake-data"].enabled) actions.push(fakeDataAction(r["fake-data"].options));
  if (r["gzip-bomb"].enabled) actions.push(gzipBombAction(r["gzip-bomb"].options));
  if (r.chaos.enabled) actions.push(chaosAction(r.chaos.options));
  if (r["rate-limit"].enabled) actions.push(rateLimitAction(r["rate-limit"].options));
  return actions;
}

export function buildPolicy(config: HackerpotConfig): ResponsePolicy {
  return defaultResponsePolicy(config.policy.blockThreshold, config.policy.tarpitThreshold);
}

export interface BuiltStore {
  store: HitStore;
  /** Human-readable summary of the backends in play, for the startup log. */
  describe: string;
  /**
   * The Redis client this store opened, if any. Surfaced so the blocklist can
   * share the one connection rather than opening a second to the same server.
   */
  redis?: Redis;
  /** Releases anything the store owns (currently the Redis connection). */
  close(): Promise<void>;
}

export function createStore(config: HackerpotConfig, onError?: (error: Error) => void): BuiltStore {
  const backends: HitStore[] = [];
  const names: string[] = [];
  let redis: Redis | undefined;

  if (config.store.redis.enabled) {
    const settings = config.store.redis;
    redis = new Redis(settings.url, { lazyConnect: false, maxRetriesPerRequest: null });
    const options: ConstructorParameters<typeof RedisStore>[0] = { client: redis, keyPrefix: settings.keyPrefix, maxHits: settings.maxHits };
    if (settings.scoreTtlSeconds > 0) options.scoreTtlSeconds = settings.scoreTtlSeconds;
    backends.push(new RedisStore(options));
    names.push(`redis(${settings.url}${settings.scoreTtlSeconds > 0 ? `, ttl=${settings.scoreTtlSeconds}s` : ""})`);
  }
  if (config.store.elastic.enabled) {
    const settings = config.store.elastic;
    const options: ConstructorParameters<typeof ElasticStore>[0] = { node: settings.node, index: settings.index, maxHits: settings.maxHits, refresh: settings.refresh };
    if (settings.apiKey) options.apiKey = settings.apiKey;
    if (settings.username) {
      options.username = settings.username;
      options.password = settings.password;
    }
    if (onError) options.onError = onError;
    backends.push(new ElasticStore(options));
    names.push(`elastic(${settings.node}/${settings.index})`);
  }
  let file: FileStore | undefined;
  if (config.store.file.enabled) {
    const settings = config.store.file;
    const options: ConstructorParameters<typeof FileStore>[0] = {
      path: settings.path,
      loadOnStart: settings.loadOnStart,
      maxBytes: settings.maxBytes,
      maxArchives: settings.maxArchives,
      maxArchiveAgeMs: settings.maxArchiveAgeSeconds * 1000,
      compressArchives: settings.compressArchives,
      maxScoreEntries: settings.maxScoreEntries,
    };
    if (onError) options.onError = onError;
    file = new FileStore(options);
    backends.push(file);
    names.push(`file(${settings.path}${settings.maxBytes > 0 ? `, roll at ${Math.round(settings.maxBytes / 1024 / 1024)}MB x${settings.maxArchives}` : ""})`);
  }

  const close = async (): Promise<void> => {
    // Flush buffered hits before the process exits — writes are batched and async now,
    // so a shutdown that skipped this would drop whatever had not reached disk yet.
    if (file) await file.close();
    if (redis) await redis.quit();
  };

  const built: BuiltStore =
    backends.length === 0
      ? { store: new MemoryStore({ maxHits: config.store.memory.maxHits, maxScoreEntries: config.store.memory.maxScoreEntries }), describe: `memory(max ${config.store.memory.maxHits})`, close }
      : backends.length === 1
        ? { store: backends[0]!, describe: names[0]!, close }
        : { store: new CompositeStore(backends[0]!, ...backends.slice(1)), describe: `composite[${names.join(" + ")}]`, close };
  if (redis) built.redis = redis;
  return built;
}

export interface BuiltBlocklist {
  blocklist: Blocklist;
  describe: string;
  /**
   * Where IOC ingest must write. By default a separate NON-enforcing child of a
   * CompositeBlocklist: an ingested IP is short-circuited by the honeypot, but its
   * block never reaches the firewall enforcer, because CompositeBlocklist.block()
   * only ever writes to the primary child. Feeds are hearsay; locally-observed
   * attacks are first-hand evidence, and only the latter earns a firewall rule.
   *
   * With `[intel] enforce = true` this is the enforcing blocklist itself — the one
   * explicit opt-in that lets a feed drive the firewall.
   */
  ingestTarget?: Blocklist;
}

/**
 * Where "this IP is blocked" lives. Memory (the default) is per-instance and
 * lost on restart; redis makes blocks survive restarts and apply across every
 * replica. The redis backend deliberately reuses the store's connection — the
 * schema refuses `backend = "redis"` without a configured [store.redis], so a
 * client is guaranteed here.
 */
export function createBlocklist(config: HackerpotConfig, redis?: Redis, onError?: (error: Error) => void): BuiltBlocklist {
  let blocklist: Blocklist;
  let describe: string;

  if (config.blocklist.backend === "redis") {
    if (!redis) throw new ConfigError('[blocklist] backend = "redis" requires a configured [store.redis] connection');
    blocklist = new RedisBlocklist({ client: redis, keyPrefix: config.blocklist.keyPrefix });
    describe = `redis(${config.blocklist.keyPrefix})`;
  } else {
    blocklist = new MemoryBlocklist();
    describe = "memory";
  }

  const settings = config.blocklist.enforcer;
  if (!settings.enabled) return withIngestTarget(config, blocklist, describe);

  // argv is assembled from a real TOML array, so the no-shell guarantee is
  // structural: there is no single string a pipeline could hide in. The library
  // validates the IP before substituting it, so config re-encodes nothing.
  let enforce: BlockEnforcer;
  if (settings.command !== "") {
    const options: Parameters<typeof commandEnforcer>[0] = { argv: [settings.command, ...settings.args], timeoutMs: settings.timeoutMs, windowMs: settings.windowMs };
    // 0 means "unset" here — leave the library default rather than passing it through.
    if (settings.maxPerWindow > 0) options.maxPerWindow = settings.maxPerWindow;
    if (onError) options.onError = onError;
    enforce = commandEnforcer(options);
    describe += ` + enforce(command:${settings.command})`;
  } else {
    const options: Parameters<typeof webhookEnforcer>[0] = { url: settings.webhook, windowMs: settings.windowMs };
    if (settings.maxPerWindow > 0) options.maxPerWindow = settings.maxPerWindow;
    if (settings.secret) options.secret = settings.secret;
    if (Object.keys(settings.headers).length > 0) options.headers = settings.headers;
    if (onError) options.onError = onError;
    enforce = webhookEnforcer(options);
    describe += ` + enforce(webhook)`;
  }

  return withIngestTarget(config, new EnforcingBlocklist(blocklist, enforce, onError), describe);
}

/**
 * Wraps the operator's blocklist so IOC ingest writes somewhere that cannot reach
 * the enforcer, unless they explicitly asked for it.
 */
function withIngestTarget(config: HackerpotConfig, local: Blocklist, describe: string): BuiltBlocklist {
  if (!config.intel.enabled) return { blocklist: local, describe };
  if (config.intel.enforce) {
    // Explicit opt-in: ingested hearsay is treated exactly like first-hand evidence.
    return { blocklist: local, describe: `${describe} + intel(enforcing)`, ingestTarget: local };
  }
  const feed = new MemoryBlocklist();
  return {
    blocklist: new CompositeBlocklist(local, feed),
    describe: `${describe} + intel(non-enforcing)`,
    ingestTarget: feed,
  };
}

export function createPortScanSentinel(config: HackerpotConfig, onEvent: (event: PortScanEvent) => void): PortScanSentinel | undefined {
  const settings = config.portScan;
  if (!settings.enabled || settings.ports.length === 0) return undefined;
  const options: PortScanSentinelOptions = {
    ports: settings.ports,
    host: settings.host,
    scanThreshold: settings.scanThreshold,
    onEvent,
  };
  if (settings.banner) options.banner = settings.banner;
  return new PortScanSentinel(options);
}

/**
 * The SMTP honeypot, if the config turns it on. Like the port-scan sentinel it is
 * a TCP listener independent of the HTTP engine, but it shares the same store, so
 * mail-side incidents accumulate against the same per-IP score and surface in the
 * management API alongside HTTP hits.
 */
export function createSmtpHoneypot(config: HackerpotConfig, store: HitStore, onHit: (hit: HoneypotHit) => void, onError?: (error: unknown) => void): SmtpHoneypot | undefined {
  const settings = config.smtp;
  if (!settings.enabled) return undefined;
  const options: SmtpHoneypotOptions = {
    port: settings.port,
    host: settings.host,
    banner: settings.banner,
    hostname: settings.hostname,
    localDomains: settings.localDomains,
    maxConnections: settings.maxConnections,
    captureBody: settings.captureBody,
    maxBodyChars: settings.maxBodyChars,
    store,
    onHit,
  };
  if (onError) options.onError = onError;
  if (settings.dropAboveScore > 0) options.dropAboveScore = settings.dropAboveScore;
  return new SmtpHoneypot(options);
}

/**
 * The SSH honeypot, if the config turns it on. Like the SMTP one it shares the
 * store, so credential brute-force from an IP already probing over HTTP stacks
 * onto the same score.
 *
 * Host keys are read here rather than at parse time, so validating a config never
 * touches private key material on disk.
 */
export function createSshHoneypot(config: HackerpotConfig, store: HitStore, onHit: (hit: HoneypotHit) => void, onError?: (error: unknown) => void): SshHoneypot | undefined {
  const settings = config.ssh;
  if (!settings.enabled) return undefined;

  const hostKeys = [...settings.hostKeys];
  for (const path of settings.hostKeyFiles) {
    try {
      hostKeys.push(readFileSync(path, "utf8"));
    } catch (err) {
      throw new ConfigError(`[ssh] host_key_files: cannot read ${path}: ${(err as Error).message}`);
    }
  }

  const options: SshHoneypotOptions = {
    port: settings.port,
    host: settings.host,
    ident: settings.ident,
    maxAuthAttempts: settings.maxAuthAttempts,
    maxConnections: settings.maxConnections,
    interactive: settings.interactive,
    acceptOnAttempt: settings.acceptOnAttempt,
    shellHostname: settings.shellHostname,
    maxCommands: settings.maxCommands,
    maxCommandLength: settings.maxCommandLength,
    maxSessionMs: settings.maxSessionMs,
    store,
    onHit,
  };
  // An empty list means "generate an ephemeral key at startup", which is what a
  // honeypot wants — never pass [] through as if it were a configured key set.
  if (hostKeys.length > 0) options.hostKeys = hostKeys;
  if (settings.dropAboveScore > 0) options.dropAboveScore = settings.dropAboveScore;
  if (onError) options.onError = onError;
  return new SshHoneypot(options);
}

/**
 * The operator-facing API, if the config turns it on. Bound separately from the
 * honeypot listener and on loopback by default — it exposes captured attacker
 * data and must never share the attacker-facing interface.
 */
export function createManagementServer(
  config: HackerpotConfig,
  store: HitStore,
  onError?: (error: Error) => void,
  metrics?: () => Record<string, number> | Promise<Record<string, number>>,
): ManagementServer | undefined {
  const settings = config.management;
  if (!settings.enabled) return undefined;
  const options: ManagementServerOptions = {
    store,
    host: settings.host,
    port: settings.port,
    apiKeys: settings.apiKeys,
    websocket: settings.websocket,
    webhooks: settings.webhooks,
  };
  if (onError) options.onError = onError;
  if (metrics) options.metrics = metrics;
  return new ManagementServer(options);
}

export interface BuiltEngineConfig extends BuiltStore {
  config: HoneypotConfig;
  /** Summary of the blocklist backend, for the startup log. */
  blocklistDescribe: string;
  /** Where IOC ingest must write — see `BuiltBlocklist.ingestTarget`. */
  ingestTarget?: Blocklist;
}

/**
 * Assembles the full `HoneypotConfig` a `HoneypotEngine`/`HoneypotServer` takes.
 * The caller supplies `onHit`, since where alerts go is a property of the
 * deployment rather than of the config file.
 */
/** Where a background failure came from, so it can be reported as itself. */
export type BuiltErrorSource = "store" | "enforce";

export function buildHoneypotConfig(
  config: HackerpotConfig,
  onHit?: (hit: HoneypotHit) => void | Promise<void>,
  /**
   * Background failures that must never throw into a request. `source` matters:
   * an unreachable Elasticsearch and a failing firewall command are different
   * problems with different fixes, and reporting both under one label sends the
   * operator to the wrong config section.
   */
  onError?: (error: Error, source: BuiltErrorSource) => void,
): BuiltEngineConfig {
  const built = createStore(config, onError && ((error) => onError(error, "store")));
  const { blocklist, describe: blocklistDescribe, ingestTarget } = createBlocklist(
    config,
    built.redis,
    onError && ((error) => onError(error, "enforce")),
  );
  const honeypot: HoneypotConfig = {
    detectors: buildDetectors(config),
    responseActions: buildResponseActions(config),
    policy: buildPolicy(config),
    store: built.store,
    blocklist,
    allowlist: config.allowlist,
    activityWindowMs: config.engine.activityWindowMs,
    fingerprintWindowMs: config.engine.fingerprintWindowMs,
    trustProxy: config.server.trustProxy,
  };
  if (onHit) honeypot.onHit = onHit;
  const result: BuiltEngineConfig = { ...built, config: honeypot, blocklistDescribe };
  if (ingestTarget) result.ingestTarget = ingestTarget;
  return result;
}
