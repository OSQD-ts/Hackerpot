import { HoneypotServer } from "./server.js";
import {
  buildDetectors,
  buildHoneypotConfig,
  buildPolicy,
  buildResponseActions,
  createManagementServer,
  createPortScanSentinel,
  createSmtpHoneypot,
  createSshHoneypot,
  createFtpHoneypot,
  createTelnetHoneypot,
  createSyslogSink,
  describeConfig,
  loadConfig,
  planReload,
  ConfigError,
} from "./config/index.js";
import type { HackerpotConfig } from "./config/index.js";
import type { ManagementServer } from "./management/index.js";
import type { SyslogSink } from "./syslog.js";
import { formatTextLine } from "./logfmt.js";
import type { IpAllowlist } from "./allowlist.js";
import type { Blocklist } from "./blocklist.js";
import { applyIocEntries, fetchIocFeed } from "./intel/index.js";
import { checkResponseActions } from "./responses/index.js";
import { HoneypotEngine } from "./core.js";
import { MemoryStore } from "./stores/index.js";
import { formatReplaySummary, readLogLines, replayLog } from "./replay.js";
import { formatExplanation, parseRequestText } from "./explain.js";
import { CrawlerRanges, startCrawlerRangeRefresh } from "./crawler-ranges.js";
import { ServiceTokens } from "./service-tokens.js";
import { buildDashboardOptions } from "./config/build.js";
import { engineSource, startDashboard, type DashboardServer } from "./dashboard/index.js";
import type { IntelConfig } from "./config/index.js";
import type { HoneypotHit } from "./types.js";

/**
 * The standalone service: every listener a config file turns on, in one process. Settings
 * come from a TOML file, with environment variables overriding it for last-mile,
 * per-deployment tweaks. Reached through the command line (`hackerpot serve`, see
 * `cli.ts`); `demo/server.ts` is the tsx-driven convenience for local testing.
 */

export const SERVICE_USAGE = `hackerpot serve — the standalone honeypot service

Usage: hackerpot serve [options]

Options:
  -c, --config <path>   Load this TOML config file (env: HACKERPOT_CONFIG).
                        Without it, the first of hackerpot.toml,
                        hackerpot.config.toml, config/hackerpot.toml, or
                        /etc/hackerpot/hackerpot.toml is used; if none exist,
                        the built-in defaults apply.
      --print-config    Print the resolved configuration as JSON and exit.
                        Validates the file without binding any port.
      --check           Validate the file, then serve every enabled response
                        action once over loopback and report each one. Exits 1
                        if any action throws or reports a failure.
      --replay <file>   Run an access log (combined log format, or one JSON
                        object per line) through the configured detectors and
                        summarise what they would have done. Binds nothing.
      --json            With --replay or --explain, print JSON.
      --explain [text]  Show which detectors fire on one request, and why. Takes a
                        User-Agent, a curl command or a block of request headers,
                        as an argument or on stdin. Binds nothing, looks nothing up.
      --url <path>      With --explain, the request path and query.
      --method <verb>   With --explain, the request method.
      --ip <address>    With --explain, the client address.
  -h, --help            Show this message.

Send SIGHUP to reload detectors, responses, policy, allowlist, service tokens,
intel feeds and logging from
the config file without restarting. Listener, store, and management settings are
reported as needing a restart rather than silently ignored.

Environment variables override the config file — see docs/reference/environment.md.
`;

interface Args {
  configPath: string | undefined;
  printConfig: boolean;
  check: boolean;
  replay: string | undefined;
  json: boolean;
  /** Set when --explain was given: the text, or "" to read it from stdin. */
  explain: string | undefined;
  url: string | undefined;
  method: string | undefined;
  ip: string | undefined;
  help: boolean;
}

export function parseArgs(argv: string[]): Args {
  const args: Args = { configPath: undefined, printConfig: false, check: false, replay: undefined, json: false, explain: undefined, url: undefined, method: undefined, ip: undefined, help: false };
  const flagValue = (arg: string, i: number, what: string): string => {
    const value = argv[i + 1];
    if (value === undefined || value.startsWith("-")) throw new ConfigError(`${arg}: expects ${what}`);
    return value;
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === "--config" || arg === "-c") {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith("-")) throw new ConfigError(`${arg}: expects a file path`);
      args.configPath = value;
      i += 1;
    } else if (arg.startsWith("--config=")) {
      args.configPath = arg.slice("--config=".length);
    } else if (arg === "--print-config") {
      args.printConfig = true;
    } else if (arg === "--check") {
      args.check = true;
    } else if (arg === "--replay") {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith("-")) throw new ConfigError(`${arg}: expects a log file path`);
      args.replay = value;
      i += 1;
    } else if (arg.startsWith("--replay=")) {
      args.replay = arg.slice("--replay=".length);
    } else if (arg === "--json") {
      args.json = true;
    } else if (arg === "--explain") {
      // The text is optional: without one it is read from stdin. A User-Agent never starts with "-".
      const value = argv[i + 1];
      if (value !== undefined && !value.startsWith("-")) {
        args.explain = value;
        i += 1;
      } else {
        args.explain = "";
      }
    } else if (arg === "--url" || arg === "--method" || arg === "--ip") {
      args[arg.slice(2) as "url" | "method" | "ip"] = flagValue(arg, i, "a value");
      i += 1;
    } else if (arg === "--help" || arg === "-h") {
      args.help = true;
    } else {
      throw new ConfigError(`unknown argument "${arg}" — run with --help`);
    }
  }
  return args;
}

let logFormat: "json" | "text" = "json";

function log(event: Record<string, unknown>): void {
  if (logFormat === "text") {
    console.log(formatTextLine(event));
  } else {
    console.log(JSON.stringify({ ts: new Date().toISOString(), ...event }));
  }
}

function hitEvent(config: HackerpotConfig, hit: HoneypotHit): Record<string, unknown> {
  const event: Record<string, unknown> = {
    kind: "hit",
    id: hit.id,
    ip: hit.ip,
    method: hit.method,
    path: hit.path,
    score: hit.score,
    totalScore: hit.totalScore,
    respondedWith: hit.respondedWith,
    detectors: hit.detections.map((d) => d.detectorId),
    reasons: hit.detections.map((d) => d.reason),
  };
  if (config.logging.includeHeaders) event["headers"] = hit.headers;
  if (config.logging.includeBody && hit.body !== undefined) event["body"] = hit.body;
  return event;
}

/** Adds the confidence filter to a feed URL without clobbering an existing query. */
function feedUrl(feed: string, minScore: number): string {
  if (minScore <= 0) return feed;
  const url = new URL(feed);
  url.searchParams.set("min_score", String(minScore));
  return url.toString();
}

/**
 * Polls peer /ioc.txt feeds and applies what they list to the ingest target.
 *
 * Deliberately dumb: it owns only scheduling and failure tolerance. Fetching and
 * applying live in the library, where the safety rules (allowlist first, https only,
 * body cap, entry cap, TTL) are enforced and can't be bypassed from here.
 */
class IntelPoller {
  private timer: NodeJS.Timeout | undefined;
  private stopped = false;

  constructor(
    private readonly settings: IntelConfig,
    private readonly target: Blocklist,
    /**
     * Read live, never captured: `reconfigure()` replaces the allowlist on SIGHUP,
     * and the allowlist is the rail that stops a poisoned feed blocking your own
     * monitoring. A stale reference here would quietly re-open exactly that hole.
     */
    private readonly allowlist: () => IpAllowlist,
  ) {}

  start(): void {
    // Never `void` a promise on an attacker-adjacent path: an unhandled rejection
    // terminates the process by default, which would make a hostile feed response
    // a remote kill switch. tick() already catches per feed; this is the backstop.
    this.tick().catch((err: unknown) => log({ kind: "intel-error", error: (err as Error).message }));
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
  }

  private schedule(): void {
    if (this.stopped) return;
    // ±10% jitter so a fleet polling one peer doesn't arrive in lockstep.
    const base = this.settings.refreshSeconds * 1000;
    this.timer = setTimeout(
      () => this.tick().catch((err: unknown) => log({ kind: "intel-error", error: (err as Error).message })),
      Math.round(base * (0.9 + Math.random() * 0.2)),
    );
    this.timer.unref();
  }

  private async tick(): Promise<void> {
    for (const feed of this.settings.feeds) {
      if (this.stopped) return;
      try {
        const options: Parameters<typeof fetchIocFeed>[1] = { timeoutMs: 10_000 };
        if (this.settings.apiKey) options.apiKey = this.settings.apiKey;
        const ips = await fetchIocFeed(feedUrl(feed, this.settings.minScore), options);
        const result = applyIocEntries(ips, {
          blocklist: this.target,
          allowlist: this.allowlist(),
          ttlMs: this.settings.ttlSeconds * 1000,
          maxEntries: this.settings.maxEntries,
          // An async blocklist (Redis under enforce=true) can reject; without this
          // the rejection is unhandled and Node terminates the process.
          onError: (error) => log({ kind: "intel-block-error", feed, error: error.message }),
        });
        log({ kind: "intel", feed, fetched: ips.length, ...result });
      } catch (err) {
        // A feed that is down, slow, or hostile must never take the honeypot with it.
        log({ kind: "intel-error", feed, error: (err as Error).message });
      }
    }
    this.schedule();
  }
}

/**
 * Runs the service, or one of the one-shot modes its flags select. Resolves when a one-shot
 * mode finishes, and once every listener is bound for the service itself; the process then
 * lives until a signal. Throws `ConfigError` for a bad config or bad arguments.
 */
export async function runService(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  if (args.help) {
    process.stdout.write(SERVICE_USAGE);
    return;
  }

  const config = loadConfig({ path: args.configPath });
  logFormat = config.logging.format;

  if (args.printConfig) {
    process.stdout.write(`${describeConfig(config)}\n`);
    return;
  }

  // A config can validate and still produce a response that breaks once a request is
  // routed to it. Serve each action once, before real traffic finds out.
  if (args.check) {
    const results = await checkResponseActions(buildResponseActions(config));
    for (const result of results) {
      const status = result.status !== undefined ? ` (${result.status})` : "";
      process.stdout.write(`${result.outcome.padEnd(6)} ${result.id}${status}${result.error ? ` — ${result.error}` : ""}\n`);
    }
    const failed = results.filter((result) => result.outcome === "failed").length;
    process.stdout.write(failed > 0 ? `\n${failed} response action(s) failed\n` : `\nall ${results.length} response actions answered\n`);
    process.exitCode = failed > 0 ? 1 : 0;
    return;
  }

  // One request, and which detectors fire on it. Offline: crawler verification gets a
  // resolver that answers nothing, so a claim reads as unverifiable rather than refuted.
  if (args.explain !== undefined) {
    const text = args.explain !== "" ? args.explain : await readStdin();
    let facts: ReturnType<typeof parseRequestText>;
    try {
      facts = parseRequestText(text, { url: args.url, method: args.method, ip: args.ip });
    } catch (err) {
      throw new ConfigError((err as Error).message);
    }
    const offline = { reverse: () => Promise.reject(new Error("offline")), resolveAddresses: () => Promise.reject(new Error("offline")) };
    const crawler = config.detectors["crawler-verification"];
    const offlineConfig: HackerpotConfig = { ...config, detectors: { ...config.detectors, "crawler-verification": { ...crawler, options: { ...crawler.options, resolver: offline } } } };
    const engine = new HoneypotEngine({
      detectors: buildDetectors(offlineConfig),
      responseActions: buildResponseActions(config),
      policy: buildPolicy(config),
      shadowDetectors: config.engine.shadowDetectors,
      store: new MemoryStore(),
      enricher: null,
    });
    const result = await engine.evaluate(facts);
    if (args.json) {
      const { tracker: _tracker, action: _action, ...rest } = result;
      process.stdout.write(`${JSON.stringify({ request: { method: facts.method, path: result.path, query: facts.query, headers: facts.headers, ip: facts.ip }, ...rest }, null, 2)}\n`);
    } else {
      process.stdout.write(formatExplanation(facts, result));
    }
    return;
  }

  // What the configured detectors would have made of real traffic, before any of it is
  // pointed at the honeypot. A store of its own, so a replay never writes into a live one.
  if (args.replay !== undefined) {
    const engine = new HoneypotEngine({
      detectors: buildDetectors(config),
      responseActions: buildResponseActions(config),
      policy: buildPolicy(config),
      allowlist: config.allowlist,
      activityWindowMs: config.engine.activityWindowMs,
      fingerprintWindowMs: config.engine.fingerprintWindowMs,
      detectorTimeoutMs: config.engine.detectorTimeoutMs,
      shadowDetectors: config.engine.shadowDetectors,
      store: new MemoryStore(),
      enricher: null,
    });
    const summary = await replayLog(engine, readLogLines(args.replay));
    process.stdout.write(args.json ? `${JSON.stringify(summary, null, 2)}\n` : formatReplaySummary(summary));
    return;
  }

  // The management server needs the store, and the engine needs an onHit that
  // feeds it — so the hit handler closes over a binding filled in just below.
  let management: ManagementServer | undefined;
  let syslogSink: SyslogSink | undefined;
  // Declared here, ahead of the shutdown handler that closes it.
  let dashboard: DashboardServer | undefined;

  /**
   * The configuration currently in force. Declared here, ahead of every closure that
   * reads it, and REASSIGNED by the SIGHUP handler — the hit-logging closures must see
   * the reloaded values, not the ones present when they were created.
   *
   * They used to close over the initial `config` while the reload assigned a separate
   * binding, so only `logFormat` (a module-level `let`) actually moved. The result was
   * worse than a reload that did nothing: `[logging] format` changed while
   * `include_headers` / `include_body` silently did not, and `planReload` reported
   * `applied: ["logging"], requiresRestart: []` — telling the operator the whole section
   * took. Silently ignoring a changed setting is the exact failure `config/reload.ts` is
   * written to prevent.
   */
  let running: HackerpotConfig = config;

  // Shared by every detector set this process builds, so a SIGHUP rebuild keeps the ranges fetched so far.
  const crawlerRanges = new CrawlerRanges();
  const shared = { crawlerRanges };

  const built = buildHoneypotConfig(
    config,
    (hit) => {
      log(hitEvent(running, hit));
      management?.publish(hit);
      // Declared below and filled in before any listener binds — the same forward
      // reference `management` uses, for the same reason: the store this closure needs
      // has to exist before the thing that consumes it can be constructed.
      syslogSink?.send(hit);
    },
    // Neither a failing firewall call nor an unreachable store may break the
    // honeypot's own response, so both are reported here rather than thrown —
    // each under its own kind, so the log points at the right thing.
    (error, source) => log({ kind: `${source}-error`, error: error.message }),
    shared,
  );

  // A swallowed failure is the invisible kind: a store that rejects every write, or
  // a detector throwing on every request, leaves the honeypot looking healthy while
  // recording nothing. The library defaults to swallowing (safe); this makes it
  // visible. Deliberately not a config option — there is no deployment that wants
  // these silent.
  built.config.onError = (error, context) =>
    log({ kind: "engine-error", source: context.source, error: error instanceof Error ? error.message : String(error) });
  // What a shadowed detector would have done, reported on its own kind so it is easy to
  // compare against the live hits before promoting the detector.
  built.config.onShadow = (event) =>
    log({ kind: "shadow", ip: event.ip, method: event.method, path: event.path, detectors: event.detections.map((d) => d.detectorId), alsoHit: event.alsoHit });
  const server = new HoneypotServer(built.config);

  // Live gauges the store cannot supply — current block count and tracked IPs.
  management = createManagementServer(config, built.store, (error) => log({ kind: "management-error", error: error.message }), async () => ({
    active_blocks: (await server.engine.blocklist.size?.()) ?? 0,
    tracked_ips: server.engine.registry.size,
  }), () => server.engine.detectorFailures);

  // Anomalies go to the log and to every webhook that accepts them.
  server.engine.audit?.start(config.audit.intervalSeconds * 1000, (anomaly) => {
    log({ kind: "anomaly", id: anomaly.id, severity: anomaly.severity, summary: anomaly.summary, value: anomaly.value, baseline: anomaly.baseline, ...(anomaly.details ?? {}) });
    management?.announce(anomaly);
  });

  const crawler = config.detectors["crawler-verification"];
  const stopRangeRefresh =
    crawler.enabled && crawler.publishedRanges
      ? startCrawlerRangeRefresh(crawlerRanges, {
          intervalMs: crawler.rangesRefreshHours * 3_600_000,
          onRefresh: (result) => {
            for (const failure of result.failed) log({ kind: "crawler-ranges-error", crawler: failure.id, error: failure.reason, note: "previous ranges kept" });
            if (result.updated.length > 0) log({ kind: "crawler-ranges", updated: result.updated });
          },
        })
      : undefined;
  // Read through the engine on every call, never captured: `reconfigure()` replaces the
  // allowlist on SIGHUP, and these listeners are not rebuilt on reload — a captured
  // instance would keep exempting yesterday's set.
  const isAllowlisted = (ip: string): boolean => server.engine.isAllowlisted(ip);

  const sentinel = createPortScanSentinel(
    config,
    (event) => log({ kind: event.isScan ? "port-scan" : "port-touch", ip: event.ip, port: event.port, portsTouched: event.portsTouched, banner: event.banner }),
    isAllowlisted,
  );

  // Syslog forwarding sits on the hit path itself rather than behind the management
  // API, so a deployment can ship to its SIEM without also exposing a REST service
  // over the captured data. `send` never throws and never returns a promise.
  syslogSink = createSyslogSink(config, (error) => log({ kind: "syslog-error", error: error.message }));

  // SMTP, SSH, FTP and Telnet incidents are already mapped into HoneypotHit, so they
  // log and reach the management API through exactly the same path as HTTP hits.
  const onProtocolHit = (hit: HoneypotHit): void => {
    log(hitEvent(running, hit));
    management?.publish(hit);
    syslogSink?.send(hit);
    // So a dashboard in this process sees the whole deployment, not only HTTP.
    server.engine.publish(hit);
  };
  const onProtocolError = (error: unknown) => log({ kind: "protocol-error", error: error instanceof Error ? error.message : String(error) });
  const smtp = createSmtpHoneypot(config, built.store, onProtocolHit, onProtocolError, isAllowlisted);
  const ssh = createSshHoneypot(config, built.store, onProtocolHit, onProtocolError, isAllowlisted);
  const ftp = createFtpHoneypot(config, built.store, onProtocolHit, onProtocolError, isAllowlisted);
  const telnet = createTelnetHoneypot(config, built.store, onProtocolHit, onProtocolError, isAllowlisted);

  let poller: IntelPoller | undefined;
  if (config.intel.enabled && built.ingestTarget) {
    poller = new IntelPoller(config.intel, built.ingestTarget, () => server.engine.allowlist);
    if (config.intel.enforce) {
      log({
        kind: "warning",
        what: "intel.enforce",
        detail: "ingested feed entries are written to the ENFORCING blocklist — a feed you enforce is as trusted as root on this host",
      });
    }
  }

  const shutdown = async (signal: string): Promise<void> => {
    log({ kind: "shutdown", signal });
    try {
      await server.close();
      if (sentinel) await sentinel.close();
      poller?.stop();
      server.engine.audit?.stop();
      stopRangeRefresh?.();
      if (smtp) await smtp.close();
      if (ssh) await ssh.close();
      if (ftp) await ftp.close();
      if (telnet) await telnet.close();
      if (management) await management.close();
      if (dashboard) await dashboard.close();
      if (syslogSink) await syslogSink.close();
      await built.close();
    } catch (err) {
      log({ kind: "shutdown-error", error: (err as Error).message });
    }
    process.exit(0);
  };

  let shuttingDown = false;
  const onSignal = (signal: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    // Same reason: a rejection here would replace a clean exit with a crash.
    shutdown(signal).catch((err: unknown) => {
      log({ kind: "shutdown-error", error: (err as Error).message });
      process.exit(1);
    });
  };
  process.on("SIGTERM", () => onSignal("SIGTERM"));
  process.on("SIGINT", () => onSignal("SIGINT"));

  // SIGHUP: re-read the file and hot-apply what can be applied safely. A bad
  // config must never take the honeypot down, so validation failures are logged
  // and the running configuration is kept.
  process.on("SIGHUP", () => {
    let next: HackerpotConfig;
    try {
      next = loadConfig({ path: args.configPath });
    } catch (err) {
      log({ kind: "reload-failed", error: (err as Error).message, note: "keeping the running configuration" });
      return;
    }

    const plan = planReload(running, next);
    if (plan.unchanged) {
      log({ kind: "reload", config: next.source, applied: [], note: "no changes" });
      return;
    }

    // Report what cannot take effect, by name, before applying the rest — an
    // operator who edited a port must not be left believing it took.
    for (const { key, why } of plan.requiresRestart) {
      log({ kind: "reload-requires-restart", key, reason: why, note: "not applied; restart to change this" });
    }

    if (plan.applied.length > 0) {
      server.engine.reconfigure({
        detectors: buildDetectors(next, shared),
        serviceTokens: { header: next.serviceTokens.header, tokens: next.serviceTokens.tokens },
        responseActions: buildResponseActions(next),
        policy: buildPolicy(next),
        allowlist: next.allowlist,
        shadowDetectors: next.engine.shadowDetectors,
      });
    }
    // Applied before anything can log: `running` carries include_headers/include_body to
    // the hit closures, `logFormat` carries the rendering choice to `log()`. Both are
    // `[logging]`, and both have to move together or the section is half-applied.
    running = next;
    logFormat = next.logging.format;

    // fetchIocFeed/applyIocEntries are pure, so the poller can simply be replaced.
    if (plan.applied.includes("intel") && poller && built.ingestTarget) {
      poller.stop();
      poller = new IntelPoller(next.intel, built.ingestTarget, () => server.engine.allowlist);
      poller.start();
    }

    log({
      kind: "reload",
      config: next.source,
      applied: plan.applied,
      requiresRestart: plan.requiresRestart.map((r) => r.key),
      detectors: server.engine.detectors.length,
    });
  });

  await server.listen(config.server.port, config.server.host);
  if (sentinel) await sentinel.listen();
  if (smtp) await smtp.listen();
  if (ssh) await ssh.listen();
  if (ftp) await ftp.listen();
  if (telnet) await telnet.listen();
  if (management) await management.listen();
  // The dashboard reads this process's engine directly, so it needs no management API.
  // A dashboard beside the stack instead of inside it is `hackerpot dashboard`.
  if (config.dashboard.enabled) {
    dashboard = await startDashboard(engineSource(server.engine), {
      ...buildDashboardOptions(config),
      onError: (error) => log({ kind: "dashboard-error", error: error instanceof Error ? error.message : String(error) }),
    });
  }
  // Before any listener takes traffic: a TCP collector that is only dialled by the
  // first incident loses that incident, and an unreachable one should be reported now
  // rather than in the middle of an attack.
  syslogSink?.start();
  poller?.start();

  const weakTokens = new ServiceTokens(config.serviceTokens).weak;
  if (weakTokens.length > 0) {
    log({ kind: "warning", what: "service_tokens", detail: `${weakTokens.join(", ")} has a secret shorter than 16 characters, short enough to guess` });
  }

  if (config.logging.startup) {
    log({
      kind: "startup",
      config: config.source,
      listen: `${config.server.host}:${config.server.port}`,
      store: built.describe,
      blocklist: built.blocklistDescribe,
      allowlist: config.allowlist.length,
      detectors: server.engine.detectors.map((detector) => detector.id),
      shadow: config.engine.shadowDetectors,
      // Names only: the secrets never reach a log.
      serviceTokens: Object.keys(config.serviceTokens.tokens),
      audit: config.audit.enabled ? `every ${config.audit.intervalSeconds}s` : "off",
      crawlerRanges: crawler.enabled && crawler.publishedRanges ? `refresh every ${crawler.rangesRefreshHours}h` : "off",
      responses: [...server.engine.actions.keys()],
      policy: config.policy,
      honeytokens: config.detectors.honeytoken.options.tokens.length,
      scanPorts: config.portScan.enabled ? config.portScan.ports : [],
      smtp: smtp ? `${config.smtp.host}:${config.smtp.port}` : "off",
      ssh: ssh ? `${config.ssh.host}:${config.ssh.port}` : "off",
      ftp: ftp ? `${config.ftp.host}:${config.ftp.port}` : "off",
      telnet: telnet ? `${config.telnet.host}:${config.telnet.port}` : "off",
      syslog: syslogSink ? `${config.syslog.protocol}://${config.syslog.host}:${config.syslog.port} (${config.syslog.format})` : "off",
      management: management ? `${config.management.host}:${config.management.port}` : "off",
      dashboard: dashboard ? dashboard.url : "off",
      intel: poller ? `${config.intel.feeds.length} feed(s)${config.intel.enforce ? ", ENFORCING" : ""}` : "off",
      trustProxy: config.server.trustProxy,
      reload: "SIGHUP",
    });
  }
}

/** Everything on stdin, or "" when stdin is a terminal nobody is typing into. */
export async function readStdin(): Promise<string> {
  if (process.stdin.isTTY) return "";
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}
