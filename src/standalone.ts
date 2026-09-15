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
import type { IntelConfig } from "./config/index.js";
import type { HoneypotHit } from "./types.js";

/**
 * Production entrypoint for running hackerpot as a standalone service (e.g. in
 * a container). Settings come from a TOML config file, with environment
 * variables overriding it for last-mile, per-deployment tweaks. This is
 * distinct from scripts/dev-server.ts, which is a tsx-driven convenience for
 * local testing.
 */

const USAGE = `hackerpot — standalone honeypot service

Usage: hackerpot [options]

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
  -h, --help            Show this message.

Send SIGHUP to reload detectors, responses, policy, allowlist, and logging from
the config file without restarting. Listener, store, and management settings are
reported as needing a restart rather than silently ignored.

Environment variables override the config file — see README.md.
`;

interface Args {
  configPath: string | undefined;
  printConfig: boolean;
  check: boolean;
  help: boolean;
}

export function parseArgs(argv: string[]): Args {
  const args: Args = { configPath: undefined, printConfig: false, check: false, help: false };
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

async function main(argv: string[]): Promise<void> {
  const args = parseArgs(argv);
  if (args.help) {
    process.stdout.write(USAGE);
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

  // The management server needs the store, and the engine needs an onHit that
  // feeds it — so the hit handler closes over a binding filled in just below.
  let management: ManagementServer | undefined;
  let syslogSink: SyslogSink | undefined;

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
  );

  // A swallowed failure is the invisible kind: a store that rejects every write, or
  // a detector throwing on every request, leaves the honeypot looking healthy while
  // recording nothing. The library defaults to swallowing (safe); this makes it
  // visible. Deliberately not a config option — there is no deployment that wants
  // these silent.
  built.config.onError = (error, context) =>
    log({ kind: "engine-error", source: context.source, error: error instanceof Error ? error.message : String(error) });
  const server = new HoneypotServer(built.config);

  // Live gauges the store cannot supply — current block count and tracked IPs.
  management = createManagementServer(config, built.store, (error) => log({ kind: "management-error", error: error.message }), async () => ({
    active_blocks: (await server.engine.blocklist.size?.()) ?? 0,
    tracked_ips: server.engine.registry.size,
  }));
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
      if (smtp) await smtp.close();
      if (ssh) await ssh.close();
      if (ftp) await ftp.close();
      if (telnet) await telnet.close();
      if (management) await management.close();
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
        detectors: buildDetectors(next),
        responseActions: buildResponseActions(next),
        policy: buildPolicy(next),
        allowlist: next.allowlist,
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
  // Before any listener takes traffic: a TCP collector that is only dialled by the
  // first incident loses that incident, and an unreachable one should be reported now
  // rather than in the middle of an attack.
  syslogSink?.start();
  poller?.start();

  if (config.logging.startup) {
    log({
      kind: "startup",
      config: config.source,
      listen: `${config.server.host}:${config.server.port}`,
      store: built.describe,
      blocklist: built.blocklistDescribe,
      allowlist: config.allowlist.length,
      detectors: server.engine.detectors.map((detector) => detector.id),
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
      intel: poller ? `${config.intel.feeds.length} feed(s)${config.intel.enforce ? ", ENFORCING" : ""}` : "off",
      trustProxy: config.server.trustProxy,
      reload: "SIGHUP",
    });
  }
}

main(process.argv.slice(2)).catch((err: unknown) => {
  if (err instanceof ConfigError) {
    // A bad config is an operator mistake, not a crash — report it plainly.
    console.error(`hackerpot: ${err.message}`);
    process.exit(2);
  }
  log({ kind: "fatal", error: (err as Error).message });
  process.exit(1);
});
