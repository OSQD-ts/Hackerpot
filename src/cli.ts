/**
 * The command line.
 *
 * `hackerpot` with no command runs the service, which is what a container does. The other
 * commands answer questions without binding a honeypot port: what a config resolves to,
 * whether its responses work, what it would have made of an access log or of one request,
 * and which detectors it installs. `hackerpot dashboard` runs only the dashboard, as its own
 * service beside a running stack.
 *
 * The flags the service took before these commands existed (`--check`, `--replay`,
 * `--explain`, `--print-config`) still work, so a container or a script written against
 * them keeps running.
 */
import { buildDashboardOptions, buildDashboardSource, buildDetectors, ConfigError, loadConfig } from "./config/index.js";
import { startDashboard } from "./dashboard/index.js";
import { DEFAULT_TRAP_PATHS, defaultDecoyPaths } from "./detectors/index.js";
import { generateRobotsTxt } from "./robots.js";
import { readStdin, runService, SERVICE_USAGE } from "./service.js";
import { VERSION } from "./version.js";

const USAGE = `hackerpot ${VERSION} — a honeypot for TypeScript servers

  hackerpot serve [options]            Run the service every enabled section describes (the default)
  hackerpot dashboard [options]        Run only the dashboard, reading a running HackerPot
  hackerpot check [options]            Validate the config and serve every response action once
  hackerpot config [options]           Print the resolved configuration as JSON
  hackerpot replay <log> [--json]      What the configured detectors would make of an access log
  hackerpot explain [request] [--json] Which detectors fire on one request, and why
  hackerpot detectors [options]        List the detectors the config installs
  hackerpot robots [options]           A robots.txt disallowing the decoys and trap paths
  hackerpot --help | --version

Every command takes -c, --config <path> (env: HACKERPOT_CONFIG).

dashboard options
  --management-url <url>   The management API to read (env: DASHBOARD_MANAGEMENT_URL).
                           Default: [dashboard] management_url, else this config's
                           own [management] listener.
  --api-key <key>          One of its api_keys (env: DASHBOARD_MANAGEMENT_API_KEY).
  --host <address>         Bind address (env: DASHBOARD_HOST). Default 127.0.0.1.
  --port <port>            Port (env: DASHBOARD_PORT). Default 9501.
  Authentication comes from [dashboard]: username and password, or a token
  (env: DASHBOARD_USERNAME, DASHBOARD_PASSWORD, DASHBOARD_TOKEN).

explain options
  --url <path>  --method <verb>  --ip <address>

robots options
  --sitemap <url>

${SERVICE_USAGE.split("\n").slice(3).join("\n")}`;

/** Commands that are the service's own flags, spelled as a command. */
const SERVICE_COMMANDS: Record<string, string | undefined> = {
  serve: undefined,
  check: "--check",
  config: "--print-config",
  replay: "--replay",
  explain: "--explain",
};

/** Reads `--name value` and `--name=value`; everything else is left for the caller. */
function takeFlag(argv: string[], name: string): string | undefined {
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === `--${name}`) {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith("-")) throw new ConfigError(`--${name}: expects a value`);
      argv.splice(i, 2);
      return value;
    }
    if (arg.startsWith(`--${name}=`)) {
      argv.splice(i, 1);
      return arg.slice(name.length + 3);
    }
  }
  return undefined;
}

function configPathOf(argv: string[]): string | undefined {
  return takeFlag(argv, "config") ?? (() => {
    const index = argv.indexOf("-c");
    if (index === -1) return undefined;
    const value = argv[index + 1];
    if (value === undefined) throw new ConfigError("-c: expects a file path");
    argv.splice(index, 2);
    return value;
  })();
}

/**
 * Runs a command and resolves to its exit code. The service's own command resolves once it
 * is listening; the process then stays up until a signal.
 */
export async function main(argv: readonly string[]): Promise<number> {
  const [first, ...rest] = argv;
  try {
    if (first === "--version" || first === "-v") {
      process.stdout.write(`hackerpot ${VERSION}\n`);
      return 0;
    }
    if (first === "help" || ((first === "--help" || first === "-h") && rest.length === 0)) {
      process.stdout.write(USAGE);
      return 0;
    }
    if (first === "dashboard") return await dashboard(rest);
    if (first === "detectors") return detectors(rest);
    if (first === "robots") return robots(rest);

    let serviceArgs: string[];
    if (first !== undefined && Object.hasOwn(SERVICE_COMMANDS, first)) {
      const flag = SERVICE_COMMANDS[first];
      serviceArgs = flag === undefined ? rest : [flag, ...rest];
    } else if (first === undefined || first.startsWith("-")) {
      serviceArgs = [...argv];
    } else {
      process.stderr.write(`Unknown command "${first}".\n\n${USAGE}`);
      return 1;
    }
    process.exitCode = undefined;
    await runService(serviceArgs);
    return typeof process.exitCode === "number" ? process.exitCode : 0;
  } catch (err) {
    if (err instanceof ConfigError) {
      // A bad config or bad arguments are an operator mistake, not a crash.
      process.stderr.write(`hackerpot: ${err.message}\n`);
      return 2;
    }
    throw err;
  }
}

/**
 * The dashboard as its own service. Reads a running HackerPot through its management API,
 * holding the API key here so no browser ever sees it, and serves the page with the
 * `[dashboard]` section's listener and authentication.
 */
async function dashboard(argv: string[]): Promise<number> {
  const args = [...argv];
  const configPath = configPathOf(args);
  const managementUrl = takeFlag(args, "management-url");
  const apiKey = takeFlag(args, "api-key");
  const host = takeFlag(args, "host");
  const port = takeFlag(args, "port");
  if (args.length > 0) throw new ConfigError(`dashboard: unexpected argument "${args[0]}"`);

  const config = loadConfig({ path: configPath });
  const source = buildDashboardSource(config, {
    managementUrl,
    apiKey,
    onError: (error) => log({ kind: "dashboard-source-error", error: error instanceof Error ? error.message : String(error) }),
  });
  const options = buildDashboardOptions(config);
  if (host !== undefined) options.host = host;
  if (port !== undefined) {
    const parsed = Number(port);
    if (!Number.isInteger(parsed) || parsed < 0 || parsed > 65_535) throw new ConfigError(`--port: "${port}" is not a port`);
    options.port = parsed;
  }
  let server: Awaited<ReturnType<typeof startDashboard>>;
  try {
    server = await startDashboard(source, { ...options, onError: (error) => log({ kind: "dashboard-error", error: error instanceof Error ? error.message : String(error) }) });
  } catch (err) {
    // The dashboard's own refusals (no auth on a public bind, a taken port) are config errors.
    if (err instanceof Error && err.name === "DashboardConfigError") throw new ConfigError(err.message);
    throw err;
  }
  log({ kind: "startup", service: "dashboard", url: server.url, source: source.description });

  const stop = (signal: string): void => {
    log({ kind: "shutdown", signal });
    server.close().then(
      () => process.exit(0),
      () => process.exit(1),
    );
  };
  process.once("SIGTERM", () => stop("SIGTERM"));
  process.once("SIGINT", () => stop("SIGINT"));
  return 0;
}

function detectors(argv: string[]): number {
  const args = [...argv];
  const config = loadConfig({ path: configPathOf(args) });
  if (args.length > 0) throw new ConfigError(`detectors: unexpected argument "${args[0]}"`);
  const installed = buildDetectors(config);
  const shadowed = new Set(config.engine.shadowDetectors);
  for (const detector of installed) {
    process.stdout.write(`${detector.id.padEnd(26)} ${(detector.needsBody ? "body" : "headers").padEnd(8)} ${shadowed.has(detector.id) ? "shadow " : "       "}${detector.description ?? ""}\n`);
  }
  process.stdout.write(`\n${installed.length} detectors installed from ${config.source}.\n`);
  return 0;
}

function robots(argv: string[]): number {
  const args = [...argv];
  const config = loadConfig({ path: configPathOf(args) });
  const sitemap = takeFlag(args, "sitemap");
  if (args.length > 0) throw new ConfigError(`robots: unexpected argument "${args[0]}"`);
  const trap = config.detectors.trap;
  const decoyConfig = config.detectors["decoy-path"];
  const decoys = [...decoyConfig.decoys, ...(decoyConfig.replaceDefaults ? [] : defaultDecoyPaths.filter((decoy) => !decoyConfig.disabled.includes(decoy.id)))];
  process.stdout.write(
    generateRobotsTxt({
      decoys,
      ...(trap.enabled ? { trapPaths: trap.options.paths ?? DEFAULT_TRAP_PATHS } : {}),
      ...(sitemap !== undefined ? { sitemap } : {}),
    }),
  );
  return 0;
}

function log(event: Record<string, unknown>): void {
  console.log(JSON.stringify({ ts: new Date().toISOString(), ...event }));
}

// Re-exported for callers that want stdin handling identical to `hackerpot explain`.
export { readStdin };
