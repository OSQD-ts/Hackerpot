import { existsSync, readFileSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { parse as parseToml } from "smol-toml";
import { applyEnvOverrides } from "./env.js";
import { ConfigError } from "./reader.js";
import { parseConfig, type HackerpotConfig } from "./schema.js";

/**
 * Locating, reading, and parsing the TOML config file.
 *
 * Nothing here is required: with no file anywhere, `loadConfig()` returns the
 * built-in defaults, which is exactly how the standalone service behaved before
 * config files existed.
 */

/** Relative paths searched, in order, when no config file is named explicitly. */
export const CONFIG_SEARCH_PATHS = ["hackerpot.toml", "hackerpot.config.toml", "config/hackerpot.toml"] as const;

/** Checked last, so a container image can ship a default without one in the working directory. */
export const SYSTEM_CONFIG_PATH = "/etc/hackerpot/hackerpot.toml";

/** Environment variable naming an explicit config file. */
export const CONFIG_PATH_ENV = "HACKERPOT_CONFIG";

export function discoverConfigPath(cwd: string = process.cwd()): string | undefined {
  for (const candidate of CONFIG_SEARCH_PATHS) {
    const path = resolve(cwd, candidate);
    if (existsSync(path)) return path;
  }
  return existsSync(SYSTEM_CONFIG_PATH) ? SYSTEM_CONFIG_PATH : undefined;
}

/** Parses TOML text. `source` is only used to label errors. */
export function parseConfigText(text: string, source: string): HackerpotConfig {
  let raw: Record<string, unknown>;
  try {
    raw = parseToml(text) as Record<string, unknown>;
  } catch (err) {
    throw new ConfigError(`${source}: invalid TOML — ${(err as Error).message}`);
  }
  return parseConfig(raw, source);
}

export function loadConfigFile(path: string, cwd: string = process.cwd()): HackerpotConfig {
  const resolved = isAbsolute(path) ? path : resolve(cwd, path);
  if (!existsSync(resolved)) throw new ConfigError(`${resolved}: config file not found`);
  return parseConfigText(readFileSync(resolved, "utf8"), resolved);
}

export interface LoadConfigOptions {
  /** An explicit file to load. Missing files are an error rather than a silent fallback. */
  path?: string | undefined;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  /** Apply the environment-variable overrides on top of the file. Default true. */
  applyEnv?: boolean;
}

/**
 * Resolves the effective configuration: an explicitly named file, else
 * `HACKERPOT_CONFIG`, else the first file found in the search paths, else the
 * built-in defaults — with environment overrides applied last.
 */
export function loadConfig(options: LoadConfigOptions = {}): HackerpotConfig {
  const cwd = options.cwd ?? process.cwd();
  const env = options.env ?? process.env;

  const explicit = options.path ?? (env[CONFIG_PATH_ENV]?.trim() || undefined);
  const config = explicit !== undefined ? loadConfigFile(explicit, cwd) : fromDiscovery(cwd);

  return (options.applyEnv ?? true) ? applyEnvOverrides(config, env) : config;
}

function fromDiscovery(cwd: string): HackerpotConfig {
  const discovered = discoverConfigPath(cwd);
  return discovered !== undefined ? loadConfigFile(discovered, cwd) : parseConfig({}, "<defaults>");
}

/** Placeholder shown in place of a secret. Non-empty secrets only, so "set" vs "unset" stays visible. */
const REDACTED = "«redacted»";

/**
 * Config keys whose values are credentials. Matched on the key name alone, so a key
 * added later to any section is covered without anyone remembering to update a path.
 */
const SECRET_KEYS = new Set(["apikey", "apikeys", "password", "secret", "token", "headers"]);

/**
 * Replaces the userinfo in a connection URL, keeping scheme, host, port and path so the
 * value stays reviewable — those are what an operator is checking. Done as a textual
 * substitution rather than through `URL`, whose setters percent-encode the placeholder
 * and re-serialize the rest, turning a readable line into `redis://:%C2%AB…%C2%BB@host`.
 */
function redactUrlCredentials(value: string): string {
  return value.replace(/^([a-z][a-z0-9+.-]*:\/\/)[^/@]*@/i, `$1${REDACTED}@`);
}

/**
 * JSON view of a resolved config, with RegExp values rendered as the `/…/flags`
 * literals the file accepts, and **every credential redacted**. Backs `--print-config`.
 *
 * The redaction is the point. This is `npm run config:check` — a validation command
 * people run casually, in CI, and over screen shares — and it printed the management
 * API keys, the webhook HMAC secrets, the Redis URL password, the Elasticsearch
 * password and the peer-feed API key verbatim to stdout, which in a container is
 * whatever collects the logs. Validating a config should never be the thing that
 * copies its secrets somewhere they are retained.
 *
 * Redaction is by key NAME rather than by path, so a credential added to any section
 * later is covered by default. `headers` is included because auth headers are the usual
 * way an operator attaches a bearer token to a webhook. Empty values are left as-is, so
 * the output still distinguishes "configured" from "not configured" — the thing an
 * operator is actually checking.
 */
export function describeConfig(config: HackerpotConfig): string {
  return JSON.stringify(
    config,
    (key, value: unknown) => {
      if (value instanceof RegExp) return `/${value.source}/${value.flags}`;
      const name = key.toLowerCase();
      if (name === "url" && typeof value === "string") return redactUrlCredentials(value);
      if (!SECRET_KEYS.has(name)) return value;
      if (typeof value === "string") return value === "" ? value : REDACTED;
      // Keep the shape so the count/keys stay reviewable; replace only the values.
      if (Array.isArray(value)) return value.map(() => REDACTED);
      if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).map((k) => [k, REDACTED]));
      return value;
    },
    2,
  );
}
