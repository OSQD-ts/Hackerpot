import { ConfigError } from "./reader.js";
import type { HackerpotConfig } from "./schema.js";

/**
 * Environment-variable overrides, applied on top of a loaded config file.
 *
 * Precedence is: built-in defaults < config file < environment. Containers get
 * their config baked into an image or mounted as a file, then tweak the last
 * mile per deployment with `-e` — so the environment has to win. Every variable
 * here predates the config file and keeps working exactly as before.
 */

function read(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const value = env[name];
  return value && value.trim() ? value.trim() : undefined;
}

function asBoolean(name: string, value: string): boolean {
  const normalized = value.toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  throw new ConfigError(`${name}: must be true or false, got "${value}"`);
}

function asInteger(name: string, value: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) throw new ConfigError(`${name}: must be a non-negative integer, got "${value}"`);
  return parsed;
}

function asList(value: string): string[] {
  return value.split(",").map((entry) => entry.trim()).filter(Boolean);
}

export function applyEnvOverrides(config: HackerpotConfig, env: NodeJS.ProcessEnv = process.env): HackerpotConfig {
  const port = read(env, "PORT");
  if (port !== undefined) config.server.port = asInteger("PORT", port);

  const host = read(env, "HOST");
  if (host !== undefined) config.server.host = host;

  const trustProxy = read(env, "TRUST_PROXY");
  if (trustProxy !== undefined) config.server.trustProxy = asBoolean("TRUST_PROXY", trustProxy);

  const logFormat = read(env, "LOG_FORMAT");
  if (logFormat !== undefined) {
    const normalized = logFormat.toLowerCase();
    if (normalized !== "json" && normalized !== "text") throw new ConfigError(`LOG_FORMAT: must be "json" or "text", got "${logFormat}"`);
    config.logging.format = normalized;
  }

  const scanPorts = read(env, "SCAN_PORTS");
  if (scanPorts !== undefined) {
    config.portScan.ports = asList(scanPorts).map((entry) => asInteger("SCAN_PORTS", entry));
    config.portScan.enabled = config.portScan.ports.length > 0;
  }

  const scanBanner = read(env, "SCAN_BANNER");
  if (scanBanner !== undefined) config.portScan.banner = scanBanner;

  const hitLog = read(env, "HIT_LOG");
  if (hitLog !== undefined) {
    config.store.file.path = hitLog;
    config.store.file.enabled = true;
  }

  const redisUrl = read(env, "REDIS_URL");
  if (redisUrl !== undefined) {
    config.store.redis.url = redisUrl;
    config.store.redis.enabled = true;
  }

  const redisTtl = read(env, "REDIS_SCORE_TTL");
  if (redisTtl !== undefined) config.store.redis.scoreTtlSeconds = asInteger("REDIS_SCORE_TTL", redisTtl);

  const honeytokens = read(env, "HONEYTOKENS");
  if (honeytokens !== undefined) {
    const tokens = asList(honeytokens).map((value) => ({ value, label: "env-honeytoken" }));
    config.detectors.honeytoken.options.tokens = tokens;
    config.detectors.honeytoken.enabled = tokens.length > 0;
  }

  const managementKeys = read(env, "MANAGEMENT_API_KEYS");
  if (managementKeys !== undefined) {
    config.management.apiKeys = asList(managementKeys);
    config.management.enabled = config.management.apiKeys.length > 0;
  }

  const managementHost = read(env, "MANAGEMENT_HOST");
  if (managementHost !== undefined) config.management.host = managementHost;

  const managementPort = read(env, "MANAGEMENT_PORT");
  if (managementPort !== undefined) config.management.port = asInteger("MANAGEMENT_PORT", managementPort);

  if (config.management.enabled && config.management.apiKeys.length === 0) {
    throw new ConfigError("MANAGEMENT_API_KEYS: is required when the management API is enabled");
  }

  return config;
}
