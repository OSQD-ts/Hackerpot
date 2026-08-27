import type { HackerpotConfig } from "./schema.js";

/**
 * Which parts of a config file can be applied to a running process, and which
 * cannot.
 *
 * `HoneypotEngine.reconfigure()` swaps detectors, response actions, the policy,
 * and the allowlist in place; the store, activity registry, and blocklist are
 * deliberately excluded because rebuilding them would discard the suspicion
 * scores, active blocks, and sliding windows an attacker has already accrued.
 * Listeners cannot be re-bound without dropping live connections.
 *
 * So a reload applies what it safely can and REFUSES the rest by name. Silently
 * ignoring a changed setting is the failure this project keeps designing out:
 * the operator edits a port, reloads, sees no error, and believes it took.
 */

/** Top-level sections that only take effect at startup, with why. */
const RESTART_REQUIRED: Array<{ key: string; select: (c: HackerpotConfig) => unknown; why: string }> = [
  { key: "server", select: (c) => c.server, why: "the HTTP listener is already bound" },
  { key: "store", select: (c) => c.store, why: "swapping the store would discard accrued scores" },
  { key: "blocklist", select: (c) => c.blocklist, why: "swapping the blocklist would drop active blocks" },
  { key: "engine.activity_window_ms", select: (c) => c.engine.activityWindowMs, why: "the sliding windows hold live per-IP history" },
  { key: "engine.fingerprint_window_ms", select: (c) => c.engine.fingerprintWindowMs, why: "the actor registry holds live fingerprint→IP history" },
  { key: "port-scan", select: (c) => c.portScan, why: "the sentinel ports are already bound" },
  { key: "smtp", select: (c) => c.smtp, why: "the SMTP listener is already bound" },
  { key: "ssh", select: (c) => c.ssh, why: "the SSH listener is already bound" },
  { key: "management", select: (c) => c.management, why: "the management listener is already bound" },
  // Turning ingest on/off or flipping enforce changes how the blocklist itself is
  // composed (whether a non-enforcing feed child exists at all), which is decided
  // when the engine is built. The feed list and schedule are reloadable; these are not.
  { key: "intel.enabled", select: (c) => c.intel.enabled, why: "the blocklist composition is built at startup" },
  { key: "intel.enforce", select: (c) => c.intel.enforce, why: "whether ingest can reach the firewall is fixed at startup" },
];

/** Sections a reload applies. */
const RELOADABLE: Array<{ key: string; select: (c: HackerpotConfig) => unknown }> = [
  { key: "detectors", select: (c) => c.detectors },
  { key: "responses", select: (c) => c.responses },
  { key: "policy", select: (c) => c.policy },
  { key: "allowlist", select: (c) => c.allowlist },
  // Feeds, schedule, and limits — the poller is rebuilt in place from these.
  { key: "intel", select: (c) => [c.intel.feeds, c.intel.refreshSeconds, c.intel.minScore, c.intel.apiKey, c.intel.ttlSeconds, c.intel.maxEntries] },
  { key: "logging", select: (c) => c.logging },
];

/**
 * Stable comparison key. Plain JSON.stringify collapses every RegExp to `{}`, so
 * two different patterns would compare equal and a changed detector regex would
 * look like no change at all.
 */
function stableKey(value: unknown): string {
  return JSON.stringify(value, (_k, v: unknown) => (v instanceof RegExp ? `/${v.source}/${v.flags}` : v)) ?? "";
}

export interface ReloadPlan {
  /** Reloadable sections whose contents differ from the running config. */
  applied: string[];
  /** Changed sections that need a restart, each with the reason. */
  requiresRestart: Array<{ key: string; why: string }>;
  /** True when nothing at all differs — the reload is a no-op. */
  unchanged: boolean;
}

/** Diffs a freshly-parsed config against the running one. Pure; applies nothing. */
export function planReload(running: HackerpotConfig, next: HackerpotConfig): ReloadPlan {
  const applied = RELOADABLE.filter((s) => stableKey(s.select(running)) !== stableKey(s.select(next))).map((s) => s.key);
  const requiresRestart = RESTART_REQUIRED.filter((s) => stableKey(s.select(running)) !== stableKey(s.select(next))).map((s) => ({ key: s.key, why: s.why }));
  return { applied, requiresRestart, unchanged: applied.length === 0 && requiresRestart.length === 0 };
}
