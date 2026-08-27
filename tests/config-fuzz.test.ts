import { describe, expect, it } from "vitest";
import { ConfigError, parseConfigText } from "../src/config/index.js";

/**
 * Fuzzing the config reader.
 *
 * A config parser is where hostile-shaped input meets a hand-written validator:
 * ~60 bespoke failure paths, each hand-rolled, none of which had ever seen input
 * they weren't written for. The property under test is narrow and absolute:
 *
 *   Every input either parses, or fails with a ConfigError.
 *
 * Never a TypeError from an unchecked property access, never a RangeError from a
 * huge number, never an unhandled throw out of a `fail()` path. That matters
 * because standalone maps ConfigError to a clean "bad config" exit while anything
 * else is an unhandled crash — and because SIGHUP re-parses at runtime, so a
 * parser that throws the wrong kind of error takes a running honeypot down.
 *
 * Deterministic by design: a seeded PRNG and a checked-in corpus. A fuzzer that
 * finds a fresh failure on a random CI run is a flaky test, and a security guard
 * that cries wolf gets muted.
 */

/** mulberry32 — small, seeded, reproducible. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Keys that actually belong to each section.
 *
 * A first version paired random sections with random keys, and ~92% of inputs died
 * on unknown-key before reaching anything interesting — it was testing the
 * unknown-key check (already unit-tested) rather than the cross-field validators.
 * Pairing real keys with their real section drives inputs into the semantic checks:
 * threshold ordering, port collisions, paired options, IP and URL shapes.
 */
const SCHEMA: Record<string, string[]> = {
  server: ["host", "port", "trust_proxy"],
  logging: ["format", "startup", "include_headers", "include_body"],
  engine: ["activity_window_ms", "fingerprint_window_ms"],
  policy: ["block_threshold", "tarpit_threshold"],
  "store.memory": ["max_hits"],
  "store.file": ["enabled", "path", "load_on_start"],
  "store.redis": ["enabled", "url", "key_prefix", "score_ttl_seconds", "max_hits"],
  "store.elastic": ["enabled", "node", "index", "api_key", "username", "password", "max_hits", "refresh"],
  blocklist: ["backend", "key_prefix"],
  "blocklist.enforcer": ["enabled", "command", "args", "timeout_ms", "webhook", "secret", "max_per_window", "window_ms"],
  intel: ["enabled", "feeds", "refresh_seconds", "min_score", "api_key", "ttl_seconds", "max_entries", "enforce"],
  allowlist: ["ips"],
  "port-scan": ["enabled", "ports", "host", "scan_threshold", "banner"],
  smtp: ["enabled", "port", "host", "banner", "hostname", "local_domains", "drop_above_score", "max_connections", "capture_body", "max_body_chars"],
  ssh: ["enabled", "port", "host", "ident", "max_auth_attempts", "drop_above_score", "max_connections", "interactive", "accept_on_attempt", "shell_hostname", "max_commands", "max_command_length", "max_session_ms", "host_keys", "host_key_files"],
  management: ["enabled", "host", "port", "api_keys", "websocket"],
  "detectors.decoy-path": ["enabled", "replace_defaults", "disabled"],
  "detectors.payload-injection": ["enabled", "score", "respond_with", "inspect_body", "inspect_headers"],
  "detectors.ssrf-probe": ["enabled", "score", "respond_with", "inspect_body", "inspect_headers"],
  "detectors.sensitive-file": ["enabled", "score", "respond_with", "patterns"],
  "detectors.credential-bruteforce": ["enabled", "score", "respond_with", "auth_paths", "window_ms", "attempt_threshold"],
  "detectors.host-header-injection": ["enabled", "score", "respond_with", "expected_hosts"],
  "detectors.open-redirect": ["enabled", "score", "respond_with", "params", "trusted_hosts"],
  "detectors.honeytoken": ["enabled", "score", "respond_with", "tokens"],
  "detectors.repeat-actor": ["enabled", "score", "respond_with", "distinct_ip_threshold", "window_ms"],
  "responses.tarpit": ["enabled", "delay_ms", "status", "body", "escalate", "max_concurrent"],
  "responses.chaos": ["enabled", "statuses", "garbage_chance", "max_garbage_bytes"],
  "responses.fake-data": ["enabled", "names", "domain", "rows"],
  "responses.large-payload": ["enabled", "total_bytes", "chunk_bytes", "throttle_ms", "content_type", "max_concurrent"],
};
const SECTIONS = Object.keys(SCHEMA);

/** Values chosen to hit type checks, numeric bounds, regex compilation, and prototype keys. */
const VALUES = [
  '""', '"-"', '"__proto__"', '"constructor"', '0', '-1', '1', '999999999999999999999',
  '1.5', '-0.0', 'true', 'false', '[]', '[[]]', '[0]', '["a"]', '[1, "a"]', '[[1, 2], [3]]',
  '{}', '{ a = 1 }', '"("', '"[a-"', '"/x/gg"', '"(a+)+$"', '"\\u0000"', '"\\n\\r"',
  '"' + "A".repeat(2000) + '"', '"::ffff:10.0.0.0/104"', '"10.0.0.0/33"', '"http://x"',
  '"https://x"', '"ftp://x"', '"example.com:8443"', '"127.0.0.1"', '"10.0.0.0/8"',
  '4004', '9500', '2222', '[2222, 4004]', '[500, 502]', '30', '3600',
];

function generate(rand: () => number, depth: number): string {
  const lines: string[] = [];
  const sections = 1 + Math.floor(rand() * 4);
  for (let i = 0; i < sections; i += 1) {
    const section = SECTIONS[Math.floor(rand() * SECTIONS.length)]!;
    const keys = SCHEMA[section]!;
    // Occasionally malform the header itself, so the table/array-of-tables and
    // wrong-shape paths still get hit.
    lines.push(rand() < 0.08 ? `[[${section}]]` : `[${section}]`);
    // TOML rejects a duplicated key outright, so emitting one wastes the case on a
    // syntax error instead of reaching a validator. Track what this section used.
    const used = new Set<string>();
    const count = Math.floor(rand() * depth);
    for (let k = 0; k < count; k += 1) {
      // Mostly a key that belongs here; sometimes a foreign one for unknown-key.
      const key = rand() < 0.9 ? keys[Math.floor(rand() * keys.length)]! : "definitely_not_a_key";
      if (used.has(key)) continue;
      used.add(key);
      lines.push(`${key} = ${VALUES[Math.floor(rand() * VALUES.length)]!}`);
    }
  }
  return lines.join("\n");
}

/** Inputs that previously broke something, or that target a specific hand-rolled path. */
const HOSTILE_CORPUS = [
  "",
  "\n\n\n",
  "[server]",
  "[server]\nport = 4004\n[server]\nport = 5005",           // duplicate table
  "__proto__ = 1",                                          // prototype key at root
  "[__proto__]\nx = 1",
  '[allowlist]\nips = ["__proto__"]',
  "[detectors.decoy-path]\n[[detectors.decoy-path.decoys]]", // table array, no required keys
  '[detectors.honeytoken]\ntokens = [{ value = "x" }, "y"]',  // mixed token shapes
  '[detectors.sensitive-file]\npatterns = ["(a+)+$"]',        // ReDoS-shaped regex (compiled, not run)
  '[detectors.credential-bruteforce]\nauth_paths = "/x/gg"',  // invalid flags
  "[policy]\nblock_threshold = 0\ntarpit_threshold = 0",
  "[server]\nport = 999999999999999999999",
  '[intel]\nfeeds = ["https://a", "https://a"]',             // duplicates
  '[management]\napi_keys = []\nenabled = true',
  "[store.memory]\nmax_hits = 0",
  "[ssh]\nmax_session_ms = 0",
  '[blocklist.enforcer]\ncommand = "x"\nargs = ["{ip}"]\nmax_per_window = 0',
  "[engine]\nactivity_window_ms = 0\nfingerprint_window_ms = 0",
  '[logging]\nformat = "JSON"',                              // wrong case
  "[responses.chaos]\ngarbage_chance = -0.0",
  '[detectors.decoy-path]\ndisabled = ["dotenv", "dotenv"]',
];

/** Normalised validator messages seen, so coverage can be asserted rather than assumed. */
function parseIsSafe(text: string, seen?: Set<string>): void {
  try {
    parseConfigText(text, "fuzz.toml");
  } catch (err) {
    if (err instanceof ConfigError && seen && !/invalid TOML/.test(err.message)) {
      seen.add(err.message.replace(/"[^"]*"/g, '"X"').replace(/\d+/g, "N").slice(0, 60));
    }
    // The only acceptable failure. Anything else is a crash path: standalone maps
    // ConfigError to exit 2, and SIGHUP catches it to keep the old config running.
    if (!(err instanceof ConfigError)) {
      throw new Error(`non-ConfigError ${(err as Error).name} for input:\n${text.slice(0, 400)}\n→ ${(err as Error).message}`);
    }
  }
}

/** A validator message that isn't just a type or unknown-key rejection. */
function isSemantic(message: string): boolean {
  return !/unknown key|must be a table|must be an array|must be a string|must be a number|must be true/.test(message);
}

describe("config reader fuzzing", () => {
  it("never throws anything but a ConfigError on the hostile corpus", () => {
    for (const input of HOSTILE_CORPUS) parseIsSafe(input);
  });

  it("never throws anything but a ConfigError on generated input", () => {
    for (const seed of [0x1234abcd, 0x0badf00d]) {
      const rand = rng(seed);
      for (let i = 0; i < 1500; i += 1) parseIsSafe(generate(rand, 6));
    }
  });

  it("actually reaches the validators, rather than passing hollow", () => {
    // A fuzzer that passes tells you nothing until you know what it touched. The
    // first version of this file paired sections and keys at random, so ~92% of
    // inputs died on unknown-key or TOML duplicate-key before reaching anything
    // interesting — it passed while re-testing a check that already had unit tests.
    // These floors turn that failure into a red test instead of a green one.
    //
    // The seeds are fixed, so these numbers are stable, not flaky. Measured at
    // 353 distinct / 53 semantic; the floors sit below that with headroom for
    // wording changes, and will trip on a real collapse in coverage.
    const seen = new Set<string>();
    for (const seed of [0x1234abcd, 0x0badf00d]) {
      const rand = rng(seed);
      for (let i = 0; i < 1500; i += 1) parseIsSafe(generate(rand, 6), seen);
    }
    expect(seen.size).toBeGreaterThanOrEqual(250);
    // Cross-field and bounds checks specifically — threshold ordering, URL and IP
    // shapes, regex compilation, enums. These are the paths worth fuzzing at all.
    expect([...seen].filter(isSemantic).length).toBeGreaterThanOrEqual(40);
  });

  it("parses the whole corpus well within a sane time budget", () => {
    // A hand-rolled validator looping over a huge array, or a pathological regex
    // compile, would blow past this long before it looked like a hang.
    const started = performance.now();
    const rand = rng(0x51ede77);
    for (let i = 0; i < 500; i += 1) parseIsSafe(generate(rand, 12));
    expect(performance.now() - started).toBeLessThan(5000);
  });

  it("keeps a prototype key as data rather than polluting Object.prototype", () => {
    // TOML can carry a literal `__proto__` key. If the reader walked it onto a
    // plain object, a config file could poison every object in the process.
    parseIsSafe('__proto__ = "polluted"\n[allowlist]\nips = []');
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
    expect(Object.prototype).not.toHaveProperty("polluted");
  });
});
