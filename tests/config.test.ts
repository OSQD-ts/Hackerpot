import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ConfigError,
  applyEnvOverrides,
  buildDetectors,
  buildHoneypotConfig,
  buildPolicy,
  buildResponseActions,
  createBlocklist,
  createPortScanSentinel,
  createStore,
  createSmtpHoneypot,
  createSshHoneypot,
  defaultConfig,
  discoverConfigPath,
  loadConfig,
  parseConfigText,
  planReload,
} from "../src/config/index.js";
import {
  CompositeBlocklist,
  EnforcingBlocklist,
  HoneypotEngine,
  IpAllowlist,
  IpTracker,
  MemoryBlocklist,
  MemoryStore,
  applyIocEntries,
  defaultDetectors,
  defaultResponseActions,
} from "../src/index.js";
import type { HackerpotConfig } from "../src/config/index.js";
import type { Detection, RequestFacts } from "../src/index.js";

function parse(toml: string) {
  return parseConfigText(toml, "test.toml");
}

function facts(partial: Partial<RequestFacts> & Pick<RequestFacts, "path">): RequestFacts {
  return { method: "GET", query: {}, headers: {}, ip: "10.0.0.1", ...partial };
}


/** Enabled-flags only — the part of the config that must match literally. */
function toggles(config: HackerpotConfig): Record<string, boolean> {
  const flags: Record<string, boolean> = {};
  for (const [id, section] of Object.entries(config.detectors)) flags[`detector.${id}`] = section.enabled;
  for (const [id, section] of Object.entries(config.responses)) flags[`response.${id}`] = section.enabled;
  return flags;
}

/**
 * Runs a fixed battery of probes through an engine built from `config` and
 * returns what fired. Two configs producing identical output are behaviorally
 * identical, thresholds and scores included.
 */
async function probe(config: HackerpotConfig): Promise<unknown[]> {
  const engine = new HoneypotEngine({
    detectors: buildDetectors(config),
    responseActions: buildResponseActions(config),
    policy: buildPolicy(config),
  });

  const requests: RequestFacts[] = [
    facts({ path: "/.env", ip: "10.1.0.1", headers: { host: "x", "user-agent": "Mozilla/5.0" } }),
    facts({ path: "/search", query: { q: "1' UNION SELECT password FROM users" }, ip: "10.1.0.2", headers: { host: "x", "user-agent": "Mozilla/5.0" } }),
    facts({ path: "/", method: "TRACE", ip: "10.1.0.3", headers: { host: "x", "user-agent": "Mozilla/5.0" } }),
    facts({ path: "/backup/db.sql", ip: "10.1.0.4", headers: { host: "x", "user-agent": "Mozilla/5.0" } }),
    facts({ path: "/", ip: "10.1.0.5", headers: { host: "x", "user-agent": "sqlmap/1.7" } }),
    facts({ path: "/", ip: "10.1.0.6" }), // no Host, no User-Agent
    facts({ path: "/fetch", query: { url: "http://169.254.169.254/latest/meta-data/" }, ip: "10.1.0.9", headers: { host: "x", "user-agent": "Mozilla/5.0" } }),
    facts({ path: "/redir", query: { next: "//evil.example.com/phish" }, ip: "10.1.0.10", headers: { host: "x", "user-agent": "Mozilla/5.0" } }),
    facts({ path: "/uploads/shell.php", ip: "10.1.0.11", headers: { host: "x", "user-agent": "Mozilla/5.0" } }),
    facts({ path: "/page", query: { q: "x%0d%0aSet-Cookie:%20admin=1" }, ip: "10.1.0.12", headers: { host: "x", "user-agent": "Mozilla/5.0" } }),
    // Header-list probes. These exist because the shipped file restating a
    // factory list is exactly how a default silently goes stale: an ordinary
    // proxied request carries an internal IP in X-Forwarded-For, so a config
    // that scans that header (and a default that doesn't) diverge right here.
    facts({ path: "/api/orders", ip: "10.1.0.13", headers: { host: "shop.example.com", "user-agent": "Mozilla/5.0", "x-forwarded-for": "10.0.0.7", "x-forwarded-host": "shop.example.com", forwarded: "for=192.168.1.10" } }),
    // NoSQL operator injection, in both shapes the detector recognizes.
    facts({ path: "/login", query: { "user[$ne]": "" }, ip: "10.1.0.15", headers: { host: "x", "user-agent": "Mozilla/5.0" } }),
    facts({ path: "/api/login", method: "POST", body: '{"username":"admin","password":{"$ne":null}}', ip: "10.1.0.16", headers: { host: "x", "user-agent": "Mozilla/5.0", "content-type": "application/json" } }),
    // GraphQL introspection, a JWT with alg:none, and a browser-claiming UA that
    // omits the headers every real browser sends.
    facts({ path: "/graphql", method: "POST", body: '{"query":"{ __schema { types { name } } }"}', ip: "10.1.0.17", headers: { host: "x", "user-agent": "Mozilla/5.0" } }),
    facts({ path: "/api/me", ip: "10.1.0.18", headers: { host: "x", "user-agent": "Mozilla/5.0", authorization: "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9." } }),
    facts({ path: "/", ip: "10.1.0.19", headers: { host: "x", "user-agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0" } }),
    // Prototype pollution, a serialized-object blob in a cookie, and a malformed Host.
    facts({ path: "/api/merge", method: "POST", body: '{"__proto__":{"isAdmin":true}}', ip: "10.1.0.20", headers: { host: "x", "user-agent": "Mozilla/5.0" } }),
    facts({ path: "/", ip: "10.1.0.21", headers: { host: "x", "user-agent": "Mozilla/5.0", cookie: "s=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA" } }),
    facts({ path: "/", ip: "10.1.0.22", headers: { host: "evil.com/../x", "user-agent": "Mozilla/5.0" } }),
    // A legitimate self-redirect back to the request's own host.
    facts({ path: "/login", query: { next: "https://shop.example.com/account" }, ip: "10.1.0.14", headers: { host: "shop.example.com", "user-agent": "Mozilla/5.0" } }),
    // Enough distinct paths to trip path-bruteforce, then one more to observe it.
    ...Array.from({ length: 16 }, (_, i) => facts({ path: `/scan-${i}`, ip: "10.1.0.7", headers: { host: "x", "user-agent": "Mozilla/5.0" } })),
    // Enough auth attempts to trip credential-bruteforce.
    ...Array.from({ length: 9 }, () => facts({ path: "/login", method: "POST", ip: "10.1.0.8", headers: { host: "x", "user-agent": "Mozilla/5.0" } })),
  ];

  const observed: unknown[] = [];
  for (const request of requests) {
    const result = await engine.evaluate(request);
    observed.push({
      path: request.path,
      actionId: result.actionId,
      detections: result.detections.map((d) => ({ id: d.detectorId, score: d.score, reason: d.reason, respondWith: d.respondWith })),
    });
  }
  return observed;
}

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "hackerpot-config-"));
}

describe("config parsing", () => {
  it("returns the documented defaults for an empty file", () => {
    const config = parse("");
    // trust_proxy defaults OFF: on, the client IP comes from an attacker-supplied
    // header, which is what the allowlist, blocklist, and firewall enforcer all act on.
    expect(config.server).toEqual({ host: "0.0.0.0", port: 4004, trustProxy: false });
    expect(config.policy).toEqual({ blockThreshold: 40, tarpitThreshold: 15 });
    expect(config.logging.format).toBe("json");
    expect(config.store.file.enabled).toBe(false);
    expect(config.store.redis.enabled).toBe(false);
    expect(config.portScan.enabled).toBe(false);
    expect(config.management.enabled).toBe(false);
  });

  it("the shipped hackerpot.toml behaves identically to the built-in defaults", async () => {
    // The file states every default explicitly, so the parsed objects differ
    // (the factories would otherwise fill those in). What has to match is the
    // behavior: same detectors, same scores, same thresholds, same responses.
    const shipped = loadConfig({ path: "hackerpot.toml", applyEnv: false });
    const builtIn = defaultConfig(shipped.source);

    expect(toggles(shipped)).toEqual(toggles(builtIn));
    expect({ ...shipped, detectors: null, responses: null }).toEqual({ ...builtIn, detectors: null, responses: null });
    expect(await probe(shipped)).toEqual(await probe(builtIn));
  });

  it("reads server, logging, and policy settings", () => {
    const config = parse(`
      [server]
      host = "127.0.0.1"
      port = 8080
      trust_proxy = false

      [logging]
      format = "text"
      include_body = true

      [policy]
      block_threshold = 50
      tarpit_threshold = 20
    `);
    expect(config.server).toEqual({ host: "127.0.0.1", port: 8080, trustProxy: false });
    expect(config.logging.format).toBe("text");
    expect(config.logging.includeBody).toBe(true);
    expect(config.policy).toEqual({ blockThreshold: 50, tarpitThreshold: 20 });
  });

  it("rejects an unknown key rather than silently ignoring it", () => {
    expect(() => parse("[server]\nprot = 8080\n")).toThrow(/unknown key: prot/);
  });

  it("rejects a value of the wrong type, naming the key", () => {
    expect(() => parse('[server]\nport = "4004"\n')).toThrow(/server\.port\] must be a number/);
  });

  it("rejects a tarpit threshold above the block threshold", () => {
    expect(() => parse("[policy]\nblock_threshold = 10\ntarpit_threshold = 20\n")).toThrow(/must not exceed block_threshold/);
  });

  it("reports invalid TOML with the source name", () => {
    expect(() => parse("[server\n")).toThrow(/test\.toml: invalid TOML/);
  });

  it("accepts detector sections written with underscores or hyphens", () => {
    const hyphen = parse("[detectors.path-bruteforce]\nunique_path_threshold = 30\n");
    const underscore = parse("[detectors.path_bruteforce]\nunique_path_threshold = 30\n");
    expect(hyphen.detectors["path-bruteforce"].options.uniquePathThreshold).toBe(30);
    expect(underscore.detectors["path-bruteforce"].options.uniquePathThreshold).toBe(30);
  });

  it("compiles regex options, honoring /pattern/flags literals", () => {
    const config = parse(`
      [detectors.credential-bruteforce]
      auth_paths = "^/api/login$"

      [detectors.scanner-signature]
      extra_patterns = ["/CustomScanner/"]
    `);
    expect(config.detectors["credential-bruteforce"].options.authPaths?.flags).toBe("i");
    expect(config.detectors["credential-bruteforce"].options.authPaths?.test("/API/LOGIN")).toBe(true);
    const extra = config.detectors["scanner-signature"].options.extraPatterns?.[0];
    expect(extra?.flags).toBe("");
    expect(extra?.test("CustomScanner")).toBe(true);
    expect(extra?.test("customscanner")).toBe(false);
  });

  it("rejects an unparsable regex", () => {
    expect(() => parse('[detectors.sensitive-file]\npatterns = ["("]\n')).toThrow(/not a valid regular expression/);
  });

  it("accepts honeytokens as bare strings or as labelled tables", () => {
    const bare = parse('[detectors.honeytoken]\ntokens = ["AKIA_ONE"]\n');
    expect(bare.detectors.honeytoken.enabled).toBe(true);
    expect(bare.detectors.honeytoken.options.tokens).toEqual(["AKIA_ONE"]);

    const labelled = parse(`
      [[detectors.honeytoken.tokens]]
      value = "AKIA_TWO"
      label = "decoy-env"
    `);
    expect(labelled.detectors.honeytoken.options.tokens).toEqual([{ value: "AKIA_TWO", label: "decoy-env" }]);
  });

  it("requires a store path or url once a backend is switched on", () => {
    expect(() => parse("[store.file]\nenabled = true\n")).toThrow(/path\] is required/);
    expect(() => parse("[store.redis]\nenabled = true\n")).toThrow(/url\] is required/);
  });

  it("enables a store backend implicitly when its path or url is set", () => {
    const config = parse('[store.file]\npath = "/data/hits.jsonl"\n\n[store.redis]\nurl = "redis://localhost:6379"\n');
    expect(config.store.file.enabled).toBe(true);
    expect(config.store.redis.enabled).toBe(true);
  });

  it("bounds the memory store and rejects a zero retention cap", () => {
    expect(defaultConfig().store.memory.maxHits).toBe(10_000);
    expect(parse("[store.memory]\nmax_hits = 500\n").store.memory.maxHits).toBe(500);
    expect(createStore(parse("[store.memory]\nmax_hits = 500\n")).describe).toBe("memory(max 500)");
    // 0 reads like a retention setting and is actually an off switch for every
    // read path — scores keep working, so nothing else looks broken.
    expect(() => parse("[store.memory]\nmax_hits = 0\n")).toThrow(/retains no incidents at all/);
  });

  it("caps SSH session lifetime and rejects an uncapped one", () => {
    expect(defaultConfig().ssh.maxSessionMs).toBe(120_000);
    expect(parse("[ssh]\nmax_session_ms = 600000\n").ssh.maxSessionMs).toBe(600_000);
    expect(() => parse("[ssh]\nmax_session_ms = 0\n")).toThrow(/held open forever/);
  });

  it("reports store and enforcer failures under distinct sources", () => {
    // Both are background failures routed through one callback; if they shared a
    // label, an unreachable Elasticsearch would send the operator to their
    // firewall config. `source` keeps each pointing at its own fix.
    const seen: string[] = [];
    const config = parse('[store.elastic]\nnode = "http://127.0.0.1:1"\n\n[blocklist.enforcer]\nwebhook = "https://waf.example/block"\n');
    const built = buildHoneypotConfig(config, undefined, (_error, source) => seen.push(source));
    expect(built.describe).toContain("elastic");
    // The store was constructed with the store-scoped reporter, the blocklist with
    // the enforce-scoped one; exercising the store surfaces "store", not "enforce".
    void built.store.record({
      id: "1", timestamp: new Date().toISOString(), ip: "1.2.3.4", method: "GET", path: "/",
      headers: {}, detections: [], score: 1, totalScore: 1, respondedWith: "not-found",
    });
    return new Promise<void>((resolve) => setTimeout(() => {
      expect(seen).toContain("store");
      expect(seen).not.toContain("enforce");
      resolve();
    }, 250));
  });

  it("enables the elastic store from a node url and validates auth", () => {
    const config = parse('[store.elastic]\nnode = "http://es:9200"\nindex = "hp"\napi_key = "k"\n');
    expect(config.store.elastic).toMatchObject({ enabled: true, node: "http://es:9200", index: "hp" });
    expect(defaultConfig().store.elastic.enabled).toBe(false);

    expect(() => parse('[store.elastic]\nenabled = true\n')).toThrow(/node\] is required/);
    expect(() => parse('[store.elastic]\nnode = "es:9200"\n')).toThrow(/must be an http\(s\) URL/);
    // Half-configured basic auth sends no Authorization header at all, so every
    // write 401s into onError and the store looks healthy from outside.
    expect(() => parse('[store.elastic]\nnode = "http://es:9200"\nusername = "u"\n')).toThrow(/basic auth needs both/);
  });

  it("requires api keys before the management API can be enabled", () => {
    expect(() => parse("[management]\nenabled = true\n")).toThrow(/api_keys\] is required/);
    const config = parse('[management]\napi_keys = ["secret"]\n');
    expect(config.management.enabled).toBe(true);
    expect(config.management.host).toBe("127.0.0.1");
  });

  it("parses webhook destinations and rejects non-http urls", () => {
    const config = parse(`
      [management]
      api_keys = ["secret"]

      [[management.webhooks]]
      url = "https://hooks.example.com/hp"
      secret = "sign-me"
      min_score = 20
      [management.webhooks.headers]
      X-Team = "security"
    `);
    expect(config.management.webhooks).toEqual([
      { url: "https://hooks.example.com/hp", secret: "sign-me", minScore: 20, headers: { "X-Team": "security" } },
    ]);
    expect(() => parse('[[management.webhooks]]\nurl = "ftp://nope"\n[management]\napi_keys = ["k"]\n')).toThrow(/must be an http\(s\) URL/);
  });
});

describe("decoy configuration", () => {
  it("appends custom decoys to the built-in set", () => {
    const config = parse(`
      [[detectors.decoy-path.decoys]]
      id = "internal-backup"
      description = "Fake internal backup"
      path = "/internal/backup.sql"
      score = 9
      respond_with = "not-found"
    `);
    expect(config.detectors["decoy-path"].decoys).toHaveLength(1);

    const engine = new HoneypotEngine({ detectors: buildDetectors(config) });
    return Promise.all([
      engine.evaluate(facts({ path: "/internal/backup.sql", ip: "10.0.0.10" })).then((result) => {
        expect(result.detections[0]?.reason).toBe("Fake internal backup");
      }),
      // A built-in decoy still fires alongside the custom one.
      engine.evaluate(facts({ path: "/.env", ip: "10.0.0.11" })).then((result) => {
        expect(result.detections.some((d) => d.detectorId === "decoy-path")).toBe(true);
      }),
    ]);
  });

  it("drops the built-ins named in `disabled`", async () => {
    const config = parse('[detectors.decoy-path]\ndisabled = ["swagger"]\n');
    const engine = new HoneypotEngine({ detectors: buildDetectors(config) });
    const result = await engine.evaluate(facts({ path: "/swagger" }));
    expect(result.detections.some((d) => d.detectorId === "decoy-path")).toBe(false);
  });

  it("rejects a `disabled` entry that names no built-in decoy", () => {
    expect(() => parse('[detectors.decoy-path]\ndisabled = ["nope"]\n')).toThrow(/do not exist: nope/);
  });

  it("replaces the built-in set when asked", async () => {
    const config = parse(`
      [detectors.decoy-path]
      replace_defaults = true

      [[detectors.decoy-path.decoys]]
      id = "only-one"
      pattern = "^/only$"
      score = 5
    `);
    const engine = new HoneypotEngine({ detectors: buildDetectors(config) });
    const builtIn = await engine.evaluate(facts({ path: "/.env", ip: "10.0.0.20" }));
    expect(builtIn.detections.some((d) => d.detectorId === "decoy-path")).toBe(false);
    const custom = await engine.evaluate(facts({ path: "/only", ip: "10.0.0.21" }));
    expect(custom.detections.some((d) => d.detectorId === "decoy-path")).toBe(true);
  });

  it("requires exactly one of `path` or `pattern`", () => {
    expect(() => parse('[[detectors.decoy-path.decoys]]\nid = "x"\n')).toThrow(/needs either "path".*or "pattern"/);
    expect(() => parse('[[detectors.decoy-path.decoys]]\nid = "x"\npath = "/a"\npattern = "b"\n')).toThrow(/cannot set both/);
  });
});

describe("building from config", () => {
  it("builds the default detector and action sets", () => {
    const config = defaultConfig();
    // The config-built set must match the library default set exactly — same
    // detectors, same order — or a config-driven deployment silently runs a
    // different honeypot than an in-code one.
    expect(buildDetectors(config).map((d) => d.id)).toEqual(defaultDetectors().map((d) => d.id));
    expect(buildResponseActions(config).map((a) => a.id)).toEqual(defaultResponseActions().map((a) => a.id));
  });

  it("covers every library default in the config schema", () => {
    // A detector or action added to the library but not to the schema would be
    // unreachable from a config file; this fails the moment that happens.
    const config = defaultConfig();
    expect(Object.keys(config.detectors).filter((id) => id !== "honeytoken").sort()).toEqual(defaultDetectors().map((d) => d.id).sort());
    expect(Object.keys(config.responses).sort()).toEqual(defaultResponseActions().map((a) => a.id).sort());
  });

  it("omits detectors and actions that are switched off", () => {
    const config = parse("[detectors.rate-spike]\nenabled = false\n\n[responses.drip-feed]\nenabled = false\n");
    expect(buildDetectors(config).map((d) => d.id)).not.toContain("rate-spike");
    expect(buildResponseActions(config).map((a) => a.id)).not.toContain("drip-feed");
  });

  it("applies configured detector thresholds and scores", async () => {
    const config = parse("[detectors.path-bruteforce]\nscore = 42\nunique_path_threshold = 3\nwindow_ms = 30000\n");
    const engine = new HoneypotEngine({ detectors: buildDetectors(config) });
    for (const path of ["/a", "/b", "/c"]) await engine.evaluate(facts({ path, ip: "10.9.9.9" }));
    const result = await engine.evaluate(facts({ path: "/d", ip: "10.9.9.9" }));
    const detection = result.detections.find((d) => d.detectorId === "path-bruteforce");
    expect(detection?.score).toBe(42);
  });

  it("does not flag ordinary proxied traffic as an SSRF probe", async () => {
    // Regression: the shipped config once restated ssrf-probe's header list and
    // went stale, re-adding the X-Forwarded-* family. A proxy legitimately puts
    // internal addresses there, so scanning it fires on every proxied request.
    const shipped = loadConfig({ path: "hackerpot.toml", applyEnv: false });
    const engine = new HoneypotEngine({ detectors: buildDetectors(shipped) });
    const result = await engine.evaluate(
      facts({
        path: "/api/orders",
        ip: "10.6.0.1",
        headers: { host: "shop.example.com", "user-agent": "Mozilla/5.0", "x-forwarded-for": "10.0.0.7", forwarded: "for=192.168.1.10" },
      }),
    );
    expect(result.detections.map((d) => d.detectorId)).not.toContain("ssrf-probe");
    expect(result.detections).toHaveLength(0);
  });

  it("pins open-redirect trusted hosts from config, overriding the request Host", async () => {
    const config = parse('[detectors.open-redirect]\ntrusted_hosts = ["App.Example"]\n');
    // Lowercased at parse time so matching is case-insensitive.
    expect(config.detectors["open-redirect"].options.trustedHosts).toEqual(["app.example"]);

    const engine = new HoneypotEngine({ detectors: buildDetectors(config) });
    // A spoofed Host cannot launder an off-site target past the pinned list...
    const spoofed = await engine.evaluate(
      facts({ path: "/login", query: { redirect_uri: "https://app.example/account" }, ip: "10.7.0.1", headers: { host: "evil.example", "user-agent": "Mozilla/5.0" } }),
    );
    expect(spoofed.detections.map((d) => d.detectorId)).not.toContain("open-redirect");

    // ...and a genuinely off-site target still fires.
    const offsite = await engine.evaluate(
      facts({ path: "/login", query: { redirect_uri: "https://evil.example/steal" }, ip: "10.7.0.2", headers: { host: "app.example", "user-agent": "Mozilla/5.0" } }),
    );
    expect(offsite.detections.map((d) => d.detectorId)).toContain("open-redirect");
  });

  it("applies nosql-injection options and can switch off body scanning", async () => {
    const config = parse("[detectors.nosql-injection]\nscore = 21\ninspect_body = false\n");
    const engine = new HoneypotEngine({ detectors: buildDetectors(config) });

    // The bracketed-key form is in the query, so it still fires with the body off.
    const query = await engine.evaluate(facts({ path: "/login", query: { "user[$ne]": "" }, ip: "10.8.0.1" }));
    expect(query.detections.find((d) => d.detectorId === "nosql-injection")?.score).toBe(21);

    // ...but the JSON-body form is not scanned once inspect_body is false.
    const body = await engine.evaluate(facts({ path: "/api/login", method: "POST", body: '{"password":{"$ne":null}}', ip: "10.8.0.2" }));
    expect(body.detections.map((d) => d.detectorId)).not.toContain("nosql-injection");

    // Default config does scan the body.
    const onByDefault = new HoneypotEngine({ detectors: buildDetectors(defaultConfig()) });
    const scanned = await onByDefault.evaluate(facts({ path: "/api/login", method: "POST", body: '{"password":{"$ne":null}}', ip: "10.8.0.3" }));
    expect(scanned.detections.map((d) => d.detectorId)).toContain("nosql-injection");
  });

  it("rejects expected_hosts entries that could never match", () => {
    // The detector strips the port from an incoming Host before comparing, but
    // does not strip it from this list — so an entry with a port would match
    // nothing, and with a list set that means every real request gets flagged.
    expect(() => parse('[detectors.host-header-injection]\nexpected_hosts = ["example.com:8443"]\n')).toThrow(/must not include a port/);
    expect(() => parse('[detectors.host-header-injection]\nexpected_hosts = ["not a host"]\n')).toThrow(/is not a valid hostname/);
  });

  it("uses expected_hosts to flag off-allowlist hosts, lowercased at parse time", async () => {
    const config = parse('[detectors.host-header-injection]\nexpected_hosts = ["Example.COM", "www.example.com"]\n');
    expect(config.detectors["host-header-injection"].options.expectedHosts).toEqual(["example.com", "www.example.com"]);

    const engine = new HoneypotEngine({ detectors: buildDetectors(config) });
    // A canonical host with a port still matches, because the incoming port is stripped.
    const ok = await engine.evaluate(facts({ path: "/", ip: "10.10.0.1", headers: { host: "example.com:8443" } }));
    expect(ok.detections.map((d) => d.detectorId)).not.toContain("host-header-injection");
    // An off-list host is flagged.
    const spoofed = await engine.evaluate(facts({ path: "/", ip: "10.10.0.2", headers: { host: "evil.example" } }));
    expect(spoofed.detections.map((d) => d.detectorId)).toContain("host-header-injection");

    // Without the list, a differing X-Forwarded-Host must NOT fire — that is
    // normal behind a proxy and would false-positive on every proxied request.
    const bare = new HoneypotEngine({ detectors: buildDetectors(defaultConfig()) });
    const proxied = await bare.evaluate(facts({ path: "/", ip: "10.10.0.3", headers: { host: "internal.lb", "x-forwarded-host": "shop.example.com" } }));
    expect(proxied.detections.map((d) => d.detectorId)).not.toContain("host-header-injection");
  });

  it("applies options for the graphql, jwt, and client-anomaly detectors", async () => {
    const config = parse(`
      [detectors.graphql-abuse]
      score = 31
      max_depth = 3

      [detectors.jwt-weakness]
      inspect_headers = ["X-Token"]

      [detectors.client-anomaly]
      enabled = false
    `);
    // Header lists are lowercased at parse time, matching the detector's lookup.
    expect(config.detectors["jwt-weakness"].options.inspectHeaders).toEqual(["x-token"]);
    expect(buildDetectors(config).map((d) => d.id)).not.toContain("client-anomaly");

    const engine = new HoneypotEngine({ detectors: buildDetectors(config) });

    // The configured max_depth applies: 4 levels of nesting exceeds a limit of 3.
    const deep = await engine.evaluate(facts({ path: "/graphql", method: "POST", body: "{ a { b { c { d } } } }", ip: "10.9.0.1" }));
    expect(deep.detections.find((d) => d.detectorId === "graphql-abuse")?.score).toBe(31);

    // The configured header list replaces the built-in one, so Authorization is
    // no longer scanned while the named header is.
    const noneAlg = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.";
    const viaCustom = await engine.evaluate(facts({ path: "/api", ip: "10.9.0.2", headers: { "x-token": noneAlg } }));
    expect(viaCustom.detections.map((d) => d.detectorId)).toContain("jwt-weakness");
    const viaAuth = await engine.evaluate(facts({ path: "/api", ip: "10.9.0.3", headers: { authorization: `Bearer ${noneAlg}` } }));
    expect(viaAuth.detections.map((d) => d.detectorId)).not.toContain("jwt-weakness");
  });

  it("correlates a repeat actor only across IPs that already scored", async () => {
    const config = parse("[detectors.repeat-actor]\nscore = 27\ndistinct_ip_threshold = 2\nwindow_ms = 600000\n");
    expect(config.detectors["repeat-actor"].options).toMatchObject({ score: 27, distinctIpThreshold: 2, windowMs: 600_000 });

    const engine = new HoneypotEngine({ detectors: buildDetectors(config) });
    const spoofing = { host: "x", "user-agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0", accept: "*/*", "accept-language": "en", "accept-encoding": "gzip" };

    // Two different IPs, same fingerprint, both probing a decoy. Each is counted only
    // once it has scored on its own merits, so the correlation lands on the actor's
    // next probe rather than on an address that has not yet done anything.
    await engine.evaluate(facts({ path: "/.env", ip: "203.0.113.1", headers: spoofing }));
    const second = await engine.evaluate(facts({ path: "/.env", ip: "203.0.113.2", headers: spoofing }));
    expect(second.detections.map((d) => d.detectorId)).not.toContain("repeat-actor");

    const third = await engine.evaluate(facts({ path: "/.env", ip: "203.0.113.2", headers: spoofing }));
    expect(third.detections.find((d) => d.detectorId === "repeat-actor")?.score).toBe(27);

    // Benign traffic sharing a fingerprint across many IPs must never correlate:
    // it scores nothing, so it never enters the registry in the first place.
    const clean = new HoneypotEngine({ detectors: buildDetectors(config) });
    for (const ip of ["198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"]) {
      const result = await clean.evaluate(facts({ path: "/", ip, headers: spoofing }));
      expect(result.detections).toHaveLength(0);
    }

    // …and it must still never correlate on the engine that HAS seen attackers under
    // that fingerprint, which is the situation a live deployment is actually in.
    for (const ip of ["198.51.100.5", "198.51.100.6", "198.51.100.7"]) {
      const result = await engine.evaluate(facts({ path: "/", ip, headers: spoofing }));
      expect(result.detections, `benign ${ip}`).toHaveLength(0);
    }
  });

  it("applies options for the newer detectors", async () => {
    const config = parse(`
      [detectors.ssrf-probe]
      score = 30

      [detectors.web-shell]
      enabled = false

      [detectors.open-redirect]
      params = ["backto"]
      score = 12
    `);
    expect(buildDetectors(config).map((d) => d.id)).not.toContain("web-shell");

    const engine = new HoneypotEngine({ detectors: buildDetectors(config) });
    const ssrf = await engine.evaluate(facts({ path: "/fetch", query: { url: "http://169.254.169.254/" }, ip: "10.5.0.1" }));
    expect(ssrf.detections.find((d) => d.detectorId === "ssrf-probe")?.score).toBe(30);

    // The configured param list replaces the built-in one.
    const custom = await engine.evaluate(facts({ path: "/go", query: { backto: "//evil.example.com" }, ip: "10.5.0.2" }));
    expect(custom.detections.find((d) => d.detectorId === "open-redirect")?.score).toBe(12);
    const builtIn = await engine.evaluate(facts({ path: "/go", query: { next: "//evil.example.com" }, ip: "10.5.0.3" }));
    expect(builtIn.detections.some((d) => d.detectorId === "open-redirect")).toBe(false);
  });

  it("applies fake-data options and can switch it off", () => {
    const config = parse(`
      [responses.fake-data]
      names = ["quinn", "rowan"]
      domain = "acme.internal"
      rows = 3
    `);
    expect(config.responses["fake-data"].options).toEqual({ names: ["quinn", "rowan"], domain: "acme.internal", rows: 3 });
    expect(buildResponseActions(config).map((a) => a.id)).toContain("fake-data");

    const off = parse("[responses.fake-data]\nenabled = false\n");
    expect(buildResponseActions(off).map((a) => a.id)).not.toContain("fake-data");
  });

  it("applies options for the newer response actions", () => {
    const config = parse(`
      [responses.chaos]
      garbage_chance = 0.25

      [responses.rate-limit]
      retry_after_seconds = 120

      [responses.gzip-bomb]
      enabled = false
    `);
    expect(config.responses.chaos.options.garbageChance).toBe(0.25);
    expect(config.responses["rate-limit"].options.retryAfterSeconds).toBe(120);
    expect(buildResponseActions(config).map((a) => a.id)).not.toContain("gzip-bomb");
  });

  it("rejects a chaos garbage_chance outside 0-1", () => {
    expect(() => parse("[responses.chaos]\ngarbage_chance = 1.5\n")).toThrow(/probability between 0 and 1/);
  });

  it("only creates the SMTP honeypot when it is enabled", () => {
    const store = new MemoryStore();
    expect(createSmtpHoneypot(defaultConfig(), store, () => undefined)).toBeUndefined();

    const config = parse('[smtp]\nenabled = true\nport = 2526\nlocal_domains = ["Example.COM"]\n');
    expect(config.smtp).toMatchObject({ enabled: true, port: 2526, hostname: "mail", banner: "Postfix" });
    // Domains are lowercased at parse time so matching is case-insensitive.
    expect(config.smtp.localDomains).toEqual(["example.com"]);
    expect(createSmtpHoneypot(config, store, () => undefined)).toBeDefined();
  });

  it("exempts allowlisted IPs and CIDR ranges from all detection", async () => {
    const config = parse('[allowlist]\nips = ["127.0.0.1", "10.0.0.0/8", "2001:db8::/32"]\n');
    expect(config.allowlist).toEqual(["127.0.0.1", "10.0.0.0/8", "2001:db8::/32"]);

    const { config: honeypot } = buildHoneypotConfig(config);
    const engine = new HoneypotEngine(honeypot);
    // A probe that would otherwise score heavily, from inside an allowlisted range.
    const exempt = await engine.evaluate(facts({ path: "/.env", ip: "10.4.2.1" }));
    expect(exempt.detections).toHaveLength(0);
    expect(exempt.totalScore).toBe(0);
    // The same probe from outside it still fires.
    const flagged = await engine.evaluate(facts({ path: "/.env", ip: "203.0.113.9" }));
    expect(flagged.detections.some((d) => d.detectorId === "decoy-path")).toBe(true);
  });

  it("rejects a malformed allowlist entry instead of silently exempting nothing", () => {
    // IpAllowlist ignores entries it cannot parse, so an unvalidated typo would
    // leave an operator believing their monitoring range was exempt.
    expect(() => parse('[allowlist]\nips = ["10.0.0.0/8x"]\n')).toThrow(/invalid \/prefix/);
    expect(() => parse('[allowlist]\nips = ["not-an-ip"]\n')).toThrow(/not a valid IP address or CIDR/);
    expect(() => parse('[allowlist]\nips = ["10.0.0.0/33"]\n')).toThrow(/expected 0-32 for IPv4/);
    expect(() => parse('[allowlist]\nips = ["2001:db8::/129"]\n')).toThrow(/expected 0-128 for IPv6/);
  });

  it("rejects allowlist entries the runtime matcher cannot actually use", () => {
    // "::ffff:10.0.0.0/104" is a well-formed IPv6 CIDR by shape, but IpAllowlist
    // normalizes the v4-mapped prefix away and then rejects /104 as out of range
    // for IPv4 — so a shape-only check would pass it and it would match nothing.
    // Guards against the config growing a second, more permissive IP parser.
    expect(() => parse('[allowlist]\nips = ["::ffff:10.0.0.0/104"]\n')).toThrow(/cannot be matched at runtime/);
    // Everything the matcher does accept still parses.
    const ok = parse('[allowlist]\nips = ["127.0.0.1", "::1", "10.0.0.0/8", "2001:db8::/32", "0.0.0.0/0", "::/0", "fe80::1%eth0"]\n');
    expect(ok.allowlist).toHaveLength(7);
  });

  it("keeps ingested blocks off the firewall enforcer by default", async () => {
    // The provenance rule: a feed is hearsay, a local detection is evidence, and
    // only evidence earns a firewall rule. Verified by counting enforcer calls.
    const config = parse(`
      [intel]
      feeds = ["https://peer.example/ioc.txt"]

      [blocklist.enforcer]
      webhook = "https://waf.example/block"
    `);
    const built = createBlocklist(config);
    expect(built.ingestTarget).toBeDefined();
    expect(built.describe).toContain("intel(non-enforcing)");

    let enforced = 0;
    const counting = new EnforcingBlocklist(new MemoryBlocklist(), () => { enforced += 1; });
    const composite = new CompositeBlocklist(counting, built.ingestTarget!);

    // An ingested entry blocks the IP for the honeypot...
    applyIocEntries(["203.0.113.5"], { blocklist: built.ingestTarget!, allowlist: new IpAllowlist([]) });
    expect(await composite.isBlocked("203.0.113.5")).toBe(true);
    // ...but never reaches the enforcer.
    expect(enforced).toBe(0);

    // A locally-observed block does.
    await composite.block("203.0.113.6", Date.now() + 60_000);
    expect(enforced).toBe(1);
  });

  it("routes ingest to the enforcing blocklist only on explicit opt-in", () => {
    const config = parse('[intel]\nfeeds = ["https://peer.example/ioc.txt"]\nenforce = true\n\n[blocklist.enforcer]\nwebhook = "https://waf.example/block"\n');
    const built = createBlocklist(config);
    expect(built.describe).toContain("intel(enforcing)");
    // With enforce on, ingest writes to the same blocklist local detections use.
    expect(built.ingestTarget).toBe(built.blocklist);
  });

  it("never lets an ingested feed block an allowlisted IP", () => {
    // The one rule with no off switch: a poisoned feed must not be able to take
    // out the operator's own monitoring.
    const allowlist = new IpAllowlist(["10.0.0.0/8", "203.0.113.9"]);
    const target = new MemoryBlocklist();
    const result = applyIocEntries(["10.1.2.3", "203.0.113.9", "198.51.100.7", "not-an-ip"], { blocklist: target, allowlist });
    expect(result).toMatchObject({ blocked: 1, skippedAllowlisted: 2, skippedInvalid: 1 });
    expect(target.isBlocked("10.1.2.3")).toBe(false);
    expect(target.isBlocked("198.51.100.7")).toBe(true);
  });

  it("validates intel feeds and schedule at parse time", () => {
    expect(() => parse('[intel]\nfeeds = ["http://feeds.evil.example/ioc.txt"]\n')).toThrow(/must use https/);
    // Plaintext to a local peer is allowed, matching the library.
    expect(() => parse('[intel]\nfeeds = ["http://127.0.0.1:9500/ioc.txt"]\n')).not.toThrow();
    expect(() => parse('[intel]\nfeeds = ["not a url"]\n')).toThrow(/is not a valid URL/);
    expect(() => parse('[intel]\nfeeds = ["https://p.example/ioc.txt"]\nrefresh_seconds = 5\n')).toThrow(/at least 30/);
    expect(() => parse('[intel]\nfeeds = ["https://p.example/ioc.txt"]\nttl_seconds = 0\n')).toThrow(/have to expire/);
    expect(() => parse("[intel]\nenabled = true\n")).toThrow(/feeds\] is required/);
    expect(defaultConfig().intel.enabled).toBe(false);
  });

  it("makes intel feeds reloadable but its wiring restart-only", () => {
    const base = parse('[intel]\nfeeds = ["https://a.example/ioc.txt"]\n');
    // Feed list and schedule: hot-applied by rebuilding the poller.
    const moreFeeds = parse('[intel]\nfeeds = ["https://a.example/ioc.txt", "https://b.example/ioc.txt"]\n');
    expect(planReload(base, moreFeeds).applied).toEqual(["intel"]);
    // enforce decides whether ingest can reach the firewall, and that wiring is
    // built once at startup — so it must never appear to change on a reload.
    const enforcing = parse('[intel]\nfeeds = ["https://a.example/ioc.txt"]\nenforce = true\n');
    expect(planReload(base, enforcing).requiresRestart.map((r) => r.key)).toEqual(["intel.enforce"]);
  });

  it("defaults the blocklist to memory and requires redis before selecting it", () => {
    // toMatchObject, not toEqual: this section grows (it gained `enforcer`), and
    // the point of the assertion is the backend default, not the exact shape.
    expect(defaultConfig().blocklist).toMatchObject({ backend: "memory", keyPrefix: "hackerpot:block:" });
    expect(createBlocklist(defaultConfig()).describe).toBe("memory(max 100000)");
    // Selecting redis without a configured store connection is a startup error,
    // not a silent fall back to a per-instance blocklist.
    expect(() => parse('[blocklist]\nbackend = "redis"\n')).toThrow(/no \[store\.redis\] url is configured/);
    const config = parse('[store.redis]\nurl = "redis://localhost:6379"\n\n[blocklist]\nbackend = "redis"\n');
    expect(config.blocklist.backend).toBe("redis");
  });

  it("leaves external block enforcement off unless configured", () => {
    const config = defaultConfig();
    expect(config.blocklist.enforcer.enabled).toBe(false);
    expect(createBlocklist(config).describe).toBe("memory(max 100000)");
  });

  it("builds a command enforcer from a real argv array", () => {
    const config = parse(`
      [blocklist.enforcer]
      command = "iptables"
      args = ["-w", "-A", "INPUT", "-s", "{ip}", "-j", "DROP"]
    `);
    // Writing a command is itself the opt-in; no separate flag needed.
    expect(config.blocklist.enforcer.enabled).toBe(true);
    expect(config.blocklist.enforcer.args).toEqual(["-w", "-A", "INPUT", "-s", "{ip}", "-j", "DROP"]);
    expect(createBlocklist(config).describe).toBe("memory(max 100000) + enforce(command:iptables)");

    // ...and `enabled = false` switches it off without deleting the command.
    const off = parse('[blocklist.enforcer]\nenabled = false\ncommand = "iptables"\nargs = ["{ip}"]\n');
    expect(createBlocklist(off).describe).toBe("memory(max 100000)");
  });

  it("builds a webhook enforcer, and refuses a non-http url", () => {
    const config = parse('[blocklist.enforcer]\nwebhook = "https://waf.example/block"\nsecret = "s3cret"\n');
    expect(createBlocklist(config).describe).toBe("memory(max 100000) + enforce(webhook)");
    expect(() => parse('[blocklist.enforcer]\nwebhook = "ftp://nope"\n')).toThrow(/must be an http\(s\) URL/);
  });

  it("rejects enforcer configurations that cannot work", () => {
    // A command with no {ip} token runs identically for every block, so it can
    // never target the offending address — always a mistake.
    expect(() => parse('[blocklist.enforcer]\ncommand = "iptables"\nargs = ["-A", "INPUT", "-j", "DROP"]\n')).toThrow(/must contain the "\{ip\}" token/);
    // A block fires exactly one enforcer, so two destinations is ambiguous.
    expect(() => parse('[blocklist.enforcer]\ncommand = "iptables"\nargs = ["{ip}"]\nwebhook = "https://x.example"\n')).toThrow(/pick one/);
    expect(() => parse("[blocklist.enforcer]\nenabled = true\n")).toThrow(/neither "command" nor "webhook"/);
    expect(() => parse('[blocklist.enforcer]\nargs = ["{ip}"]\n')).toThrow(/requires "command"/);
  });

  it("wraps the redis blocklist with enforcement rather than replacing it", () => {
    const config = parse(`
      [store.redis]
      url = "redis://localhost:6379"

      [blocklist]
      backend = "redis"

      [blocklist.enforcer]
      webhook = "https://waf.example/block"
    `);
    // Enforcement is a wrapper: the shared-state backend is still underneath.
    expect(config.blocklist.backend).toBe("redis");
    expect(config.blocklist.enforcer.enabled).toBe(true);
  });

  it("reads the connection and concurrency caps", () => {
    const config = parse(`
      [smtp]
      enabled = true
      max_connections = 32

      [ssh]
      enabled = true
      port = 2225
      max_connections = 16

      [responses.tarpit]
      max_concurrent = 500

      [responses.large-payload]
      max_concurrent = 8
    `);
    expect(config.smtp.maxConnections).toBe(32);
    expect(config.ssh.maxConnections).toBe(16);
    expect(config.responses.tarpit.options.maxConcurrent).toBe(500);
    expect(config.responses["large-payload"].options.maxConcurrent).toBe(8);
    expect(defaultConfig().smtp.maxConnections).toBe(256);
  });

  it("escapes attacker-controlled values in the text log format", async () => {
    // A captured SSH shell command is attacker-supplied text that reaches the log.
    // In text mode a bare newline would end the line and let them write entirely
    // fabricated entries after it; JSON mode was always safe.
    const { formatValue, formatTextLine } = await import("../src/logfmt.js");
    const forged = 'ls\n[2026-01-01T00:00:00Z] kind=startup store=PWNED';
    expect(formatValue(forged)).not.toContain("\n");
    expect(formatValue(forged)).toBe(JSON.stringify(forged));
    // Ordinary values stay unquoted and readable.
    expect(formatValue("not-found")).toBe("not-found");
    expect(formatValue(403)).toBe("403");
    // And the whole line stays one line.
    expect(formatTextLine({ ts: "T", kind: "hit", command: forged }).split("\n")).toHaveLength(1);
  });

  it("validates the interactive SSH settings", () => {
    const config = parse('[ssh]\nenabled = true\ninteractive = true\naccept_on_attempt = 2\nshell_hostname = "db-prod-01"\n');
    expect(config.ssh).toMatchObject({ interactive: true, acceptOnAttempt: 2, shellHostname: "db-prod-01", maxCommands: 100, maxCommandLength: 4096 });
    expect(defaultConfig().ssh.interactive).toBe(false);

    // Accepting on an attempt the connection never reaches means no shell is ever
    // entered — the feature would appear enabled and silently never fire.
    expect(() => parse("[ssh]\ninteractive = true\naccept_on_attempt = 9\nmax_auth_attempts = 3\n")).toThrow(/exceeds max_auth_attempts/);
    expect(() => parse("[ssh]\ninteractive = true\naccept_on_attempt = 0\n")).toThrow(/at least 1/);
    expect(() => parse("[ssh]\ninteractive = true\nmax_commands = 0\n")).toThrow(/no commands are captured/);
  });

  it("reads the SMTP body-capture settings", () => {
    expect(defaultConfig().smtp).toMatchObject({ captureBody: true, maxBodyChars: 2_000 });
    expect(parse("[smtp]\ncapture_body = false\n").smtp.captureBody).toBe(false);
    // Capturing into a zero-length buffer is a contradiction, not a way to disable.
    expect(() => parse("[smtp]\nmax_body_chars = 0\n")).toThrow(/set capture_body = false/);
  });

  it("reads webhook alerting filters and rejects half-configured throttling", () => {
    const config = parse(`
      [management]
      api_keys = ["k"]

      [[management.webhooks]]
      url = "https://hooks.example/alert"
      min_score = 40
      dedupe_window_seconds = 300
      throttle_window_seconds = 60
      max_per_window = 10
      omit_body = true
    `);
    expect(config.management.webhooks[0]).toMatchObject({ minScore: 40, dedupeWindowSeconds: 300, throttleWindowSeconds: 60, maxPerWindow: 10, omitBody: true });

    // Throttling needs both halves; one alone silently does nothing, which an
    // operator would discover only when a flood pages them hundreds of times.
    expect(() => parse('[[management.webhooks]]\nurl = "https://h.example/a"\nthrottle_window_seconds = 60\n')).toThrow(/needs both/);
    expect(() => parse('[[management.webhooks]]\nurl = "https://h.example/a"\nmax_per_window = 10\n')).toThrow(/needs both/);
    expect(() => parse('[[management.webhooks]]\nurl = "https://h.example/a"\nthrottle_window_seconds = 60\nmax_per_window = 0\n')).toThrow(/drop every alert/);
  });

  it("only creates the SSH honeypot when it is enabled", () => {
    const store = new MemoryStore();
    expect(createSshHoneypot(defaultConfig(), store, () => undefined)).toBeUndefined();

    const config = parse("[ssh]\nenabled = true\nport = 2223\nmax_auth_attempts = 3\n");
    expect(config.ssh).toMatchObject({ enabled: true, port: 2223, ident: "OpenSSH_8.4", maxAuthAttempts: 3 });
    expect(createSshHoneypot(config, store, () => undefined)).toBeDefined();
  });

  it("reports an unreadable SSH host-key file instead of starting keyless", () => {
    const config = parse('[ssh]\nenabled = true\nhost_key_files = ["/nonexistent/ssh_host_rsa_key"]\n');
    expect(() => createSshHoneypot(config, new MemoryStore(), () => undefined)).toThrow(/cannot read \/nonexistent/);
  });

  it("rejects a max_auth_attempts of zero", () => {
    expect(() => parse("[ssh]\nmax_auth_attempts = 0\n")).toThrow(/must be at least 1/);
  });

  it("rejects two listeners claiming the same port", () => {
    expect(() => parse("[server]\nport = 4004\n\n[ssh]\nenabled = true\nport = 4004\n")).toThrow(/port 4004 is claimed by both \[server\] and \[ssh\]/);
    expect(() => parse("[ssh]\nenabled = true\nport = 2222\n\n[port-scan]\nports = [2222]\n")).toThrow(/port 2222 is claimed by both/);
    // A disabled listener never claims its port.
    expect(() => parse("[ssh]\nport = 4004\n")).not.toThrow();
  });

  it("only creates the port-scan sentinel when ports are configured", () => {
    expect(createPortScanSentinel(defaultConfig(), () => undefined)).toBeUndefined();
    const config = parse("[port-scan]\nports = [2222, 8022]\n");
    expect(config.portScan.enabled).toBe(true);
    expect(createPortScanSentinel(config, () => undefined)).toBeDefined();
  });

  it("honors the configured escalation thresholds", () => {
    const policy = buildPolicy(parse("[policy]\nblock_threshold = 5\ntarpit_threshold = 2\n"));
    const at = (totalScore: number, respondWith?: string) => {
      const detection: Detection = { detectorId: "test", reason: "test", score: totalScore };
      if (respondWith) detection.respondWith = respondWith;
      return policy({ detection, detections: [detection], ip: "10.0.0.1", path: "/", totalScore, tracker: new IpTracker("10.0.0.1", 60_000) });
    };
    expect(at(6)).toBe("block");
    expect(at(6, "decoy-content")).toBe("block"); // a confirmed attacker is blocked regardless
    expect(at(3)).toBe("tarpit");
    expect(at(3, "decoy-content")).toBe("decoy-content");
    expect(at(1)).toBe("not-found");
  });
});

describe("reload planning", () => {
  it("treats an identical config as a no-op", () => {
    const plan = planReload(defaultConfig(), defaultConfig());
    expect(plan).toEqual({ applied: [], requiresRestart: [], unchanged: true });
  });

  it("applies the hot-swappable sections", () => {
    const next = parse("[policy]\nblock_threshold = 30\ntarpit_threshold = 10\n\n[detectors.rate-spike]\nenabled = false\n");
    const plan = planReload(defaultConfig(), next);
    expect(plan.applied.sort()).toEqual(["detectors", "policy"]);
    expect(plan.requiresRestart).toEqual([]);
    expect(plan.unchanged).toBe(false);
  });

  it("refuses bound-listener and live-state changes by name, with a reason", () => {
    const next = parse('[server]\nport = 9999\n\n[store.file]\npath = "/tmp/x.jsonl"\n\n[smtp]\nenabled = true\n\n[engine]\nfingerprint_window_ms = 60000\n');
    const plan = planReload(defaultConfig(), next);
    const keys = plan.requiresRestart.map((r) => r.key).sort();
    // The fingerprint registry holds live actor→IP history, so its window is
    // restart-only for the same reason the activity window is.
    expect(keys).toEqual(["engine.fingerprint_window_ms", "server", "smtp", "store"]);
    // Every refusal carries an explanation the operator can act on.
    expect(plan.requiresRestart.every((r) => r.why.length > 0)).toBe(true);
  });

  it("notices a changed regex, which a naive JSON compare would miss", () => {
    // JSON.stringify turns every RegExp into {}, so without the custom replacer
    // a changed detector pattern would look like no change and never be applied.
    const a = parse('[detectors.credential-bruteforce]\nauth_paths = "^/login$"\n');
    const b = parse('[detectors.credential-bruteforce]\nauth_paths = "^/signin$"\n');
    expect(planReload(a, b).applied).toEqual(["detectors"]);
  });

  it("reports both halves when a reload mixes applicable and refused changes", () => {
    const next = parse("[policy]\nblock_threshold = 25\ntarpit_threshold = 5\n\n[management]\napi_keys = [\"k\"]\n");
    const plan = planReload(defaultConfig(), next);
    expect(plan.applied).toEqual(["policy"]);
    expect(plan.requiresRestart.map((r) => r.key)).toEqual(["management"]);
  });
});

describe("file discovery and env overrides", () => {
  it("discovers hackerpot.toml in the working directory", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "hackerpot.toml"), "[server]\nport = 5005\n");
    expect(discoverConfigPath(dir)).toBe(join(dir, "hackerpot.toml"));
    expect(loadConfig({ cwd: dir, env: {} }).server.port).toBe(5005);
  });

  it("falls back to the built-in defaults when no file exists", () => {
    const config = loadConfig({ cwd: tempDir(), env: {} });
    expect(config.source).toBe("<defaults>");
    expect(config.server.port).toBe(4004);
  });

  it("errors when an explicitly named file is missing", () => {
    expect(() => loadConfig({ path: join(tempDir(), "absent.toml"), env: {} })).toThrow(ConfigError);
  });

  it("takes the path from HACKERPOT_CONFIG", () => {
    const dir = tempDir();
    const path = join(dir, "custom.toml");
    writeFileSync(path, "[server]\nport = 6006\n");
    expect(loadConfig({ env: { HACKERPOT_CONFIG: path } }).server.port).toBe(6006);
  });

  it("lets environment variables override the file", () => {
    const dir = tempDir();
    writeFileSync(join(dir, "hackerpot.toml"), '[server]\nport = 5005\ntrust_proxy = true\n\n[logging]\nformat = "json"\n');
    const config = loadConfig({ cwd: dir, env: { PORT: "7007", TRUST_PROXY: "false", LOG_FORMAT: "text", HIT_LOG: "/tmp/hits.jsonl" } });
    expect(config.server.port).toBe(7007);
    expect(config.server.trustProxy).toBe(false);
    expect(config.logging.format).toBe("text");
    expect(config.store.file).toMatchObject({ enabled: true, path: "/tmp/hits.jsonl" });
  });

  it("maps the container environment variables onto the config", () => {
    const config = applyEnvOverrides(defaultConfig(), {
      SCAN_PORTS: "2222, 8022",
      SCAN_BANNER: "SSH-2.0-Custom",
      REDIS_URL: "redis://redis:6379",
      REDIS_SCORE_TTL: "3600",
      HONEYTOKENS: "AKIA_ONE,AKIA_TWO",
      MANAGEMENT_API_KEYS: "k1,k2",
    });
    expect(config.portScan).toMatchObject({ enabled: true, ports: [2222, 8022], banner: "SSH-2.0-Custom" });
    expect(config.store.redis).toMatchObject({ enabled: true, url: "redis://redis:6379", scoreTtlSeconds: 3600 });
    expect(config.detectors.honeytoken.enabled).toBe(true);
    expect(config.detectors.honeytoken.options.tokens).toHaveLength(2);
    expect(config.management).toMatchObject({ enabled: true, apiKeys: ["k1", "k2"] });
  });

  it("rejects a malformed environment value", () => {
    expect(() => applyEnvOverrides(defaultConfig(), { PORT: "not-a-port" })).toThrow(/PORT: must be a non-negative integer/);
    expect(() => applyEnvOverrides(defaultConfig(), { TRUST_PROXY: "maybe" })).toThrow(/TRUST_PROXY: must be true or false/);
  });
});
