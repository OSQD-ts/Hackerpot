import { describe, expect, it } from "vitest";
import { HoneypotEngine, pathBruteforceDetector, payloadInjectionDetector, credentialBruteforceDetector, decoyPathDetector, type RequestFacts, type EvaluationResult, ssrfProbeDetector, openRedirectDetector, crlfInjectionDetector, webShellDetector, nosqlInjectionDetector, graphqlAbuseDetector, jwtWeaknessDetector, clientAnomalyDetector, prototypePollutionDetector, insecureDeserializationDetector, hostHeaderInjectionDetector, honeytokenDetector, sensitiveFileDetector, headerAnomalyDetector } from "../src/index.js";
import { injectionSignatures } from "../src/detectors/index.js";
import type { DetectionContext } from "../src/detectors/types.js";
import { facts } from "./helpers.js";

const factsWithClient = (p: Partial<RequestFacts> & Pick<RequestFacts, "path">): RequestFacts => ({ method: "GET", query: {}, headers: { host: "x", "user-agent": "m" }, ip: "1.2.3.4", ...p });

const ctxFor = (value: string): DetectionContext =>
  ({ method: "POST", path: "/", query: {}, headers: {}, rawHeaders: [], ip: "1.2.3.4", body: value }) as unknown as DetectionContext;

/**
 * Fastest of `runs` timings, in ms.
 *
 * These are ReDoS regression guards, so they assert on wall-clock cost — but a single
 * sample measures the machine as much as the regex. Vitest runs suites in parallel, and
 * one preempted sample against a 25ms bound is enough to fail a run with nothing wrong
 * (it did). The minimum discards scheduling spikes without weakening the guard: the
 * behaviour these tests exist to catch is ~100ms on *every* pass, so its minimum is
 * still far over the bound.
 */
function fastestMs(work: () => void, runs = 5): number {
  let best = Infinity;
  for (let i = 0; i < runs; i += 1) {
    const started = process.hrtime.bigint();
    work();
    best = Math.min(best, Number(process.hrtime.bigint() - started) / 1e6);
  }
  return best;
}

describe("detectors", () => {
  it("decoy path detector flags a known bait path", async () => {
    const engine = new HoneypotEngine({ detectors: [decoyPathDetector()] });
    const result = await engine.evaluate(facts({ path: "/.env" }));
    expect(result.detections[0]?.detector).toBe("decoy-path");
    expect(result.actionId).toBe("decoy-content");
  });

  it("payload injection detector flags a traversal attempt in the query", async () => {
    const engine = new HoneypotEngine({ detectors: [payloadInjectionDetector()] });
    const result = await engine.evaluate(facts({ path: "/x", query: { file: "../../../../etc/passwd" } }));
    expect(result.detections[0]?.detector).toBe("payload-injection");
    expect(result.detections[0]?.metadata?.["kind"]).toBe("path-traversal");
  });

  it("path bruteforce detector flags many distinct paths from one IP", async () => {
    const engine = new HoneypotEngine({ detectors: [pathBruteforceDetector({ uniquePathThreshold: 5, windowMs: 10_000 })] });
    let last: EvaluationResult | undefined;
    for (let i = 0; i < 6; i++) last = await engine.evaluate(facts({ path: `/dir-${i}` }));
    expect(last?.detections[0]?.detector).toBe("path-bruteforce");
  });

  it("credential bruteforce detector flags repeated auth POSTs", async () => {
    const engine = new HoneypotEngine({ detectors: [credentialBruteforceDetector({ attemptThreshold: 3, windowMs: 10_000 })] });
    let last: EvaluationResult | undefined;
    for (let i = 0; i < 3; i++) last = await engine.evaluate(facts({ method: "POST", path: "/login", body: "u=a&p=b" }));
    expect(last?.detections[0]?.detector).toBe("credential-bruteforce");
  });

  it("leaves ordinary traffic alone", async () => {
    const engine = new HoneypotEngine();
    const result = await engine.evaluate(facts({ path: "/api/users", headers: { "user-agent": "Mozilla/5.0", host: "example.com" } }));
    expect(result.detections).toHaveLength(0);
  });
});

describe("new detectors", () => {
  it("ssrf-probe flags an internal/metadata target", async () => {
    const engine = new HoneypotEngine({ detectors: [ssrfProbeDetector()] });
    const meta = await engine.evaluate(facts({ path: "/fetch", query: { url: "http://169.254.169.254/latest/meta-data/" } }));
    expect(meta.detections[0]?.detector).toBe("ssrf-probe");
    const file = await engine.evaluate(facts({ path: "/img", query: { src: "file:///etc/passwd" }, ip: "203.0.113.10" }));
    expect(file.detections[0]?.detector).toBe("ssrf-probe");
    const ok = await engine.evaluate(facts({ path: "/fetch", query: { url: "https://example.com/logo.png" }, ip: "203.0.113.11" }));
    expect(ok.detections).toHaveLength(0);
  });

  it("open-redirect flags an off-site redirect param", async () => {
    const engine = new HoneypotEngine({ detectors: [openRedirectDetector()] });
    expect((await engine.evaluate(facts({ path: "/login", query: { next: "//evil.example/phish" } }))).detections[0]?.detector).toBe("open-redirect");
    expect((await engine.evaluate(facts({ path: "/go", query: { url: "https://evil.example" }, ip: "203.0.113.12" }))).detections[0]?.detector).toBe("open-redirect");
    expect((await engine.evaluate(facts({ path: "/login", query: { next: "/dashboard" }, ip: "203.0.113.13" }))).detections).toHaveLength(0);
  });

  it("open-redirect treats same-host and trustedHosts targets as legitimate", async () => {
    // Fallback to request Host: a self-redirect to the same domain is not flagged.
    const byHost = new HoneypotEngine({ detectors: [openRedirectDetector()] });
    expect((await byHost.evaluate(facts({ path: "/cb", query: { redirect_uri: "https://app.example/home" }, headers: { host: "app.example" } }))).detections).toHaveLength(0);
    // But an off-site target with a spoofed Host still can't launder itself past a pinned allowlist:
    const pinned = new HoneypotEngine({ detectors: [openRedirectDetector({ trustedHosts: ["app.example"] })] });
    expect((await pinned.evaluate(facts({ path: "/cb", query: { redirect_uri: "https://app.example/home" }, headers: { host: "evil.example" }, ip: "203.0.113.30" }))).detections).toHaveLength(0);
    expect((await pinned.evaluate(facts({ path: "/cb", query: { redirect_uri: "https://evil.example/x" }, headers: { host: "app.example" }, ip: "203.0.113.31" }))).detections[0]?.detector).toBe("open-redirect");
  });

  it("crlf-injection flags encoded CRLF in a query value", async () => {
    const engine = new HoneypotEngine({ detectors: [crlfInjectionDetector()] });
    const r = await engine.evaluate(facts({ path: "/x", query: { q: "foo%0d%0aSet-Cookie:%20admin=1" } }));
    expect(r.detections[0]?.detector).toBe("crlf-injection");
  });

  it("web-shell flags a shell filename and an upload-dir script", async () => {
    const engine = new HoneypotEngine({ detectors: [webShellDetector()] });
    expect((await engine.evaluate(facts({ path: "/wso.php" }))).detections[0]?.detector).toBe("web-shell");
    expect((await engine.evaluate(facts({ path: "/uploads/avatar.php", ip: "203.0.113.14" }))).detections[0]?.detector).toBe("web-shell");
    expect((await engine.evaluate(facts({ path: "/uploads/avatar.png", ip: "203.0.113.15" }))).detections).toHaveLength(0);
  });

  it("nosql-injection flags Mongo operators in query keys and JSON bodies, not bare $ text", async () => {
    const engine = new HoneypotEngine({ detectors: [nosqlInjectionDetector()] });
    expect((await engine.evaluate(facts({ path: "/login", query: { "user[$ne]": "" } }))).detections[0]?.detector).toBe("nosql-injection");
    expect((await engine.evaluate(facts({ method: "POST", path: "/login", body: '{"username":"admin","password":{"$ne":null}}', ip: "203.0.113.16" }))).detections[0]?.detector).toBe("nosql-injection");
    expect((await engine.evaluate(facts({ path: "/search", query: { q: '{"$where":"sleep(5000)"}' }, ip: "203.0.113.17" }))).detections[0]?.detector).toBe("nosql-injection");
    // Legit: array-style params and a price like "$5" must NOT fire.
    expect((await engine.evaluate(facts({ path: "/products", query: { "filter[name]": "widget", sort: "price", note: "costs $5" }, ip: "203.0.113.18" }))).detections).toHaveLength(0);
  });

  it("graphql-abuse flags introspection and deep nesting, not a shallow query", async () => {
    const engine = new HoneypotEngine({ detectors: [graphqlAbuseDetector({ maxDepth: 6 })] });
    expect((await engine.evaluate(facts({ method: "POST", path: "/graphql", body: JSON.stringify({ query: "query IntrospectionQuery { __schema { types { name } } }" }) }))).detections[0]?.detector).toBe("graphql-abuse");
    const deep = "query{" + "a{".repeat(8) + "id" + "}".repeat(8) + "}";
    expect((await engine.evaluate(facts({ method: "POST", path: "/graphql", body: JSON.stringify({ query: deep }), ip: "203.0.113.20" }))).detections[0]?.detector).toBe("graphql-abuse");
    expect((await engine.evaluate(facts({ method: "POST", path: "/graphql", body: JSON.stringify({ query: "query { me { id name } }" }), ip: "203.0.113.21" }))).detections).toHaveLength(0);
  });

  it("jwt-weakness flags an alg:none token but not a signed one", async () => {
    const engine = new HoneypotEngine({ detectors: [jwtWeaknessDetector()] });
    const noneJwt = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url") + "." + Buffer.from(JSON.stringify({ sub: "admin" })).toString("base64url") + ".";
    expect((await engine.evaluate(facts({ path: "/api/me", headers: { authorization: `Bearer ${noneJwt}` } }))).detections[0]?.detector).toBe("jwt-weakness");
    // A normal signed HS256 token must not fire.
    expect((await engine.evaluate(facts({ path: "/api/me", headers: { authorization: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9.c2ln" }, ip: "203.0.113.22" }))).detections).toHaveLength(0);
  });

  it("client-anomaly flags a browser UA missing all browser headers, not a real browser or a non-browser UA", async () => {
    const engine = new HoneypotEngine({ detectors: [clientAnomalyDetector()] });
    const chrome = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36";
    expect((await engine.evaluate(facts({ path: "/", headers: { host: "x", "user-agent": chrome } }))).detections[0]?.detector).toBe("client-anomaly");
    expect((await engine.evaluate(facts({ path: "/", headers: { host: "x", "user-agent": chrome, accept: "text/html", "accept-language": "en", "accept-encoding": "gzip" }, ip: "203.0.113.23" }))).detections).toHaveLength(0);
    expect((await engine.evaluate(facts({ path: "/", headers: { host: "x", "user-agent": "curl/8.5.0" }, ip: "203.0.113.24" }))).detections).toHaveLength(0);
  });

  it("prototype-pollution flags __proto__ / constructor.prototype, not the words in prose", async () => {
    const engine = new HoneypotEngine({ detectors: [prototypePollutionDetector()] });
    expect((await engine.evaluate(facts({ path: "/api/merge", query: { "a[__proto__][isAdmin]": "true" } }))).detections[0]?.detector).toBe("prototype-pollution");
    expect((await engine.evaluate(facts({ method: "POST", path: "/api/merge", body: '{"__proto__":{"isAdmin":true}}', ip: "203.0.113.25" }))).detections[0]?.detector).toBe("prototype-pollution");
    expect((await engine.evaluate(facts({ method: "POST", path: "/api/merge", body: '{"a":{"constructor":{"prototype":{"x":1}}}}', ip: "203.0.113.26" }))).detections[0]?.detector).toBe("prototype-pollution");
    // Legit: a search discussing constructors and prototypes (words, not key access).
    expect((await engine.evaluate(facts({ path: "/search", query: { q: "how does the constructor and prototype chain work" }, ip: "203.0.113.27" }))).detections).toHaveLength(0);
  });

  it("insecure-deserialization flags Java/PHP payloads, not ordinary base64/text", async () => {
    const engine = new HoneypotEngine({ detectors: [insecureDeserializationDetector()] });
    expect((await engine.evaluate(facts({ path: "/api", headers: { host: "x", cookie: "sess=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA" } }))).detections[0]?.detector).toBe("insecure-deserialization");
    expect((await engine.evaluate(facts({ method: "POST", path: "/api", body: 'data=O:4:"Evil":1:{s:3:"cmd";s:2:"id";}', ip: "203.0.113.28" }))).detections[0]?.detector).toBe("insecure-deserialization");
    // node-serialize still caught — via the marker that makes the payload execute,
    // which is the only thing that makes it a node-serialize payload at all.
    const nodeSerialize = JSON.stringify({ rce: "_$$ND_FUNC$$_function (){require('child_process').exec('id')}()" });
    expect((await engine.evaluate(facts({ method: "POST", path: "/api", body: nodeSerialize, ip: "203.0.113.29" }))).detections[0]?.detector).toBe("insecure-deserialization");
    expect((await engine.evaluate(facts({ path: "/api", headers: { host: "x", cookie: "sess=eyJ1c2VyIjoiYWxpY2UifQ; theme=dark" }, ip: "203.0.113.29" }))).detections).toHaveLength(0);
  });

  it("host-header-injection flags malformed/duplicate hosts, and off-list hosts when expectedHosts is set", async () => {
    const engine = new HoneypotEngine({ detectors: [hostHeaderInjectionDetector()] });
    expect((await engine.evaluate(facts({ path: "/", headers: { host: "evil.com/reset" } }))).detections[0]?.detector).toBe("host-header-injection");
    expect((await engine.evaluate(facts({ path: "/", headers: { host: ["a.com", "b.com"] }, ip: "203.0.113.31" }))).detections[0]?.detector).toBe("host-header-injection");
    expect((await engine.evaluate(facts({ path: "/", headers: { host: "example.com:8443" }, ip: "203.0.113.32" }))).detections).toHaveLength(0);
    // With a canonical set, an off-list Host (or X-Forwarded-Host) is spoofing.
    const pinned = new HoneypotEngine({ detectors: [hostHeaderInjectionDetector({ expectedHosts: ["example.com"] })] });
    expect((await pinned.evaluate(facts({ path: "/", headers: { host: "attacker.example" }, ip: "203.0.113.33" }))).detections[0]?.detector).toBe("host-header-injection");
    expect((await pinned.evaluate(facts({ path: "/", headers: { host: "example.com", "x-forwarded-host": "evil.com" }, ip: "203.0.113.34" }))).detections[0]?.detector).toBe("host-header-injection");
    expect((await pinned.evaluate(facts({ path: "/", headers: { host: "example.com" }, ip: "203.0.113.35" }))).detections).toHaveLength(0);
    // An expectedHosts entry written WITH a port must still match a real (port-stripped) Host,
    // and not turn legitimate traffic into a firehose of false positives.
    const withPort = new HoneypotEngine({ detectors: [hostHeaderInjectionDetector({ expectedHosts: ["example.com:8443"] })] });
    expect((await withPort.evaluate(facts({ path: "/", headers: { host: "example.com:8443" }, ip: "203.0.113.36" }))).detections).toHaveLength(0);
    expect((await withPort.evaluate(facts({ path: "/", headers: { host: "example.com" }, ip: "203.0.113.37" }))).detections).toHaveLength(0);
  });
});

describe("new detectors", () => {
  it("honeytoken detector flags a seeded token replayed in a header", async () => {
    const engine = new HoneypotEngine({
      detectors: [honeytokenDetector({ tokens: [{ value: "AKIAI_HONEY_TOKEN_123", label: "fake-aws-key" }] })],
    });
    const clean = await engine.evaluate(facts({ path: "/", headers: { authorization: "Bearer real" } }));
    expect(clean.detections).toHaveLength(0);

    const tripped = await engine.evaluate(facts({ path: "/api", headers: { authorization: "AKIAI_HONEY_TOKEN_123" }, ip: "10.0.0.2" }));
    expect(tripped.detections[0]?.detector).toBe("honeytoken");
    expect(tripped.detections[0]?.metadata?.["label"]).toBe("fake-aws-key");
  });

  it("sensitive-file detector flags backup and dump file requests", async () => {
    const engine = new HoneypotEngine({ detectors: [sensitiveFileDetector()] });
    for (const path of ["/wp-config.php.bak", "/index.php~", "/db.sql", "/.svn/entries", "/backup.tar.gz"]) {
      const r = await engine.evaluate(facts({ path, ip: `1.1.1.${path.length}` }));
      expect(r.detections[0]?.detector, path).toBe("sensitive-file");
    }
    const ok = await engine.evaluate(facts({ path: "/assets/app.js", ip: "1.1.1.99" }));
    expect(ok.detections).toHaveLength(0);
  });

  it("header-anomaly detector flags smuggling, shellshock and absolute-URI", async () => {
    const engine = new HoneypotEngine({ detectors: [headerAnomalyDetector()] });

    const smuggle = await engine.evaluate(facts({ method: "POST", path: "/", headers: { "content-length": "5", "transfer-encoding": "chunked" }, ip: "2.2.2.1" }));
    expect(smuggle.detections[0]?.metadata?.["kind"]).toBe("smuggling");

    const shell = await engine.evaluate(facts({ path: "/", headers: { "user-agent": "() { :; }; echo vuln", host: "x" }, ip: "2.2.2.2" }));
    expect(shell.detections[0]?.metadata?.["kind"]).toBe("shellshock");

    const proxy = await engine.evaluate(facts({ path: "http://evil.example/", headers: { host: "x" }, ip: "2.2.2.3" }));
    expect(proxy.detections[0]?.metadata?.["kind"]).toBe("absolute-uri");
  });
});

describe("ReDoS resistance", () => {
  it("stays fast on adversarial inputs across every detector", async () => {
    const engine = new HoneypotEngine();
    const big = "a".repeat(60000);
    const cases: RequestFacts[] = [
      factsWithClient({ path: "/x", query: { q: `{{${big}` } }), // template-injection
      factsWithClient({ path: "/x", query: { q: `union${" ".repeat(60000)}` } }), // sql-injection
      factsWithClient({ path: `/uploads/${big}` }), // web-shell
      factsWithClient({ path: `/${big}.bak` }), // sensitive-file
      factsWithClient({ path: "/x", query: { url: `http://${big}` } }), // ssrf
      factsWithClient({ path: "/x", query: { redirect: `//${big}` } }), // open-redirect
      factsWithClient({ path: "/x", headers: { host: "x", "user-agent": big } }), // scanner-signature
      factsWithClient({ method: "POST", path: "/x", body: `{{${big}` }), // body scanning
    ];
    for (const f of cases) {
      const t = performance.now();
      await engine.evaluate(f);
      // A loose absolute bound on purpose: real catastrophic backtracking is orders
      // of magnitude (seconds+), so 500ms catches it with room to spare while never
      // flaking on a loaded box — a ReDoS guard that cries wolf under CI load is one
      // that gets muted. Typical run here is single-digit ms.
      expect(performance.now() - t, `slow on ${f.path}`).toBeLessThan(500);
    }
  });
});

describe("the template-injection signature is linear, not a CPU amplifier", () => {
  // With `.*?` inner spans this signature re-scanned to end-of-string from every `{{`
  // in the value. A 16 KB body of `{{` cost ~100ms per value / ~200ms per request, so
  // roughly 5 unauthenticated requests/second pinned the event loop — and in middleware
  // mode that stalls the host application the honeypot is mounted in.
  const detector = payloadInjectionDetector();

  it("scans a pathological brace payload in well under the old cost", () => {
    for (const payload of ["{{".repeat(8192), "${".repeat(8192), "{".repeat(16384), "{{a".repeat(5461)]) {
      const ctx = ctxFor(payload);
      expect(fastestMs(() => void detector.inspect(ctx))).toBeLessThan(25);
    }
  });

  it("scales linearly, not quadratically, with payload length", () => {
    // Both ends are measured with `fastestMs`, for the reason its own docstring gives:
    // a single sample measures the machine as much as the regex. This test used one
    // sample per end and divided them, which compounds the problem — one preempted
    // `large` sample against a fixed ratio bound is enough to fail a run with nothing
    // wrong, and it did, intermittently, under full-suite parallelism. Measured on an
    // idle machine the ratio is a stable ~7.6x; the bound of 24 still leaves the old
    // quadratic behaviour (~64x) nowhere to hide.
    //
    // A flaky guard in a security suite is worse than no guard: it teaches whoever sees
    // it to rerun rather than look, which is exactly how a real archive data-loss bug in
    // this repository stayed hidden behind an "intermittent" failure.
    const cost = (n: number): number => {
      const payload = "{{".repeat(n);
      return fastestMs(() => {
        for (let i = 0; i < 20; i += 1) detector.inspect(ctxFor(payload));
      });
    };
    cost(500); // warm up the JIT so the comparison is about the regex, not compilation
    const small = Math.max(cost(1000), 0.1);
    const large = cost(8000);
    // 8x the input. Linear ⇒ ~8x the time; the old quadratic behaviour was ~64x.
    expect(large / small).toBeLessThan(24);
  });

  it("still detects the SSTI payloads attackers actually send", () => {
    const payloads = [
      "{{config}}",
      "{{config.items()}}",
      "{{self.__init__.__globals__}}",
      "{{''.__class__.__mro__[2].__subclasses__()}}",
      "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
      "{{ process.mainModule.require('child_process').execSync('id') }}",
      "{{global.process.mainModule.require('os')}}",
      "${T(java.lang.Runtime).getRuntime().exec('id')}",
      "${java.lang.Runtime}",
      "%7B%7Bconfig%7D%7D",
    ];
    for (const payload of payloads) {
      const detection = detector.inspect(ctxFor(payload));
      expect(detection, `missed ${payload}`).toBeDefined();
    }
  });

  it("does not fire on ordinary prose that merely mentions the keywords", () => {
    expect(detector.inspect(ctxFor("please update the config for this process"))).toBeUndefined();
    expect(detector.inspect(ctxFor("{{ }}"))).toBeUndefined();
  });

  it("has no signature that goes superlinear on a long repeated-token value", () => {
    // A guard for signatures added later: every pattern, against every adversarial
    // shape, must stay cheap at the full 16 KB scan width.
    const adversarial = [
      "{{".repeat(8192),
      "${".repeat(8192),
      "<!DOCTYPE ".concat("a".repeat(16000)),
      "../".repeat(5461),
      "or ".concat(" ".repeat(16000), "x"),
      "<script".concat(" ".repeat(16000)),
      ";".concat("c".repeat(16000)),
    ];
    for (const { kind, pattern } of injectionSignatures) {
      for (const value of adversarial) {
        expect(fastestMs(() => void pattern.test(value)), `signature ${kind} was slow`).toBeLessThan(25);
      }
    }
  });
});

describe("open-redirect does not fire on same-site targets containing @", () => {
  const detector = openRedirectDetector();
  const ctx = (query: Record<string, string>): DetectionContext =>
    ({ method: "GET", path: "/login", query, headers: { host: "app.example.com" }, rawHeaders: [], ip: "1.2.3.4" }) as unknown as DetectionContext;

  it("ignores an @ that is not part of an off-site authority", () => {
    // The bare `@` alternative was unanchored, so it matched an @ anywhere in the value
    // and reported ordinary same-site targets as "malformed off-site target".
    for (const query of [
      { next: "/dashboard?email=foo@bar.com" },
      { u: "alice@example.com" },
      { r: "/u/@alice" },
      { next: "/profile/@handle/settings" },
      { redirect: "/search?q=a@b" },
    ]) {
      expect(detector.inspect(ctx(query)), `false positive on ${JSON.stringify(query)}`).toBeUndefined();
    }
  });

  it("still catches the redirects that actually leave the site", () => {
    for (const query of [
      { next: "//evil.example" },
      { next: "https://evil.example/phish" },
      { redirect_uri: "https://app.example.com.evil.example/x" },
      { next: "/\\evil.example" },
      // userinfo trick: the real host is what counts, and it is off-site
      { next: "//app.example.com@evil.example" },
      { next: "https://app.example.com@evil.example/x" },
    ]) {
      expect(detector.inspect(ctx(query)), `missed ${JSON.stringify(query)}`).toBeDefined();
    }
  });

  it("still treats a genuine same-site absolute redirect as fine", () => {
    expect(detector.inspect(ctx({ next: "https://app.example.com/dashboard" }))).toBeUndefined();
    // …including the inverse userinfo form, which sends the browser to the trusted host.
    expect(detector.inspect(ctx({ next: "https://evil.example@app.example.com/x" }))).toBeUndefined();
  });
});
