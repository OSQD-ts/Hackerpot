import http from "node:http";
import { describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import { toRegExp } from "../src/config/reader.js";
import { decoyPathDetector, headerIntegrityDetector, sensitiveFileDetector, targetIntegrityDetector } from "../src/detectors/index.js";
import type { DetectionContext, RequestFacts } from "../src/detectors/types.js";
import { normalizePath } from "../src/http-request.js";
import { HoneypotServer } from "../src/server.js";
import type { HoneypotHit } from "../src/types.js";

const BROWSER = {
  host: "target.example",
  "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
  accept: "text/html,*/*",
  "accept-language": "en-US,en;q=0.9",
  "accept-encoding": "gzip, deflate, br",
};

const facts = (path: string, extra: Partial<RequestFacts> = {}): RequestFacts => ({ method: "GET", path, query: {}, headers: { ...BROWSER }, ip: "203.0.113.9", ...extra });

describe("normalizePath", () => {
  it.each([
    ["//.env", "/.env"],
    ["/./.env", "/.env"],
    ["/%2eenv", "/.env"],
    ["/%2e%65nv", "/.env"],
    ["/foo/../.env", "/.env"],
    ["/\\.env", "/.env"],
    ["/.env/", "/.env"],
    ["/foo/..", "/"],
    ["/.git//config", "/.git/config"],
    ["/", "/"],
  ])("%s -> %s", (raw, expected) => {
    expect(normalizePath(raw)).toBe(expected);
  });

  // Decoding until the value stops changing is the classic traversal-filter bypass.
  it("decodes exactly once", () => {
    expect(normalizePath("/%252e%252e/secret")).toBe("/%2e%2e/secret");
  });

  it("leaves an absolute-form proxy target and malformed escapes alone", () => {
    expect(normalizePath("http://elsewhere.example//x")).toBe("http://elsewhere.example//x");
    expect(normalizePath("/bad%E0%A4%A")).toBe("/bad%E0%A4%A");
  });
});

describe("decoy detection survives alternate spellings of the same path", () => {
  const variants: Array<[string, string]> = [
    ["/.env", "//.env"],
    ["/.env", "/./.env"],
    ["/.env", "/%2eenv"],
    ["/.env", "/%2e%65nv"],
    ["/.env", "/foo/../.env"],
    ["/.git/config", "//.git/config"],
    ["/.git/config", "/.git//config"],
    ["/.git/config", "/%2egit/config"],
    ["/wp-login.php", "//wp-login.php"],
    ["/phpmyadmin/", "//phpmyadmin/"],
  ];

  it.each(variants)("%s spelled %s still fires decoy-path", async (canonical, spelled) => {
    const expected = (await new HoneypotEngine({ enricher: null }).evaluate(facts(canonical))).detections.find((d) => d.detectorId === "decoy-path");
    const result = await new HoneypotEngine({ enricher: null }).evaluate(facts(spelled));
    const decoy = result.detections.find((d) => d.detectorId === "decoy-path");
    expect(expected).toBeDefined();
    expect(decoy?.score).toBe(expected!.score);
  });

  it("records the spelling that was sent, and only when it differs", async () => {
    const hits: HoneypotHit[] = [];
    const engine = new HoneypotEngine({ enricher: null, onHit: (hit) => void hits.push(hit) });
    await engine.evaluate(facts("//.env"));
    await engine.evaluate(facts("/.env", { ip: "203.0.113.10" }));
    expect(hits[0]).toMatchObject({ path: "/.env", rawPath: "//.env" });
    expect(hits[1]!.rawPath).toBeUndefined();
  });

  // End to end over a real socket: Node hands the handler the target unchanged.
  it("serves the decoy to an alternate spelling through the standalone server", async () => {
    const server = new HoneypotServer({ enricher: null });
    await server.listen(0, "127.0.0.1");
    const { port } = server.address() as { port: number };
    try {
      for (const path of ["//.env", "/%2eenv"]) {
        const body = await new Promise<string>((resolve, reject) => {
          const req = http.request({ host: "127.0.0.1", port, path, headers: BROWSER }, (res) => {
            let text = "";
            res.setEncoding("utf8");
            res.on("data", (chunk: string) => (text += chunk));
            res.on("end", () => resolve(text));
          });
          req.on("error", reject);
          req.end();
        });
        expect(body, path).toContain("APP_ENV=production");
      }
    } finally {
      await server.close();
    }
  });
});

describe("regex patterns carrying g or y stay stateless", () => {
  const ctx = (path: string): DetectionContext => ({ ...facts(path), tracker: undefined as never, timestamp: new Date(), fingerprint: "", fingerprintRegistry: undefined as never });

  it("a g-flagged decoy matches on every request, not every other one", async () => {
    const detector = decoyPathDetector([{ id: "secret", description: "secret", path: /^\/secret/g, score: 5 }]);
    const outcomes = [];
    for (let i = 0; i < 4; i += 1) outcomes.push(Boolean(await detector.inspect(ctx("/secret"))));
    expect(outcomes).toEqual([true, true, true, true]);
  });

  it("a g-flagged sensitive-file pattern matches on every request", async () => {
    const detector = sensitiveFileDetector({ patterns: [/\.bak$/g] });
    const outcomes = [];
    for (let i = 0; i < 4; i += 1) outcomes.push(Boolean(await detector.inspect(ctx("/index.php.bak"))));
    expect(outcomes).toEqual([true, true, true, true]);
  });

  it("config regex literals drop g and y", () => {
    const pattern = toRegExp("/\\.env/giy", (message) => {
      throw new Error(message);
    });
    expect(pattern.flags).toBe("i");
  });
});

describe("header-integrity", () => {
  const ctx = (rawHeaders: string[], httpVersion?: string): DetectionContext => {
    const headers: Record<string, string> = {};
    for (let i = 0; i < rawHeaders.length; i += 2) headers[rawHeaders[i]!.toLowerCase()] ??= rawHeaders[i + 1]!;
    return { method: "GET", path: "/", query: {}, headers, rawHeaders, ip: "203.0.113.9", httpVersion, tracker: undefined as never, timestamp: new Date(), fingerprint: "", fingerprintRegistry: undefined as never };
  };
  const detector = headerIntegrityDetector();

  it("reports a repeated Host as proof", async () => {
    const hit = await detector.inspect(ctx(["Host", "a.example", "User-Agent", "x", "Host", "b.example"]));
    expect(hit).toMatchObject({ score: 9, certain: true, metadata: { kind: "repeated-framing-header" } });
  });

  it("reports a connection-specific header over HTTP/2 as proof, but not over HTTP/1.1", async () => {
    expect(await detector.inspect(ctx(["host", "a", "connection", "keep-alive"], "2.0"))).toMatchObject({ certain: true });
    expect(await detector.inspect(ctx(["Host", "a", "Connection", "keep-alive"], "1.1"))).toBeUndefined();
  });

  it("reports a duplicated User-Agent as weak suspicion only", async () => {
    const hit = await detector.inspect(ctx(["Host", "a", "User-Agent", "x", "User-Agent", "y"], "1.1"));
    expect(hit).toMatchObject({ score: 3 });
    expect(hit?.certain).toBeUndefined();
  });

  it("stays quiet on an ordinary browser header set", async () => {
    expect(await detector.inspect(ctx(Object.entries(BROWSER).flat(), "1.1"))).toBeUndefined();
  });
});

describe("target-integrity and one-act scoring", () => {
  it("flags a double-encoded target without decoding it twice", async () => {
    const result = await new HoneypotEngine({ enricher: null }).evaluate(facts("/%252e%252e%252fsecret"));
    expect(result.path).toBe("/%2e%2e%2fsecret");
    expect(result.detections.find((d) => d.detectorId === "target-integrity")?.metadata?.["findings"]).toContain("double-encoded");
  });

  it("counts an encoded traversal once even though two detectors see it", async () => {
    const result = await new HoneypotEngine({ enricher: null }).evaluate(facts("/%2e%2e%2f%2e%2e%2fapp/config.yml"));
    const ids = result.detections.map((d) => d.detectorId);
    expect(ids).toEqual(expect.arrayContaining(["payload-injection", "target-integrity"]));
    const traversal = result.detections.filter((d) => d.family === "path-traversal");
    const naive = result.detections.reduce((sum, d) => sum + d.score, 0);
    const expected = naive - traversal.reduce((sum, d) => sum + d.score, 0) + Math.max(...traversal.map((d) => d.score));
    expect(result.score).toBe(expected);
    expect(result.score).toBeLessThan(naive);
  });

  it("is silent on targets that normalise without evasion", async () => {
    const detector = targetIntegrityDetector();
    const base = { method: "GET", query: {}, headers: {}, ip: "203.0.113.9", tracker: undefined as never, timestamp: new Date(), fingerprint: "", fingerprintRegistry: undefined as never };
    expect(await detector.inspect({ ...base, path: "/my file.pdf", rawPath: "/my%20file.pdf" })).toBeUndefined();
    expect(await detector.inspect({ ...base, path: "/café", rawPath: "/caf%C3%A9" })).toBeUndefined();
  });
});
