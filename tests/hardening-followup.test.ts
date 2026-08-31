import { describe, expect, it } from "vitest";
import http from "node:http";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { HoneypotServer } from "../src/server.js";
import { MemoryBlocklist } from "../src/blocklist.js";
import { FileStore } from "../src/stores/index.js";
import { tarpitAction } from "../src/responses/index.js";
import { payloadInjectionDetector, injectionSignatures } from "../src/detectors/index.js";
import { fetchIocFeed } from "../src/intel/index.js";
import type { DetectionContext } from "../src/detectors/types.js";

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
    const cost = (n: number): number => {
      const payload = "{{".repeat(n);
      const started = process.hrtime.bigint();
      for (let i = 0; i < 20; i += 1) detector.inspect(ctxFor(payload));
      return Number(process.hrtime.bigint() - started) / 1e6;
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

describe("a pathological payload does not stall the honeypot end to end", () => {
  it("serves a 16 KB brace body without blocking the event loop", async () => {
    const server = new HoneypotServer({});
    await server.listen(0, "127.0.0.1");
    const address = server.address();
    const port = typeof address === "object" && address !== null ? address.port : 0;

    // A complete, browser-shaped header set: no detector fires, so this measures the cost
    // of *scanning* the payload and not a response action's deliberate delay. (Without
    // these, `scanner-signature` and `client-anomaly` score the request into a tarpit and
    // the timing says nothing about the regex.)
    const headers = {
      "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
      accept: "text/html,application/xhtml+xml",
      "accept-language": "en-US,en;q=0.9",
      "accept-encoding": "gzip, deflate",
    };
    const hit = (body: string): Promise<void> =>
      new Promise((resolve) => {
        const req = http.request({ host: "127.0.0.1", port, path: "/probe", method: "POST", headers }, (res) => {
          res.resume();
          res.on("end", () => resolve());
        });
        req.end(body);
      });

    const evil = "{{".repeat(8192);
    await hit(evil); // warm up
    const started = Date.now();
    await Promise.all(Array.from({ length: 20 }, () => hit(evil)));
    const elapsed = Date.now() - started;
    await server.close();

    // These are serialized on one event loop. Before the fix, 20 requests took ~4s.
    expect(elapsed).toBeLessThan(1500);
  }, 20_000);
});

describe("an IOC feed cannot harvest the operator's API key via a redirect", () => {
  const responses = (...list: Array<{ status: number; location?: string; body?: string }>) => {
    const seen: Array<{ url: string; auth: string | undefined }> = [];
    let i = 0;
    const doFetch = (async (url: string, init: RequestInit) => {
      const headers = (init.headers ?? {}) as Record<string, string>;
      seen.push({ url, auth: headers["Authorization"] });
      const step = list[Math.min(i, list.length - 1)]!;
      i += 1;
      return new Response(step.body ?? "", {
        status: step.status,
        headers: step.location ? { location: step.location } : {},
      });
    }) as unknown as typeof fetch;
    return { doFetch, seen };
  };

  it("drops Authorization when a redirect leaves the original origin", async () => {
    // The management API key is what feeds authenticate with, so leaking it hands over
    // read access to the operator's captured-incident API — not just a public IOC list.
    const { doFetch, seen } = responses(
      { status: 302, location: "https://attacker.example/steal" },
      { status: 200, body: "203.0.113.7\n" },
    );
    const ips = await fetchIocFeed("https://peer.example/ioc.txt", { apiKey: "SUPER-SECRET-KEY", fetch: doFetch });

    expect(ips).toEqual(["203.0.113.7"]);
    expect(seen[0]!.auth).toBe("Bearer SUPER-SECRET-KEY");
    expect(seen[1]!.url).toBe("https://attacker.example/steal");
    expect(seen[1]!.auth).toBeUndefined();
    expect(JSON.stringify(seen)).not.toContain("SUPER-SECRET-KEY".slice(0, 6) + "-SECRET");
  });

  it("keeps Authorization on a same-origin redirect", async () => {
    const { doFetch, seen } = responses(
      { status: 301, location: "https://peer.example/ioc/v2.txt" },
      { status: 200, body: "198.51.100.4\n" },
    );
    await fetchIocFeed("https://peer.example/ioc.txt", { apiKey: "KEY", fetch: doFetch });
    expect(seen[1]!.auth).toBe("Bearer KEY");
  });

  it("never re-attaches the key after a hop has left the origin", async () => {
    const { doFetch, seen } = responses(
      { status: 302, location: "https://attacker.example/a" },
      { status: 302, location: "https://peer.example/back" },
      { status: 200, body: "" },
    );
    await fetchIocFeed("https://peer.example/ioc.txt", { apiKey: "KEY", fetch: doFetch });
    expect(seen.slice(1).every((s) => s.auth === undefined)).toBe(true);
  });

  it("still refuses a redirect that drops to plaintext", async () => {
    const { doFetch } = responses({ status: 302, location: "http://attacker.example/steal" });
    await expect(fetchIocFeed("https://peer.example/ioc.txt", { apiKey: "KEY", fetch: doFetch })).rejects.toThrow(/https required/);
  });
});

describe("the in-memory blocklist is bounded", () => {
  it("stays at or under maxEntries under a flood of distinct live blocks", () => {
    const blocklist = new MemoryBlocklist({ maxEntries: 100 });
    const until = Date.now() + 3_600_000;
    for (let i = 0; i < 5_000; i += 1) blocklist.block(`10.0.${(i >> 8) & 255}.${i & 255}`, until);
    expect(blocklist.size()).toBeLessThanOrEqual(100);
  });

  it("sheds expired entries before live ones", () => {
    const now = Date.now();
    const blocklist = new MemoryBlocklist({ maxEntries: 10 });
    for (let i = 0; i < 9; i += 1) blocklist.block(`10.0.0.${i}`, now - 1_000); // already expired
    blocklist.block("203.0.113.1", now + 3_600_000);
    for (let i = 0; i < 5; i += 1) blocklist.block(`198.51.100.${i}`, now + 3_600_000);
    // The expired nine were free to drop, so the live block survives.
    expect(blocklist.isBlocked("203.0.113.1", now)).toBe(true);
    expect(blocklist.size(now)).toBeLessThanOrEqual(10);
  });

  it("still blocks and expires normally", () => {
    const now = Date.now();
    const blocklist = new MemoryBlocklist();
    blocklist.block("203.0.113.9", now + 1_000);
    expect(blocklist.isBlocked("203.0.113.9", now)).toBe(true);
    expect(blocklist.isBlocked("203.0.113.9", now + 2_000)).toBe(false);
    // A later, longer block extends; a shorter one never shortens.
    blocklist.block("203.0.113.9", now + 10_000);
    blocklist.block("203.0.113.9", now + 5_000);
    expect(blocklist.isBlocked("203.0.113.9", now + 7_000)).toBe(true);
  });
});

describe("a tarpit slot is released as soon as the attacker hangs up", () => {
  it("does not hold the slot for the full delay after the response closes", async () => {
    const action = tarpitAction({ delayMs: 5_000, escalate: false, maxConcurrent: 1 });
    const listeners = new Map<string, Array<() => void>>();
    const res = {
      writableEnded: false,
      statusCode: 200,
      setHeader: () => undefined,
      end: () => undefined,
      once: (event: string, fn: () => void) => {
        listeners.set(event, [...(listeners.get(event) ?? []), fn]);
      },
      off: (event: string, fn: () => void) => {
        listeners.set(event, (listeners.get(event) ?? []).filter((f) => f !== fn));
      },
    };
    const ctx = { res, totalScore: 0 } as never;

    const started = Date.now();
    const inFlight = action.execute(ctx);
    // The attacker disconnects immediately — a scanner timing out does exactly this.
    for (const fn of listeners.get("close") ?? []) fn();
    await inFlight;
    expect(Date.now() - started).toBeLessThan(1_000);

    // Slot is free again: the next request is genuinely tarpitted rather than being
    // waved through by the at-capacity branch.
    const second = tarpitAction({ delayMs: 40, escalate: false, maxConcurrent: 1 });
    const t = Date.now();
    await second.execute({ res: { ...res, once: () => undefined, off: () => undefined }, totalScore: 0 } as never);
    expect(Date.now() - t).toBeGreaterThanOrEqual(30);
  });
});

describe("the file store never loads an attacker-grown file whole", () => {
  const write = (lines: string[]): string => {
    const path = join(mkdtempSync(join(tmpdir(), "hackerpot-file-")), "hits.jsonl");
    writeFileSync(path, lines.map((l) => `${l}\n`).join(""));
    return path;
  };
  const hit = (ip: string, score: number, id: string): string =>
    JSON.stringify({ id, timestamp: new Date().toISOString(), ip, method: "GET", path: "/x", headers: {}, detections: [], score, totalScore: score, respondedWith: "not-found" });

  it("reads only the newest records once the file exceeds maxReadBytes", () => {
    const path = write(Array.from({ length: 400 }, (_, i) => hit(`10.0.0.${i % 255}`, 1, `id-${i}`)));
    const store = new FileStore({ path, maxReadBytes: 4096, loadOnStart: false });
    const hits = store.list();
    expect(store.truncated).toBe(true);
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.length).toBeLessThan(400);
    // Newest survive; no partial leading record slipped through as a parsed row.
    expect(hits[hits.length - 1]!.id).toBe("id-399");
    expect(hits.every((h) => typeof h.ip === "string" && typeof h.score === "number")).toBe(true);
  });

  it("returns everything, untruncated, when the file fits", () => {
    const path = write([hit("10.0.0.1", 3, "a"), hit("10.0.0.2", 4, "b")]);
    const store = new FileStore({ path, loadOnStart: false });
    expect(store.list().map((h) => h.id)).toEqual(["a", "b"]);
    expect(store.truncated).toBe(false);
  });

  it("replays complete scores at startup even for a large file", () => {
    const path = write(Array.from({ length: 400 }, () => hit("203.0.113.5", 2, "x")));
    // maxReadBytes bounds reads, but scores must still reflect every record.
    const store = new FileStore({ path, maxReadBytes: 4096 });
    expect(store.scoreFor("203.0.113.5")).toBe(800);
  });

  it("still skips corrupt lines instead of failing the read", () => {
    const path = write([hit("10.0.0.1", 1, "a"), "{not json", hit("10.0.0.2", 1, "b")]);
    const store = new FileStore({ path, loadOnStart: false });
    expect(store.list().map((h) => h.id)).toEqual(["a", "b"]);
  });

  it("does not buffer a file that contains no newline at all", () => {
    const path = join(mkdtempSync(join(tmpdir(), "hackerpot-file-")), "hits.jsonl");
    writeFileSync(path, "x".repeat(9 * 1024 * 1024));
    const store = new FileStore({ path, loadOnStart: false });
    expect(store.list()).toEqual([]);
  });
});
