import net from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { HoneypotEngine, SmtpHoneypot, defaultDetectors } from "../src/index.js";
import type { RequestFacts } from "../src/index.js";

// Deterministic PRNG (mulberry32). A fuzzer that finds a new failure on a random CI run
// is a flaky test; with a fixed seed a failure is always reproducible from the seed.
function mulberry32(seed: number): () => number {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// The token shapes that break naive parsers and regexes: pollution keys, injection
// payloads, encodings, control chars, and the openers that drive catastrophic backtracking.
// Plus tokens that actually MATCH each detector, so the fuzz exercises the match+extract
// code paths (metadata pulls, decoding, JSON handling) — not just the "scan, find nothing"
// branch. Coverage was measured (see the coverage assertion below): seeding these took the
// fuzz from 10 detectors reached to nearly all the per-request ones.
const HOSTILE = [
  "__proto__", "constructor", "prototype", "%", "%%", "%zz", "%c0", "\x00", "\r\n", "\n",
  "../", "..\\", "' OR 1=1--", "<script>", "{{7*7}}", "${jndi:ldap://x}", "O:8:\"x\":1:{",
  "rO0ABXNy", "]]>", "&&", "||", "|", "=", "\\", "(((((", "{{{{{", "\"\"\"", "::", "@", "\t",
  "a".repeat(50), "/".repeat(50), "%2e%2e%2f", "0x", "SELECT", "UNION", "javascript:", "￿",
  // Match-triggering seeds, one family per detector:
  '{"$ne":null}', "$gt", "$where:", "0e0",                                   // nosql-injection
  "query{__schema{types{name}}}", "{a{b{c{d{e{f}}}}}}", "mutation{x}",       // graphql-abuse
  "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.",                              // jwt-weakness (alg:none)
  "c99.php", "eval(", "system(", "shell_exec(",                             // web-shell
  "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd",          // ssrf-probe
];

// Paths that trip the path/method/file detectors; sometimes used verbatim, sometimes fuzzed.
const SEED_PATHS = [
  "/.env", "/wp-login.php", "/.git/config", "/backup.sql", "/database.bak", "/shell.php",
  "/.aws/credentials", "/actuator/env", "/api/graphql", "/admin", "/.svn/entries", "/config.php~",
  "/redirect?url=http://evil.example", "/go?next=//evil.example", "/phpMyAdmin/", "/.DS_Store",
];
const SEED_METHODS = ["GET", "POST", "PUT", "PROPFIND", "MKCOL", "TRACE", "DEBUG", "MOVE"];

function fuzzString(rand: () => number, maxLen: number): string {
  const parts: string[] = [];
  let len = 0;
  while (len < maxLen && rand() > 0.05) {
    const pick = rand();
    let piece: string;
    if (pick < 0.5) {
      piece = HOSTILE[Math.floor(rand() * HOSTILE.length)]!;
    } else if (pick < 0.7) {
      // A long repeat of one hostile token — the ReDoS stressor.
      piece = HOSTILE[Math.floor(rand() * HOSTILE.length)]!.repeat(1 + Math.floor(rand() * 40));
    } else {
      // Random bytes, including non-ASCII / control.
      piece = String.fromCharCode(Math.floor(rand() * 0x2000));
    }
    parts.push(piece);
    len += piece.length;
  }
  return parts.join("");
}

function fuzzFacts(rand: () => number): RequestFacts {
  const headerNames = ["user-agent", "referer", "cookie", "host", "x-forwarded-for", "content-type", "authorization", "x-serialized"];
  const headers: Record<string, string> = {};
  const n = Math.floor(rand() * headerNames.length);
  for (let i = 0; i < n; i++) headers[headerNames[Math.floor(rand() * headerNames.length)]!] = fuzzString(rand, 4000);
  // Sometimes plant a scanner UA (scanner-signature), or a browser UA with NO Accept
  // headers (client-anomaly), so those detectors' paths are reached too.
  if (rand() < 0.15) headers["user-agent"] = ["sqlmap/1.7", "nikto", "curl/8", "nmap"][Math.floor(rand() * 4)]!;
  else if (rand() < 0.12) {
    headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537 Chrome/120 Safari/537";
    delete headers["accept"]; // no such key anyway, but be explicit — client-anomaly needs them absent
  }

  const query: Record<string, string> = Object.create(null);
  const qn = Math.floor(rand() * 4);
  for (let i = 0; i < qn; i++) query[fuzzString(rand, 40)] = fuzzString(rand, 4000);
  // Sometimes a redirect-style param carrying an off-site target (open-redirect).
  if (rand() < 0.15) query[["url", "next", "redirect", "dest"][Math.floor(rand() * 4)]!] = "http://evil.example/" + fuzzString(rand, 40);

  // Half the time use a real bait path (fuzzed), half a fully-random one, so decoy/file/
  // method detectors' match paths get exercised alongside the pure-garbage inputs.
  let path = rand() < 0.5 ? SEED_PATHS[Math.floor(rand() * SEED_PATHS.length)]! + (rand() < 0.5 ? "" : fuzzString(rand, 200)) : "/" + fuzzString(rand, 4000);
  // Bias toward a login endpoint often enough that one IP crosses the credential-bruteforce
  // attempt threshold (a stateful detector a wide path spread never reaches).
  if (rand() < 0.15) path = "/wp-login.php";

  return {
    method: rand() < 0.7 ? SEED_METHODS[Math.floor(rand() * SEED_METHODS.length)]! : fuzzString(rand, 8),
    path,
    query,
    headers,
    // A small IP pool so requests repeat per IP — reaches the stateful detectors
    // (path/credential bruteforce, rate-spike) that a wide IP spread never triggers.
    ip: `198.51.100.${Math.floor(rand() * 12)}`,
    body: rand() > 0.5 ? fuzzString(rand, 20000) : undefined,
  };
}

describe("fuzzing — detectors never throw or hang on hostile input", () => {
  it("runs every default detector over 2000 adversarial requests with no throw and no ReDoS", async () => {
    const rand = mulberry32(0x1234abcd); // fixed seed → reproducible
    // onError fires if ANY detector throws out of inspect(); the run must leave it empty.
    const thrown: Array<{ source: string; error: unknown }> = [];
    const engine = new HoneypotEngine({
      detectors: defaultDetectors(),
      onError: (error, ctx) => thrown.push({ source: ctx.source, error }),
    });

    const hitDetectors = new Set<string>();
    const start = Date.now();
    for (let i = 0; i < 2000; i++) {
      // Must not reject regardless of input (isolation + best-effort recording).
      const r = await engine.evaluate(fuzzFacts(rand));
      for (const d of r.detections) hitDetectors.add(d.detectorId);
    }
    const elapsed = Date.now() - start;

    expect(thrown).toEqual([]); // no detector threw on any of the 2000 hostile inputs
    // 2000 iterations in well under the ReDoS-would-blow-this bound: proves the 16KB
    // scan caps hold — a catastrophic-backtracking regex would take minutes here.
    expect(elapsed).toBeLessThan(20_000);
    // Coverage guard: a fuzzer that passes proves nothing until you know what it REACHED.
    // The corpus is seeded so the run exercises the match+extract path of nearly every
    // default detector — not just their "scan, find nothing" branch. If a corpus change
    // drops coverage below this floor, this fails rather than passing hollow.
    expect(hitDetectors.size).toBeGreaterThanOrEqual(20);
  }, 30_000);
});

describe("fuzzing — the SMTP line parser survives hostile sessions", () => {
  let smtp: SmtpHoneypot | undefined;
  afterEach(async () => { await smtp?.close(); smtp = undefined; });

  it("stays up after a flood of malformed commands and can still serve a fresh connection", async () => {
    smtp = new SmtpHoneypot({ port: 0 });
    await smtp.listen();
    const port = (smtp.address() as { port: number }).port;
    const rand = mulberry32(0x0badf00d);

    // Fire many garbage lines at one session.
    await new Promise<void>((resolve) => {
      const socket = net.createConnection({ port }, () => {
        const lines: string[] = [];
        for (let i = 0; i < 300; i++) lines.push(fuzzString(rand, 200).replace(/\n/g, " "));
        socket.write(lines.join("\r\n") + "\r\n");
      });
      socket.on("error", () => resolve()); // a reset is fine; a crash would fail the next check
      socket.setTimeout(1500, () => socket.destroy());
      socket.on("close", () => resolve());
      setTimeout(() => { socket.destroy(); resolve(); }, 800);
    });

    // The honeypot must still be alive: a fresh connection gets the 220 greeting.
    const greeting = await new Promise<string>((resolve, reject) => {
      const s = net.createConnection({ port }, () => {});
      s.setTimeout(1500, () => { s.destroy(); reject(new Error("no greeting — server died")); });
      s.on("data", (d) => { resolve(d.toString()); s.destroy(); });
      s.on("error", reject);
    });
    expect(greeting).toContain("220");
  }, 15_000);
});
