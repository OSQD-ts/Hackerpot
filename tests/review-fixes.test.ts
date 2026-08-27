import { afterEach, describe, expect, it } from "vitest";
import net from "node:net";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SmtpHoneypot } from "../src/smtp/index.js";
import { RedisStore } from "../src/stores/index.js";
import { openRedirectDetector } from "../src/detectors/index.js";
import { WebhookDispatcher } from "../src/management/webhooks.js";
import { IncidentBroker } from "../src/management/broker.js";
import { describeConfig, parseConfigText } from "../src/config/index.js";
import type { DetectionContext } from "../src/detectors/types.js";
import type { Incident } from "../src/management/types.js";

const portOf = (a: unknown): number => (typeof a === "object" && a !== null ? (a as net.AddressInfo).port : 0);

describe("the SMTP honeypot survives a client that resets mid-handshake", () => {
  const captured: Error[] = [];
  const onUncaught = (err: Error): void => void captured.push(err);

  afterEach(() => process.off("uncaughtException", onUncaught));

  it("does not throw an unhandled socket error while awaiting the store", async () => {
    // `handleConnection` used to attach `socket.on("error")` only at the very end —
    // below two `socket.write()` early returns and below `await store.scoreFor(ip)`.
    // A net.Socket rethrows an 'error' with no listener as an uncaughtException, so a
    // client that connected and reset during that await killed the whole process: the
    // HTTP honeypot, the SSH honeypot and the management API all share it. And the
    // window only opened once the operator enabled `drop_above_score`, so switching on
    // a hardening option was what made the service remotely killable.
    process.on("uncaughtException", onUncaught);

    const store = {
      record: async () => undefined,
      list: async () => [],
      // A real store is a network round-trip; that is the window.
      scoreFor: async () => {
        await new Promise((r) => setTimeout(r, 60));
        return 0;
      },
    };
    const honeypot = new SmtpHoneypot({ port: 0, host: "127.0.0.1", store, dropAboveScore: 100, onHit: () => undefined });
    await honeypot.listen();
    const port = portOf(honeypot.address());

    for (let i = 0; i < 8; i += 1) {
      const socket = net.connect({ port, host: "127.0.0.1" });
      socket.on("error", () => undefined);
      socket.on("connect", () => socket.resetAndDestroy());
    }
    await new Promise((r) => setTimeout(r, 400));
    await honeypot.close();

    expect(captured.map((e) => e.message)).toEqual([]);
  });

  it("still serves the greeting to a well-behaved client", async () => {
    const honeypot = new SmtpHoneypot({ port: 0, host: "127.0.0.1", onHit: () => undefined });
    await honeypot.listen();
    const port = portOf(honeypot.address());
    const greeting = await new Promise<string>((resolve) => {
      const socket = net.connect({ port, host: "127.0.0.1" });
      socket.on("error", () => resolve(""));
      socket.once("data", (chunk: Buffer) => {
        resolve(chunk.toString());
        socket.destroy();
      });
    });
    await honeypot.close();
    expect(greeting).toMatch(/^220 /);
  });
});

describe("--print-config never prints a credential", () => {
  const withSecrets = `
[management]
enabled = true
api_keys = ["SUPER-SECRET-MANAGEMENT-KEY"]

[[management.webhooks]]
url = "https://hooks.example/alert"
secret = "WEBHOOK-HMAC-SIGNING-SECRET"
headers = { authorization = "Bearer BEARER-TOKEN-VALUE" }

[store.redis]
url = "redis://:REDIS-PASSWORD@redis:6379"

[store.elastic]
node = "https://es.example:9200"
username = "elastic"
password = "ELASTIC-PASSWORD"

[intel]
enabled = true
feeds = ["https://peer.example/ioc.txt"]
api_key = "PEER-FEED-API-KEY"
`;

  it("redacts every secret in the resolved config", () => {
    // This backs `npm run config:check` — run casually, in CI, and over screen shares.
    // Validating a config must not be the thing that copies its secrets into a log.
    const printed = describeConfig(parseConfigText(withSecrets, "<test>"));
    for (const secret of [
      "SUPER-SECRET-MANAGEMENT-KEY",
      "WEBHOOK-HMAC-SIGNING-SECRET",
      "BEARER-TOKEN-VALUE",
      "REDIS-PASSWORD",
      "ELASTIC-PASSWORD",
      "PEER-FEED-API-KEY",
    ]) {
      expect(printed, `${secret} leaked into --print-config`).not.toContain(secret);
    }
  });

  it("keeps everything an operator is actually checking", () => {
    const printed = describeConfig(parseConfigText(withSecrets, "<test>"));
    // Non-secret values, and the host/port halves of credentialed URLs, stay readable.
    expect(printed).toContain("https://hooks.example/alert");
    expect(printed).toContain("https://es.example:9200");
    expect(printed).toContain("redis:6379");
    expect(printed).toContain("https://peer.example/ioc.txt");
    expect(printed).toContain("elastic"); // username is not a credential
    // The shape survives: one API key configured, one webhook header set.
    expect(printed).toMatch(/"apiKeys":\s*\[\s*"«redacted»"\s*\]/);
    expect(printed).toContain("authorization");
  });

  it("still distinguishes a configured secret from an unset one", () => {
    const printed = describeConfig(parseConfigText(`[store.elastic]\nnode = "https://es.example:9200"\n`, "<test>"));
    // Empty stays empty rather than becoming a misleading «redacted».
    expect(printed).toMatch(/"password":\s*""/);
  });

  it("leaves a URL with no credentials byte-for-byte alone", () => {
    const printed = describeConfig(parseConfigText(`[store.redis]\nurl = "redis://redis:6379/2"\n`, "<test>"));
    expect(printed).toContain('"url": "redis://redis:6379/2"');
  });
});

describe("webhook delivery is bounded", () => {
  const incident = (ip: string): Incident =>
    ({ id: ip, timestamp: new Date().toISOString(), ip, method: "GET", path: "/.env", headers: {}, detections: [], score: 5, totalScore: 5, respondedWith: "not-found" }) as Incident;

  it("caps deliveries in flight and reports what it dropped", async () => {
    // Deliveries are attacker-driven — one incident, one POST. A receiver that accepts
    // and stalls used to leave an unbounded number of concurrent fetches in the air.
    let peak = 0;
    let live = 0;
    const errors: string[] = [];
    const hanging = (async () => {
      live += 1;
      peak = Math.max(peak, live);
      await new Promise((r) => setTimeout(r, 300));
      live -= 1;
      return new Response("", { status: 200 });
    }) as unknown as typeof fetch;

    const original = globalThis.fetch;
    globalThis.fetch = hanging;
    try {
      const broker = new IncidentBroker();
      const dispatcher = new WebhookDispatcher({
        webhooks: [{ url: "https://sink.example/hook", maxInFlight: 4 }],
        onError: (_url, err) => errors.push(err.message),
      });
      dispatcher.attach(broker);
      for (let i = 0; i < 50; i += 1) broker.publish(incident(`10.0.0.${i}`));
      await new Promise((r) => setTimeout(r, 500));
      dispatcher.detach();
    } finally {
      globalThis.fetch = original;
    }

    expect(peak).toBeLessThanOrEqual(4);
    expect(errors.some((e) => e.includes("already in flight"))).toBe(true);
  });

  it("abandons an attempt that exceeds the timeout instead of hanging forever", async () => {
    const original = globalThis.fetch;
    const errors: string[] = [];
    // Honour the abort signal the dispatcher passes, as a real fetch does.
    globalThis.fetch = ((_url: string, init: RequestInit) =>
      new Promise((_resolve, reject) => {
        init.signal?.addEventListener("abort", () => reject(new Error("TimeoutError")));
      })) as unknown as typeof fetch;
    try {
      const broker = new IncidentBroker();
      const dispatcher = new WebhookDispatcher({
        webhooks: [{ url: "https://sink.example/hook", timeoutMs: 50, maxRetries: 1 }],
        onError: (_url, err) => errors.push(err.message),
      });
      dispatcher.attach(broker);
      broker.publish(incident("10.0.0.1"));
      await new Promise((r) => setTimeout(r, 400));
      dispatcher.detach();
    } finally {
      globalThis.fetch = original;
    }
    expect(errors.length).toBeGreaterThan(0);
  });

  it("accepts the new knobs from TOML and rejects nonsense values", () => {
    const config = parseConfigText(
      `[management]\nenabled = true\napi_keys = ["k"]\n\n[[management.webhooks]]\nurl = "https://h.example/x"\nmax_in_flight = 8\ntimeout_ms = 2000\n`,
      "<test>",
    );
    expect(config.management.webhooks[0]!.maxInFlight).toBe(8);
    expect(config.management.webhooks[0]!.timeoutMs).toBe(2000);
    expect(() =>
      parseConfigText(`[management]\nenabled = true\napi_keys = ["k"]\n\n[[management.webhooks]]\nurl = "https://h/x"\nmax_in_flight = 0\n`, "<test>"),
    ).toThrow(/max_in_flight/);
  });
});

describe("a damaged Redis entry does not break every management endpoint", () => {
  it("skips what will not parse and returns the rest", async () => {
    const entries = ['{"id":"a","ip":"1.1.1.1","score":1}', "{truncated", '{"id":"b","ip":"2.2.2.2","score":2}'];
    const fake = { lrange: async () => entries } as never;
    const store = new RedisStore({ client: fake });
    const hits = await store.list();
    expect(hits.map((h) => h.id)).toEqual(["a", "b"]);
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

describe("a SIGHUP reload applies all of [logging], not half of it", () => {
  it("applies include_headers, not only format", () => {
    // `format` lived in a module-level binding and reloaded; include_headers/include_body
    // were read from a config object captured in the hit closure and did not. The reload
    // still reported `applied: ["logging"], requiresRestart: []`, so the operator was
    // told the whole section took effect. Half-applied is worse than not applied: seeing
    // format change is what convinces you the rest did too.
    //
    // The child runs the entrypoint FROM SOURCE via `node --import tsx`, not from
    // `dist/`: CI runs `npm test` before `npm run build`, so a test that reached for a
    // build artifact failed there while passing locally off a stale dist. It must also
    // be a single `node` process — `npx tsx` wraps the real process in a launcher that
    // does not forward SIGHUP, so the reload under test would never fire.
    const dir = mkdtempSync(join(tmpdir(), "hackerpot-reload-"));
    const configPath = join(dir, "hackerpot.toml");
    const port = 4655;
    const config = (includeHeaders: boolean): string =>
      `[server]\nhost = "127.0.0.1"\nport = ${port}\n\n[policy]\nblock_threshold = 1000000\ntarpit_threshold = 999999\n\n[logging]\nstartup = false\nformat = "json"\ninclude_headers = ${includeHeaders}\n`;
    writeFileSync(configPath, config(false));

    const runner = join(dir, "runner.cjs");
    writeFileSync(
      runner,
      `
      const { spawn } = require("node:child_process");
      const { writeFileSync } = require("node:fs");
      const http = require("node:http");
      const [entry, cfg, port, reloaded] = process.argv.slice(2);
      const child = spawn(process.execPath, ["--import", "tsx", entry, "-c", cfg], { stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      let err = "";
      let exited = null;
      child.stdout.on("data", (d) => (out += d));
      child.stderr.on("data", (d) => (err += d));
      child.on("exit", (code) => (exited = code));
      const hit = (path) => new Promise((res) => {
        const req = http.request({ host: "127.0.0.1", port: Number(port), path, headers: { "user-agent": "sqlmap/1.7" } }, (r) => { r.resume(); r.on("end", res); });
        req.on("error", res);
        req.end();
      });
      (async () => {
        // Wait for the listener rather than a fixed sleep: tsx compiles on first run,
        // and a CI runner is slower and noisier than a laptop.
        for (let i = 0; i < 100 && exited === null; i++) {
          const up = await new Promise((res) => {
            const r = http.request({ host: "127.0.0.1", port: Number(port), path: "/__probe" }, (x) => { x.resume(); res(true); });
            r.on("error", () => res(false));
            r.end();
          });
          if (up) break;
          await new Promise((r) => setTimeout(r, 100));
        }
        await hit("/.env");
        await new Promise((r) => setTimeout(r, 300));
        const before = out.includes('"headers"');
        writeFileSync(cfg, reloaded);
        child.kill("SIGHUP");
        for (let i = 0; i < 50 && !/"kind":"reload"/.test(out); i++) await new Promise((r) => setTimeout(r, 100));
        await hit("/.env?after=1");
        await new Promise((r) => setTimeout(r, 300));
        const after = out.includes('"headers"');
        child.kill();
        console.log("RESULT" + JSON.stringify({ before, after, sawReload: /"applied":\\["logging"\\]/.test(out), exited, err: err.slice(0, 400) }));
      })();
    `,
    );

    const stdout = execFileSync("node", [runner, "src/standalone.ts", configPath, String(port), config(true)], {
      encoding: "utf8",
      timeout: 60_000,
    });
    const line = stdout.split("\n").find((l) => l.startsWith("RESULT"));
    expect(line, `runner produced no result:\n${stdout}`).toBeDefined();
    const { before, after, sawReload, exited, err } = JSON.parse(line!.slice("RESULT".length));

    // Diagnose a dead child as a dead child, rather than as a reload that misbehaved.
    expect(exited, `the service exited early (code ${exited}):\n${err}`).toBeNull();
    expect(before, "headers were logged before the reload asked for them").toBe(false);
    expect(sawReload, `the service never reported [logging] as reloaded:\n${err}`).toBe(true);
    expect(after, "include_headers was reported applied but had no effect").toBe(true);
  }, 90_000);
});
