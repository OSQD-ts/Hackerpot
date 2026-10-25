import http from "node:http";
import type net from "node:net";
import { describe, expect, it } from "vitest";
import { fastifyHoneypot } from "../src/adapters/fastify.js";
import { fetchHoneypot } from "../src/adapters/fetch.js";
import { koaHoneypot, type KoaLikeContext } from "../src/adapters/koa.js";
import { createMiddleware, trapFormGuard } from "../src/adapters/node.js";
import { HoneypotServer } from "../src/adapters/server.js";
import { HoneypotEngine } from "../src/core.js";
import { MarkerCookie } from "../src/marker.js";
import { observe, protectApp, rulePolicy } from "../src/policy/index.js";
import { MemoryStore } from "../src/stores/index.js";
import { applyEnvOverrides } from "../src/config/env.js";
import { parseConfigText } from "../src/config/index.js";

/**
 * The three things a deployment in front of real users depends on and HackerPot lacked:
 * a policy decision that lets the request through (`pass`), paths it never looks at
 * (`ignorePaths`), and a forwarded address it believes only from its own proxies
 * (`proxy.trustedProxies`). The proxy and ignore-path cases are adapted from bothandlerjs's
 * `tests/facts.test.ts` and `tests/config.test.ts`; the rest is HackerPot's own front ends.
 */

const BROWSER = {
  "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
  accept: "text/html,*/*",
  "accept-language": "en-US,en;q=0.9",
  "accept-encoding": "gzip, deflate, br",
};

async function withServer<T>(server: http.Server, run: (port: number) => Promise<T>): Promise<T> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    return await run((server.address() as net.AddressInfo).port);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

function send(port: number, path: string, method = "GET", body?: string): Promise<{ status: number; body: string; cookie: string | undefined }> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path, method, headers: { ...BROWSER, host: "shop.example" } }, (res) => {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", (chunk: string) => (text += chunk));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: text, cookie: res.headers["set-cookie"]?.join(";") }));
    });
    req.on("error", reject);
    req.end(body);
  });
}

function readAll(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    req.setEncoding("utf8");
    req.on("data", (chunk: string) => (data += chunk));
    req.on("end", () => resolve(data));
  });
}

const markers = (): MarkerCookie => new MarkerCookie({ secret: "s".repeat(32) });

/** An Express-shaped app: the honeypot middleware, then a route that echoes the body. */
function expressLike(engine: HoneypotEngine, calls: { next: number }): http.Server {
  const middleware = createMiddleware(engine);
  return http.createServer((req, res) => {
    void middleware(req, res, async () => {
      calls.next++;
      res.statusCode = 200;
      res.end(`app:${req.url}:${await readAll(req)}`);
    });
  });
}

describe("respondWith: pass", () => {
  it("hands a flagged request to the application untouched, and still records the incident", async () => {
    const store = new MemoryStore();
    const engine = new HoneypotEngine({ enricher: null, store, policy: rulePolicy(observe()), markers: markers() });
    const calls = { next: 0 };
    await withServer(expressLike(engine, calls), async (port) => {
      const response = await send(port, "/.env");
      // The application answered — not the decoy, not a 404 — and it was asked exactly once.
      expect(response).toMatchObject({ status: 200, body: "app:/.env:" });
      expect(calls.next).toBe(1);
      // No probe marker on a response the application wrote.
      expect(response.cookie).toBeUndefined();
    });
    const hits = await store.list();
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ path: "/.env", respondedWith: "pass" });
  });

  it("never reads the body of a request it passes, so the application gets all of it", async () => {
    const engine = new HoneypotEngine({ enricher: null, policy: rulePolicy(observe()) });
    const calls = { next: 0 };
    await withServer(expressLike(engine, calls), async (port) => {
      // Flagged on its path before any body is read; with a body-inspecting detector loaded
      // the middleware would read the body for a second pass if the answer were not `pass`.
      const response = await send(port, "/.env", "POST", "item=42&note=' OR 1=1 --");
      expect(response).toMatchObject({ status: 200, body: "app:/.env:item=42&note=' OR 1=1 --" });
    });
  });

  it("is what protect-app does with a weak signal, while bait still works", async () => {
    const engine = new HoneypotEngine({ enricher: null, policy: rulePolicy(protectApp()) });
    const calls = { next: 0 };
    await withServer(expressLike(engine, calls), async (port) => {
      const bait = await send(port, "/.env");
      expect(bait.body).toContain("APP_ENV=production");
      expect(calls.next).toBe(0);
    });
  });

  it("passes through Koa", async () => {
    const engine = new HoneypotEngine({ enricher: null, policy: rulePolicy(observe()) });
    const middleware = koaHoneypot(engine);
    const server = http.createServer((req, res) => {
      const ctx: KoaLikeContext = { req, res };
      void middleware(ctx, async () => {
        res.statusCode = 200;
        res.end(`koa:${await readAll(req)}`);
      }).then(() => {
        if (ctx.respond !== false && !res.writableEnded) {
          res.statusCode = 404;
          res.end();
        }
      });
    });
    await withServer(server, async (port) => expect(await send(port, "/.env", "POST", "x=1")).toMatchObject({ status: 200, body: "koa:x=1" }));
  });

  it("passes through Fastify", async () => {
    const hook = fastifyHoneypot(new HoneypotEngine({ enricher: null, policy: rulePolicy(observe()) }));
    const server = http.createServer((req, res) => {
      let hijacked = false;
      void hook({ raw: req }, { raw: res, hijack: () => void (hijacked = true) }).then(async () => {
        if (hijacked) return;
        res.statusCode = 200;
        res.end(`route:${await readAll(req)}`);
      });
    });
    await withServer(server, async (port) => expect(await send(port, "/.env", "POST", "x=1")).toMatchObject({ status: 200, body: "route:x=1" }));
  });

  it("passes through the Fetch adapter with the body still readable", async () => {
    const original = new Request("http://shop.example/.env", { method: "POST", headers: BROWSER, body: "x=1" });
    const response = await fetchHoneypot(new HoneypotEngine({ enricher: null, policy: rulePolicy(observe()) }))(original, { ip: "203.0.113.40" });
    expect(response).toBeUndefined();
    expect(await original.text()).toBe("x=1");
  });

  it("answers with a plain 404 standalone, where there is no application to pass to", async () => {
    const server = new HoneypotServer({ enricher: null, policy: rulePolicy(observe()) });
    await server.listen(0, "127.0.0.1");
    try {
      const response = await send((server.address() as net.AddressInfo).port, "/.env");
      expect(response).toMatchObject({ status: 404, body: "Not Found" });
    } finally {
      await server.close();
    }
  });

  it("lets the form guard pass a trapped form when the policy says so", async () => {
    const engine = new HoneypotEngine({ enricher: null, policy: rulePolicy(observe()) });
    const guard = trapFormGuard(engine);
    let continued = 0;
    const req = Object.assign(new http.IncomingMessage(null as unknown as net.Socket), {
      method: "POST",
      url: "/signup",
      headers: { ...BROWSER },
      socket: { remoteAddress: "203.0.113.41" },
      body: { website: "http://spam.example" },
    });
    const res = new http.ServerResponse(req);
    await guard(req, res, () => void continued++);
    expect(continued).toBe(1);
  });
});

describe("ignorePaths", () => {
  // Adapted from bothandlerjs: a `g` or `y` regex resumes from lastIndex, so the rule that
  // decides whether detection runs at all would ignore every second request.
  it("keeps a global ignorePaths regex from matching only every other time", () => {
    const engine = new HoneypotEngine({ enricher: null, ignorePaths: [/\.png$/g] });
    for (let i = 0; i < 4; i++) expect(engine.isIgnoredPath("/assets/logo.png"), `call ${i + 1}`).toBe(true);
    expect(engine.isIgnoredPath("/assets/logo.svg")).toBe(false);
  });

  it("reads a trailing slash as the difference between a path and a subtree", () => {
    const exact = new HoneypotEngine({ enricher: null, ignorePaths: ["/healthz"] });
    expect(exact.isIgnoredPath("/healthz")).toBe(true);
    expect(exact.isIgnoredPath("/healthz/live"), "an exact entry is not a prefix").toBe(false);
    expect(exact.isIgnoredPath("/healthzzz")).toBe(false);
    const subtree = new HoneypotEngine({ enricher: null, ignorePaths: ["/assets/"] });
    expect(subtree.isIgnoredPath("/assets/app.js")).toBe(true);
    expect(subtree.isIgnoredPath("/assets/img/logo.png")).toBe(true);
    expect(subtree.isIgnoredPath("/assets")).toBe(false);
  });

  it("matches the normalised path, so a traversal cannot borrow an ignored prefix", () => {
    const engine = new HoneypotEngine({ enricher: null, ignorePaths: ["/assets/"] });
    expect(engine.isIgnoredPath("/assets/../.env")).toBe(false);
    expect(engine.isIgnoredPath("/assets/%2e%2e/.env")).toBe(false);
  });

  it("refuses an entry that can never match a path", () => {
    expect(() => new HoneypotEngine({ enricher: null, ignorePaths: ["healthz"] })).toThrow(/does not start with "\/"/);
  });

  it("skips an ignored path in the middleware: no evaluation, no record, counted as a bypass", async () => {
    const store = new MemoryStore();
    const engine = new HoneypotEngine({ enricher: null, store, ignorePaths: ["/wp-login.php"] });
    const calls = { next: 0 };
    await withServer(expressLike(engine, calls), async (port) => {
      expect(await send(port, "/wp-login.php")).toMatchObject({ status: 200, body: "app:/wp-login.php:" });
      // The decoy still works everywhere else.
      expect((await send(port, "/.env")).body).toContain("APP_ENV=production");
    });
    expect(calls.next).toBe(1);
    expect((await store.list()).map((h) => h.path)).toEqual(["/.env"]);
    expect(engine.bypassed.get("ignored-path")).toBe(1);
  });

  it("skips an ignored path in Koa, Fastify and Fetch", async () => {
    const engine = (): HoneypotEngine => new HoneypotEngine({ enricher: null, ignorePaths: ["/.env"] });
    const koa = koaHoneypot(engine());
    let koaNext = 0;
    await koa({ req: Object.assign(new http.IncomingMessage(null as unknown as net.Socket), { method: "GET", url: "/.env", headers: BROWSER, socket: { remoteAddress: "203.0.113.42" } }), res: new http.ServerResponse(new http.IncomingMessage(null as unknown as net.Socket)) }, async () => void koaNext++);
    expect(koaNext).toBe(1);

    let hijacked = false;
    const req = Object.assign(new http.IncomingMessage(null as unknown as net.Socket), { method: "GET", url: "/.env", headers: BROWSER, socket: { remoteAddress: "203.0.113.43" } });
    await fastifyHoneypot(engine())({ raw: req }, { raw: new http.ServerResponse(req), hijack: () => void (hijacked = true) });
    expect(hijacked).toBe(false);

    expect(await fetchHoneypot(engine())(new Request("http://shop.example/.env", { headers: BROWSER }), { ip: "203.0.113.44" })).toBeUndefined();
  });

  it("answers an ignored path standalone as an empty path, without evaluating it", async () => {
    const store = new MemoryStore();
    const server = new HoneypotServer({ enricher: null, store, ignorePaths: ["/.env"] });
    await server.listen(0, "127.0.0.1");
    try {
      expect(await send((server.address() as net.AddressInfo).port, "/.env")).toMatchObject({ status: 404, body: "Not Found" });
    } finally {
      await server.close();
    }
    expect(await store.list()).toHaveLength(0);
  });
});

describe("client IP resolution (adapted from bothandlerjs resolveClientIp)", () => {
  const ip = (config: ConstructorParameters<typeof HoneypotEngine>[0], peer: string | undefined, xff?: string): string =>
    new HoneypotEngine({ enricher: null, ...config }).resolveIp(peer, xff === undefined ? {} : { "x-forwarded-for": xff });

  it("ignores the forwarded header entirely when proxies are not trusted", () => {
    expect(ip({}, "198.51.100.7", "1.2.3.4")).toBe("198.51.100.7");
  });

  it("is not fooled by a client-prepended entry", () => {
    expect(ip({ proxy: { trustProxy: true, hops: 1 } }, "10.0.0.1", "1.1.1.1, 203.0.113.9")).toBe("203.0.113.9");
  });

  it("walks past every trusted proxy and stops at the first address that is not ours", () => {
    expect(ip({ proxy: { trustProxy: true, trustedProxies: ["10.0.0.0/8"] } }, "10.0.0.1", "1.1.1.1, 203.0.113.9, 10.0.0.5, 10.0.0.6")).toBe("203.0.113.9");
  });

  it("falls back to the socket address when the whole chain is our own infrastructure", () => {
    expect(ip({ proxy: { trustProxy: true, trustedProxies: ["10.0.0.0/8"] } }, "10.0.0.1", "10.0.0.5, 10.0.0.6")).toBe("10.0.0.1");
  });

  it("discards junk entries in the chain", () => {
    expect(ip({ proxy: { trustProxy: true, hops: 1 } }, "10.0.0.1", "not-an-ip, <script>, 203.0.113.9")).toBe("203.0.113.9");
  });

  it("strips a port from an entry rather than discarding the chain", () => {
    expect(ip({ proxy: { trustProxy: true, trustedProxies: ["10.0.0.0/8"] } }, "10.0.0.1", "203.0.113.9:51234, [2001:db8::7]:443")).toBe("2001:db8::7");
  });

  it("normalises the address it returns", () => {
    expect(ip({}, "::ffff:203.0.113.9")).toBe("203.0.113.9");
  });

  it("uses the socket address when the chain is shorter than the hops it expects", () => {
    expect(ip({ proxy: { trustProxy: true, hops: 2 } }, "10.0.0.1", "203.0.113.9")).toBe("10.0.0.1");
    expect(ip({ proxy: { trustProxy: true, hops: 2 } }, "10.0.0.1", "203.0.113.9, 10.0.0.5")).toBe("203.0.113.9");
  });

  describe("when the connecting peer is not one of our proxies", () => {
    const trusted = { proxy: { trustProxy: true, trustedProxies: ["10.0.0.0/8"] } };

    it("ignores the forwarded header and uses the socket address", () => {
      expect(ip(trusted, "203.0.113.9", "8.8.8.8")).toBe("203.0.113.9");
    });

    it("cannot be talked round with a chain of plausible-looking hops", () => {
      expect(ip(trusted, "203.0.113.9", "8.8.8.8, 10.0.0.5, 10.0.0.6")).toBe("203.0.113.9");
    });

    it("cannot reach an allowlisted address by naming it", () => {
      const engine = new HoneypotEngine({ enricher: null, ...trusted, allowlist: ["192.0.2.10"] });
      const resolved = engine.resolveIp("203.0.113.9", { "x-forwarded-for": "192.0.2.10" });
      expect(engine.isAllowlisted(resolved)).toBe(false);
    });

    it("still reads the header for a peer that is one of ours", () => {
      expect(ip(trusted, "10.0.0.5", "8.8.8.8")).toBe("8.8.8.8");
    });

    it("keeps working on a request that has no peer", () => {
      expect(ip(trusted, undefined, "8.8.8.8")).toBe("8.8.8.8");
    });
  });

  it("keeps the old trustProxy shorthand, read from the right", () => {
    expect(ip({ trustProxy: true }, "10.0.0.1", "1.1.1.1, 203.0.113.9")).toBe("203.0.113.9");
  });

  it("refuses settings that could never select the right hop", () => {
    expect(() => new HoneypotEngine({ proxy: { trustProxy: true, trustedProxies: ["10.0.0.0/8x"] } })).toThrow(/not valid addresses or CIDRs: 10.0.0.0\/8x/);
    expect(() => new HoneypotEngine({ proxy: { trustProxy: true, trustedProxies: [] } })).toThrow(/empty/);
    for (const hops of [1.5, 0, -1, Number.NaN]) {
      expect(() => new HoneypotEngine({ proxy: { trustProxy: true, hops } }), String(hops)).toThrow(/positive integer/);
    }
    expect(() => new HoneypotEngine({ proxy: { trustProxy: true, header: " " } })).toThrow(/empty/);
  });
});

describe("the configuration file", () => {
  const parse = (text: string) => parseConfigText(text, "test.toml");

  it("reads trusted proxies, hops and the header", () => {
    const config = parse(`[server]\ntrust_proxy = true\ntrusted_proxies = ["10.0.0.0/8", "2001:db8::/32"]\nforwarded_header = "X-Real-Chain"\n`);
    expect(config.server).toMatchObject({ trustProxy: true, trustedProxies: ["10.0.0.0/8", "2001:db8::/32"], forwardedHeader: "x-real-chain" });
  });

  it("refuses proxy settings that would do nothing", () => {
    expect(() => parse(`[server]\ntrusted_proxies = ["10.0.0.0/8"]\n`)).toThrow(/trust_proxy is false/);
    expect(() => parse(`[server]\ntrust_proxy = true\ntrusted_proxies = []\n`)).toThrow(/empty/);
    expect(() => parse(`[server]\ntrust_proxy = true\ntrusted_proxies = ["10.0.0.0/33"]\n`)).toThrow(/trusted_proxies/);
    expect(() => parse(`[server]\ntrust_proxy = true\nproxy_hops = 0\n`)).toThrow(/proxy_hops/);
  });

  it("reads ignore paths and refuses one that can never match", () => {
    const config = parse(`[engine]\nignore_paths = ["/healthz", "/assets/"]\nignore_path_patterns = ["\\\\.png$"]\n`);
    expect(config.engine).toMatchObject({ ignorePaths: ["/healthz", "/assets/"], ignorePathPatterns: ["\\.png$"] });
    expect(() => parse(`[engine]\nignore_paths = ["healthz"]\n`)).toThrow(/ignore_paths/);
    expect(() => parse(`[engine]\nignore_path_patterns = ["("]\n`)).toThrow(/ignore_path_patterns/);
  });

  it("accepts pass as a rule's response, and refuses it when switched off", () => {
    const rule = `[[policy.rules]]\nid = "watch"\nrespond_with = "pass"\n`;
    expect(parse(rule).policy.rules[0]).toMatchObject({ respondWith: "pass" });
    expect(() => parse(`${rule}[responses.pass]\nenabled = false\n`)).toThrow(/disabled/);
  });

  it("refuses proxy settings from the environment that would do nothing", () => {
    const config = parse("");
    expect(() => applyEnvOverrides(config, { TRUSTED_PROXIES: "10.0.0.0/8" })).toThrow(/TRUST_PROXY/);
    const on = applyEnvOverrides(parse(""), { TRUST_PROXY: "true", TRUSTED_PROXIES: "10.0.0.0/8, 192.0.2.1", PROXY_HOPS: "2" });
    expect(on.server).toMatchObject({ trustProxy: true, trustedProxies: ["10.0.0.0/8", "192.0.2.1"], proxyHops: 2 });
  });
});
