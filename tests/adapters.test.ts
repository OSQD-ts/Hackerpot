import http from "node:http";
import type net from "node:net";
import { describe, expect, it } from "vitest";
import { fastifyHoneypot } from "../src/adapters/fastify.js";
import { koaHoneypot, type KoaLikeContext } from "../src/adapters/koa.js";
import { HoneypotEngine } from "../src/core.js";

/**
 * The adapters are exercised over real sockets against the contracts Koa and Fastify
 * define: Koa skips writing a response when `ctx.respond` is false, and Fastify stops
 * routing a request whose reply was hijacked in `onRequest`. Neither framework is a
 * dependency of this project, so these servers reproduce just those two rules.
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

function send(port: number, path: string, method = "GET", body?: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path, method, headers: { ...BROWSER, host: "shop.example" } }, (res) => {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", (chunk: string) => (text += chunk));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: text }));
    });
    req.on("error", reject);
    req.end(body);
  });
}

/** Reads the request body, as a route would once the honeypot has passed the request on. */
function readAll(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    req.setEncoding("utf8");
    req.on("data", (chunk: string) => (data += chunk));
    req.on("end", () => resolve(data));
  });
}

describe("koaHoneypot", () => {
  const koaLikeServer = (): http.Server => {
    const middleware = koaHoneypot(new HoneypotEngine({ enricher: null }));
    return http.createServer((req, res) => {
      const ctx: KoaLikeContext = { req, res };
      void middleware(ctx, async () => {
        res.statusCode = 200;
        res.end(`app:${await readAll(req)}`);
      }).then(() => {
        // Koa's own respond(): it writes nothing when a middleware set respond = false.
        if (ctx.respond !== false && !res.writableEnded) {
          res.statusCode = 404;
          res.end();
        }
      });
    });
  };

  it("answers a probe itself and keeps the app out of it", () =>
    withServer(koaLikeServer(), async (port) => {
      const probe = await send(port, "/.env");
      expect(probe.body).toContain("APP_ENV=production");
      expect(probe.body).not.toContain("app:");
    }));

  it("passes ordinary traffic to the app with its body intact", () =>
    withServer(koaLikeServer(), async (port) => {
      const page = await send(port, "/api/orders", "POST", "item=42");
      expect(page).toEqual({ status: 200, body: "app:item=42" });
    }));
});

describe("fastifyHoneypot", () => {
  const fastifyLikeServer = (): http.Server => {
    const hook = fastifyHoneypot(new HoneypotEngine({ enricher: null }));
    return http.createServer((req, res) => {
      let hijacked = false;
      void hook({ raw: req }, { raw: res, hijack: () => void (hijacked = true) }).then(async () => {
        // Fastify's own routing: a hijacked reply is left alone.
        if (hijacked) return;
        res.statusCode = 200;
        res.end(`route:${await readAll(req)}`);
      });
    });
  };

  it("answers a probe itself and hijacks the reply", () =>
    withServer(fastifyLikeServer(), async (port) => {
      const probe = await send(port, "/.env");
      expect(probe.body).toContain("APP_ENV=production");
      expect(probe.body).not.toContain("route:");
    }));

  it("leaves the body unread for a request it passes on", () =>
    withServer(fastifyLikeServer(), async (port) => {
      const page = await send(port, "/api/orders", "POST", "item=42");
      expect(page).toEqual({ status: 200, body: "route:item=42" });
    }));
});
