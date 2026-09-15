import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import { DEFAULT_TRAP_PATHS, renderTrapField, renderTrapLink, trapDetector, trapRobotsEntries } from "../src/detectors/index.js";
import type { RequestFacts } from "../src/detectors/types.js";
import { createMiddleware, trapFormGuard } from "../src/middleware.js";
import { generateRobotsTxt } from "../src/robots.js";

const facts = (extra: Partial<RequestFacts> = {}): RequestFacts => ({ method: "GET", path: "/", query: {}, headers: { host: "shop.example" }, ip: "198.51.100.20", ...extra });
const engineWith = (options: Parameters<typeof trapDetector>[0] = {}) => new HoneypotEngine({ enricher: null, detectors: [trapDetector(options)], policy: () => "not-found" });

describe("trapDetector", () => {
  it("treats a request for a trap path as proof", async () => {
    const result = await engineWith().evaluate(facts({ path: DEFAULT_TRAP_PATHS[0]! }));
    expect(result.detections[0]).toMatchObject({ detectorId: "trap", certain: true, score: 15 });
  });

  it("matches a trailing-slash entry as a prefix and everything else exactly", async () => {
    const engine = engineWith({ paths: ["/bait/", "/exact"] });
    expect((await engine.evaluate(facts({ path: "/bait/anything" }))).detections).toHaveLength(1);
    expect((await engine.evaluate(facts({ path: "/exact/more", ip: "198.51.100.21" }))).detections).toHaveLength(0);
  });

  it("reads a filled hidden field from the query, a form body, a JSON body and parsed fields", async () => {
    const engine = engineWith({ formFields: ["website"] });
    expect((await engine.evaluate(facts({ query: { website: "spam.example" } }))).detections[0]?.metadata).toMatchObject({ source: "query" });
    expect((await engine.evaluate(facts({ method: "POST", body: "name=a&website=x" }))).detections[0]?.metadata).toMatchObject({ source: "body" });
    expect((await engine.evaluate(facts({ method: "POST", body: '{"website":"x"}' }))).detections[0]?.metadata).toMatchObject({ source: "body" });
    expect((await engine.evaluate(facts({ method: "POST", formFields: { website: "x" } }))).detections[0]?.metadata).toMatchObject({ source: "form" });
  });

  it("ignores an empty field and a value that is not a string", async () => {
    const engine = engineWith({ formFields: ["website"] });
    expect((await engine.evaluate(facts({ query: { website: "" } }))).detections).toHaveLength(0);
    expect((await engine.evaluate(facts({ formFields: { website: { nested: "x" } } }))).detections).toHaveLength(0);
  });

  it("fires on the trap header", async () => {
    const result = await engineWith({ headerName: "X-Trap" }).evaluate(facts({ headers: { host: "shop.example", "x-trap": "1" } }));
    expect(result.detections[0]?.metadata).toMatchObject({ trap: "header" });
  });

  it("refuses a trap path that could never match", () => {
    expect(() => trapDetector({ paths: ["internal/export.csv"] })).toThrow(/begin with "\/"/);
  });
});

describe("trap rendering", () => {
  it("hides the link from layout, the tab order and assistive technology, and escapes it", () => {
    const html = renderTrapLink('/x"><script>', "<b>");
    expect(html).toContain('aria-hidden="true"');
    expect(html).toContain('tabindex="-1"');
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<b>");
    expect(() => renderTrapLink("javascript:alert(1)")).toThrow();
  });

  it("renders a hidden, unfocusable field", () => {
    const html = renderTrapField("website");
    expect(html).toContain('name="website"');
    expect(html).toContain('tabindex="-1"');
    expect(html).toContain('autocomplete="off"');
  });

  it("disallows trap paths in robots.txt", () => {
    expect(trapRobotsEntries(["/a", "/b"])).toBe("User-agent: *\nDisallow: /a\nDisallow: /b");
    expect(generateRobotsTxt({ trapPaths: ["/internal/export.csv"] })).toContain("Disallow: /internal/export.csv");
  });
});

describe("trapFormGuard", () => {
  let server: http.Server | undefined;
  afterEach(() => new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve())));

  /** A tiny app: honeypot middleware, a urlencoded body parser, the guard, then the real handler. */
  async function start(engine: HoneypotEngine): Promise<string> {
    const middleware = createMiddleware(engine);
    const guard = trapFormGuard(engine);
    server = http.createServer((req, res) => {
      void middleware(req, res, () => {
        const chunks: Buffer[] = [];
        req.on("data", (chunk: Buffer) => chunks.push(chunk));
        req.on("end", () => {
          (req as http.IncomingMessage & { body?: unknown }).body = Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString()));
          void guard(req, res, () => {
            res.statusCode = 201;
            res.end("signed up");
          });
        });
      });
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    return `http://127.0.0.1:${(server!.address() as AddressInfo).port}/signup`;
  }

  const post = (url: string, body: string) =>
    fetch(url, { method: "POST", body, headers: { "content-type": "application/x-www-form-urlencoded", "user-agent": "Mozilla/5.0 Chrome/122", accept: "text/html", "accept-language": "en", "accept-encoding": "gzip" } });

  it("lets a person who left the field empty through, and answers a bot that filled it", async () => {
    const hits: string[] = [];
    const engine = new HoneypotEngine({ enricher: null, detectors: [trapDetector({ formFields: ["website"] })], policy: () => "not-found", onHit: (hit) => void hits.push(hit.detections[0]!.detectorId) });
    const url = await start(engine);
    const person = await post(url, "email=a%40example.com&website=");
    expect(person.status).toBe(201);
    const bot = await post(url, "email=b%40example.com&website=http%3A%2F%2Fspam.example");
    expect(bot.status).toBe(404);
    expect(hits).toEqual(["trap"]);
  });
});
