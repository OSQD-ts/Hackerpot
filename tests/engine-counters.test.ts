import http from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import { renderMetrics, IncidentCounters } from "../src/management/metrics.js";
import { createMiddleware, trapFormGuard } from "../src/adapters/node.js";
import type { RequestFacts } from "../src/detectors/types.js";
import { DEFAULT_SERVICE_TOKEN_HEADER } from "../src/service-tokens.js";
import { Histogram } from "../src/internal/histogram.js";

/**
 * What the engine counts that no incident carries.
 *
 * An exemption is a control, and a control nobody can observe cannot be audited. The two
 * properties worth pinning are that each exemption is counted exactly once — the front end and a
 * second pass over the same request must not both count it — and that work which is not traffic
 * (the dashboard's dry run) is neither counted nor timed.
 */

const TOKEN = "service-token-long-enough-to-matter";

const probe = (ip = "203.0.113.40", headers: Record<string, string> = {}): RequestFacts => ({
  method: "GET",
  path: "/.env",
  query: {},
  headers: { host: "shop.example", "user-agent": "curl/8.4.0", ...headers },
  ip,
});

const servers: http.Server[] = [];
afterEach(async () => {
  while (servers.length > 0) await new Promise<void>((resolve) => servers.pop()?.close(() => resolve()));
});

async function serve(handler: http.RequestListener): Promise<string> {
  const server = http.createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as { port: number };
  return `http://127.0.0.1:${address.port}`;
}

describe("exemptions", () => {
  it("counts each reason at the front end that decides it", () => {
    const engine = new HoneypotEngine({ enricher: null, allowlist: ["198.51.100.0/24"], serviceTokens: { tokens: { monitor: TOKEN } } });

    expect(engine.exempt("198.51.100.7", {})).toBe("allowlist");
    expect(engine.exempt("203.0.113.1", { [DEFAULT_SERVICE_TOKEN_HEADER]: TOKEN })).toBe("service-token");
    expect(engine.exempt("203.0.113.1", {})).toBeUndefined();

    expect(Object.fromEntries(engine.bypassed)).toEqual({ allowlist: 1, "service-token": 1, "ignored-path": 0 });
  });

  it("leaves the pure predicates pure, because they are asked more than once per request", () => {
    const engine = new HoneypotEngine({ enricher: null, allowlist: ["198.51.100.0/24"] });
    for (let i = 0; i < 5; i += 1) expect(engine.isAllowlisted("198.51.100.7")).toBe(true);
    expect(engine.bypassed.get("allowlist")).toBe(0);
  });

  it("starts every reason at zero, so a scrape has a series to watch from the first request", () => {
    expect(Object.fromEntries(new HoneypotEngine({ enricher: null }).bypassed)).toEqual({ allowlist: 0, "service-token": 0, "ignored-path": 0 });
  });

  it("counts an exemption reached by evaluating directly, but not in a dry run", async () => {
    const engine = new HoneypotEngine({ enricher: null, allowlist: ["198.51.100.0/24"] });
    await engine.evaluate(probe("198.51.100.7"));
    // The dashboard's tester passes `audit: false`: a request somebody pasted is not traffic.
    await engine.evaluate(probe("198.51.100.8"), { recordHit: false, trackActivity: false, audit: false });
    expect(engine.bypassed.get("allowlist")).toBe(1);
  });

  it("is counted once through the middleware, and not again by the form guard behind it", async () => {
    const engine = new HoneypotEngine({ enricher: null, allowlist: ["127.0.0.1"] });
    const middleware = createMiddleware(engine);
    const guard = trapFormGuard(engine);
    const url = await serve((req, res) => {
      void middleware(req, res, () => {
        // The form guard sits on the route, after a body parser; it re-checks the same request.
        (req as http.IncomingMessage & { body?: unknown }).body = { email: "ada@example.com" };
        void guard(req, res, () => {
          res.end("app");
        });
      });
    });

    const response = await fetch(`${url}/signup`, { method: "POST" });
    expect(await response.text()).toBe("app");
    expect(engine.bypassed.get("allowlist")).toBe(1);
  });
});

describe("time spent evaluating", () => {
  it("is timed for requests that ran detection", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    await engine.evaluate(probe());
    await engine.evaluate(probe("203.0.113.41"));
    expect(engine.counters().evaluationDuration.count).toBe(2);
  });

  it("is not timed for an exempt request, which ran no detection", async () => {
    const engine = new HoneypotEngine({ enricher: null, allowlist: ["198.51.100.0/24"] });
    await engine.evaluate(probe("198.51.100.7"));
    expect(engine.counters().evaluationDuration.count).toBe(0);
  });

  it("is not timed for work that is not traffic", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    await engine.evaluate(probe(), { recordHit: false, trackActivity: false, audit: false });
    expect(engine.counters().evaluationDuration.count).toBe(0);
  });
});

describe("in the exposition", () => {
  it("renders exemptions and evaluation time from the management counters", async () => {
    const engine = new HoneypotEngine({ enricher: null, allowlist: ["198.51.100.0/24"] });
    engine.exempt("198.51.100.7", {});
    await engine.evaluate(probe());

    const text = new IncidentCounters().render(undefined, undefined, undefined, engine.counters());
    expect(text).toContain('hackerpot_bypassed_total{reason="allowlist"} 1');
    expect(text).toContain('hackerpot_bypassed_total{reason="service-token"} 0');
    expect(text).toContain("# TYPE hackerpot_evaluation_duration_ms histogram");
    expect(text).toContain('hackerpot_evaluation_duration_ms_bucket{le="+Inf"} 1');
    expect(text).toContain("hackerpot_evaluation_duration_ms_count 1");
  });

  it("reaches an in-process dashboard too, which used to drop detector failures", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    engine.detectorFailures.set("slow-detector", 2);
    const text = await renderMetrics(engine.store, undefined, engine.counters());
    expect(text).toContain('hackerpot_detector_failures_total{detector="slow-detector"} 2');
    expect(text).toContain("hackerpot_bypassed_total");
  });

  it("leaves the store-only path as it was when no engine is given", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    const text = await renderMetrics(engine.store);
    expect(text).not.toContain("hackerpot_bypassed_total");
    expect(text).not.toContain("hackerpot_evaluation_duration_ms");
  });
});

describe("the shared histogram", () => {
  it("is cumulative, puts overflow past the last bound, and ignores what is not a number", () => {
    const histogram = new Histogram([1, 10]);
    for (const value of [0.5, 1, 5, 50, Number.NaN]) histogram.observe(value);
    const snapshot = histogram.snapshot();
    // NaN is observed as 0, so it lands in the first bucket rather than corrupting the sum.
    expect(snapshot.buckets).toEqual([3, 4, 5]);
    expect(snapshot).toMatchObject({ count: 5, total: 56.5, max: 50 });
  });
});
