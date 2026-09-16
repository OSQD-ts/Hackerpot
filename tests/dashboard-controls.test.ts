import { afterEach, describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import { startDashboard } from "../src/dashboard/index.js";
import type { DashboardServer } from "../src/dashboard/index.js";
import type { RequestFacts } from "../src/detectors/types.js";

/**
 * The controls: what a viewer may *do*. Two properties matter more than the plumbing — a
 * control nobody granted does not exist, and the one that only *reads* the engine leaves no
 * trace of having been used.
 */

const TOKEN = "dashboard-token-0123456789";

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

async function started(engine: HoneypotEngine, options: Parameters<typeof startDashboard>[1] = {}): Promise<DashboardServer> {
  const server = await startDashboard(engine, { port: 0, ...options });
  cleanups.push(() => server.close());
  return server;
}

const probe = (ip = "203.0.113.40"): RequestFacts => ({
  method: "GET",
  path: "/.env",
  query: {},
  headers: { host: "shop.example", "user-agent": "curl/8.4.0" },
  ip,
});

const post = (server: DashboardServer, path: string, body: unknown, token?: string): Promise<Response> =>
  fetch(`${server.url}api/${path}${token === undefined ? "" : `?token=${token}`}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

describe("a control nobody granted", () => {
  it("does not exist, and the dashboard still refuses every other POST", async () => {
    const server = await started(new HoneypotEngine({ enricher: null }));

    for (const path of ["test", "policy/preview", "policy/apply"]) {
      const response = await post(server, path, { rules: [] });
      expect(response.status).toBe(404);
      // 404 rather than 403: saying "forbidden" would tell a caller there is something here.
      expect(((await response.json()) as { error: string }).error).toMatch(/control is switched off/);
    }

    const other = await post(server, "stats", {});
    expect(other.status).toBe(405);
    expect(((await other.json()) as { error: string }).error).toMatch(/read-only/);
  });

  it("refuses to hand the policy to whoever can open an unauthenticated page", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    await expect(startDashboard(engine, { port: 0, auth: false, controls: { editPolicy: true } })).rejects.toThrow(/needs authentication/);
  });
});

describe("trying a request", () => {
  it("answers what would have happened, and records none of it", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    const server = await started(engine, { controls: { testRequest: true } });

    const response = await post(server, "test", { text: "curl https://shop.example/.env" });
    expect(response.status).toBe(200);
    const result = (await response.json()) as { request: { ip: string }; detections: Array<{ detectorId: string }>; actionId: string; rule?: string };
    expect(result.detections.map((detection) => detection.detectorId)).toContain("decoy-path");
    expect(result.actionId).not.toBe("");

    // The whole point of a dry run: reproducing a complaint must not change what is being
    // investigated. Nothing is recorded, and the request is counted toward nobody's history.
    expect(engine.store.list()).toHaveLength(0);
    // A tracker exists for the address because every detector is handed one, but it holds no
    // events — so no window, threshold or score has moved for whoever that address belongs to.
    expect(engine.registry.for(result.request.ip).recent()).toHaveLength(0);
  });

  it("says what it could not read rather than guessing", async () => {
    const server = await started(new HoneypotEngine({ enricher: null }), { controls: { testRequest: true } });

    expect((await post(server, "test", "not json at all")).status).toBe(400);
    const empty = await post(server, "test", {});
    expect(empty.status).toBe(400);
    expect(((await empty.json()) as { error: string }).error).toMatch(/nothing to explain/);
  });
});

describe("previewing and applying a policy", () => {
  const RULES = [{ id: "everything", respondWith: "tarpit", reason: "Trying a stricter answer.", match: {} }];

  it("says what would change, and changes nothing", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    await engine.evaluate(probe());
    const server = await started(engine, { controls: { previewPolicy: true } });

    const response = await post(server, "policy/preview", { rules: RULES });
    expect(response.status).toBe(200);
    const preview = (await response.json()) as { total: number; changed: Array<{ was: string; now: string; rule: string }> };
    expect(preview.total).toBe(1);
    expect(preview.changed[0]).toMatchObject({ now: "tarpit", rule: "everything" });

    // The running policy is untouched until somebody applies it.
    const after = await engine.evaluate(probe("203.0.113.41"));
    expect(after.actionId).not.toBe("tarpit");
  });

  it("refuses a draft it would have to guess about", async () => {
    const server = await started(new HoneypotEngine({ enricher: null }), { controls: { previewPolicy: true } });
    const response = await post(server, "policy/preview", { rules: [{ respondWith: "tarpit" }] });
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: string }).error).toMatch(/id must be a non-empty string/);
  });

  it("replaces the running policy, attributed to whoever asked", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    const server = await started(engine, { auth: { token: TOKEN }, controls: { editPolicy: true } });

    const response = await post(server, "policy/apply", { rules: RULES }, TOKEN);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ applied: 1, by: "dashboard" });

    // The next request is answered by the rules that were just applied.
    const after = await engine.evaluate(probe());
    expect(after).toMatchObject({ actionId: "tarpit", rule: "everything" });
  });

  it("will not let an unauthenticated caller apply anything", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    const server = await started(engine, { auth: { token: TOKEN }, controls: { editPolicy: true } });

    // No token: refused before the control is even considered.
    expect((await post(server, "policy/apply", { rules: RULES })).status).toBe(401);
    const after = await engine.evaluate(probe());
    expect(after.actionId).not.toBe("tarpit");
  });
});
