import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildResponseActions } from "../src/config/build.js";
import { parseConfig } from "../src/config/schema.js";
import { checkResponseActions, type ResponseAction } from "../src/responses/index.js";

describe("checkResponseActions", () => {
  it("reports every default action, in order, and fails none", async () => {
    const actions = buildResponseActions(parseConfig({}, "<defaults>"));
    const results = await checkResponseActions(actions, { budgetMs: 400 });
    expect(results.map((result) => result.id)).toEqual(actions.map((action) => action.id));
    expect(results.filter((result) => result.outcome === "failed")).toEqual([]);
    // Delaying for seconds is tarpit's job, so it is held, not failed.
    expect(results.find((result) => result.id === "tarpit")?.outcome).toBe("held");
  }, 30_000);

  it("fails an action that throws, and one that rejects after a delay", async () => {
    const throws: ResponseAction = {
      id: "throws",
      execute() {
        throw new Error("boom");
      },
    };
    const rejects: ResponseAction = {
      id: "rejects",
      async execute() {
        await new Promise((resolve) => setTimeout(resolve, 10));
        throw new Error("late boom");
      },
    };
    const [first, second] = await checkResponseActions([throws, rejects], { budgetMs: 1_000 });
    expect(first).toMatchObject({ id: "throws", outcome: "failed", error: "boom" });
    expect(second).toMatchObject({ id: "rejects", outcome: "failed", error: "late boom" });
  });

  // `chaos` answers 5xx on purpose, so a status alone must not fail an action.
  it("does not fail an action that answers 5xx deliberately", async () => {
    const outage: ResponseAction = {
      id: "outage",
      execute(ctx) {
        ctx.res.statusCode = 503;
        ctx.res.end();
      },
    };
    expect((await checkResponseActions([outage]))[0]).toMatchObject({ outcome: "ok", status: 503 });
  });

  it("fails an action that reports a failed side effect", async () => {
    const reports: ResponseAction = {
      id: "reports",
      execute(ctx) {
        ctx.onError?.(new Error("backend down"), { source: "blocklist" });
        ctx.res.end();
      },
    };
    expect((await checkResponseActions([reports]))[0]).toMatchObject({ outcome: "failed", error: "backend down" });
  });
});

describe("hackerpot --check", () => {
  it("serves every configured action and exits 0 on a sound config", () => {
    const dir = mkdtempSync(join(tmpdir(), "hackerpot-check-"));
    const configPath = join(dir, "hackerpot.toml");
    writeFileSync(configPath, "");
    const out = execFileSync(process.execPath, ["--import", "tsx", "src/standalone.ts", "--check", "--config", configPath], {
      encoding: "utf8",
      timeout: 60_000,
    });
    expect(out).toMatch(/^held\s+tarpit/m);
    expect(out).toMatch(/all \d+ response actions answered/);
  }, 90_000);
});
