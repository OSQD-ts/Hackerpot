import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import { startDashboard } from "../src/dashboard/index.js";
import type { DashboardServer } from "../src/dashboard/index.js";
import { cleanSavedFilter } from "../src/dashboard/saved-filters.js";

/** The chips this dashboard draws, as its server passes them in. */
const CHIPS: ReadonlySet<string> = new Set(["all", "decoy", "time cost", "block", "protocol capture", "silent 404"]);

/**
 * Saved filters, kept by the dashboard the way bothandlerjs's keeps them: there after a reload,
 * in another browser, inside an embedding page, and across a restart when a file is given.
 */

const dir = mkdtempSync(join(tmpdir(), "hackerpot-filters-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

async function started(options: Parameters<typeof startDashboard>[1] = {}): Promise<DashboardServer> {
  const server = await startDashboard(new HoneypotEngine({ enricher: null }), { port: 0, ...options });
  cleanups.push(() => server.close());
  return server;
}

const post = (server: DashboardServer, body: unknown): Promise<Response> =>
  fetch(`${server.url}api/filters`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

const list = async (server: DashboardServer): Promise<unknown> => ((await (await fetch(`${server.url}api/filters`)).json()) as { filters: unknown }).filters;

describe("saved filters", () => {
  it("saves, replaces by name newest first, and deletes", async () => {
    const server = await started();
    expect(await list(server)).toEqual([]);
    await post(server, { name: "blocks", query: "", filter: "block" });
    await post(server, { name: "scanners", query: "detector:scanner-signature", filter: "all" });
    await post(server, { name: "blocks", query: "ip:198.51.100.7", filter: "block" });
    expect(await list(server)).toEqual([
      { name: "blocks", query: "ip:198.51.100.7", filter: "block" },
      { name: "scanners", query: "detector:scanner-signature", filter: "all" },
    ]);
    const response = await post(server, { action: "delete", name: "blocks" });
    expect(response.status).toBe(200);
    expect(await list(server)).toEqual([{ name: "scanners", query: "detector:scanner-signature", filter: "all" }]);
  });

  it("keeps them across a restart when a file is given", async () => {
    const file = join(dir, "filters.json");
    const first = await started({ savedFilters: { file } });
    await post(first, { name: "decoys", query: "", filter: "decoy" });
    expect(JSON.parse(readFileSync(file, "utf8"))).toEqual([{ name: "decoys", query: "", filter: "decoy" }]);
    const second = await started({ savedFilters: { file } });
    expect(await list(second)).toEqual([{ name: "decoys", query: "", filter: "decoy" }]);
  });

  it("refuses what is not a filter, and cleans what it keeps", async () => {
    const server = await started();
    expect((await post(server, { query: "no name" })).status).toBe(400);
    expect(cleanSavedFilter({ name: `  ${"x".repeat(200)}`, query: "q", filter: "not-a-chip" }, CHIPS)).toEqual({ name: "x".repeat(60), query: "q", filter: "all" });
    expect(cleanSavedFilter({ name: `a${String.fromCharCode(7)}b`, query: "", filter: "time cost" }, CHIPS)).toEqual({ name: "a b", query: "", filter: "time cost" });
  });

  it("goes with the Incidents screen", async () => {
    const server = await started({ sections: { incidents: false } });
    expect((await fetch(`${server.url}api/filters`)).status).toBe(404);
  });
});
