import { afterEach, describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import { MemoryStore } from "../src/stores/index.js";
import { startDashboard, storeSource } from "../src/dashboard/index.js";
import type { DashboardServer } from "../src/dashboard/index.js";

/**
 * What the honeypot has said about itself.
 *
 * The engine has always kept this history; nothing showed it, so the only way to learn that a
 * rule was swapped — or that an allowlist entry matches nothing — was to have been watching the
 * log at the moment it happened.
 */

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

async function started(source: Parameters<typeof startDashboard>[0]): Promise<DashboardServer> {
  const server = await startDashboard(source, { port: 0 });
  cleanups.push(() => server.close());
  return server;
}

const noticesFrom = async (server: DashboardServer): Promise<Response> => fetch(`${server.url}api/notices`);

describe("the notices a dashboard can show", () => {
  it("serves what the engine has said, with the attribution it recorded", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    // A setting that would quietly do nothing, and a change somebody made.
    engine.reconfigure({ allowlist: ["10.0.0.0/8x"] });
    engine.reconfigure({ shadowDetectors: ["rate-spike"] }, { by: "ada@example.com" });

    const response = await noticesFrom(await started(engine));
    expect(response.status).toBe(200);

    const { notices } = (await response.json()) as { notices: Array<{ message: string; change?: { part: string; by?: string } }> };
    expect(notices.some((notice) => notice.message.includes("match nothing"))).toBe(true);
    const attributed = notices.find((notice) => notice.change?.part === "shadow-detectors");
    expect(attributed?.change?.by).toBe("ada@example.com");
    expect(attributed?.message).toContain("ada@example.com");
  });

  it("says there is no engine here rather than showing an empty panel", async () => {
    // A dashboard reading recorded incidents from somewhere else. "No notices" and "no engine
    // to ask" must not look the same: one is silence, the other is a different deployment.
    const source = storeSource({ store: new MemoryStore(), subscribe: () => () => undefined });
    const response = await noticesFrom(await started(source));

    expect(response.status).toBe(404);
    expect(((await response.json()) as { error: string }).error).toMatch(/no engine here/);
  });

  it("is withheld with the section it belongs to", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    const server = await startDashboard(engine, { port: 0, sections: { overview: false } });
    cleanups.push(() => server.close());

    const response = await noticesFrom(server);
    expect(response.status).toBe(404);
    expect(((await response.json()) as { error: string }).error).toMatch(/overview section is switched off/);
  });
});
