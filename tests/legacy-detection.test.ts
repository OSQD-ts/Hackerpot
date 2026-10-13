import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import { upgradeDetection, upgradeHit } from "../src/detectors/legacy.js";
import type { Detector } from "../src/detectors/types.js";
import { isIncident, upgradeIncident } from "../src/dashboard/client/query.js";
import { FileStore } from "../src/stores/file.js";
import type { HoneypotHit } from "../src/types.js";

/**
 * Detections are shaped `{ detector, summary }`, bothandlerjs's names, where they were
 * `{ detectorId, reason }`. The rename is only safe if what was already written keeps working:
 * a detector somebody wrote against the old names, a store full of hits recorded before it, and
 * a dashboard reading an older honeypot. Each is pinned here.
 */

const dir = mkdtempSync(join(tmpdir(), "hackerpot-legacy-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const oldHit = {
  id: "old-1",
  timestamp: "2026-01-01T00:00:00.000Z",
  ip: "203.0.113.9",
  method: "GET",
  path: "/.env",
  headers: {},
  detections: [{ detectorId: "decoy-path", reason: "Exposed .env probe", score: 10 }],
  shadowDetections: [{ detectorId: "path-novelty", reason: "unseen path", score: 3 }],
  score: 10,
  totalScore: 10,
  respondedWith: "decoy-content",
};

describe("detections in the shape they had before the rename", () => {
  it("are upgraded from a detector that still returns detectorId and reason", async () => {
    // Cast, because the old shape no longer type-checks: what is pinned is that it still runs.
    const legacy = { id: "legacy", inspect: (ctx: { path: string }) => (ctx.path === "/old" ? { detectorId: "legacy", reason: "written long ago", score: 7 } : undefined) } as unknown as Detector;
    const engine = new HoneypotEngine({ enricher: null, detectors: [legacy] });
    const result = await engine.evaluate({ method: "GET", path: "/old", query: {}, headers: {}, ip: "203.0.113.9" });
    expect(result.detections).toEqual([{ detector: "legacy", summary: "written long ago", score: 7 }]);
  });

  it("are upgraded when a file store reads hits recorded before it", async () => {
    const path = join(dir, "hits.jsonl");
    writeFileSync(path, `${JSON.stringify(oldHit)}\n`);
    const store = new FileStore({ path });
    const [hit] = await store.list();
    expect(hit?.detections).toEqual([{ detector: "decoy-path", summary: "Exposed .env probe", score: 10 }]);
    expect(hit?.shadowDetections).toEqual([{ detector: "path-novelty", summary: "unseen path", score: 3 }]);
    expect(await store.query?.({ detector: "decoy-path" })).toHaveLength(1);
  });

  it("are left alone, the same object, when already current", () => {
    const current = { detector: "trap", summary: "hidden link", score: 15, certain: true };
    expect(upgradeDetection(current)).toBe(current);
    const hit = { ...oldHit, detections: [current], shadowDetections: [] } as unknown as HoneypotHit;
    expect(upgradeHit(hit)).toBe(hit);
  });

  it("are upgraded by a dashboard page reading an older server", () => {
    expect(isIncident(oldHit)).toBe(false);
    const upgraded = upgradeIncident(oldHit);
    expect(isIncident(upgraded)).toBe(true);
    expect((upgraded as { detections: unknown[] }).detections).toEqual([{ detector: "decoy-path", summary: "Exposed .env probe", score: 10 }]);
  });
});
