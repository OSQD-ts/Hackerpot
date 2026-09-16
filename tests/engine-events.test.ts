import { describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import type { ChangeEvent, Notice } from "../src/core.js";
import type { Detector, RequestFacts } from "../src/detectors/types.js";
import { ManualClock } from "../src/internal/clock.js";

/**
 * What the engine announces, and the rule that makes it safe to announce anything: a
 * listener is somebody else's code, so one that throws may break only itself.
 */

const probe = (ip = "203.0.113.40"): RequestFacts => ({
  method: "GET",
  path: "/.env",
  query: {},
  headers: { host: "shop.example", "user-agent": "curl/8.4.0" },
  ip,
});

describe("engine events", () => {
  it("announces a hit to every listener, and unsubscribes on demand", async () => {
    const engine = new HoneypotEngine({ enricher: null });
    const first: string[] = [];
    const second: string[] = [];
    const stop = engine.on("hit", (hit) => first.push(hit.path));
    engine.subscribe((hit) => second.push(hit.path));

    await engine.evaluate(probe());
    stop();
    await engine.evaluate(probe("203.0.113.41"));

    expect(first).toEqual(["/.env"]);
    expect(second).toEqual(["/.env", "/.env"]);
  });

  it("isolates a listener that throws, and one that rejects", async () => {
    const errors: string[] = [];
    const engine = new HoneypotEngine({ enricher: null, onError: (_error, context) => void errors.push(context.source) });
    const heard: string[] = [];
    engine.on("hit", () => {
      throw new Error("subscriber is broken");
    });
    engine.on("hit", async () => {
      await Promise.reject(new Error("and this one rejects"));
    });
    engine.on("hit", (hit) => heard.push(hit.ip));

    // The request itself must be unaffected: the detections are still returned.
    const result = await engine.evaluate(probe());
    expect(result.detections.map((detection) => detection.detectorId)).toContain("decoy-path");
    // Listeners registered after the broken one still heard it.
    expect(heard).toEqual(["203.0.113.40"]);
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(errors.filter((source) => source === "listener:hit")).toHaveLength(2);
  });

  it("announces shadowed findings and isolated errors", async () => {
    const broken: Detector = {
      id: "broken",
      inspect: () => {
        throw new Error("crafted input");
      },
    };
    const engine = new HoneypotEngine({ enricher: null, extraDetectors: [broken], shadowDetectors: ["decoy-path"] });
    const shadows: string[] = [];
    const errors: string[] = [];
    engine.on("shadow", (event) => shadows.push(event.path));
    engine.on("error", (event) => errors.push(event.source));

    await engine.evaluate(probe());
    expect(shadows).toEqual(["/.env"]);
    // The detector that threw was isolated and reported, not swallowed.
    expect(errors).toContain("broken");
  });
});

describe("runtime changes", () => {
  it("reports what changed, with who changed it", () => {
    const engine = new HoneypotEngine({ enricher: null });
    const changes: ChangeEvent[] = [];
    const notices: Notice[] = [];
    engine.on("change", (change) => changes.push(change));
    engine.on("warning", (notice) => notices.push(notice));

    const reported = engine.reconfigure({ allowlist: ["10.0.0.0/8"], shadowDetectors: ["rate-spike"] }, { by: "ada@example.com" });

    expect(reported.map((change) => change.part)).toEqual(["allowlist", "shadow-detectors"]);
    expect(changes).toEqual(reported);
    expect(changes.every((change) => change.by === "ada@example.com")).toBe(true);
    expect(notices.map((notice) => notice.message)).toEqual([
      "allowlist replaced: 1 entry (by ada@example.com)",
      "shadowed: rate-spike (by ada@example.com)",
    ]);
    expect(engine.isAllowlisted("10.1.2.3")).toBe(true);
  });

  it("says nothing when nothing was passed, and warns about settings that would do nothing", () => {
    const engine = new HoneypotEngine({ enricher: null });
    expect(engine.reconfigure({})).toEqual([]);

    // An allowlist entry that cannot be matched exempts nobody, and the symptom is silence.
    engine.reconfigure({ allowlist: ["10.0.0.0/8x"] });
    expect(engine.notices().some((notice) => notice.message.includes("match nothing"))).toBe(true);

    engine.reconfigure({ serviceTokens: { tokens: { monitor: "short" } } });
    expect(engine.notices().some((notice) => notice.message.includes("short enough to guess"))).toBe(true);
  });

  it("keeps a bounded, timestamped notice history for a dashboard opened later", () => {
    const clock = new ManualClock(Date.UTC(2026, 8, 16, 12, 0, 0));
    const engine = new HoneypotEngine({ enricher: null, clock });
    engine.warn("the store is answering slowly");
    expect(engine.notices()[0]).toMatchObject({ message: "the store is answering slowly", timestamp: "2026-09-16T12:00:00.000Z" });

    for (let i = 0; i < 400; i += 1) engine.warn(`notice ${i}`);
    const notices = engine.notices();
    expect(notices).toHaveLength(200);
    // The oldest are dropped, so what is kept is the most recent.
    expect(notices.at(-1)?.message).toBe("notice 399");
  });
});
