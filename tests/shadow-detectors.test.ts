import http from "node:http";
import { planReload } from "../src/config/reload.js";
import { parseConfig } from "../src/config/schema.js";
import type net from "node:net";
import { describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import { createMiddleware } from "../src/middleware.js";
import { MemoryStore } from "../src/stores/index.js";
import type { RequestFacts } from "../src/detectors/types.js";
import type { HoneypotHit, ShadowEvent } from "../src/types.js";

const BROWSER = {
  host: "shop.example",
  "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
  accept: "text/html,*/*",
  "accept-language": "en-US,en;q=0.9",
  "accept-encoding": "gzip, deflate, br",
};

const facts = (path: string, headers: Record<string, string> = BROWSER): RequestFacts => ({ method: "GET", path, query: {}, headers, ip: "203.0.113.60" });

function engineWith(shadowDetectors: string[]) {
  const store = new MemoryStore();
  const hits: HoneypotHit[] = [];
  const shadows: ShadowEvent[] = [];
  const engine = new HoneypotEngine({ store, enricher: null, shadowDetectors, onHit: (hit) => void hits.push(hit), onShadow: (event) => void shadows.push(event) });
  return { engine, store, hits, shadows };
}

describe("shadow detectors report findings without acting on them", () => {
  it("a shadowed detection alone scores nothing and records no hit", async () => {
    const { engine, store, hits, shadows } = engineWith(["decoy-path"]);
    const result = await engine.evaluate(facts("/.env"));
    expect(result.detections).toEqual([]);
    expect(result.shadowDetections.map((d) => d.detectorId)).toEqual(["decoy-path"]);
    expect(result.actionId).toBe("");
    expect(hits).toHaveLength(0);
    expect(await store.scoreFor("203.0.113.60")).toBe(0);
    expect(shadows).toMatchObject([{ path: "/.env", alsoHit: false }]);
  });

  it("rides along on a hit live detectors caused, adding nothing to its score", async () => {
    const { engine, hits, shadows } = engineWith(["decoy-path"]);
    const result = await engine.evaluate(facts("/.env", { ...BROWSER, "user-agent": "sqlmap/1.7" }));
    expect(result.detections.map((d) => d.detectorId)).toEqual(["scanner-signature"]);
    expect(result.score).toBe(result.detections[0]!.score);
    expect(hits[0]!.shadowDetections?.map((d) => d.detectorId)).toEqual(["decoy-path"]);
    expect(shadows).toMatchObject([{ alsoHit: true }]);
  });

  it("can be switched off by reconfigure, and the detector counts again", async () => {
    const { engine } = engineWith(["decoy-path"]);
    engine.reconfigure({ shadowDetectors: [] });
    const result = await engine.evaluate(facts("/.env"));
    expect(result.detections.map((d) => d.detectorId)).toContain("decoy-path");
  });

  it("reports a throwing onShadow on the error channel instead of failing the request", async () => {
    const sources: string[] = [];
    const engine = new HoneypotEngine({
      enricher: null,
      shadowDetectors: ["decoy-path"],
      onShadow: () => {
        throw new Error("sink down");
      },
      onError: (_error, context) => void sources.push(context.source),
    });
    await expect(engine.evaluate(facts("/.env"))).resolves.toBeDefined();
    expect(sources).toEqual(["onShadow"]);
  });

  // The body is read only for a request the honeypot is answering. A shadowed finding
  // must not count as a reason to, or it would consume the stream the app's route needs.
  it("a shadowed finding alone does not make middleware read the body", async () => {
    const { engine, shadows } = engineWith(["payload-injection"]);
    const middleware = createMiddleware(engine);
    const server = http.createServer((req, res) => {
      void middleware(req, res, () => {
        let body = "";
        req.setEncoding("utf8");
        req.on("data", (chunk: string) => (body += chunk));
        req.on("end", () => res.end(`app:${body}`));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as net.AddressInfo;
    try {
      const reply = await new Promise<string>((resolve, reject) => {
        const req = http.request({ host: "127.0.0.1", port, method: "POST", path: "/search?q=%27%20union%20select%201", headers: BROWSER }, (res) => {
          let text = "";
          res.setEncoding("utf8");
          res.on("data", (chunk: string) => (text += chunk));
          res.on("end", () => resolve(text));
        });
        req.on("error", reject);
        req.end("item=42");
      });
      expect(reply).toBe("app:item=42");
      expect(shadows.map((event) => event.detections[0]!.detectorId)).toEqual(["payload-injection"]);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

describe("[engine] shadow_detectors", () => {
  it("rejects an id that is not a detector instead of shadowing nothing", () => {
    expect(() => parseConfig({ engine: { shadow_detectors: ["decoy-paths"] } }, "<test>")).toThrow(/engine\.shadow_detectors.*"decoy-paths"/);
  });

  it("accepts real ids and applies a change on reload, without a restart", () => {
    const running = parseConfig({}, "<test>");
    const next = parseConfig({ engine: { shadow_detectors: ["target-integrity"] } }, "<test>");
    expect(next.engine.shadowDetectors).toEqual(["target-integrity"]);
    const plan = planReload(running, next);
    expect(plan.applied).toContain("engine.shadow_detectors");
    expect(plan.requiresRestart).toEqual([]);
  });
});
