import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import type { TrafficAnomaly } from "../src/audit.js";
import { IncidentCounters, renderAnomaly, WebhookDispatcher } from "../src/management/index.js";
import type { Incident } from "../src/management/index.js";

const incident = (extra: Partial<Incident> = {}): Incident => ({
  id: "i1",
  timestamp: "2026-09-01T00:00:00.000Z",
  ip: "198.51.100.1",
  method: "GET",
  path: "/",
  headers: {},
  detections: [{ detector: "rate-spike", summary: "fast", score: 4 }],
  score: 4,
  totalScore: 45,
  respondedWith: "tarpit",
  ...extra,
});

const anomaly: TrafficAnomaly = {
  id: "probe-campaign",
  severity: "warning",
  metric: "distinct sources probing a new path",
  value: 12,
  baseline: 0,
  summary: '12 different addresses started probing "/@everyone <!channel>" in the last 5 minute(s).',
  timestamp: "2026-09-01T00:00:00.000Z",
  details: { path: "/@everyone <!channel>" },
};

describe("metrics", () => {
  it("counts proof-guard downgrades and labels detector failures", () => {
    const counters = new IncidentCounters();
    counters.record(incident({ downgradedFrom: "block" }));
    counters.record(incident());
    const text = counters.render(undefined, undefined, new Map([["slow\"detector", 3]]));
    expect(text).toContain("hackerpot_downgrades_total 1");
    expect(text).toContain('hackerpot_detector_failures_total{detector="slow\\"detector"} 3');
  });
});

describe("what the counters can answer that the store cannot", () => {
  it("counts proof apart from suspicion", () => {
    const counters = new IncidentCounters();
    counters.record(incident({ detections: [{ detector: "honeytoken", summary: "replayed", score: 15, certain: true }] }));
    counters.record(incident());
    expect(counters.render()).toContain("hackerpot_proven_total 1");
  });

  it("gives shadow mode a metric, apart from the detectors that decided", () => {
    const counters = new IncidentCounters();
    counters.record(incident({ shadowDetections: [{ detector: "path-novelty", summary: "trial", score: 6 }] }));
    counters.record(incident({ shadowDetections: [{ detector: "path-novelty", summary: "trial", score: 6 }] }));
    const text = counters.render();
    expect(text).toContain('hackerpot_shadow_firings_total{detector="path-novelty"} 2');
    // A shadowed finding decided nothing, so it must not be counted as a detector that fired.
    expect(text).not.toContain('hackerpot_incidents_by_detector{detector="path-novelty"}');
  });

  it("says nothing about shadow mode when nothing is shadowed", () => {
    expect(new IncidentCounters().render()).not.toContain("hackerpot_shadow_firings_total");
  });

  it("distributes cumulative scores around the lines that decide something", () => {
    const counters = new IncidentCounters();
    for (const totalScore of [3, 12, 15, 38, 45, 250]) counters.record(incident({ totalScore }));
    const text = counters.render();

    expect(text).toContain("# TYPE hackerpot_score histogram");
    // Cumulative, as Prometheus defines a histogram: each bound counts everything at or below it.
    expect(text).toContain('hackerpot_score_bucket{le="5"} 1');
    expect(text).toContain('hackerpot_score_bucket{le="15"} 3');
    expect(text).toContain('hackerpot_score_bucket{le="40"} 4');
    expect(text).toContain('hackerpot_score_bucket{le="100"} 5');
    // A cumulative score is unbounded, so +Inf is where the persistent attacker actually lands.
    expect(text).toContain('hackerpot_score_bucket{le="+Inf"} 6');
    expect(text).toContain("hackerpot_score_count 6");
    expect(text).toContain("hackerpot_score_sum 363");
  });

  it("buckets proven incidents too, because here proof carries an ordinary score", () => {
    const counters = new IncidentCounters();
    counters.record(incident({ totalScore: 15, detections: [{ detector: "honeytoken", summary: "replayed", score: 15, certain: true }] }));
    expect(counters.render()).toContain("hackerpot_score_count 1");
  });
});

describe("renderAnomaly", () => {
  it("sends native JSON to your own receiver", () => {
    expect(JSON.parse(renderAnomaly("hackerpot", anomaly))).toEqual({ type: "anomaly", anomaly });
  });

  it("neuters mentions in the quoted path for chat platforms", () => {
    const slack = JSON.parse(renderAnomaly("slack", anomaly));
    expect(slack.text).not.toContain("<!channel>");
    const discord = JSON.parse(renderAnomaly("discord", anomaly));
    expect(discord.allowed_mentions).toEqual({ parse: [] });
    expect(discord.content).toContain("\\@everyone");
  });
});

describe("WebhookDispatcher.announce", () => {
  let receiver: http.Server | undefined;
  afterEach(() => new Promise<void>((resolve) => (receiver ? receiver.close(() => resolve()) : resolve())));

  it("delivers to hooks that accept anomalies and skips those that opted out", async () => {
    const bodies: Array<{ path: string; body: string }> = [];
    receiver = http.createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        bodies.push({ path: req.url ?? "", body });
        res.end("ok");
      });
    });
    await new Promise<void>((resolve) => receiver!.listen(0, "127.0.0.1", resolve));
    const base = `http://127.0.0.1:${(receiver.address() as AddressInfo).port}`;
    const dispatcher = new WebhookDispatcher({ webhooks: [{ url: `${base}/yes` }, { url: `${base}/no`, anomalies: false }] });
    dispatcher.announce(anomaly);
    for (let i = 0; i < 50 && bodies.length === 0; i++) await new Promise((resolve) => setTimeout(resolve, 20));
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(bodies.map((entry) => entry.path)).toEqual(["/yes"]);
    expect(JSON.parse(bodies[0]!.body).type).toBe("anomaly");
    dispatcher.detach();
  });
});
