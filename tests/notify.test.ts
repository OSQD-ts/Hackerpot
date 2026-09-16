import { describe, expect, it } from "vitest";
import { IncidentBroker } from "../src/management/broker.js";
import { NotificationHub, consoleNotifier } from "../src/notify/index.js";
import type { NotifyEvent, NotifySink } from "../src/notify/index.js";
import { ManualClock } from "../src/internal/clock.js";
import type { HoneypotHit } from "../src/types.js";
import type { TrafficAnomaly } from "../src/audit.js";

/**
 * The hub's job is that a sink cannot hurt anything — not the request, not the other sinks,
 * not the shutdown — and that a flood cannot turn alerting into a second outage.
 */

const START = Date.UTC(2026, 8, 16, 12, 0, 0);

const incident = (over: Partial<HoneypotHit> = {}): HoneypotHit => ({
  id: "a",
  timestamp: new Date(START).toISOString(),
  ip: "198.51.100.7",
  method: "GET",
  path: "/.env",
  headers: {},
  detections: [{ detectorId: "decoy-path", reason: "probe", score: 10 }],
  score: 10,
  totalScore: 10,
  respondedWith: "decoy-content",
  ...over,
});

const anomaly = (): TrafficAnomaly => ({ id: "flagged-share", severity: "warning", summary: "a spike", value: 1, baseline: 0 }) as TrafficAnomaly;

const collecting = (id: string, into: NotifyEvent[]): NotifySink => ({ id, notify: (event) => void into.push(event) });

const hubWith = (sinks: NotifySink[], options: ConstructorParameters<typeof NotificationHub>[0] = {}): NotificationHub => {
  const hub = new NotificationHub({ clock: new ManualClock(START), ...options });
  for (const sink of sinks) hub.add(sink);
  return hub;
};

describe("fanning out", () => {
  it("sends one event to every sink", () => {
    const seen: NotifyEvent[] = [];
    const hub = hubWith([collecting("syslog", seen), collecting("webhooks", seen)]);

    hub.publish(incident());

    expect(seen.map((event) => `${event.type}:${event.incident?.path}`)).toEqual(["hit:/.env", "hit:/.env"]);
    expect(hub.names()).toEqual(["syslog", "webhooks"]);
  });

  it("calls a refused block what it is", () => {
    const seen: NotifyEvent[] = [];
    const hub = hubWith([collecting("syslog", seen)]);

    hub.publish(incident({ downgradedFrom: "block", respondedWith: "tarpit" }));

    // The guard saying the policy asked for more than the evidence supports is a tuning
    // signal, not another hit.
    expect(seen[0]?.type).toBe("downgrade");
  });

  it("carries anomalies and operational failures", () => {
    const seen: NotifyEvent[] = [];
    const hub = hubWith([collecting("syslog", seen)]);

    hub.announce(anomaly());
    hub.reportError("store", "elasticsearch is unreachable");

    expect(seen.map((event) => event.type)).toEqual(["anomaly", "error"]);
    expect(seen[0]?.anomaly?.id).toBe("flagged-share");
    expect(seen[1]?.error).toEqual({ source: "store", message: "elasticsearch is unreachable" });
  });

  it("isolates a sink that throws, and one that rejects", async () => {
    const seen: NotifyEvent[] = [];
    const failures: Array<[string, string]> = [];
    const hub = new NotificationHub({ clock: new ManualClock(START), onError: (sink, error) => failures.push([sink, (error as Error).message]) });
    hub.add({
      id: "broken",
      notify: () => {
        throw new Error("the collector is down");
      },
    });
    hub.add({ id: "slow", notify: async () => Promise.reject(new Error("timed out")) });
    hub.add(collecting("syslog", seen));

    hub.publish(incident());
    await new Promise((resolve) => setTimeout(resolve, 10));

    // The sink registered after the broken ones still received it.
    expect(seen).toHaveLength(1);
    expect(failures.map(([sink]) => sink).sort()).toEqual(["broken", "slow"]);
  });

  it("stops delivering to a sink that was removed", () => {
    const seen: NotifyEvent[] = [];
    const hub = hubWith([]);
    const remove = hub.add(collecting("syslog", seen));

    hub.publish(incident());
    remove();
    hub.publish(incident({ id: "b", ip: "203.0.113.9" }));

    expect(seen).toHaveLength(1);
    expect(hub.size).toBe(0);
  });

  it("can share a fan-out with the management server rather than owning a second one", () => {
    const seen: NotifyEvent[] = [];
    const broker = new IncidentBroker();
    hubWith([collecting("syslog", seen)], { broker });

    // Published by whoever else holds the broker — the management server's own feed.
    broker.publish(incident({ path: "/from-management" }));

    expect(seen[0]?.incident?.path).toBe("/from-management");
  });
});

describe("what reaches a sink", () => {
  it("delivers everything by default, because here an incident is the thing worth saying", () => {
    const seen: NotifyEvent[] = [];
    const hub = hubWith([collecting("syslog", seen)]);
    hub.publish(incident());
    hub.announce(anomaly());
    expect(seen.map((event) => event.type)).toEqual(["hit", "anomaly"]);
  });

  it("can be narrowed to the types somebody wants", () => {
    const seen: NotifyEvent[] = [];
    const hub = hubWith([collecting("alerts", seen)], { filter: { types: ["anomaly", "error"] } });

    hub.publish(incident());
    hub.announce(anomaly());

    expect(seen.map((event) => event.type)).toEqual(["anomaly"]);
  });

  it("can be held to a score, and to proof", () => {
    const scored: NotifyEvent[] = [];
    const scoreHub = hubWith([collecting("alerts", scored)], { filter: { minScore: 40 } });
    scoreHub.publish(incident({ totalScore: 10 }));
    scoreHub.publish(incident({ id: "b", ip: "203.0.113.9", totalScore: 80 }));
    expect(scored.map((event) => event.incident?.totalScore)).toEqual([80]);

    const proven: NotifyEvent[] = [];
    const proofHub = hubWith([collecting("alerts", proven)], { filter: { certainOnly: true } });
    proofHub.publish(incident({ totalScore: 900 }));
    proofHub.publish(incident({ id: "b", ip: "203.0.113.9", detections: [{ detectorId: "honeytoken", reason: "replayed", score: 15, certain: true }] }));
    expect(proven.map((event) => event.incident?.id)).toEqual(["b"]);
  });

  it("lets proof through a score gate it would not otherwise pass", () => {
    const seen: NotifyEvent[] = [];
    const hub = hubWith([collecting("alerts", seen)], { filter: { minScore: 100 } });
    // A replayed honeytoken scores little and settles the question; a threshold meant for
    // accumulated suspicion should not be what hides it.
    hub.publish(incident({ totalScore: 15, detections: [{ detectorId: "honeytoken", reason: "replayed", score: 15, certain: true }] }));
    expect(seen).toHaveLength(1);
  });
});

describe("under a flood", () => {
  it("collapses repeats from one address into one event per window", () => {
    const seen: NotifyEvent[] = [];
    const hub = hubWith([collecting("syslog", seen)]);

    for (let i = 0; i < 50; i += 1) hub.publish(incident({ id: `i${i}` }));
    // A different address is a different actor, and is never collapsed into the first.
    hub.publish(incident({ id: "other", ip: "203.0.113.9" }));

    expect(seen).toHaveLength(2);
  });

  it("has a ceiling for traffic where every event really is distinct", () => {
    const seen: NotifyEvent[] = [];
    const hub = hubWith([collecting("syslog", seen)], { maxPerWindow: 5 });

    // A distributed scan: ten thousand addresses, nothing to deduplicate.
    for (let i = 0; i < 40; i += 1) hub.publish(incident({ id: `i${i}`, ip: `203.0.113.${i}` }));

    expect(seen).toHaveLength(5);
  });

  it("says what the window hid, so a quiet channel is not mistaken for quiet traffic", () => {
    const seen: NotifyEvent[] = [];
    const clock = new ManualClock(START);
    const hub = new NotificationHub({ clock, maxPerWindow: 2, dedupeWindowMs: 60_000 });
    hub.add(collecting("syslog", seen));

    for (let i = 0; i < 10; i += 1) hub.publish(incident({ id: `i${i}`, ip: `203.0.113.${i}` }));
    expect(seen).toHaveLength(2);

    clock.advance(61_000);
    hub.publish(incident({ id: "next", ip: "198.51.100.200" }));

    const summary = seen.find((event) => event.error?.source === "notification-hub");
    expect(summary?.error?.message).toMatch(/8 notification\(s\) were suppressed/);
  });

  it("never deduplicates a failure or an anomaly", () => {
    const seen: NotifyEvent[] = [];
    const hub = hubWith([collecting("syslog", seen)]);

    hub.reportError("store", "unreachable");
    hub.reportError("store", "unreachable");
    hub.announce(anomaly());
    hub.announce(anomaly());

    // Two failures with the same shape are two problems, and the audit already decided an
    // anomaly was worth saying.
    expect(seen).toHaveLength(4);
  });
});

describe("closing", () => {
  it("closes every sink, and keeps going when one refuses", async () => {
    const closed: string[] = [];
    const failures: string[] = [];
    const hub = new NotificationHub({ clock: new ManualClock(START), onError: (sink) => failures.push(sink) });
    hub.add({
      id: "stuck",
      notify: () => undefined,
      close: () => {
        throw new Error("socket is wedged");
      },
    });
    hub.add({ id: "syslog", notify: () => undefined, close: () => void closed.push("syslog") });

    await hub.close();

    expect(closed).toEqual(["syslog"]);
    expect(failures).toEqual(["stuck"]);
    expect(hub.size).toBe(0);
  });
});

describe("the console sink", () => {
  const lines = (): { out: string[]; sink: NotifySink } => {
    const out: string[] = [];
    const target = { log: (line: string) => void out.push(line), warn: (line: string) => void out.push(line), error: (line: string) => void out.push(line) };
    return { out, sink: consoleNotifier({ target }) };
  };

  it("says what happened and why, in one place", () => {
    const { out, sink } = lines();
    sink.notify({ type: "hit", at: new Date(START).toISOString(), incident: incident({ reason: "A probe for a dotfile." }) });
    expect(out[0]).toContain("198.51.100.7 GET /.env");
    expect(out[0]).toContain("-> decoy-content");
    expect(out[0]).toContain("A probe for a dotfile.");
  });

  it("reports a failure as itself rather than as traffic", () => {
    const { out, sink } = lines();
    sink.notify({ type: "error", at: new Date(START).toISOString(), error: { source: "store", message: "unreachable" } });
    expect(out[0]).toBe("[hackerpot] error store — unreachable");
  });

  it("writes the whole event when a log pipeline is reading", () => {
    const out: string[] = [];
    const target = { log: (line: string) => void out.push(line), warn: () => undefined, error: () => undefined };
    consoleNotifier({ format: "json", target }).notify({ type: "hit", at: new Date(START).toISOString(), incident: incident() });
    expect(JSON.parse(out[0] as string)).toMatchObject({ type: "hit", incident: { ip: "198.51.100.7" } });
  });
});
