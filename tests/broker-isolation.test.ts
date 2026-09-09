import { describe, expect, it } from "vitest";
import { IncidentBroker } from "../src/management/broker.js";
import type { Incident } from "../src/management/types.js";

const incident = { ip: "203.0.113.7", totalScore: 10 } as unknown as Incident;

describe("one misbehaving subscriber cannot starve the others", () => {
  // `emit()` runs listeners synchronously in registration order, so a throwing listener
  // aborted the loop: everything registered after it never saw the incident, and the
  // throw propagated back out of `publish()`. The WebSocket transport's listener calls
  // `JSON.stringify` and `ws.send`, either of which can throw — so one bad WS client
  // silently starved the other WS clients and any syslog sink on the same broker.

  it("delivers to every subscriber even when one throws", () => {
    const errors: unknown[] = [];
    const broker = new IncidentBroker((err) => errors.push(err));
    const received: string[] = [];

    broker.subscribe(() => received.push("webhooks"));
    broker.subscribe(() => {
      throw new Error("ws.send failed");
    });
    broker.subscribe(() => received.push("ws-client"));
    broker.subscribe(() => received.push("syslog"));

    expect(() => broker.publish(incident)).not.toThrow();
    expect(received).toEqual(["webhooks", "ws-client", "syslog"]);
    expect(errors).toHaveLength(1);
    expect((errors[0] as Error).message).toBe("ws.send failed");
  });

  it("survives the real trigger — an incident that will not serialize", () => {
    const errors: unknown[] = [];
    const broker = new IncidentBroker((err) => errors.push(err));
    const received: string[] = [];

    // A custom detector is free to put anything in `metadata`; a BigInt makes
    // JSON.stringify throw, which is exactly what the WS listener does per incident.
    broker.subscribe((i) => void JSON.stringify(i));
    broker.subscribe(() => received.push("still delivered"));

    const unserializable = { ip: "203.0.113.7", detections: [{ metadata: { n: 1n } }] } as unknown as Incident;
    expect(() => broker.publish(unserializable)).not.toThrow();
    expect(received).toEqual(["still delivered"]);
    expect(errors).toHaveLength(1);
  });

  it("catches a listener that rejects rather than throwing", async () => {
    const errors: unknown[] = [];
    const broker = new IncidentBroker((err) => errors.push(err));
    const received: string[] = [];

    broker.subscribe((() => Promise.reject(new Error("async failure"))) as (i: Incident) => void);
    broker.subscribe(() => received.push("delivered"));

    expect(() => broker.publish(incident)).not.toThrow();
    await new Promise((resolve) => setImmediate(resolve));
    expect(received).toEqual(["delivered"]);
    expect(errors).toHaveLength(1);
  });

  it("still unsubscribes correctly through the isolating wrapper", () => {
    const broker = new IncidentBroker();
    const received: string[] = [];
    const unsubscribe = broker.subscribe(() => received.push("x"));

    broker.publish(incident);
    unsubscribe();
    broker.publish(incident);

    expect(received).toEqual(["x"]);
  });

  it("works without an error channel", () => {
    const broker = new IncidentBroker();
    broker.subscribe(() => {
      throw new Error("boom");
    });
    expect(() => broker.publish(incident)).not.toThrow();
  });
});
