import { describe, expect, it } from "vitest";
import { notifyJsSink } from "../src/notify/index.js";
import type { HoneypotHit } from "../src/types.js";
import type { TrafficAnomaly } from "../src/audit.js";

/**
 * The hub's ingest contract, pinned.
 *
 * Written against what `POST /api/notify` actually reads — it builds the notification field by
 * field and ignores anything else — so these tests are what stops this sink from drifting into
 * posting a shape the hub quietly drops.
 */

const AT = "2026-09-16T12:00:00.000Z";

const incident = (over: Partial<HoneypotHit> = {}): HoneypotHit => ({
  id: "a",
  timestamp: AT,
  ip: "198.51.100.7",
  method: "GET",
  path: "/.env",
  headers: { authorization: "Bearer super-secret" },
  body: "user=ada&password=hunter2",
  detections: [{ detectorId: "decoy-path", reason: "probe for a bait path", score: 10 }],
  score: 10,
  totalScore: 25,
  respondedWith: "decoy-content",
  reason: "A probe for a dotfile that does not exist.",
  ...over,
});

interface Sent {
  url: string;
  init: { method?: string; headers?: Record<string, string>; body?: string };
}

const capturing = (status = 202): { sent: Sent[]; fetch: typeof globalThis.fetch } => {
  const sent: Sent[] = [];
  const fetchImpl = (async (url: string | URL, init: unknown) => {
    sent.push({ url: String(url), init: init as Sent["init"] });
    return new Response(status === 202 ? JSON.stringify({ ok: true, id: "n1", seq: 4 }) : "", { status });
  }) as unknown as typeof globalThis.fetch;
  return { sent, fetch: fetchImpl };
};

const bodyOf = (sent: Sent): Record<string, unknown> => JSON.parse(sent.init.body as string) as Record<string, unknown>;

describe("publishing to a NotifyJS hub", () => {
  it("posts to the ingest route with a bearer token", async () => {
    const { sent, fetch } = capturing();
    await notifyJsSink({ url: "https://hub.example.com/", token: "njs_abc", fetch }).notify({ type: "hit", at: AT, incident: incident() });

    expect(sent[0]?.url).toBe("https://hub.example.com/api/notify");
    expect(sent[0]?.init.method).toBe("POST");
    expect(sent[0]?.init.headers?.["authorization"]).toBe("Bearer njs_abc");
  });

  it("sends who, what and what the honeypot did — and none of the capture", async () => {
    const { sent, fetch } = capturing();
    await notifyJsSink({ url: "https://hub.example.com", token: "njs_abc", fetch }).notify({ type: "hit", at: AT, incident: incident() });

    const body = bodyOf(sent[0] as Sent);
    expect(body["title"]).toBe("hackerpot: decoy-path from 198.51.100.7");
    expect(body["body"]).toContain("GET /.env → decoy-content");
    expect(body["channel"]).toBe("hackerpot");
    expect(body["tags"]).toEqual(["hackerpot", "hit", "decoy-path"]);
    // One alert per address, however many times it probes.
    expect(body["dedupeKey"]).toBe("hackerpot:hit:198.51.100.7");

    // This lands on a lock screen. The captured request stays in the store.
    const serialised = sent[0]?.init.body as string;
    expect(serialised).not.toContain("super-secret");
    expect(serialised).not.toContain("hunter2");
    expect(serialised).not.toContain("authorization");
  });

  it("raises the severity for proof, and names a refused block", async () => {
    const { sent, fetch } = capturing();
    const sink = notifyJsSink({ url: "https://hub.example.com", token: "njs_abc", fetch });

    await sink.notify({ type: "hit", at: AT, incident: incident({ detections: [{ detectorId: "honeytoken", reason: "replayed", score: 15, certain: true }] }) });
    await sink.notify({ type: "downgrade", at: AT, incident: incident({ downgradedFrom: "block", respondedWith: "tarpit" }) });

    expect(bodyOf(sent[0] as Sent)["severity"]).toBe("error");
    expect(bodyOf(sent[1] as Sent)).toMatchObject({ severity: "warning", title: "hackerpot: refused a block for 198.51.100.7" });
  });

  it("carries an anomaly at the severity the audit gave it", async () => {
    const { sent, fetch } = capturing();
    const anomaly = { id: "flagged-share-spike", severity: "critical", summary: "Detectors flagged 70% of requests.", metric: "flaggedShare", value: 0.7, baseline: 0.02, timestamp: AT } as TrafficAnomaly;

    await notifyJsSink({ url: "https://hub.example.com", token: "njs_abc", fetch }).notify({ type: "anomaly", at: AT, anomaly });

    // The audit's severities are already the hub's vocabulary, so nothing is coerced.
    expect(bodyOf(sent[0] as Sent)).toMatchObject({ severity: "critical", title: "hackerpot: flagged-share-spike", dedupeKey: "hackerpot:anomaly:flagged-share-spike" });
  });

  it("reports a failing component as a failure, deduplicated per component", async () => {
    const { sent, fetch } = capturing();
    await notifyJsSink({ url: "https://hub.example.com", token: "njs_abc", fetch }).notify({ type: "error", at: AT, error: { source: "store", message: "elasticsearch is unreachable" } });

    expect(bodyOf(sent[0] as Sent)).toMatchObject({ severity: "error", title: "hackerpot: store failed", dedupeKey: "hackerpot:error:store" });
  });

  it("clips attacker-chosen text rather than sending all of it to a phone", async () => {
    const { sent, fetch } = capturing();
    await notifyJsSink({ url: "https://hub.example.com", token: "njs_abc", fetch }).notify({ type: "hit", at: AT, incident: incident({ path: `/${"A".repeat(5000)}` }) });

    const body = bodyOf(sent[0] as Sent);
    expect((body["title"] as string).length).toBeLessThanOrEqual(120);
    expect((body["body"] as string).length).toBeLessThanOrEqual(400);
  });
});

describe("what the hub's refusals mean", () => {
  const cases: Array<[number, RegExp]> = [
    // A disabled feature answers 404 rather than confirming it exists — so this must not read
    // as "wrong URL".
    [404, /ingest switched off/],
    [421, /plain HTTP/],
    [401, /unknown or revoked/],
    [403, /cannot publish/],
    [429, /rate-limiting/],
    [413, /too large/],
    [500, /refused the notification with 500/],
  ];

  for (const [status, expected] of cases) {
    it(`explains ${status} as itself`, async () => {
      const { fetch } = capturing(status);
      await expect(notifyJsSink({ url: "https://hub.example.com", token: "njs_abc", fetch }).notify({ type: "error", at: AT, error: { source: "store", message: "down" } })).rejects.toThrow(expected);
    });
  }

  it("succeeds on the 202 the hub actually answers with", async () => {
    const { fetch } = capturing(202);
    await expect(notifyJsSink({ url: "https://hub.example.com", token: "njs_abc", fetch }).notify({ type: "error", at: AT, error: { source: "store", message: "down" } })).resolves.toBeUndefined();
  });
});
