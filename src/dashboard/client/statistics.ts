import {
  type Analysis,
  CADENCE_LABELS,
  CORPUS_LIMIT,
  cadence,
  classSlot,
  cooccurrence,
  funnel,
  histogram,
  type IpSortKey,
  ipRows,
  PROTOCOLS,
  percentile,
  RUNGS,
  ranked,
  responseClassEntries,
  strongestResponse,
} from "./analysis.js";
import { responseBadge } from "./badges.js";
import { columnChart, dataTable, factList, heatGrid, meter, noData, rankedBars, replace, sparkline, stackBar, timeChart } from "./charts.js";
import { $, all, byId, el, maybe, setText, strong } from "./dom.js";
import { DASH, fmtClock, fmtDateTime, fmtDur, fmtInt, fmtNum, fmtPct, sevClass, truncate } from "./format.js";
import { metric } from "./overview.js";
import { ordinalStep } from "./palette.js";
import { SECTIONS } from "./boot.js";
import { state } from "./store.js";
import { setTip } from "./tooltip.js";
import { bucketLabel, volumeChart } from "./volume.js";

/**
 * The Statistics screen: KPIs, then volume and tempo, detections, severity, attack
 * surface, sources and obfuscation, each a section of panels over the same scoped corpus.
 */

export function initStatistics(): void {
  for (const button of all<HTMLButtonElement>("#st-range button")) {
    button.addEventListener("click", () => {
      state.range = Number(button.dataset["range"] ?? 0) || 0;
      for (const other of all<HTMLButtonElement>("#st-range button")) other.setAttribute("aria-pressed", String(other === button));
      renderNowIfVisible();
    });
  }
  const proto = byId<HTMLSelectElement>("st-proto");
  for (const name of PROTOCOLS) {
    const option = el("option", null, name);
    option.value = name;
    proto.append(option);
  }
  proto.addEventListener("change", () => {
    state.proto = proto.value;
    renderNowIfVisible();
  });
  const tables = byId<HTMLInputElement>("st-tables");
  tables.addEventListener("change", () => {
    for (const table of all("#pane-statistics .datatable")) table.hidden = !tables.checked;
    for (const toggle of all<HTMLButtonElement>("#pane-statistics .tabletoggle")) {
      toggle.setAttribute("aria-expanded", String(tables.checked));
      toggle.textContent = tables.checked ? "hide table" : "table view";
    }
  });
}

let renderHook: () => void = () => {};

/** Set by `index.ts`: re-renders the Statistics screen at once, for a control somebody just pressed. */
export function onStatisticsChange(hook: () => void): void {
  renderHook = hook;
}

function renderNowIfVisible(): void {
  renderHook();
}

function kpi(label: string, value: string, sub: string, spark?: SVGSVGElement): HTMLElement {
  const card = el("div", "card");
  card.append(el("div", "label", label), el("div", value.length > 9 ? "value small" : "value", value), el("div", "sub", sub));
  if (spark !== undefined) {
    const holder = el("div", "spark");
    holder.append(spark);
    card.append(holder);
  }
  return card;
}

export function renderStats(a: Analysis): void {
  setText(
    "st-scope",
    a.n && a.firstMs !== undefined && a.lastMs !== undefined
      ? `${fmtInt(a.n)} incidents · ${fmtDateTime(a.firstMs)} → ${fmtClock(a.lastMs)}${state.all.length >= CORPUS_LIMIT ? ` · the most recent ${fmtInt(CORPUS_LIMIT)} loaded` : ""}`
      : "no incidents in this window",
  );

  const minutes = Math.max(a.span / 6e4, 1 / 60);
  const blocked = a.byResponse.get("block") ?? 0;
  const rotators = [...a.actors.values()].filter((actor) => actor.ips.size > 1).length;
  const cards = [
    kpi("Incidents", fmtInt(a.n), a.n ? `${fmtNum(a.n / minutes, 2)} per minute` : "", a.n ? sparkline(a.buckets.map((b) => b.n), 150, 26, 0) : undefined),
    kpi("Source IPs", fmtInt(a.ips.size), a.n ? `${fmtNum(a.n / Math.max(1, a.ips.size), 1)} incidents each` : "", a.n ? sparkline(a.buckets.map((b) => b.cumIps), 150, 26, 1) : undefined),
    kpi("Actor fingerprints", fmtInt(a.actors.size), rotators ? `${rotators} rotated across IPs` : "no IP rotation seen"),
    kpi("Detectors fired", fmtInt(a.byDetector.size), a.byDetector.size ? `top: ${ranked(a.byDetector, 1)[0]?.[0] ?? ""}` : ""),
    kpi("Paths probed", fmtInt(a.byPath.size), a.n ? `${fmtNum(a.byPath.size / Math.max(1, a.ips.size), 1)} per IP` : ""),
    kpi("Observation window", a.n ? fmtDur(a.span) : DASH, a.n && a.firstMs !== undefined ? `first seen ${fmtClock(a.firstMs)}` : ""),
    kpi("Peak burst", a.peakBucket ? fmtInt(a.peakBucket.n) : DASH, a.n ? `in one ${fmtDur(a.bucketSize)} bucket` : ""),
    kpi("Median gap", a.gaps.length ? fmtDur(percentile(a.gaps, 0.5)) : DASH, a.gaps.length ? "between one IP's requests" : "single request per IP"),
    kpi("Median score", a.n ? fmtNum(percentile(a.scores, 0.5), 0) : DASH, a.n ? `p95 ${fmtNum(percentile(a.scores, 0.95), 0)} · max ${fmtInt(a.scores[a.scores.length - 1] ?? 0)}` : ""),
    kpi("Corroborated", fmtPct(a.multiDetector, a.n, 0), `${fmtInt(a.multiDetector)} hit 2+ detectors`),
    kpi("Obfuscated", fmtPct(a.obfuscated, a.n, 0), `${fmtInt(a.obfuscated)} carried an encoded value`),
    kpi("Blocked", fmtPct(blocked, a.n, 0), `${fmtInt(blocked)} incidents`),
  ];
  if (SECTIONS.intel) {
    cards.push(kpi("Active blocks", metric("active_blocks"), "live gauge from /metrics"), kpi("Tracked IPs", metric("tracked_ips"), "in the scoring registry"));
  }
  replace($("st-kpis"), ...cards);

  setText("st-bucket", a.n ? `${fmtDur(a.bucketSize)} buckets` : "");
  volumeChart($("st-vol"), a, maybe("st-vol-table"), "Incidents over time");

  if (a.n) {
    timeChart(
      $("st-cum"),
      a.buckets.map((b) => ({ label: bucketLabel(b.start, a.bucketSize), full: fmtDateTime(b.start) })),
      [
        { name: "unique source IPs", values: a.buckets.map((b) => b.cumIps), slot: 0 },
        { name: "unique actors", values: a.buckets.map((b) => b.cumActors), slot: 1 },
      ],
      { height: 180, label: "Cumulative unique source IPs and actors" },
    );
  } else replace($("st-cum"), noData());

  renderCadence(a);
  renderHeat(a);

  const detectors = ranked(a.byDetector, 14);
  rankedBars($("st-det"), detectors, { total: a.n, wide: true });
  dataTable(maybe("st-det-table"), ["Detector", "Incidents", "Share", "Points"], detectors.map(([k, v]) => [k, fmtInt(v), fmtPct(v, a.n), fmtInt(a.detectorScore.get(k) ?? 0)]));
  const totalPoints = [...a.detectorScore.values()].reduce((x, y) => x + y, 0);
  rankedBars(
    $("st-detscore"),
    ranked(a.detectorScore, 14).map(([k, v]) => [k, v, `${fmtInt(a.byDetector.get(k) ?? 0)} incidents · ${fmtNum(v / Math.max(1, a.byDetector.get(k) ?? 1), 1)} pts each`] as const),
    { total: totalPoints, unit: "points", wide: true },
  );
  renderCooccurrence(a);

  renderHistogram(a);
  renderPercentiles(a);
  stackBar($("st-resp-mix"), responseClassEntries(a.byResponse), { slotFor: classSlot });
  rankedBars($("st-resp-list"), ranked(a.byResponse, 10), { total: a.n, emptyText: "" });
  renderFunnel(a);

  const paths = ranked(a.byPath, 12);
  rankedBars($("st-paths"), paths, { total: a.n });
  dataTable(maybe("st-path-table"), ["Path", "Incidents", "Share"], paths.map(([k, v]) => [k, fmtInt(v), fmtPct(v, a.n)]));
  rankedBars($("st-methods"), ranked(a.byMethod, 10), { total: a.n });
  const protocols = [...a.byProto.entries()].sort((x, y) => y[1] - x[1]);
  stackBar($("st-protos"), protocols, { slotFor: (name) => (PROTOCOLS as readonly string[]).indexOf(name) });

  rankedBars($("st-uas"), ranked(a.byUa, 10).map(([k, v]) => [truncate(k, 46), v, k] as const), { total: a.n, wide: true });
  dataTable(maybe("st-ua-table"), ["User-Agent", "Incidents", "Share"], ranked(a.byUa, 20).map(([k, v]) => [k, fmtInt(v), fmtPct(v, a.n)]));
  renderShape(a);

  rankedBars($("st-cats"), ranked(a.byCategory, 8), { total: a.n, emptyText: "no enrichment on these incidents" });
  rankedBars($("st-countries"), ranked(a.byCountry, 10), { total: a.n, emptyText: "no country data: configure a geo enricher" });
  rankedBars($("st-asns"), ranked(a.byAsn, 8), { total: a.n, wide: true, emptyText: "no ASN data: configure a geo/ASN enricher" });
  renderIpTable(a);

  rankedBars($("st-enc"), ranked(a.byEncoding, 10), { unit: "values", share: false, emptyText: "nothing was encoded" });
  meter($("st-encrate"), a.obfuscated, a.n, {
    note: "Layered URL-, base64- and hex-encoding is how a payload gets past a naive filter; each one is decoded in the incident detail. Scanned across the headers, the body, and the samples the detectors captured. The recorded incident keeps the path without its query string, so a query-only payload is visible only through its detector's sample.",
  });
}

function renderCadence(a: Analysis): void {
  const result = cadence(a.gaps);
  const chart = $("st-cadence-chart");
  const facts = $("st-cadence-facts");
  if (result === undefined) {
    replace(chart, noData("every IP sent a single request: no gaps to measure"));
    replace(facts);
    return;
  }
  columnChart(
    chart,
    CADENCE_LABELS.map((label, i) => ({ label, axis: label, value: result.counts[i] ?? 0 })),
    { height: 150, unit: "gaps", xTitle: "gap between consecutive requests from one IP", label: "Distribution of gaps between requests from one address" },
  );
  factList(facts, [
    { key: "Median gap", value: [strong(fmtDur(result.median))] },
    { key: "Fastest 10%", value: [fmtDur(result.p10)] },
    { key: "Slowest 10%", value: [fmtDur(result.p90)] },
    { key: "Mean ± sd", value: [`${fmtDur(result.mean)} ± ${fmtDur(result.sd)}`] },
    { key: "Coefficient of variation", value: [`${fmtNum(result.cv, 2)} — `, strong(result.verdict)], help: "Standard deviation divided by the mean. Near zero means a fixed interval, i.e. a script on a timer." },
    { key: "Gaps measured", value: [fmtInt(a.gaps.length)] },
  ]);
}

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"] as const;

function renderHeat(a: Analysis): void {
  const hours = Array.from({ length: 24 }, (_, h) => {
    const hh = String(h).padStart(2, "0");
    return { label: hh, full: `${hh}:00–${hh}:59` };
  });
  heatGrid($("st-heat"), DAYS.map((label) => ({ label })), hours, (r, c) => a.hourDow[r]?.[c] ?? 0, { labelWidth: 42, cellHeight: 22, scaleNote: "busier →", label: "Incidents by hour of day and day of week" });
  dataTable(
    maybe("st-heat-table"),
    ["Day", ...hours.map((h) => h.label)],
    DAYS.map((day, r) => [day, ...(a.hourDow[r] ?? []).map((v) => (v ? fmtInt(v) : "·"))]),
  );
}

function renderCooccurrence(a: Analysis): void {
  const { top, get } = cooccurrence(a, 9);
  if (top.length < 2) {
    replace($("st-cooc"), noData("need at least two detectors firing"));
    const table = maybe("st-cooc-table");
    if (table !== null) replace(table);
    return;
  }
  // Columns are numbered: a full detector id on every column would not fit.
  heatGrid(
    $("st-cooc"),
    top.map((d, i) => ({ label: `${i + 1} ${truncate(d, 20)}` })),
    top.map((d, i) => ({ label: String(i + 1), full: d })),
    get,
    { labelWidth: 178, cellHeight: 26, scaleNote: "co-occurring incidents", label: "Detector co-occurrence matrix" },
  );
  dataTable(
    maybe("st-cooc-table"),
    ["Detector", ...top.map((_, i) => String(i + 1))],
    top.map((d, r) => [`${r + 1} ${d}`, ...top.map((_, c) => (get(r, c) ? fmtInt(get(r, c)) : "·"))]),
  );
}

function renderHistogram(a: Analysis): void {
  const bins = histogram(a.scores);
  const table = maybe("st-hist-table");
  if (bins.length === 0) {
    replace($("st-hist"), noData());
    if (table !== null) replace(table);
    return;
  }
  const width = (bins[0]?.to ?? 1) - (bins[0]?.from ?? 0);
  const dp = width < 1 ? 1 : 0;
  const items = bins.map((bin) => ({ label: `${fmtNum(bin.from, dp)}–${fmtNum(bin.to, dp)} points`, axis: fmtNum(bin.from, 0), value: bin.value, note: `${fmtPct(bin.value, a.n)} of incidents` }));
  columnChart($("st-hist"), items, { height: 190, xTitle: "points added by the single request", label: "Distribution of per-incident scores" });
  dataTable(table, ["Score range", "Incidents", "Share"], items.map((d) => [d.label, fmtInt(d.value), fmtPct(d.value, a.n)]));
}

function renderPercentiles(a: Analysis): void {
  const target = $("st-pct");
  if (!a.n) {
    replace(target, noData());
    return;
  }
  const ipScores = [...a.ips.values()].map((ip) => ip.peak).sort((x, y) => x - y);
  const rows: Array<[string, string, string]> = [0.5, 0.75, 0.9, 0.95, 0.99].map((p) => [`p${Math.round(p * 100)}`, fmtNum(percentile(a.scores, p), 0), fmtNum(percentile(ipScores, p), 0)]);
  rows.push(["max", fmtInt(a.scores[a.scores.length - 1] ?? 0), fmtInt(ipScores[ipScores.length - 1] ?? 0)]);
  rows.push(["mean", fmtNum(a.scores.reduce((x, y) => x + y, 0) / a.n, 1), fmtNum(ipScores.reduce((x, y) => x + y, 0) / Math.max(1, ipScores.length), 1)]);
  const table = el("table", "plain");
  const head = el("thead");
  const headRow = el("tr");
  for (const [text, cls] of [["", ""], ["Per incident", "r"], ["Per IP (peak total)", "r"]] as const) {
    const th = el("th", cls, text);
    th.scope = "col";
    headRow.append(th);
  }
  head.append(headRow);
  const body = el("tbody");
  for (const [name, incident, ip] of rows) {
    const tr = el("tr");
    const th = el("th", "muted mono", name);
    th.scope = "row";
    tr.append(th, el("td", "r num", incident), el("td", "r num", ip));
    body.append(tr);
  }
  table.append(head, body);
  replace(target, table, el("p", "sub gap-top", "Per-incident score is what one request was worth. Per-IP is the cumulative total that drives escalation: the number the block threshold is compared against."));
}

function renderFunnel(a: Analysis): void {
  const target = $("st-funnel");
  if (a.ips.size === 0) {
    replace(target, noData());
    return;
  }
  const totals = funnel(a);
  const top = totals[0] || 1;
  const stages = RUNGS.map((stage, i) => {
    const n = totals[i] ?? 0;
    const box = el("div", "stage");
    const head = el("div", "stage-head");
    head.append(el("span", null, stage.name), el("span", "faint num", `${fmtInt(n)} IPs · ${fmtPct(n, top, 0)}`));
    const track = el("div", "stage-track");
    const fill = el("div", `stage-fill bg-${ordinalStep(i)}`);
    fill.style.width = `${Math.max(1, (n / top) * 100).toFixed(2)}%`;
    track.append(fill);
    box.append(head, track, el("div", "faint tiny", stage.note));
    setTip(box, { title: stage.name, lines: [[{ strong: fmtInt(n) }, ` of ${fmtInt(top)} IPs · ${fmtPct(n, top)}`], [stage.note]] });
    return box;
  });
  replace(target, ...stages);
}

function renderShape(a: Analysis): void {
  const target = $("st-shape");
  if (!a.n) {
    replace(target, noData());
    return;
  }
  const totalDetections = [...a.byDetector.values()].reduce((x, y) => x + y, 0);
  factList(target, [
    { key: "Carried a body", value: [strong(fmtInt(a.withBody)), ` · ${fmtPct(a.withBody, a.n)}`] },
    { key: "Mean body size", value: [a.withBody ? `${fmtInt(Math.round(a.bodyBytes / a.withBody))} bytes` : DASH] },
    { key: "Paths seen once", value: [`${fmtInt(a.singletonPaths)} · ${fmtPct(a.singletonPaths, a.byPath.size)} of paths`], help: "A long tail of one-hit paths is wordlist enumeration; a real client revisits a small set." },
    { key: "Mean headers", value: [fmtNum(a.headerCount / a.n, 1)] },
    { key: "No User-Agent", value: [`${fmtInt(a.noUa)} · ${fmtPct(a.noUa, a.n)}`], help: "A missing User-Agent is itself a scanner signature: no real client omits it." },
    { key: "Distinct User-Agents", value: [fmtInt(a.byUa.size)] },
    { key: "Detectors per incident", value: [fmtNum(totalDetections / a.n, 2)] },
    { key: "Two or more detectors", value: [`${fmtInt(a.multiDetector)} · ${fmtPct(a.multiDetector, a.n)}`], help: "Independent detectors agreeing on one request is the strongest signal the honeypot produces." },
    { key: "Distinct paths", value: [fmtInt(a.byPath.size)] },
    { key: "Distinct methods", value: [fmtInt(a.byMethod.size)] },
  ]);
}

const IP_COLUMNS: ReadonlyArray<{ key: IpSortKey; label: string; numeric: boolean }> = [
  { key: "ip", label: "Source IP", numeric: false },
  { key: "incidents", label: "Incidents", numeric: true },
  { key: "score", label: "Score", numeric: true },
  { key: "peak", label: "Peak total", numeric: true },
  { key: "detectors", label: "Detectors", numeric: true },
  { key: "rung", label: "Reached", numeric: true },
  { key: "first", label: "First seen", numeric: true },
  { key: "duration", label: "Active for", numeric: true },
];

const IP_TABLE_ROWS = 60;

function renderIpTable(a: Analysis): void {
  const target = $("st-iptable");
  if (a.ips.size === 0) {
    replace(target, noData());
    return;
  }
  const sort = state.ipSort;
  const rows = ipRows(a, sort);
  const table = el("table");
  const head = el("thead");
  const headRow = el("tr");
  for (const column of IP_COLUMNS) {
    const th = el("th", column.numeric ? "r" : null);
    th.scope = "col";
    const active = sort.key === column.key;
    th.setAttribute("aria-sort", active ? (sort.dir < 0 ? "descending" : "ascending") : "none");
    // A button inside the header rather than a clickable cell, so sorting is reachable
    // from the keyboard and announced as a control.
    const button = el("button", "sortbtn", column.label);
    button.type = "button";
    if (active) button.append(el("span", "arrow", sort.dir < 0 ? " ▼" : " ▲"));
    button.addEventListener("click", () => {
      state.ipSort = { key: column.key, dir: active ? (sort.dir === 1 ? -1 : 1) : column.key === "ip" ? 1 : -1 };
      renderIpTable(a);
      maybe("st-iptable")?.querySelector<HTMLButtonElement>(`thead th:nth-child(${IP_COLUMNS.indexOf(column) + 1}) button`)?.focus();
    });
    th.append(button);
    headRow.append(th);
  }
  const activity = el("th", null, "Activity");
  activity.scope = "col";
  headRow.append(activity);
  head.append(headRow);

  const body = el("tbody");
  for (const row of rows.slice(0, IP_TABLE_ROWS)) {
    const tr = el("tr");
    const detectors = el("td", "r num", fmtInt(row.detectors.size));
    detectors.title = [...row.detectors].join(", ");
    setTip(detectors, { title: row.ip, lines: [...row.detectors].map((d) => [d]) });
    const reached = el("td", "r");
    reached.append(responseBadge(strongestResponse(row.responses), RUNGS[row.rung]?.name ?? ""));
    const spark = el("td", "sparkcell");
    spark.append(sparkline(row.slots, 120, 22, 0));
    tr.append(
      el("td", "ip", row.ip),
      el("td", "r num", fmtInt(row.incidents)),
      el("td", "r num", fmtInt(row.score)),
      el("td", `r num ${sevClass(row.peak)}`, fmtInt(row.peak)),
      detectors,
      reached,
      el("td", "r mono faint small", fmtClock(row.first)),
      el("td", "r num", fmtDur(row.duration)),
      spark,
    );
    body.append(tr);
  }
  table.append(head, body);
  const wrap = el("div", "tablewrap scroll");
  wrap.append(table);
  const content: Node[] = [wrap];
  if (rows.length > IP_TABLE_ROWS) content.push(el("p", "sub gap-top", `Showing the first ${IP_TABLE_ROWS} of ${fmtInt(rows.length)} source IPs under this sort.`));
  replace(target, ...content);
}
