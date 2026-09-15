import { type Analysis, classSlot, peakPerMinute, percentile, ranked, responseClassEntries, timeOf } from "./analysis.js";
import { detectorBadges } from "./badges.js";
import { volumeChart } from "./volume.js";
import { dataTable, rankedBars, replace, stackBar } from "./charts.js";
import { $, el, maybe, setText } from "./dom.js";
import { DASH, fmtClock, fmtDur, fmtInt, fmtNum, fmtPct, fmtTime } from "./format.js";
import { state } from "./store.js";
import type { Incident } from "./types.js";

/**
 * The Overview screen: the hero count, five tiles, the volume chart and the four summary
 * panels. Everything is derived from the corpus except the headline count, which is the
 * store's own total when the page has it, because "incidents captured" should not stop at
 * the thousand the analytics happen to cover.
 */

export function metric(name: string): string {
  const value = state.metrics[name];
  return value === undefined ? DASH : fmtInt(value);
}

export function renderOverview(a: Analysis): void {
  const total = state.stats === undefined ? a.n : Math.max(a.n, state.stats.totalIncidents + state.liveSinceStats);
  setText("h-total", fmtInt(total));
  setText("h-total-sub", state.stats !== undefined && total > a.n ? `analytics below cover the most recent ${fmtInt(a.n)}` : "");
  setText("h-ips", fmtInt(a.ips.size));
  setText("h-actors", fmtInt(a.actors.size));
  setText("h-blocks", metric("active_blocks"));
  setText("h-tracked", metric("tracked_ips"));
  setText("h-dets", fmtInt(a.byDetector.size));
  setText("h-span", a.n ? fmtDur(a.span) : DASH);

  const offenders = [...a.ips.values()].sort((x, y) => y.score - x.score || x.ip.localeCompare(y.ip));
  const top = offenders[0];
  setText("c-top", top ? top.ip : DASH);
  setText("c-top-sub", top ? `${fmtInt(top.score)} pts · ${fmtInt(top.incidents)} incidents · peak total ${fmtInt(top.peak)}` : "");
  setText("c-last", a.lastMs !== undefined ? fmtClock(a.lastMs) : DASH);
  setText("c-last-sub", a.lastMs !== undefined ? `${fmtDur(Math.max(0, Date.now() - a.lastMs))} ago` : "");
  const peak = peakPerMinute(a);
  setText("c-peak", a.n ? fmtNum(peak, peak >= 10 ? 0 : 1) : DASH);
  setText("c-peak-sub", a.n && a.peakBucket ? `requests/min at peak · ${fmtInt(a.peakBucket.n)} in one ${fmtDur(a.bucketSize)} bucket` : "");
  setText("c-median", a.n ? fmtNum(percentile(a.scores, 0.5), 0) : DASH);
  setText("c-median-sub", a.n ? `points per incident · p95 ${fmtNum(percentile(a.scores, 0.95), 0)} · max ${fmtInt(a.scores[a.scores.length - 1] ?? 0)}` : "");
  const blocked = a.byResponse.get("block") ?? 0;
  setText("c-blockshare", a.n ? fmtPct(blocked, a.n, 0) : DASH);
  setText("c-blockshare-sub", a.n ? `${fmtInt(blocked)} requests refused at the door` : "");

  setText("ov-bucket", a.n ? `${fmtDur(a.bucketSize)} buckets` : "");
  volumeChart($("ov-vol"), a, maybe("ov-vol-table"), "Incident volume over time");

  const detectors = ranked(a.byDetector, 10);
  rankedBars($("p-detectors"), detectors, { total: a.n });
  dataTable(maybe("ov-det-table"), ["Detector", "Incidents", "Share"], detectors.map(([k, v]) => [k, fmtInt(v), fmtPct(v, a.n)]));

  const tenOffenders = offenders.slice(0, 10);
  rankedBars($("p-offenders"), tenOffenders.map((o) => [o.ip, o.score, `${o.incidents} incidents · ${o.detectors.size} detectors`] as const), { unit: "points", share: false });
  dataTable(maybe("ov-off-table"), ["Source IP", "Score", "Incidents", "Detectors"], tenOffenders.map((o) => [o.ip, fmtInt(o.score), fmtInt(o.incidents), fmtInt(o.detectors.size)]));

  stackBar($("p-responses-mix"), responseClassEntries(a.byResponse), { slotFor: classSlot, emptyText: "no responses recorded" });
  rankedBars($("p-responses-list"), ranked(a.byResponse, 8), { total: a.n, emptyText: "" });

  const recent = state.all.slice(-5).reverse();
  replace($("p-recent"), recent.length > 0 ? timeline(recent) : el("div", "nodata", "nothing captured yet"));
}

/** The last few incidents as a vertical timeline. Shared with the session list's layout. */
export function timeline(incidents: readonly Incident[]): HTMLElement {
  const box = el("div", "timeline");
  for (const incident of incidents) {
    const item = el("div", incident.totalScore >= 40 ? "tl-item hi" : "tl-item");
    const path = el("span", "path", incident.path);
    path.title = incident.path;
    item.append(el("span", "tl-time", Number.isFinite(timeOf(incident)) ? fmtTime(incident.timestamp) : DASH), el("span", "ip", incident.ip), el("span", "method", incident.method), path);
    const badges = detectorBadges(
      incident.detections.map((d) => d.detectorId),
      3,
    );
    badges.classList.add("push");
    item.append(badges);
    box.append(item);
  }
  return box;
}
