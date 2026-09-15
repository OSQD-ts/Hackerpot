import type { Analysis } from "./analysis.js";
import { dataTable, noData, replace, timeChart } from "./charts.js";
import { fmtDateTime, fmtDur, fmtInt } from "./format.js";

/**
 * The volume chart, shared by Overview and Statistics so the two screens can never draw
 * the same corpus two different ways.
 */

/** A bucket start as an axis label, at the precision the bucket size makes meaningful. */
export function bucketLabel(ms: number, size: number): string {
  const d = new Date(ms);
  if (size >= 864e5) return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  if (size >= 36e5) return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit" });
  if (size >= 6e4) return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  return d.toLocaleTimeString();
}

export function volumeChart(target: HTMLElement, a: Analysis, table: HTMLElement | null, label: string): void {
  if (a.n === 0) {
    replace(target, noData());
    if (table !== null) replace(table);
    return;
  }
  const buckets = a.buckets.map((b) => ({ label: bucketLabel(b.start, a.bucketSize), full: `${fmtDateTime(b.start)}  +${fmtDur(a.bucketSize)}` }));
  timeChart(
    target,
    buckets,
    [
      { name: "incidents", values: a.buckets.map((b) => b.n), slot: 0 },
      { name: "distinct source IPs", values: a.buckets.map((b) => b.ips.size), slot: 1 },
    ],
    { height: 210, label },
  );
  dataTable(
    table,
    ["Bucket", "Incidents", "Source IPs", "Points", "Blocked"],
    a.buckets.filter((b) => b.n > 0).map((b) => [fmtDateTime(b.start), fmtInt(b.n), fmtInt(b.ips.size), fmtInt(b.score), fmtInt(b.blocked)]),
  );
}
