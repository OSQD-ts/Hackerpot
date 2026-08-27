import type { HitStore } from "../types.js";
import { computeStats } from "./rest.js";

function escapeLabel(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

/**
 * Renders the incident store as Prometheus text-format metrics (v0.0.4). Counters
 * for total incidents and per-detector / per-response breakdowns, gauges for unique
 * IPs and the top offender's score, plus any extra gauges the deployment injects
 * (e.g. active blocks or open honeypot connections).
 */
export async function renderMetrics(store: HitStore, extra?: Record<string, number>): Promise<string> {
  const s = await computeStats(store);
  const out: string[] = [];

  out.push("# HELP hackerpot_incidents_total Total incidents recorded.");
  out.push("# TYPE hackerpot_incidents_total counter");
  out.push(`hackerpot_incidents_total ${s.totalIncidents}`);

  out.push("# HELP hackerpot_unique_ips Distinct source IPs seen.");
  out.push("# TYPE hackerpot_unique_ips gauge");
  out.push(`hackerpot_unique_ips ${s.uniqueIps}`);

  out.push("# HELP hackerpot_incidents_by_detector Incidents in which a detector fired.");
  out.push("# TYPE hackerpot_incidents_by_detector counter");
  for (const [detector, count] of Object.entries(s.byDetector)) {
    out.push(`hackerpot_incidents_by_detector{detector="${escapeLabel(detector)}"} ${count}`);
  }

  out.push("# HELP hackerpot_incidents_by_response Incidents by the response action served.");
  out.push("# TYPE hackerpot_incidents_by_response counter");
  for (const [response, count] of Object.entries(s.byResponse)) {
    out.push(`hackerpot_incidents_by_response{response="${escapeLabel(response)}"} ${count}`);
  }

  out.push("# HELP hackerpot_top_offender_score Highest cumulative score of any single IP.");
  out.push("# TYPE hackerpot_top_offender_score gauge");
  out.push(`hackerpot_top_offender_score ${s.topOffenders[0]?.score ?? 0}`);

  for (const [name, value] of Object.entries(extra ?? {})) {
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) continue;
    out.push(`# TYPE hackerpot_${name} gauge`);
    out.push(`hackerpot_${name} ${value}`);
  }

  return out.join("\n") + "\n";
}
