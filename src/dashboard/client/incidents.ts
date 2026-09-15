import { app } from "./app.js";
import { asApiError, getJson } from "./api.js";
import { detectorBadges, responseBadge } from "./badges.js";
import { buildDetail } from "./detail.js";
import { $, byId, clear, el, maybe } from "./dom.js";
import { fmtCompact, fmtInt, fmtTime, sevClass } from "./format.js";
import { explainFailure, incidentQuery, isIncident, LIMITS, matchesFilter } from "./query.js";
import { state } from "./store.js";
import type { Incident } from "./types.js";

/**
 * The Incidents screen: a filtered table, newest first, where every row opens into the
 * explanation of that incident.
 *
 * Rows are real keyboard stops. Enter or Space opens and closes one, the arrow keys move
 * between rows, and each carries `aria-expanded` pointing at its detail, so the table is
 * as usable without a pointer as with one.
 */

const COLUMNS = 7;
const rowIncident = new WeakMap<HTMLTableRowElement, Incident>();
let sequence = 0;

function tbody(): HTMLElement {
  return $("rows");
}

export function initIncidents(): void {
  const detector = byId<HTMLSelectElement>("f-detector");
  const ip = byId<HTMLInputElement>("f-ip");
  const limit = byId<HTMLSelectElement>("f-limit");
  for (const value of LIMITS) {
    const option = el("option", null, String(value));
    option.value = String(value);
    option.selected = value === state.filter.limit;
    limit.append(option);
  }
  setDetectorOptions([]);
  ip.value = state.filter.ip;

  detector.addEventListener("change", () => {
    state.filter.detector = detector.value;
    void loadIncidents();
  });
  const applyIp = (): void => {
    if (ip.value.trim() === state.filter.ip) return;
    state.filter.ip = ip.value.trim();
    void loadIncidents();
  };
  ip.addEventListener("change", applyIp);
  ip.addEventListener("keydown", (event) => {
    if (event.key === "Enter") applyIp();
  });
  limit.addEventListener("change", () => {
    state.filter.limit = Number(limit.value) || 100;
    void loadIncidents();
  });
  $("f-clear").addEventListener("click", () => {
    state.filter.detector = "";
    state.filter.ip = "";
    detector.value = "";
    ip.value = "";
    void loadIncidents();
  });

  const body = tbody();
  body.addEventListener("click", (event) => {
    const row = rowOf(event.target);
    // A click inside an open detail (a <details> summary, a button) is that control's.
    if (row !== undefined) toggle(row);
  });
  body.addEventListener("keydown", (event) => {
    const row = event.target instanceof HTMLTableRowElement && event.target.classList.contains("row") ? event.target : undefined;
    if (row === undefined) return;
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      toggle(row);
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const rows = Array.from(body.querySelectorAll<HTMLTableRowElement>("tr.row"));
      const next = rows[rows.indexOf(row) + (event.key === "ArrowDown" ? 1 : -1)];
      next?.focus();
    }
  });
}

function rowOf(target: EventTarget | null): HTMLTableRowElement | undefined {
  let node = target instanceof Element ? target : null;
  while (node !== null && node !== tbody()) {
    if (node instanceof HTMLTableRowElement) return node.classList.contains("row") ? node : undefined;
    node = node.parentElement;
  }
  return undefined;
}

/** The detector filter's choices: every detector the store has seen, plus whichever is selected. */
export function setDetectorOptions(names: readonly string[]): void {
  const select = maybe<HTMLSelectElement>("f-detector");
  if (select === null) return;
  const wanted = [...new Set([...names, ...(state.filter.detector !== "" ? [state.filter.detector] : [])])].sort();
  clear(select);
  const any = el("option", null, "all detectors");
  any.value = "";
  select.append(any);
  for (const name of wanted) {
    const option = el("option", null, name);
    option.value = name;
    select.append(option);
  }
  select.value = state.filter.detector;
}

export async function loadIncidents(): Promise<void> {
  const path = `/api/incidents?${incidentQuery(state.filter)}`;
  try {
    const data = await getJson<{ incidents?: unknown }>(path);
    state.incidents = Array.isArray(data.incidents) ? data.incidents.filter(isIncident).reverse() : [];
    // The management API answers oldest first; the screen reads newest first.
    state.incidents.sort((x, y) => Date.parse(y.timestamp) - Date.parse(x.timestamp));
    app.showFailure("/api/incidents (list)", undefined);
  } catch (error) {
    const failure = asApiError(error, path);
    app.showFailure("/api/incidents (list)", explainFailure(failure.status, failure.endpoint, failure.message));
  }
  renderIncidentRows();
}

function emptyRow(text: string): HTMLTableRowElement {
  const tr = el("tr");
  const td = el("td");
  td.colSpan = COLUMNS;
  td.append(el("div", "empty", text));
  tr.append(td);
  return tr;
}

function buildRow(incident: Incident, flash: boolean): HTMLTableRowElement {
  const tr = el("tr", flash ? "row flash" : "row");
  tr.tabIndex = 0;
  tr.id = `incident-row-${++sequence}`;
  tr.setAttribute("aria-expanded", "false");
  tr.setAttribute("aria-controls", `incident-detail-${sequence}`);
  rowIncident.set(tr, incident);
  const path = el("span", "path", incident.path);
  path.title = incident.path;
  const pathCell = el("td");
  pathCell.append(path);
  const detectors = el("td");
  detectors.append(detectorBadges(incident.detections.map((d) => d.detectorId)));
  const score = el("td", `score ${sevClass(incident.totalScore)}`, fmtInt(incident.score));
  score.append(el("span", "score-total", ` / ${fmtInt(incident.totalScore)}`));
  const response = el("td");
  response.append(responseBadge(incident.respondedWith));
  tr.append(el("td", "when", fmtTime(incident.timestamp)), el("td", "ip", incident.ip), el("td", "method", incident.method), pathCell, detectors, score, response);
  return tr;
}

function toggle(row: HTMLTableRowElement): void {
  setOpen(row, row.getAttribute("aria-expanded") !== "true");
}

function setOpen(row: HTMLTableRowElement, open: boolean): void {
  const incident = rowIncident.get(row);
  if (incident === undefined) return;
  row.setAttribute("aria-expanded", String(open));
  const next = row.nextElementSibling;
  let detail = next instanceof HTMLTableRowElement && next.classList.contains("detail") ? next : undefined;
  if (open) {
    if (detail === undefined) {
      detail = el("tr", "detail");
      detail.id = row.getAttribute("aria-controls") ?? "";
      const td = el("td");
      td.colSpan = COLUMNS;
      td.append(buildDetail(incident));
      detail.append(td);
      row.after(detail);
    }
    detail.hidden = false;
    state.openIncidents.add(incident.id);
  } else {
    if (detail !== undefined) detail.hidden = true;
    state.openIncidents.delete(incident.id);
  }
}

export function renderIncidentRows(): void {
  const body = tbody();
  clear(body);
  const pill = maybe("tc-incidents");
  if (pill !== null) pill.textContent = fmtCompact(state.incidents.length);
  if (state.incidents.length === 0) {
    body.append(emptyRow(state.filter.ip !== "" || state.filter.detector !== "" ? "No incidents match this filter." : "No incidents yet. Run `npm run attack:all` against the honeypot to see some."));
    return;
  }
  for (const incident of state.incidents) {
    const row = buildRow(incident, false);
    body.append(row);
    if (state.openIncidents.has(incident.id)) setOpen(row, true);
  }
}

/** A live incident at the top of the table, if the filter wants it, keeping the row limit. */
export function prependIncident(incident: Incident): void {
  if (!matchesFilter(incident, state.filter)) return;
  if (state.incidents.some((existing) => existing.id === incident.id)) return;
  state.incidents.unshift(incident);
  const body = tbody();
  if (body.querySelector(".empty") !== null) clear(body);
  body.prepend(buildRow(incident, true));
  while (state.incidents.length > state.filter.limit) {
    const dropped = state.incidents.pop();
    const rows = body.querySelectorAll<HTMLTableRowElement>("tr.row");
    const last = rows[rows.length - 1];
    if (last === undefined) break;
    const detail = last.nextElementSibling;
    if (detail instanceof HTMLTableRowElement && detail.classList.contains("detail")) detail.remove();
    last.remove();
    if (dropped !== undefined) state.openIncidents.delete(dropped.id);
  }
  const pill = maybe("tc-incidents");
  if (pill !== null) pill.textContent = fmtCompact(state.incidents.length);
}
