import { classOf, RESPONSE_CLASSES } from "./analysis.js";
import { app } from "./app.js";
import { asApiError, getJson } from "./api.js";
import { detectorBadges, responseBadge } from "./badges.js";
import { rankedBars } from "./charts.js";
import { buildDetail } from "./detail.js";
import { $, byId, clear, el, maybe } from "./dom.js";
import { fmtCompact, fmtDate, fmtDateTime, fmtInt, fmtTime, sevClass } from "./format.js";
import { renderPager } from "./pager.js";
import { explainFailure, incidentQuery, isIncident, LIMITS, matchesFilter, queryMatcher, suggestFor, upgradeIncident } from "./query.js";
import { deleteFilter, refreshSavedFilters, saveFilter, savedFilters } from "./saved.js";
import { type FeedGroup, type FeedOrder, state } from "./store.js";
import { toast } from "./toast.js";
import { download } from "./transfer.js";
import type { Incident } from "./types.js";

/**
 * The Incidents screen, with bothandlerjs's feed controls: outcome chips, a search box that
 * completes its own language, saved filters, a From/To window, order and grouping, export, and a
 * pager. The same controls, in the same order, under the same names, so a hand used to one
 * dashboard finds everything where it expects it in the other.
 *
 * Each row's request is a button: it carries the name, the state and the keys, Enter or Space
 * opens and closes the detail it points at, and the arrow keys walk the feed a row at a time.
 * The row itself keeps a click handler, which needs no role to be useful.
 */

const COLUMNS = 5;
/** Most bars either side panel draws; past that a panel is a list nobody reads. */
const SIDE_ROWS = 10;
const PAGE_SIZES = [25, 50, 100, 250] as const;
const rowIncident = new WeakMap<HTMLTableRowElement, Incident>();
let sequence = 0;
/** Detector names the store has reported, offered as completions for `detector:`. */
let knownDetectors: string[] = [];

function tbody(): HTMLElement {
  return $("rows");
}

export function initIncidents(): void {
  const limit = byId<HTMLSelectElement>("f-limit");
  for (const value of LIMITS) {
    const option = el("option", null, String(value));
    option.value = String(value);
    option.selected = value === state.filter.limit;
    limit.append(option);
  }
  limit.addEventListener("change", () => {
    state.filter.limit = Number(limit.value) || 100;
    void loadIncidents();
  });

  const query = byId<HTMLInputElement>("f-query");
  query.value = state.filter.query;
  // The expression filters what has already been fetched, so typing in it re-renders rather
  // than re-requesting: the API has no grammar, and asking again would return the same rows.
  query.addEventListener("input", () => {
    if (query.value === state.filter.query) return;
    setQuery(query.value);
    showSuggestions(query);
  });
  initSuggestions(query);
  initOutcomeChips();
  initSavedFilters(query);
  initTimeframe();
  initArrangement();

  $("f-export").addEventListener("click", () => {
    const visible = arranged();
    if (visible.length === 0) {
      toast("warn", "Nothing to export", "No incident loaded matches this filter.");
      return;
    }
    // Oldest first, so the file replays in the order the traffic happened. Each line carries the
    // ip, method, path, timestamp and headers `hackerpot replay` reads, and nothing the page was
    // not already sent: redaction happened on the server before the incidents reached it.
    const lines = [...visible].sort((x, y) => Date.parse(x.timestamp) - Date.parse(y.timestamp)).map((incident) => JSON.stringify(incident));
    download(`${lines.join("\n")}\n`, `hackerpot-incidents-${new Date().toISOString().slice(0, 10)}.jsonl`, "application/x-ndjson");
    toast("ok", `Exported ${fmtInt(lines.length)} incident${lines.length === 1 ? "" : "s"}`, "Replay them with `hackerpot replay`.");
  });

  const body = tbody();
  body.addEventListener("click", (event) => {
    const group = (event.target as Element | null)?.closest?.("button.grp-toggle");
    if (group instanceof HTMLButtonElement) {
      toggleGroup(group.dataset["group"] ?? "");
      return;
    }
    const only = (event.target as Element | null)?.closest?.("button.grp-only");
    if (only instanceof HTMLButtonElement) {
      narrowToGroup(only.dataset["group"] ?? "");
      return;
    }
    const row = rowOf(event.target);
    // A click inside an open detail (a <details> summary, a button) is that control's.
    if (row !== undefined) toggle(row);
  });
  // Enter and Space are the disclosure button's own, and its click reaches the handler above.
  // What the browser does not give is walking the feed a row at a time without tabbing through
  // every link inside the ones already open.
  body.addEventListener("keydown", (event) => {
    if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
    const current = event.target instanceof Element ? event.target.closest("button.row-toggle") : null;
    if (current === null) return;
    event.preventDefault();
    const toggles = Array.from(body.querySelectorAll<HTMLButtonElement>("tr.row button.row-toggle"));
    toggles[toggles.indexOf(current as HTMLButtonElement) + (event.key === "ArrowDown" ? 1 : -1)]?.focus();
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

/** The detectors the store has seen, for completing `detector:`. */
export function setDetectorOptions(names: readonly string[]): void {
  knownDetectors = [...new Set(names)].sort();
}

/** Narrows the feed to one address, from a session, an actor or an opened incident. */
export function showAddress(ip: string): void {
  const query = maybe<HTMLInputElement>("f-query");
  const text = `ip:${ip}`;
  if (query !== null) query.value = text;
  setQuery(text);
}

export async function loadIncidents(): Promise<void> {
  const path = `/api/incidents?${incidentQuery(state.filter)}`;
  try {
    const data = await getJson<{ incidents?: unknown }>(path);
    state.incidents = Array.isArray(data.incidents) ? data.incidents.map(upgradeIncident).filter(isIncident).reverse() : [];
    // The management API answers oldest first; the screen reads newest first.
    state.incidents.sort((x, y) => Date.parse(y.timestamp) - Date.parse(x.timestamp));
    app.showFailure("/api/incidents (list)", undefined);
  } catch (error) {
    const failure = asApiError(error, path);
    app.showFailure("/api/incidents (list)", explainFailure(failure.status, failure.endpoint, failure.message));
  }
  renderIncidentRows();
}

// ---- filtering, ordering, grouping ----------------------------------------------

function setQuery(text: string): void {
  state.filter.query = text;
  state.feed.page = 0;
  renderIncidentRows();
}

/** Clears the expression box, as Escape does in it. */
export function clearQuery(): void {
  const query = maybe<HTMLInputElement>("f-query");
  if (query !== null) query.value = "";
  closeSuggestions();
  setQuery("");
}

/** What the chips, the search and the window let through, in the chosen order and grouping. */
function arranged(): Incident[] {
  const outcome = state.filter.outcome ?? "";
  const { from, to } = state.feed;
  const expression = state.filter.query.trim() === "" ? undefined : queryMatcher(state.filter.query);
  const visible = state.incidents.filter((incident) => {
    if (outcome !== "" && classOf(incident.respondedWith) !== outcome) return false;
    const at = Date.parse(incident.timestamp);
    if (from !== undefined && at < from) return false;
    if (to !== undefined && at > to) return false;
    return expression === undefined || expression(incident);
  });
  const order = orderBy(state.feed.order);
  if (state.feed.group === "none") return visible.sort(order);
  // Grouped: the groups in the order their first row would appear, the rows inside each in order.
  const key = groupKey(state.feed.group);
  const sorted = visible.sort(order);
  const firstSeen = new Map<string, number>();
  sorted.forEach((incident, index) => {
    const k = key(incident);
    if (!firstSeen.has(k)) firstSeen.set(k, index);
  });
  return sorted.sort((x, y) => (firstSeen.get(key(x)) ?? 0) - (firstSeen.get(key(y)) ?? 0) || order(x, y));
}

function orderBy(order: FeedOrder): (x: Incident, y: Incident) => number {
  const time = (x: Incident, y: Incident): number => Date.parse(y.timestamp) - Date.parse(x.timestamp);
  if (order === "oldest") return (x, y) => -time(x, y);
  if (order === "score-high") return (x, y) => y.totalScore - x.totalScore || time(x, y);
  if (order === "score-low") return (x, y) => x.totalScore - y.totalScore || time(x, y);
  return time;
}

function groupKey(group: FeedGroup): (incident: Incident) => string {
  if (group === "ip") return (incident) => incident.ip;
  if (group === "actor") return (incident) => incident.actor?.name ?? incident.fingerprint ?? "no fingerprint";
  if (group === "detector") return (incident) => incident.detections[0]?.detector ?? "no detector";
  if (group === "outcome") return (incident) => classOf(incident.respondedWith);
  if (group === "path") return (incident) => incident.path;
  return () => "";
}

/** The query that narrows the feed to one group, for the "only this" button on its heading. */
function groupQuery(group: FeedGroup, value: string): string | undefined {
  const quoted = /[\s"]/.test(value) ? `"${value.replaceAll('"', "")}"` : value;
  if (group === "ip") return `ip:${quoted}`;
  if (group === "detector") return `detector:${quoted}`;
  if (group === "outcome") return `outcome:${quoted}`;
  if (group === "path") return `path:${quoted}`;
  if (group === "actor") return `actor:${quoted}`;
  return undefined;
}

function toggleGroup(key: string): void {
  if (state.feed.collapsed.has(key)) state.feed.collapsed.delete(key);
  else state.feed.collapsed.add(key);
  renderIncidentRows();
}

function narrowToGroup(key: string): void {
  const text = groupQuery(state.feed.group, key);
  if (text === undefined) return;
  const query = maybe<HTMLInputElement>("f-query");
  if (query !== null) query.value = text;
  setQuery(text);
}

// ---- rendering -------------------------------------------------------------------

function emptyRow(text: string): HTMLTableRowElement {
  const tr = el("tr");
  const td = el("td");
  td.colSpan = COLUMNS;
  td.append(el("div", "empty", text));
  tr.append(td);
  return tr;
}

function groupRow(key: string, count: number, collapsed: boolean): HTMLTableRowElement {
  const tr = el("tr", "grp");
  const th = el("th");
  th.colSpan = COLUMNS;
  th.scope = "rowgroup";
  const button = el("button", "grp-toggle");
  button.type = "button";
  button.dataset["group"] = key;
  button.setAttribute("aria-expanded", String(!collapsed));
  button.append(el("span", "chev", collapsed ? "▸" : "▾"), el("span", "grp-key", key), el("span", "grp-n", fmtInt(count)));
  th.append(button);
  if (groupQuery(state.feed.group, key) !== undefined) {
    const only = el("button", "grp-only", "Only this");
    only.type = "button";
    only.dataset["group"] = key;
    only.title = "Narrow the search to this group";
    th.append(only);
  }
  tr.append(th);
  return tr;
}

function buildRow(incident: Incident, flash: boolean): HTMLTableRowElement {
  const tr = el("tr", flash ? "row flash" : "row");
  tr.id = `incident-row-${++sequence}`;
  rowIncident.set(tr, incident);
  // The response's class, not its id: a dozen actions fold into the edges the Overview's
  // part-to-whole bar already names, in the same colours.
  tr.classList.add(`c-${classOf(incident.respondedWith).replaceAll(" ", "-")}`);
  const path = el("span", "path", incident.path);
  path.title = incident.path;
  const request = el("td", "req");
  // The row's one control. It carries the name, the state and the keys; the row itself keeps a
  // click handler for the mouse, which needs no role to be useful. Putting `aria-expanded` on
  // the <tr> instead is what a treegrid does, and this is a table.
  const line = el("button", "row-toggle req-line");
  line.type = "button";
  line.setAttribute("aria-expanded", "false");
  line.setAttribute("aria-controls", `incident-detail-${sequence}`);
  line.setAttribute("aria-label", `${incident.method} ${incident.path}, answered with ${incident.respondedWith}. Evidence.`);
  line.append(el("span", "method", incident.method), path);
  const sub = el("div", "req-sub");
  if (incident.actor !== undefined) sub.append(el("span", "actor", incident.actor.name), " · ");
  sub.append(el("span", "ip", incident.ip));
  const agent = headerValue(incident, "user-agent");
  sub.append(` · ${agent === undefined || agent === "" ? "no User-Agent" : agent}`);
  sub.title = agent ?? "";
  request.append(line, sub);
  const detectors = el("td");
  detectors.append(detectorBadges(incident.detections.map((d) => d.detector)));
  const score = el("td", `score ${sevClass(incident.totalScore)}`, fmtInt(incident.score));
  score.append(el("span", "score-total", ` / ${fmtInt(incident.totalScore)}`));
  score.classList.add("r");
  const response = el("td");
  response.append(responseBadge(incident.respondedWith));
  // The date as well as the time. A feed retaining an hour can be read as "today" without
  // thinking about it; one retaining a week cannot, and "09:14:02" on a row from last Tuesday
  // is the kind of wrong nobody catches because it looks right. The date is its own element so
  // the stylesheet can drop it where the column has no room.
  const when = el("td", "when edge");
  when.append(el("span", "when-date", fmtDate(incident.timestamp)), el("span", "when-time", fmtTime(incident.timestamp)));
  when.title = fmtDateTime(incident.timestamp);
  tr.append(when, request, detectors, score, response);
  return tr;
}

function headerValue(incident: Incident, name: string): string | undefined {
  const value = incident.headers[name];
  return Array.isArray(value) ? value.join(", ") : (value as string | undefined);
}

export function renderIncidentRows(): void {
  const body = tbody();
  clear(body);
  updateIncidentPill();
  const visible = arranged();
  renderSide(visible);
  renderSummary(visible.length);

  const size = state.feed.pageSize;
  const pages = Math.max(1, Math.ceil(visible.length / size));
  state.feed.page = Math.min(state.feed.page, pages - 1);
  const start = state.feed.page * size;
  const page = visible.slice(start, start + size);
  renderPagers(visible.length, start, page.length, pages);

  if (page.length === 0) {
    const filtered = state.filter.query.trim() !== "" || (state.filter.outcome ?? "") !== "" || state.feed.from !== undefined || state.feed.to !== undefined;
    body.append(emptyRow(filtered ? "No incidents match this filter." : "No incidents yet. Run `npm run simulate` against the demo to see some."));
    return;
  }

  if (state.feed.group === "none") {
    for (const incident of page) appendRow(body, incident);
    return;
  }
  // Each group's heading counts the whole group, not just the part on this page.
  const key = groupKey(state.feed.group);
  const totals = new Map<string, number>();
  for (const incident of visible) totals.set(key(incident), (totals.get(key(incident)) ?? 0) + 1);
  let current: string | undefined;
  for (const incident of page) {
    const k = key(incident);
    if (k !== current) {
      current = k;
      body.append(groupRow(k, totals.get(k) ?? 0, state.feed.collapsed.has(k)));
    }
    if (!state.feed.collapsed.has(k)) appendRow(body, incident);
  }
}

function appendRow(body: HTMLElement, incident: Incident): void {
  const row = buildRow(incident, false);
  body.append(row);
  if (state.openIncidents.has(incident.id)) setOpen(row, true);
}

function renderPagers(total: number, start: number, shown: number, pages: number): void {
  const model = {
    page: state.feed.page,
    from: total === 0 ? 0 : start + 1,
    to: start + shown,
    total,
    atStart: state.feed.page === 0,
    atEnd: state.feed.page >= pages - 1,
    go: (page: number) => {
      state.feed.page = page;
      renderIncidentRows();
    },
    size: {
      current: state.feed.pageSize,
      choices: PAGE_SIZES,
      set: (next: number) => {
        state.feed.pageSize = next;
        state.feed.page = 0;
        renderIncidentRows();
      },
    },
  };
  const top = maybe("feed-pager-top");
  const bottom = maybe("feed-pager-bottom");
  // Hidden while everything fits: a pager with nowhere to go is a control that does nothing.
  const needed = total > PAGE_SIZES[0];
  if (top !== null) {
    top.hidden = !needed;
    if (needed) renderPager(top, model, { withSize: true });
  }
  if (bottom !== null) {
    bottom.hidden = pages <= 1;
    if (pages > 1) renderPager(bottom, model, { withSize: false });
  }
}

/**
 * What the rows the filter shows add up to: which detectors fired in them, and who sent them.
 * Drawn from every matching row rather than one page, so a page boundary does not change them.
 */
function renderSide(visible: readonly Incident[]): void {
  const detectorsHost = maybe("side-detectors");
  const sourcesHost = maybe("side-sources");
  if (detectorsHost === null || sourcesHost === null) return;
  const detectors = new Map<string, number>();
  const sources = new Map<string, number>();
  for (const incident of visible) {
    for (const detection of incident.detections) detectors.set(detection.detector, (detectors.get(detection.detector) ?? 0) + 1);
    const who = incident.actor === undefined ? incident.ip : `${incident.ip} (${incident.actor.name})`;
    sources.set(who, (sources.get(who) ?? 0) + 1);
  }
  const top = (counts: Map<string, number>): Array<readonly [string, number]> => [...counts].sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0])).slice(0, SIDE_ROWS);
  const scope = visible.length === 0 ? "" : `in these ${fmtInt(visible.length)}`;
  setHint("side-scope", scope);
  setHint("side-scope-ips", scope);
  rankedBars(detectorsHost, top(detectors), { total: visible.length, emptyText: "Nothing has fired in these rows." });
  rankedBars(sourcesHost, top(sources), { total: visible.length, emptyText: "No sources in these rows." });
}

function setHint(id: string, text: string): void {
  const node = maybe(id);
  if (node !== null) node.textContent = text;
}

/** The feed panel's heading: what the table holds against what the filter lets through. */
function renderSummary(shown: number): void {
  const held = state.incidents.length;
  setHint("feed-summary", shown === held ? `${fmtInt(held)} loaded` : `${fmtInt(shown)} of ${fmtInt(held)} loaded match`);
}

// ---- controls ----------------------------------------------------------------------

/** "All", then one chip per response class, in the Overview's order. */
function initOutcomeChips(): void {
  const host = maybe("f-outcome");
  if (host === null) return;
  const choices: Array<[value: string, label: string, note: string]> = [["", "All", "every incident loaded"], ...RESPONSE_CLASSES.map((c) => [c.name, c.name.charAt(0).toUpperCase() + c.name.slice(1), c.note] as [string, string, string])];
  for (const [value, label, note] of choices) {
    const button = el("button", null, label);
    button.type = "button";
    button.dataset["outcome"] = value;
    button.title = note;
    button.addEventListener("click", () => {
      state.filter.outcome = value;
      state.feed.page = 0;
      drawOutcomeChips();
      renderIncidentRows();
    });
    host.append(button);
  }
  drawOutcomeChips();
}

function drawOutcomeChips(): void {
  const host = maybe("f-outcome");
  if (host === null) return;
  for (const button of host.querySelectorAll<HTMLButtonElement>("button")) button.setAttribute("aria-pressed", String(button.dataset["outcome"] === (state.filter.outcome ?? "")));
}

let highlighted = -1;

function suggestionValues(): Record<string, readonly string[]> {
  const actions = [...new Set(state.incidents.map((incident) => incident.respondedWith))].sort();
  const methods = [...new Set(state.incidents.map((incident) => incident.method))].sort();
  return { detector: knownDetectors, action: actions, method: methods };
}

function closeSuggestions(): void {
  const list = maybe("f-suggest");
  const input = maybe<HTMLInputElement>("f-query");
  if (list === null) return;
  list.hidden = true;
  clear(list);
  highlighted = -1;
  input?.setAttribute("aria-expanded", "false");
}

function showSuggestions(input: HTMLInputElement): void {
  const caret = input.selectionStart ?? input.value.length;
  const { options, from, to } = suggestFor(input.value, caret, suggestionValues());
  const list = $("f-suggest");
  if (options.length === 0 || input.value.slice(from, to) === options[0]) {
    closeSuggestions();
    return;
  }
  clear(list);
  highlighted = -1;
  options.slice(0, 12).forEach((option) => {
    const item = el("li", null, option);
    item.setAttribute("role", "option");
    item.setAttribute("aria-selected", "false");
    // mousedown rather than click: the input would lose focus first, and its blur closes the list.
    item.addEventListener("mousedown", (event) => {
      event.preventDefault();
      applySuggestion(input, option, from, to);
    });
    list.append(item);
  });
  list.hidden = false;
  input.setAttribute("aria-expanded", "true");
}

function applySuggestion(input: HTMLInputElement, option: string, from: number, to: number): void {
  const before = input.value.slice(0, from);
  input.value = `${before}${option}${input.value.slice(to)}`;
  const caret = before.length + option.length;
  input.setSelectionRange(caret, caret);
  setQuery(input.value);
  closeSuggestions();
  // Completing a field leaves the caret after its colon, where the values are: offer them now.
  showSuggestions(input);
  input.focus();
}

function initSuggestions(input: HTMLInputElement): void {
  input.addEventListener("keydown", (event) => {
    const list = $("f-suggest");
    const items = Array.from(list.querySelectorAll("li"));
    if (list.hidden || items.length === 0) return;
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      highlighted = (highlighted + (event.key === "ArrowDown" ? 1 : items.length - 1) + (highlighted === -1 && event.key === "ArrowUp" ? 1 : 0)) % items.length;
      items.forEach((item, index) => item.setAttribute("aria-selected", String(index === highlighted)));
      return;
    }
    if ((event.key === "Enter" || event.key === "Tab") && highlighted >= 0) {
      event.preventDefault();
      const caret = input.selectionStart ?? input.value.length;
      const { from, to } = suggestFor(input.value, caret, suggestionValues());
      applySuggestion(input, items[highlighted]?.textContent ?? "", from, to);
    }
  });
  input.addEventListener("focus", () => showSuggestions(input));
  input.addEventListener("blur", () => {
    setTimeout(closeSuggestions, 120);
  });
}

/** The saved-filter control: a list to load from, a name box to save under, and Delete. */
function initSavedFilters(input: HTMLInputElement): void {
  const host = maybe("saved-filters");
  if (host === null) return;
  let selected = "";
  let naming = false;

  const redraw = (): void => {
    clear(host);
    const entries = savedFilters();
    if (!entries.some((entry) => entry.name === selected)) selected = "";

    const select = el("select");
    select.setAttribute("aria-label", "Saved filters");
    const first = el("option", null, entries.length === 0 ? "No saved filters" : "Saved filters…");
    first.value = "";
    select.append(first);
    for (const entry of entries) {
      const option = el("option", null, entry.name);
      option.value = entry.name;
      select.append(option);
    }
    select.value = selected;
    select.addEventListener("change", () => {
      selected = select.value;
      const chosen = entries.find((entry) => entry.name === selected);
      if (chosen !== undefined) {
        input.value = chosen.query;
        state.filter.outcome = chosen.filter === "all" ? "" : chosen.filter;
        drawOutcomeChips();
        setQuery(chosen.query);
      }
      redraw();
    });
    host.append(select);

    if (naming) {
      const name = el("input", "saved-name");
      name.type = "text";
      name.maxLength = 60;
      name.placeholder = "Name this filter";
      name.setAttribute("aria-label", "Name for this filter");
      name.title = "Enter to save, Escape to cancel";
      name.value = selected;
      const confirm = el("button", "saved-confirm", "Save");
      confirm.type = "button";
      const cancel = el("button", null, "Cancel");
      cancel.type = "button";
      let finished = false;
      let leavingFor: "cancel" | "confirm" | undefined;
      const done = (): void => {
        finished = true;
        naming = false;
        redraw();
      };
      const commit = (options: { fromBlur?: boolean } = {}): void => {
        if (finished) return;
        const chosen = name.value.trim();
        if (chosen === "") {
          if (options.fromBlur === true) done();
          else name.focus();
          return;
        }
        finished = true;
        void saveFilter({ name: chosen, query: input.value.trim(), filter: state.filter.outcome === "" || state.filter.outcome === undefined ? "all" : state.filter.outcome }).then((result) => {
          selected = chosen;
          done();
          if (result.ok) toast("ok", "Filter saved", `"${chosen}" is kept by this dashboard, for anybody who opens it.`);
          else toast("warn", "Saved in this browser only", `The dashboard did not take it${result.error === undefined ? "" : ` (${result.error})`}.`);
        });
      };
      name.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          commit();
        } else if (event.key === "Escape") {
          event.preventDefault();
          done();
        }
      });
      // Leaving the box with a name in it saves under that name; Escape and Cancel cancel. The
      // pointer-down flag tells them apart, because a button does not take focus on click everywhere.
      cancel.addEventListener("pointerdown", () => {
        leavingFor = "cancel";
      });
      confirm.addEventListener("pointerdown", () => {
        leavingFor = "confirm";
      });
      name.addEventListener("blur", () => {
        setTimeout(() => {
          if (finished) return;
          if (leavingFor !== undefined) {
            leavingFor = undefined;
            return;
          }
          commit({ fromBlur: true });
        }, 140);
      });
      confirm.addEventListener("click", () => commit());
      cancel.addEventListener("click", done);
      host.append(name, confirm, cancel);
      name.focus();
      name.select();
      return;
    }

    const save = el("button", null, "Save");
    save.type = "button";
    save.title = "Save this filter under a name. The dashboard keeps it, for anybody who opens it.";
    save.addEventListener("click", () => {
      naming = true;
      redraw();
    });
    host.append(save);

    if (selected !== "") {
      const remove = el("button", null, "Delete");
      remove.type = "button";
      remove.title = `Delete the saved filter "${selected}". The query in the box is left as it is.`;
      remove.addEventListener("click", () => {
        const gone = selected;
        void deleteFilter(gone).then(() => {
          selected = "";
          redraw();
          toast("ok", "Filter deleted", `"${gone}" is no longer saved.`);
        });
      });
      host.append(remove);
    }
  };

  redraw();
  // Drawn at once from what is known, then again when the listener has answered.
  void refreshSavedFilters().then(redraw);
}

/** From and To, either end open: "since the incident", "up to when it stopped", or between. */
function initTimeframe(): void {
  const from = maybe<HTMLInputElement>("from-at");
  const to = maybe<HTMLInputElement>("to-at");
  const clearButton = maybe<HTMLButtonElement>("timeframe-clear");
  if (from === null || to === null || clearButton === null) return;
  const read = (input: HTMLInputElement): number | undefined => {
    if (input.value === "") return undefined;
    const parsed = new Date(input.value).getTime();
    return Number.isFinite(parsed) ? parsed : undefined;
  };
  const apply = (settled: boolean): void => {
    const start = read(from);
    const end = read(to);
    if (settled && start !== undefined && end !== undefined && end < start) toast("warn", "That window runs backwards", "The end is before the start, so nothing can fall inside it.");
    state.feed.from = start;
    state.feed.to = end;
    state.feed.page = 0;
    clearButton.hidden = start === undefined && end === undefined;
    renderIncidentRows();
  };
  // `input` as well as `change`: a datetime-local holds `change` back until blur while it is typed.
  for (const input of [from, to]) {
    input.addEventListener("input", () => apply(false));
    input.addEventListener("change", () => apply(true));
  }
  clearButton.addEventListener("click", () => {
    from.value = "";
    to.value = "";
    apply(true);
  });
}

function initArrangement(): void {
  const order = maybe<HTMLSelectElement>("feed-order");
  const group = maybe<HTMLSelectElement>("feed-group");
  const roll = maybe<HTMLButtonElement>("feed-roll");
  if (order === null || group === null || roll === null) return;
  order.value = state.feed.order;
  group.value = state.feed.group;
  const reflectRoll = (): void => {
    roll.hidden = state.feed.group === "none";
    const rolled = state.feed.collapsed.size > 0;
    roll.textContent = rolled ? "Expand all" : "Roll up all";
    roll.setAttribute("aria-pressed", String(rolled));
  };
  order.addEventListener("change", () => {
    state.feed.order = order.value as FeedOrder;
    state.feed.page = 0;
    renderIncidentRows();
  });
  group.addEventListener("change", () => {
    state.feed.group = group.value as FeedGroup;
    // A grouping somebody has just chosen opens: rolled up, it would be headings for rows unseen.
    state.feed.collapsed = new Set();
    state.feed.page = 0;
    reflectRoll();
    renderIncidentRows();
  });
  roll.addEventListener("click", () => {
    if (state.feed.collapsed.size > 0) state.feed.collapsed = new Set();
    else {
      const key = groupKey(state.feed.group);
      state.feed.collapsed = new Set(state.incidents.map(key));
    }
    reflectRoll();
    renderIncidentRows();
  });
  reflectRoll();
}

// ---- opening rows --------------------------------------------------------------------

function toggle(row: HTMLTableRowElement): void {
  setOpen(row, !row.classList.contains("open"));
}

/** The disclosure the row's state lives on, when the row has one. */
const toggleOf = (row: HTMLTableRowElement): HTMLButtonElement | null => row.querySelector<HTMLButtonElement>("button.row-toggle");

function setOpen(row: HTMLTableRowElement, open: boolean): void {
  const incident = rowIncident.get(row);
  if (incident === undefined) return;
  row.classList.toggle("open", open);
  const button = toggleOf(row);
  button?.setAttribute("aria-expanded", String(open));
  const next = row.nextElementSibling;
  let detail = next instanceof HTMLTableRowElement && next.classList.contains("detail") ? next : undefined;
  if (open) {
    if (detail === undefined) {
      detail = el("tr", "detail");
      detail.id = button?.getAttribute("aria-controls") ?? "";
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

// ---- counts and live incidents ------------------------------------------------------

/**
 * The Incidents pill: how many were recorded, from whichever source knows more. The title says
 * what the table itself holds, so neither number pretends to be the other.
 */
function updateIncidentPill(): void {
  const pill = maybe("tc-incidents");
  if (pill === null) return;
  const held = state.incidents.length;
  const counted = incidentTotal();
  pill.textContent = fmtCompact(counted ?? held);
  pill.title = counted === undefined ? `${held} incidents loaded` : `${counted} incidents recorded · ${held} shown here`;
}

/**
 * How many incidents happened, from whichever source knows more.
 *
 * The minute counts start when the dashboard first subscribes to the feed, which is when the
 * first viewer opens it, so everything before that is missing from them; the store's total is
 * missing whatever retention evicted. Neither can over-count, so the larger is the better lower
 * bound. Undefined until either has arrived.
 */
export function incidentTotal(): number | undefined {
  const counted = state.counts?.total;
  const stored = state.stats === undefined ? undefined : state.stats.totalIncidents + state.liveSinceStats;
  if (counted === undefined) return stored;
  return stored === undefined ? counted : Math.max(counted, stored);
}

/** A live incident into the table, keeping the load limit. */
export function prependIncident(incident: Incident): void {
  // Counted before the filter, because an incident the current filter hides still happened.
  if (state.counts !== undefined) state.counts = { ...state.counts, total: state.counts.total + 1 };
  if (!matchesFilter(incident, state.filter)) return;
  if (state.incidents.some((existing) => existing.id === incident.id)) return;
  state.incidents.unshift(incident);
  while (state.incidents.length > state.filter.limit) {
    const dropped = state.incidents.pop();
    if (dropped !== undefined) state.openIncidents.delete(dropped.id);
  }
  // The fast path: newest first, ungrouped, on the first page, the row simply goes on top.
  const body = tbody();
  if (state.feed.order === "newest" && state.feed.group === "none" && state.feed.page === 0 && state.feed.from === undefined && state.feed.to === undefined && body.querySelector(".empty") === null) {
    body.prepend(buildRow(incident, true));
    const rows = body.querySelectorAll<HTMLTableRowElement>("tr.row");
    if (rows.length > state.feed.pageSize) {
      const last = rows[rows.length - 1];
      const detail = last?.nextElementSibling;
      if (detail instanceof HTMLTableRowElement && detail.classList.contains("detail")) detail.remove();
      last?.remove();
    }
    updateIncidentPill();
    scheduleRender(false);
    return;
  }
  scheduleRender(true);
}

let renderTimer: ReturnType<typeof setTimeout> | undefined;
let fullPending = false;

/**
 * A burst of live incidents redraws once rather than once per incident: the rows when their
 * order or grouping has to be worked out again, and otherwise only the side panels and pagers.
 */
function scheduleRender(full: boolean): void {
  fullPending ||= full;
  if (renderTimer !== undefined) return;
  renderTimer = setTimeout(() => {
    renderTimer = undefined;
    if (fullPending) {
      fullPending = false;
      renderIncidentRows();
      return;
    }
    const visible = arranged();
    renderSide(visible);
    renderSummary(visible.length);
    const pages = Math.max(1, Math.ceil(visible.length / state.feed.pageSize));
    renderPagers(visible.length, state.feed.page * state.feed.pageSize, Math.min(state.feed.pageSize, visible.length), pages);
  }, 250);
}
