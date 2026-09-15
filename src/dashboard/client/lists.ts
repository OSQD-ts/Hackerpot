import { app } from "./app.js";
import { detectorBadges, plainBadge, responseBadge } from "./badges.js";
import { SECTIONS } from "./boot.js";
import { replace } from "./charts.js";
import { $, all, el, maybe } from "./dom.js";
import { fmtCompact, fmtDateTime, fmtDur, fmtInt, fmtNum, fmtTime, plural, sevClass } from "./format.js";
import { state } from "./store.js";
import type { AttackSession } from "./types.js";

/**
 * Sessions, Actors and Threat intel: the three screens that show the server's own
 * aggregates rather than something derived in the browser.
 */

function setPill(id: string, n: number): void {
  const pill = maybe(id);
  if (pill !== null) pill.textContent = fmtCompact(n);
}

// ---- sessions -------------------------------------------------------------------

export function renderSessions(): void {
  const host = $("sessions-list");
  setPill("tc-sessions", state.sessions.length);
  if (state.sessions.length === 0) {
    replace(host, el("div", "empty", "No sessions yet."));
    return;
  }
  replace(host, ...state.sessions.map((session, index) => sessionPanel(session, index)));
}

function sessionPanel(session: AttackSession, index: number): HTMLElement {
  const panel = el("div", "panel session");
  const duration = Date.parse(session.lastSeen) - Date.parse(session.firstSeen);
  // A per-minute rate extrapolated from a two-millisecond span is a meaningless six-figure
  // number, so a sub-second session is called a burst.
  const rate = duration >= 1000 ? `${fmtNum(session.incidents / (duration / 6e4), 1)}/min` : "single burst";
  const peak = Math.max(0, ...session.timeline.map((step) => step.totalScore || 0));
  const open = state.openSessions.has(session.ip);

  const head = el("button", "session-head");
  head.type = "button";
  head.setAttribute("aria-expanded", String(open));
  head.setAttribute("aria-controls", `tl-${index}`);
  head.append(
    el("span", "ip big", session.ip),
    detectorBadges(session.detectors, 6),
    el("span", "spacer"),
    el("span", "faint num small", `${plural(session.incidents, "incident")} · ${fmtDur(duration)} · ${rate}`),
    el("span", `score ${sevClass(peak)}`, `${fmtInt(session.score)} pts`),
  );

  const body = el("div", "tl-wrap");
  body.id = `tl-${index}`;
  body.hidden = !open;
  head.addEventListener("click", () => {
    const next = head.getAttribute("aria-expanded") !== "true";
    head.setAttribute("aria-expanded", String(next));
    body.hidden = !next;
    if (next) {
      state.openSessions.add(session.ip);
      if (body.childElementCount === 0) fillSession(body, session);
    } else state.openSessions.delete(session.ip);
  });
  if (open) fillSession(body, session);
  panel.append(head, body);
  return panel;
}

function fillSession(body: HTMLElement, session: AttackSession): void {
  const timeline = el("div", "timeline");
  for (const step of session.timeline) {
    const item = el("div", step.totalScore >= 40 ? "tl-item hi" : "tl-item");
    const path = el("span", "path", step.path);
    path.title = step.path;
    item.append(
      el("span", "tl-time", fmtTime(step.timestamp)),
      el("span", "method", step.method),
      path,
      detectorBadges(step.detectors),
      el("span", "spacer"),
      el("span", "num faint", `+${fmtInt(step.score)} → ${fmtInt(step.totalScore)}`),
      responseBadge(step.respondedWith),
    );
    timeline.append(item);
  }
  const note = el("p", "sub gap-top", "Score climbs top to bottom; the response escalates with it. Responses seen in this session: ");
  for (const response of session.responses) note.append(responseBadge(response), " ");
  body.append(timeline, note);
  if (SECTIONS.incidents) {
    const button = el("button", "sm", "Show these incidents");
    button.type = "button";
    button.addEventListener("click", () => app.incidentsFor(session.ip));
    body.append(button);
  }
}

// ---- actors ---------------------------------------------------------------------

export function renderActors(): void {
  const host = $("actors-list");
  setPill("tc-actors", state.actors.length);
  if (state.actors.length === 0) {
    replace(host, el("div", "empty", "No fingerprinted actors yet. Fingerprints come from HTTP header order and User-Agent family, so protocol-only (SSH, SMTP) traffic does not appear here."));
    return;
  }
  replace(
    host,
    ...state.actors.map((actor) => {
      const panel = el("div", "panel session");
      const duration = Date.parse(actor.lastSeen) - Date.parse(actor.firstSeen);
      const head = el("div", "row-flex");
      head.append(
        el("code", "fp", actor.fingerprint),
        plainBadge(`${actor.ips.length} source IP${actor.ips.length === 1 ? "" : "s"}`, actor.ips.length > 1 ? "rotating" : ""),
        el("span", "spacer"),
        el("span", "faint num small", `${plural(actor.incidents, "incident")} · ${fmtDur(duration)}`),
        el("span", `score ${sevClass(actor.score)}`, `${fmtInt(actor.score)} pts`),
      );
      const note = el(
        "p",
        "sub",
        actor.ips.length > 1 ? "One actor, many addresses: the same client signature arrived from each of these IPs, so rate-limiting any single one would not have stopped them." : "Seen from a single address.",
      );
      const ips = el("div", "badges gap-bottom");
      for (const ip of actor.ips) {
        if (SECTIONS.incidents) {
          const button = el("button", "badge ipbtn", ip);
          button.type = "button";
          button.title = `Show incidents from ${ip}`;
          button.addEventListener("click", () => app.incidentsFor(ip));
          ips.append(button);
        } else ips.append(plainBadge(ip, "ipbadge"));
      }
      panel.append(head, note, ips, detectorBadges(actor.detectors));
      return panel;
    }),
  );
}

// ---- threat intel ---------------------------------------------------------------

export function initIntel(): void {
  for (const button of all<HTMLButtonElement>("#ioc-min button")) {
    button.addEventListener("click", () => {
      state.iocMin = Number(button.dataset["min"] ?? 0) || 0;
      for (const other of all<HTMLButtonElement>("#ioc-min button")) other.setAttribute("aria-pressed", String(other === button));
      renderIoc();
    });
  }
  const listed = (): typeof state.ioc => state.ioc.filter((entry) => entry.score >= state.iocMin);
  $("ioc-copy-txt").addEventListener("click", (event) => void copyText(listed().map((entry) => entry.ip).join("\n"), event.currentTarget as HTMLButtonElement));
  $("ioc-copy-json").addEventListener("click", (event) => void copyText(JSON.stringify(listed(), null, 2), event.currentTarget as HTMLButtonElement));
}

export function renderIoc(): void {
  const host = $("ioc-list");
  const list = state.ioc.filter((entry) => entry.score >= state.iocMin);
  setPill("tc-ioc", state.ioc.length);
  if (list.length === 0) {
    replace(host, el("div", "empty", `No indicators at or above ${state.iocMin} points.`));
    return;
  }
  const table = el("table");
  const head = el("thead");
  const headRow = el("tr");
  for (const [text, cls] of [
    ["Indicator", ""],
    ["Score", "r"],
    ["Incidents", "r"],
    ["Detectors", ""],
    ["First seen", ""],
    ["Last seen", ""],
  ] as const) {
    const th = el("th", cls, text);
    th.scope = "col";
    headRow.append(th);
  }
  head.append(headRow);
  const body = el("tbody");
  for (const entry of list) {
    const tr = el("tr");
    const detectors = el("td");
    detectors.append(detectorBadges(entry.detectors));
    tr.append(
      el("td", "ip", entry.ip),
      el("td", `r num ${sevClass(entry.score)}`, fmtInt(entry.score)),
      el("td", "r num", fmtInt(entry.incidents)),
      detectors,
      el("td", "when", fmtDateTime(entry.firstSeen)),
      el("td", "when", fmtDateTime(entry.lastSeen)),
    );
    body.append(tr);
  }
  table.append(head, body);
  const wrap = el("div", "tablewrap scroll");
  wrap.append(table);
  replace(host, wrap, el("p", "foot", `${fmtInt(list.length)} indicators at or above ${state.iocMin} points.`));
}

export function renderMetrics(): void {
  const pre = maybe("metrics-raw");
  if (pre !== null) pre.textContent = state.metricsRaw === "" ? "—" : state.metricsRaw;
}

async function copyText(text: string, button: HTMLButtonElement): Promise<void> {
  const label = button.textContent ?? "";
  try {
    // Absent outside a secure context (plain http to anything but localhost).
    await navigator.clipboard.writeText(text);
    button.textContent = "copied";
  } catch {
    button.textContent = "copy failed";
  }
  setTimeout(() => {
    button.textContent = label;
  }, 1400);
}
