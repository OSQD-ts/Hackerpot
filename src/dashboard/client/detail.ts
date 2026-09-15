import { timeOf } from "./analysis.js";
import { app } from "./app.js";
import { detectorBadge, detectorBadges, plainBadge, responseBadge } from "./badges.js";
import { BOOT, SECTIONS } from "./boot.js";
import { decodeCandidates } from "./decode.js";
import { el } from "./dom.js";
import { DASH, fmtClock, fmtDur, fmtInt, truncate } from "./format.js";
import { detectorInfo, responseInfo } from "./knowledge.js";
import { state } from "./store.js";
import type { Detection, Incident } from "./types.js";

/**
 * One incident, explained: why each detector fired, what the response did and why, what
 * this address did overall, the payloads it hid behind encodings, its headers, its body,
 * and the raw record.
 *
 * Built when a row is first opened rather than for every row up front. A table of five
 * hundred incidents does not need five hundred detail panels in the document, most of
 * them never looked at.
 */

function line(key: string, value: ReadonlyArray<Node | string>): HTMLElement {
  const row = el("div", "ex-line");
  const v = el("span", "ex-v");
  v.append(...value);
  row.append(el("span", "ex-k", key), v);
  return row;
}

function detectionCard(detection: Detection, shadow: boolean): HTMLElement {
  const info = detectorInfo(detection.detectorId);
  const card = el("div", shadow ? "ex-card shadow" : "ex-card");
  const head = el("div", "ex-head");
  head.append(detectorBadge(detection.detectorId), el("span", "ex-reason", detection.reason), el("span", "ex-score", shadow ? "shadow, +0" : `+${fmtInt(detection.score)}`));
  card.append(head, line("Goal", [info?.goal ?? DASH]), line("Detection", [info?.how ?? DASH]));
  return card;
}

function column(title: string, cards: readonly Node[]): HTMLElement {
  const box = el("div", "explain-col");
  box.append(el("h4", null, title), ...cards);
  return box;
}

function details(summary: string, content: Node): HTMLDetailsElement {
  const box = el("details", "raw");
  box.append(el("summary", null, summary), content);
  return box;
}

export function buildDetail(incident: Incident): HTMLElement {
  const root = el("div", "detail-inner");

  if (incident.fingerprint !== undefined || incident.enrichment !== undefined) {
    const actor = el("div", "actor");
    actor.title = "Header-order and User-Agent fingerprint: the same value from other addresses is the same actor rotating through them. Source is the address's special-use class; private or loopback on a public honeypot means a proxy is leaking internal clients.";
    if (incident.fingerprint !== undefined) actor.append("Actor fingerprint ", el("code", "fp", incident.fingerprint));
    const enrichment = incident.enrichment;
    if (enrichment !== undefined) {
      actor.append(" · source ", el("code", null, enrichment.category));
      if (enrichment.asn) actor.append(` · AS${enrichment.asn}${enrichment.org ? ` ${enrichment.org}` : ""}`);
      if (enrichment.country) actor.append(` · ${enrichment.country}`);
    }
    root.append(actor);
  }

  const why = incident.detections.map((d) => detectionCard(d, false));
  const shadow = (incident.shadowDetections ?? []).map((d) => detectionCard(d, true));
  const left = column(`Why this fired (${incident.detections.length})`, why);
  if (shadow.length > 0) left.append(el("h4", "gap-top", `Shadow detectors (${shadow.length}), not scored`), ...shadow);

  const response = responseInfo(incident.respondedWith);
  const responseCard = el("div", "ex-card");
  const responseHead = el("div", "ex-head");
  responseHead.append(responseBadge(incident.respondedWith), el("span", "ex-score", `IP total ${fmtInt(incident.totalScore)}`));
  responseCard.append(responseHead, line("Action", [response?.does ?? DASH]), line("Why", [response?.why ?? DASH]));
  if (incident.downgradedFrom !== undefined) {
    responseCard.append(line("Downgraded", [`from ${incident.downgradedFrom}: the policy chose it, and a proof requirement refused it.`]));
  }
  const rightCards: Node[] = [responseCard];

  // One request is rarely the story; the address's arc is.
  const kin = state.all.filter((other) => other.ip === incident.ip && Number.isFinite(timeOf(other)));
  if (kin.length > 1) {
    const times = kin.map(timeOf);
    const first = Math.min(...times);
    const last = Math.max(...times);
    const card = el("div", "ex-card");
    const head = el("div", "ex-head");
    head.append(plainBadge("this IP overall"), el("span", "ex-score", `${fmtInt(kin.length)} incidents`));
    card.append(
      head,
      line("Active", [el("b", null, fmtDur(last - first)), ` · ${fmtClock(first)} → ${fmtClock(last)}`]),
      line("Tripped", [detectorBadges(kin.flatMap((h) => h.detections.map((d) => d.detectorId)))]),
      line("Reached", [el("b", null, fmtInt(new Set(kin.map((h) => h.path.split("?")[0])).size)), " distinct paths"]),
    );
    if (SECTIONS.incidents && state.filter.ip !== incident.ip) {
      const only = el("button", "sm", "Show only this address");
      only.type = "button";
      only.addEventListener("click", () => app.incidentsFor(incident.ip));
      card.append(only);
    }
    rightCards.push(card);
  }

  const grid = el("div", "explain-grid");
  grid.append(left, column("Response", rightCards));
  root.append(grid);

  const decoded = decodeCandidates(incident);
  if (decoded.length > 0) {
    const box = el("div", "decode");
    box.append(el("h4", null, `Decoded payloads (${decoded.length})`));
    for (const row of decoded) {
      const item = el("div", "dec-row");
      const meta = el("div", "dec-meta");
      meta.append(el("span", "dec-src", row.src), el("span", "dec-enc", row.encoding));
      item.append(meta, el("pre", "dec-val", row.decoded), el("div", "dec-raw", truncate(row.raw, 160)));
      box.append(item);
    }
    root.append(box);
  }

  const headers = Object.entries(incident.headers ?? {});
  if (headers.length > 0) {
    const table = el("table");
    const head = el("thead");
    const headRow = el("tr");
    for (const text of ["Header", "Value"]) {
      const th = el("th", null, text);
      th.scope = "col";
      headRow.append(th);
    }
    head.append(headRow);
    const body = el("tbody");
    for (const [name, value] of headers) {
      const tr = el("tr");
      tr.append(el("td", "mono muted", name), el("td", "mono breakall", Array.isArray(value) ? value.join(", ") : String(value ?? "")));
      body.append(tr);
    }
    table.append(head, body);
    const wrap = el("div", "tablewrap scroll");
    wrap.append(table);
    root.append(details(`Request headers (${headers.length})${BOOT.redaction.credentials ? ", credentials redacted by the server" : ""}`, wrap));
  }
  if (typeof incident.body === "string" && incident.body !== "") {
    root.append(details(`Request body (${fmtInt(incident.body.length)} characters)`, el("pre", "breakall", incident.body)));
  }

  // Serialised when opened, not when the panel is built: most people never open it.
  const raw = details("Raw incident JSON", el("pre"));
  raw.addEventListener("toggle", () => {
    const pre = raw.querySelector("pre");
    if (raw.open && pre !== null && pre.textContent === "") pre.textContent = JSON.stringify(incident, null, 2);
  });
  root.append(raw);
  return root;
}
