import { app } from "./app.js";
import { detectorBadge, responseBadge } from "./badges.js";
import { $, clear, el, maybe } from "./dom.js";
import { fmtInt } from "./format.js";
import { detectorInfo, detectorList, responseInfo, responseList } from "./knowledge.js";

/**
 * What each detector looks for and what each response does, on a screen of its own.
 *
 * The same shape bothandlerjs's Reference has: an index on the left, one entry open on the
 * right, and every name elsewhere on the page a link into it. An expanded incident explains
 * the detectors that fired on *it*, which is no help to somebody reading a rule, a metric or
 * an alert that names one they have not seen — so this answers for all of them, from static
 * text, with no request and no engine behind it.
 */

/** `detector:decoy-path`, or `""` for the screen's own introduction. */
let selected = "";
/** Detectors this deployment actually runs, reported by the store. */
let installed = new Set<string>();
/** The open entry's heading, kept rather than looked up: the article is redrawn whole. */
let title: HTMLElement | undefined;

export function selectedReference(): string {
  return selected;
}

/**
 * Sets the selection from a URL. Checked for shape rather than against the entries: a link
 * may name a detector this build does not carry, and that is drawn as the introduction.
 */
export function setSelectedReference(value: string): void {
  selected = /^(?:detector|action):[\w.:-]{1,120}$/.test(value) ? value : "";
}

/** The detectors the store has seen, so the index can say which ones are running here. */
export function setInstalledDetectors(names: readonly string[]): void {
  installed = new Set(names);
  if (drawn) draw();
}

export function hasReference(kind: "detector" | "action", id: string): boolean {
  return kind === "detector" ? detectorInfo(id) !== undefined : responseInfo(id) !== undefined;
}

/** Switches to the Reference screen with one entry open. */
export function openReference(kind: "detector" | "action", id: string): void {
  selected = `${kind}:${id}`;
  app.showTab("reference");
  draw();
  title?.focus({ preventScroll: true });
}

/**
 * A name, as a link to its entry where there is one and as plain text where there is not.
 *
 * A button rather than an anchor: it changes what this page shows, and embedded it must not
 * touch the host page's URL. The click stops where it lands, because most of these sit inside
 * rows that open and close on a click of their own.
 */
export function referenceLink(kind: "detector" | "action", id: string, node: HTMLElement): HTMLElement {
  if (!hasReference(kind, id)) return node;
  const link = el("button", "ref-link");
  link.type = "button";
  link.title = `How ${kind === "detector" ? "the detector" : "the action"} “${id}” works`;
  link.append(node);
  link.addEventListener("click", (event) => {
    event.stopPropagation();
    openReference(kind, id);
  });
  return link;
}

let drawn = false;

export function initReference(): void {
  const filter = maybe<HTMLInputElement>("ref-filter");
  if (filter === null) return;
  filter.addEventListener("input", () => draw());
  filter.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || filter.value === "") return;
    filter.value = "";
    draw();
  });
}

export function renderReference(): void {
  drawn = true;
  draw();
}

function draw(): void {
  const needle = (maybe<HTMLInputElement>("ref-filter")?.value ?? "").trim().toLowerCase();
  const matches = (...text: string[]): boolean => needle === "" || text.some((part) => part.toLowerCase().includes(needle));
  const detectors = detectorList().filter(([id, info]) => matches(id, info.goal, info.how));
  const responses = responseList().filter(([id, info]) => matches(id, info.does, info.why));

  drawIndex(detectors, responses);
  drawArticle();

  const count = maybe("ref-count");
  if (count !== null) count.textContent = `${fmtInt(detectors.length)} detectors · ${fmtInt(responses.length)} actions`;
  const empty = maybe("ref-empty");
  if (empty !== null) empty.hidden = detectors.length > 0 || responses.length > 0;
}

function drawIndex(detectors: ReadonlyArray<[string, unknown]>, responses: ReadonlyArray<[string, unknown]>): void {
  const nav = $("ref-index");
  clear(nav);
  nav.append(
    group(
      "Detectors",
      detectors.map(([id]) => item("detector", id, installed.has(id) ? "running" : undefined)),
    ),
    group(
      "Response actions",
      responses.map(([id]) => item("action", id, undefined)),
    ),
  );
}

function group(title: string, items: readonly HTMLElement[]): HTMLElement {
  const box = el("div", "ref-group");
  box.append(el("h3", null, title));
  const list = el("ul");
  for (const node of items) {
    const li = el("li");
    li.append(node);
    list.append(li);
  }
  if (items.length === 0) list.append(el("li", "ref-none", "Nothing matches that."));
  box.append(list);
  return box;
}

function item(kind: "detector" | "action", id: string, tag: string | undefined): HTMLElement {
  const button = el("button", "ref-item");
  button.type = "button";
  button.append(el("span", "ref-id", id));
  if (tag !== undefined) button.append(el("span", "ref-tag", tag));
  if (selected === `${kind}:${id}`) button.setAttribute("aria-current", "true");
  button.addEventListener("click", () => {
    selected = `${kind}:${id}`;
    draw();
    title?.focus({ preventScroll: true });
  });
  return button;
}

function drawArticle(): void {
  const article = $("ref-article");
  clear(article);
  const [kind, id] = selected.split(":", 2) as [string, string | undefined];
  const detector = kind === "detector" && id !== undefined ? detectorInfo(id) : undefined;
  const response = kind === "action" && id !== undefined ? responseInfo(id) : undefined;

  if (detector !== undefined && id !== undefined) {
    article.append(
      head("Detector", id, detectorBadge(id), detector.goal, [installed.has(id) ? fact("running here", true) : fact("not installed here", false)]),
      // The goal is the lede, so the body is the half a reader came for: the method.
      body([["How it is recognised", detector.how]]),
    );
    return;
  }
  if (response !== undefined && id !== undefined) {
    article.append(
      head("Response action", id, responseBadge(id), response.does, []),
      body([["Why a policy chooses it", response.why]]),
    );
    return;
  }
  article.append(intro());
}

function head(kicker: string, id: string, badge: HTMLElement, lede: string, facts: readonly HTMLElement[]): HTMLElement {
  const header = el("header");
  header.append(el("div", "ref-kicker", kicker));
  title = el("h2", null, id);
  title.tabIndex = -1;
  header.append(title, el("p", "ref-lede", lede));
  const row = el("div", "ref-facts");
  row.append(badge, ...facts);
  header.append(row);
  return header;
}

function fact(text: string, on: boolean): HTMLElement {
  return el("span", `ref-fact ${on ? "on" : "off"}`, text);
}

function body(lines: ReadonlyArray<[string, string]>): HTMLElement {
  const box = el("div", "ref-body");
  for (const [heading, text] of lines) {
    box.append(el("h3", null, heading), el("p", null, text));
  }
  return box;
}

function intro(): HTMLElement {
  const header = el("header");
  header.append(el("div", "ref-kicker", "Reference"));
  title = el("h2", null, "How detectors and actions work");
  title.tabIndex = -1;
  header.append(title, el("p", "ref-lede", "Pick one from the list, or click a detector or a response anywhere else on this dashboard to land on its entry."));
  const box = el("div", "ref-body");
  box.append(
    el("h3", null, "Detectors"),
    el("p", null, "A detector reports what it saw and how sure it is; none of them decides anything on its own. The scores add up per address, and the policy reads the total — which is why an incident's score is printed beside the address's running one."),
    el("h3", null, "Response actions"),
    el("p", null, "An action is what the caller was served. They range from answering as if nothing were there, through spending the caller's time, to refusing outright — and what a policy may choose is limited by what the evidence supports."),
  );
  const wrap = el("div", "ref-intro");
  wrap.append(header, box);
  return wrap;
}
