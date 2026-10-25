import { type Analysis, analyze, CORPUS_LIMIT, chronological, scopeIncidents } from "./analysis.js";
import { asApiError, getJson, getText } from "./api.js";
import type { DashboardNotice, FeedCountsSnapshot } from "./store.js";
import { app } from "./app.js";
import { applyBoot, BOOT, SECTIONS } from "./boot.js";
import { repaintVisible } from "./charts.js";
import { $, all, byId, clear, el, eventTarget, isEmbedded, maybe, rootNode, setRoot, setText, setThemeHost, themeElement } from "./dom.js";
import { fmtClock, fmtCompact } from "./format.js";
import { clearQuery, incidentTotal, initIncidents, loadIncidents, prependIncident, setDetectorOptions, showAddress } from "./incidents.js";
import { initIntel, renderActors, renderIoc, renderMetrics, renderNotices, renderSessions } from "./lists.js";
import { renderOverview } from "./overview.js";
import { canPreviewPolicy, initPolicy, renderPolicyChanges } from "./policy.js";
import { initReference, renderReference, setInstalledDetectors } from "./reference.js";
import { availableTabs, explainFailure, type Failure, isIncident, isTabName, mergeIncident, parseMetrics, safeHref, streamNotice, TAB_ORDER, tabFromHash, upgradeIncident } from "./query.js";
import { initStatistics, onStatisticsChange, renderStats } from "./statistics.js";
import { state } from "./store.js";
import { connectStream, streamAvailable, suspendStream } from "./stream.js";
import { initTester } from "./tester.js";
import { renderTiles, TILE_TABS } from "./tiles.js";
import { initTooltip } from "./tooltip.js";
import type { ActorGroup, AttackSession, Boot, IocEntry, StatsSummary, TabName } from "./types.js";

/**
 * The dashboard's browser code: wiring, loading and rendering.
 *
 * Bundled by `scripts/build-client.mjs` into one IIFE that `page.ts` stamps into the page's
 * nonced script. On the standalone page it starts itself from `window.__HACKERPOT_DASHBOARD__`;
 * `<hackerpot-dashboard>` imports `mountDashboard` and points it at a shadow root instead.
 */

export interface MountOptions {
  /** The subtree holding the dashboard's markup: the document, or the element's frame. */
  root: Document | ShadowRoot | HTMLElement;
  /** Where the theme lives: the document element, or the custom element. */
  host: HTMLElement;
  boot: Boot;
}

let mounted = false;

/**
 * Starts the dashboard against a root. Once per page: the client is a module graph with its
 * own state, and a second mount would be a second client drawing the first one's data.
 */
export function mountDashboard(options: MountOptions): void {
  if (mounted) return;
  mounted = true;
  setRoot(options.root, options.host);
  applyBoot(options.boot);
  start();
}

/** Stops the live feed and the timers, keeping the rendered subtree for a remount. */
export function suspendDashboard(): void {
  suspendStream();
  if (renderTimer !== undefined) clearTimeout(renderTimer);
  renderTimer = undefined;
}

/** Picks a suspended dashboard back up under a new host element. */
export function resumeDashboard(host: HTMLElement): void {
  if (!mounted) return;
  setThemeHost(host);
  applyStoredTheme();
  if (state.live) connectStream();
  void refresh();
}

// ---- analysis cache -------------------------------------------------------------

let cachedAll: { version: number; analysis: Analysis } | undefined;
let cachedScoped: { key: string; analysis: Analysis } | undefined;

function analysisAll(): Analysis {
  if (cachedAll?.version !== state.version) cachedAll = { version: state.version, analysis: analyze(state.all) };
  return cachedAll.analysis;
}

function analysisScoped(): Analysis {
  if (state.range === 0 && state.proto === "") return analysisAll();
  const key = `${state.version}|${state.range}|${state.proto}`;
  if (cachedScoped?.key !== key) cachedScoped = { key, analysis: analyze(scopeIncidents(state.all, state.range, state.proto)) };
  return cachedScoped.analysis;
}

// ---- rendering ------------------------------------------------------------------

/** Screens whose content is older than the data. Only the visible one is drawn; the rest catch up when shown. */
const dirty = new Set<TabName>();
let renderTimer: ReturnType<typeof setTimeout> | undefined;

function renderTab(tab: TabName): void {
  // The policy screen is drawn once, when it is initialised: it holds what somebody typed.
  if (tab === "reference") {
    renderReference();
    return;
  }
  if (!dirty.has(tab) || tab === "policy" || !SECTIONS[tab]) return;
  dirty.delete(tab);
  if (tab === "overview") {
    renderOverview(analysisAll());
    renderNotices();
  } else if (tab === "statistics") renderStats(analysisScoped());
  else if (tab === "sessions") renderSessions();
  else if (tab === "actors") renderActors();
  else if (tab === "intel") {
    renderIoc();
    renderMetrics();
  }
}

function renderAll(): void {
  for (const tab of TAB_ORDER) dirty.add(tab);
  renderTab(state.tab);
  if (TILE_TABS.has(state.tab)) renderTiles();
}

/**
 * A burst of live incidents is one render, not one per incident. The table row appears at
 * once; the charts and counts follow within a second and a bit.
 */
function scheduleRender(): void {
  if (renderTimer !== undefined) return;
  renderTimer = setTimeout(() => {
    renderTimer = undefined;
    renderAll();
  }, 1200);
}

// ---- loading --------------------------------------------------------------------

let refreshing: Promise<void> | undefined;
let refreshAgain = false;

/** Reloads everything this dashboard has sections for. Concurrent calls collapse into one more pass. */
async function refresh(): Promise<void> {
  if (refreshing !== undefined) {
    refreshAgain = true;
    return refreshing;
  }
  refreshing = (async () => {
    do {
      refreshAgain = false;
      await loadEverything();
    } while (refreshAgain);
  })();
  try {
    await refreshing;
  } finally {
    refreshing = undefined;
  }
}

async function attempt<T>(path: string, read: (path: string) => Promise<T>, apply: (value: T) => void): Promise<void> {
  try {
    apply(await read(path));
    app.showFailure(path.split("?")[0] ?? path, undefined);
  } catch (error) {
    const failure = asApiError(error, path);
    app.showFailure(failure.endpoint, explainFailure(failure.status, failure.endpoint, failure.message));
  }
}

async function loadEverything(): Promise<void> {
  const jobs: Array<Promise<void>> = [];
  if (SECTIONS.overview || SECTIONS.statistics) {
    jobs.push(
      attempt("/api/stats", getJson<StatsSummary>, (stats) => {
        state.stats = stats;
        state.liveSinceStats = 0;
        setDetectorOptions(Object.keys(stats.byDetector ?? {}));
        // The Reference index says which of the documented detectors this deployment runs.
        setInstalledDetectors(Object.keys(stats.byDetector ?? {}));
      }),
    );
  }
  if (SECTIONS.overview || SECTIONS.statistics || SECTIONS.incidents) {
    // Counted server-side in minute buckets, so this says how many incidents happened rather
    // than how many the page managed to hold.
    jobs.push(
      attempt("/api/counts", getJson<FeedCountsSnapshot>, (counts) => {
        state.counts = counts;
      }),
    );
  }
  if (SECTIONS.overview) {
    // Only an engine in this process keeps notices; a dashboard reading a management API is
    // answered 404 and simply shows none.
    jobs.push(
      attempt("/api/notices", getJson<{ notices?: DashboardNotice[] }>, (data) => {
        state.notices = Array.isArray(data.notices) ? data.notices : [];
        // The Policy screen is drawn once, when it is initialised, so it is told directly.
        renderPolicyChanges();
      }),
    );
  }
  if (SECTIONS.overview || SECTIONS.statistics || SECTIONS.incidents) {
    jobs.push(
      attempt(`/api/incidents?limit=${CORPUS_LIMIT}`, getJson<{ incidents?: unknown }>, (data) => {
        state.all = chronological(Array.isArray(data.incidents) ? data.incidents.map(upgradeIncident).filter(isIncident) : []);
        state.version++;
        if (!(SECTIONS.overview || SECTIONS.statistics)) {
          const seen = [...new Set(state.all.flatMap((i) => i.detections.map((d) => d.detector)))];
          setDetectorOptions(seen);
          setInstalledDetectors(seen);
        }
      }),
    );
  }
  if (SECTIONS.incidents) jobs.push(loadIncidents());
  if (SECTIONS.intel) {
    jobs.push(
      attempt("/api/metrics", getText, (text) => {
        state.metricsRaw = text;
        state.metrics = parseMetrics(text);
      }),
      attempt("/api/ioc", getJson<{ indicators?: IocEntry[] }>, (data) => {
        state.ioc = Array.isArray(data.indicators) ? data.indicators : [];
      }),
    );
  }
  if (SECTIONS.sessions) jobs.push(attempt("/api/sessions", getJson<{ sessions?: AttackSession[] }>, (data) => void (state.sessions = Array.isArray(data.sessions) ? data.sessions : [])));
  if (SECTIONS.actors) jobs.push(attempt("/api/actors", getJson<{ actors?: ActorGroup[] }>, (data) => void (state.actors = Array.isArray(data.actors) ? data.actors : [])));
  await Promise.all(jobs);
  sideStale = false;
  state.loadedAt = Date.now();
  setText("last-refresh", fmtClock(state.loadedAt));
  drawPills();
  renderAll();
}

/**
 * Sessions, actors and indicators are the server's aggregates, so a live incident cannot be
 * folded into them in the browser. They are refetched a few seconds after activity, and
 * only while their screen is the one somebody is looking at.
 */
let sideStale = false;
let sideTimer: ReturnType<typeof setTimeout> | undefined;

function markSideStale(): void {
  sideStale = true;
  if (sideTimer !== undefined || !isSideTab(state.tab)) return;
  sideTimer = setTimeout(() => {
    sideTimer = undefined;
    if (isSideTab(state.tab)) void loadSide(state.tab);
  }, 5000);
}

function isSideTab(tab: TabName): tab is "sessions" | "actors" | "intel" {
  return tab === "sessions" || tab === "actors" || tab === "intel";
}

async function loadSide(tab: "sessions" | "actors" | "intel"): Promise<void> {
  sideStale = false;
  if (tab === "sessions") await attempt("/api/sessions", getJson<{ sessions?: AttackSession[] }>, (data) => void (state.sessions = Array.isArray(data.sessions) ? data.sessions : []));
  else if (tab === "actors") await attempt("/api/actors", getJson<{ actors?: ActorGroup[] }>, (data) => void (state.actors = Array.isArray(data.actors) ? data.actors : []));
  else {
    await Promise.all([
      attempt("/api/ioc", getJson<{ indicators?: IocEntry[] }>, (data) => void (state.ioc = Array.isArray(data.indicators) ? data.indicators : [])),
      attempt("/api/metrics", getText, (text) => {
        state.metricsRaw = text;
        state.metrics = parseMetrics(text);
      }),
    ]);
  }
  dirty.add(tab);
  drawPills();
  renderTab(tab);
}

function ingest(incident: Parameters<typeof app.ingest>[0]): void {
  state.all = mergeIncident(state.all, incident, CORPUS_LIMIT);
  state.version++;
  if (state.stats !== undefined) state.liveSinceStats++;
  if (SECTIONS.incidents) prependIncident(incident);
  markSideStale();
  scheduleRender();
}

// ---- status, errors, notices ------------------------------------------------------

function showFailure(endpoint: string, failure: Failure | undefined): void {
  if (failure === undefined) state.failures.delete(endpoint);
  else state.failures.set(endpoint, failure);
  drawBanner();
  drawStatus();
}

/**
 * The error panel. Every endpoint's latest failure, worst first, in the server's own words:
 * a 502 carries the reason the source could not answer, and that sentence is worth more
 * to the operator than any the page could compose.
 */
function drawBanner(): void {
  const banner = $("banner");
  const failures = [...state.failures.values()].filter((failure) => failure.kind !== "off");
  if (failures.length === 0) {
    banner.hidden = true;
    return;
  }
  const order = ["auth", "source", "network", "busy", "other", "off"];
  failures.sort((x, y) => order.indexOf(x.kind) - order.indexOf(y.kind));
  const worst = failures[0] as Failure;
  banner.className = worst.kind === "busy" || worst.kind === "other" ? "banner warn" : "banner err";
  setText("banner-title", worst.title);
  const list = $("banner-list");
  clear(list);
  for (const detail of new Set(failures.map((failure) => failure.detail))) list.append(el("li", null, detail));
  banner.hidden = false;
}

function drawStatus(): void {
  const kinds = new Set([...state.failures.values()].map((failure) => failure.kind));
  let cls = "idle";
  let text = "snapshot";
  if (kinds.has("auth")) [cls, text] = ["auth", "not signed in"];
  else if (kinds.has("source")) [cls, text] = ["offline", "source unavailable"];
  else if (kinds.has("network")) [cls, text] = ["offline", "unreachable"];
  else if (state.stream === "live") [cls, text] = ["online", "live"];
  else if (state.stream === "connecting") [cls, text] = ["connecting", state.streamDetail || "connecting"];
  else if (state.stream === "down") [cls, text] = ["offline", state.streamDetail || "disconnected"];
  else if (state.stream === "paused") [cls, text] = ["idle", "live feed paused"];
  else if (state.loadedAt > 0) [cls, text] = ["idle", streamAvailable() ? "snapshot" : "snapshot, no live feed"];
  const status = maybe("status");
  if (status !== null) status.className = `status ${cls}`;
  setText("status-text", text);
}

function drawNotice(): void {
  const text = streamNotice(state.dropped, state.skipped);
  const notice = $("stream-notice");
  if (text === undefined || state.dropped + state.skipped <= state.acknowledged) {
    notice.hidden = true;
    return;
  }
  setText("stream-notice-text", text);
  notice.hidden = false;
}

function drawPills(): void {
  const set = (id: string, n: number): void => setText(id, fmtCompact(n));
  // What happened, when the server could say; what is loaded, when it could not.
  set("tc-incidents", incidentTotal() ?? state.incidents.length);
  set("tc-sessions", state.sessions.length);
  set("tc-actors", state.actors.length);
  set("tc-ioc", state.ioc.length);
}

// ---- header -----------------------------------------------------------------------

const THEME_KEY = "hackerpot-dashboard-theme";

/**
 * The OSQD UI kit's themes plus "auto", which follows the system's light or dark setting, in the
 * order the picker lists them. "light" and "dark" are two of them, so a choice stored by the old
 * two-way toggle still works.
 */
const THEMES: readonly string[] = ["auto", "light", "dark", "graphite", "midnight", "contrast", "paper", "slate"];

function applyStoredTheme(): void {
  try {
    const stored = localStorage.getItem(THEME_KEY);
    // Embedded, a scheme the host set explicitly wins over one remembered from the standalone page.
    if (stored !== null && THEMES.includes(stored) && !(isEmbedded() && themeElement().hasAttribute("data-theme"))) themeElement().setAttribute("data-theme", stored);
  } catch {
    /* storage refused: private mode, or a sandboxed frame */
  }
  const picker = maybe<HTMLSelectElement>("theme");
  const current = themeElement().getAttribute("data-theme") ?? "auto";
  if (picker !== null) picker.value = THEMES.includes(current) ? current : "auto";
}

function initHeader(): void {
  setText("hp-title", BOOT.title);
  setText("hp-instance", BOOT.instance);
  setText("hp-source", BOOT.source);
  setText("hp-version", BOOT.version === "" ? "" : `@osqd/hackerpot ${BOOT.version}`);
  const redaction = $("hp-redaction");
  const parts = [BOOT.redaction.credentials ? "redacted" : "shown in full"];
  if (BOOT.redaction.maskIp) parts.push("addresses masked");
  redaction.textContent = parts.join(", ");
  redaction.classList.toggle("warn-text", !BOOT.redaction.credentials);
  redaction.title = BOOT.redaction.credentials
    ? "The server strips Authorization, cookies, API keys and secret-named fields from every incident before it reaches this page."
    : "Credentials attackers sent are shown as captured. They are often real people's passwords.";

  const links = $("hp-links");
  for (const link of BOOT.links) {
    const href = safeHref(link.href);
    if (href === undefined) continue;
    const anchor = el("a", "linkbtn", link.label);
    anchor.href = href;
    anchor.rel = "noreferrer noopener";
    links.append(anchor);
  }
  links.hidden = links.childElementCount === 0;

  applyStoredTheme();
  const picker = $("theme") as HTMLSelectElement;
  picker.addEventListener("change", () => {
    const next = THEMES.includes(picker.value) ? picker.value : "auto";
    themeElement().setAttribute("data-theme", next);
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {
      /* storage refused */
    }
  });

  // The skip link is a fragment anchor, and fragment navigation does not cross a shadow boundary.
  const skip = rootNode().querySelector<HTMLAnchorElement>("a.skip");
  skip?.addEventListener("click", (event) => {
    if (!isEmbedded()) return;
    event.preventDefault();
    const main = maybe("hp-main");
    if (main === null) return;
    main.tabIndex = -1;
    main.focus();
  });

  /**
   * The feed's sticky column headers sit under this one, and the header is not a fixed
   * height: the tab strip wraps on a narrow window and grows. Measure it, and let the CSS
   * read the measurement rather than guess at a literal.
   */
  const header = rootNode().querySelector("header");
  if (header !== null) {
    const apply = (): void => {
      themeElement().style.setProperty("--header-h", `${header.getBoundingClientRect().height}px`);
    };
    apply();
    if (typeof ResizeObserver === "function") new ResizeObserver(apply).observe(header);
    else addEventListener("resize", apply);
  }
}

// ---- tabs -------------------------------------------------------------------------

let available: TabName[] = [];

function showTab(name: TabName, options: { focus?: boolean; push?: boolean } = {}): void {
  const target = available.includes(name) ? name : available[0];
  if (target === undefined) return;
  state.tab = target;
  for (const tab of available) {
    const selected = tab === target;
    const button = $(`tab-${tab}`);
    button.setAttribute("aria-selected", String(selected));
    // Roving tabindex: the selected tab is the strip's one stop in the tab order.
    button.tabIndex = selected ? 0 : -1;
    $(`pane-${tab}`).hidden = !selected;
  }
  if (options.focus === true) $(`tab-${target}`).focus();
  if (options.push === true && !isEmbedded() && location.hash !== `#${target}`) history.pushState(null, "", `#${target}`);
  renderTab(target);
  const tiles = maybe("tiles");
  if (tiles !== null) {
    tiles.hidden = !TILE_TABS.has(target);
    if (!tiles.hidden) renderTiles();
  }
  // Charts drawn while their screen was hidden were drawn at a guessed width.
  repaintVisible();
  if (isSideTab(target) && sideStale) void loadSide(target);
}

function initTabs(): void {
  available = availableTabs(SECTIONS, canPreviewPolicy());
  available.forEach((tab, index) => {
    const button = $(`tab-${tab}`);
    button.addEventListener("click", () => showTab(tab, { push: true }));
    button.addEventListener("keydown", (event) => {
      let next = -1;
      if (event.key === "ArrowRight") next = (index + 1) % available.length;
      else if (event.key === "ArrowLeft") next = (index - 1 + available.length) % available.length;
      else if (event.key === "Home") next = 0;
      else if (event.key === "End") next = available.length - 1;
      if (next === -1) return;
      event.preventDefault();
      showTab(available[next] as TabName, { focus: true, push: true });
    });
  });
  if (!isEmbedded()) {
    const follow = (): void => {
      const tab = tabFromHash(location.hash, available);
      if (tab !== undefined && tab !== state.tab) showTab(tab);
    };
    addEventListener("hashchange", follow);
    addEventListener("popstate", follow);
  }
}

/**
 * A section switched off is removed, not hidden: nothing can tab into it, and no panel sits
 * waiting for data the server will refuse to send.
 */
function applySections(): void {
  for (const tab of TAB_ORDER) {
    if (tab === "policy" ? canPreviewPolicy() : tab === "reference" || SECTIONS[tab]) continue;
    maybe(`tab-${tab}`)?.remove();
    maybe(`pane-${tab}`)?.remove();
  }
  for (const node of all("[data-needs]")) {
    const needs = node.dataset["needs"];
    if (isTabName(needs) && needs !== "policy" && needs !== "reference" && !SECTIONS[needs]) node.remove();
  }
  if (availableTabs(SECTIONS).length === 0) {
    const main = $("hp-main");
    clear(main);
    main.append(el("div", "empty", "Every section of this dashboard is switched off on the server."));
  }
}

// ---- toolbar ----------------------------------------------------------------------

function initToolbar(): void {
  $("refresh").addEventListener("click", () => void refresh());
  const live = byId<HTMLButtonElement>("live");
  if (!streamAvailable()) {
    live.hidden = true;
    state.live = false;
  }
  drawLiveButton();
  live.addEventListener("click", () => {
    state.live = !state.live;
    drawLiveButton();
    if (state.live) {
      connectStream();
      // Whatever arrived while paused was not heard; reload rather than show a gap.
      void refresh();
    } else suspendStream();
  });
  $("stream-notice-reload").addEventListener("click", () => {
    state.acknowledged = state.dropped + state.skipped;
    drawNotice();
    void refresh();
  });
  $("stream-notice-dismiss").addEventListener("click", () => {
    state.acknowledged = state.dropped + state.skipped;
    drawNotice();
  });
}

/**
 * Pause and Refresh are one control's two halves. While the feed is live the page is already
 * current, so Refresh would only repeat what the stream delivers and is hidden; paused, or with
 * no stream to follow, it is the only way to see what changed.
 */
function drawLiveButton(): void {
  const live = byId<HTMLButtonElement>("live");
  live.setAttribute("aria-pressed", String(!state.live));
  live.textContent = state.live ? "Pause" : "Resume";
  $("refresh").hidden = state.live;
}

/**
 * The keys bothandlerjs's dashboard answers, so a hand used to one works in the other: `/` to
 * search the incidents, 1 to 6 for the screens this dashboard has, and Escape to clear a search
 * or dismiss the stream notice. Listened for on the dashboard's own root when embedded, so a key
 * pressed while the host page has focus is the host page's.
 */
function initKeyboard(): void {
  eventTarget().addEventListener("keydown", (raw) => {
    const event = raw as KeyboardEvent;
    const target = event.target as HTMLElement | null;
    const typing = target !== null && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.tagName === "SELECT");
    if (event.key === "Escape") {
      if (target?.id === "f-query" && (target as HTMLInputElement).value !== "") {
        clearQuery();
        return;
      }
      if (typing) {
        target?.blur();
        return;
      }
      if (!$("stream-notice").hidden) {
        state.acknowledged = state.dropped + state.skipped;
        drawNotice();
      }
      return;
    }
    if (typing || event.metaKey || event.ctrlKey || event.altKey) return;
    if (event.key === "/" && SECTIONS.incidents) {
      event.preventDefault();
      showTab("incidents", { push: true });
      const query = byId<HTMLInputElement>("f-query");
      query.focus();
      query.select();
      return;
    }
    const digit = ["1", "2", "3", "4", "5", "6"].indexOf(event.key);
    if (digit !== -1 && digit < available.length) {
      event.preventDefault();
      showTab(available[digit] as TabName, { focus: true, push: true });
    }
  });
}

function initTableToggles(): void {
  for (const toggle of all<HTMLButtonElement>(".tabletoggle")) {
    const table = maybe(toggle.dataset["table"] ?? "");
    if (table === null) {
      toggle.remove();
      continue;
    }
    toggle.setAttribute("aria-controls", table.id);
    toggle.setAttribute("aria-expanded", "false");
    toggle.addEventListener("click", () => {
      table.hidden = !table.hidden;
      toggle.setAttribute("aria-expanded", String(!table.hidden));
      toggle.textContent = table.hidden ? "table view" : "hide table";
    });
  }
}

/** "Show only this address", from a session, an actor or an opened incident: a search, as in bothandlerjs. */
function incidentsFor(ip: string): void {
  if (!SECTIONS.incidents) return;
  showAddress(ip);
  showTab("incidents", { push: true });
}

function initialTab(): TabName | undefined {
  if (isEmbedded()) {
    const wanted = BOOT.view?.tab;
    return wanted !== undefined && available.includes(wanted) ? wanted : available[0];
  }
  return tabFromHash(location.hash, available);
}

function start(): void {
  app.refresh = refresh;
  app.ingest = ingest;
  app.schedule = scheduleRender;
  app.showTab = showTab;
  app.showFailure = showFailure;
  app.drawStatus = drawStatus;
  app.drawNotice = drawNotice;
  app.incidentsFor = incidentsFor;

  if (isEmbedded() && BOOT.view !== undefined) {
    if (typeof BOOT.view.ip === "string") state.filter.ip = BOOT.view.ip;
    if (typeof BOOT.view.detector === "string") state.filter.detector = BOOT.view.detector;
  }

  applySections();
  initHeader();
  initTabs();
  initToolbar();
  initTooltip();
  initTableToggles();
  if (SECTIONS.incidents) {
    initIncidents();
    initTester();
  }
  if (canPreviewPolicy()) initPolicy();
  initReference();
  if (SECTIONS.statistics) {
    initStatistics();
    onStatisticsChange(() => {
      dirty.add("statistics");
      renderTab(state.tab);
    });
  }
  if (SECTIONS.intel) initIntel();

  const first = initialTab();
  if (first !== undefined) showTab(first);
  drawStatus();

  let resizeTimer: ReturnType<typeof setTimeout> | undefined;
  addEventListener("resize", () => {
    if (resizeTimer !== undefined) clearTimeout(resizeTimer);
    resizeTimer = setTimeout(repaintVisible, 160);
  });
  initKeyboard();

  void refresh();
  if (state.live) connectStream();
}

// The standalone page starts itself. The check for the page's own root element in the
// *document* is what keeps an import by `<hackerpot-dashboard>` from starting a second
// copy against a page whose dashboard lives in a shadow root.
const standalone = (globalThis as { __HACKERPOT_DASHBOARD__?: Boot }).__HACKERPOT_DASHBOARD__;
if (standalone !== undefined && typeof document !== "undefined" && document.getElementById("hp-app") !== null) {
  mountDashboard({ root: document, host: document.documentElement, boot: standalone });
}
