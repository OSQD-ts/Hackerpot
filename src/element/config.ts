/**
 * The element's decisions, with no document in sight.
 *
 * Everything here answers a question from its arguments rather than by looking at the page:
 * which screens survive a config, what a status code means, where the handler is mounted,
 * whether `src` is same-origin, whether two configs describe the same screens, whether the
 * element and the handler are the same release. That is exactly the logic that is fiddly
 * enough to have bugs and, inside a custom element, awkward to reach from a test, so it
 * lives here and `tests/dashboard-client.test.ts` calls it directly.
 */

/**
 * One screen of the dashboard. The names are the server's section names, so the word you
 * put in `tabs` is the word you put in `hide` and the word you put in the handler's
 * `sections`.
 */
export type HackerpotDashboardTabId = "overview" | "incidents" | "statistics" | "sessions" | "actors" | "intel";

export const TAB_IDS: readonly HackerpotDashboardTabId[] = ["overview", "incidents", "statistics", "sessions", "actors", "intel"];

export interface HackerpotDashboardTab {
  id: HackerpotDashboardTabId;
  /** Shown in the tab strip. Defaults to the built-in name. */
  label?: string;
}

export interface HackerpotDashboardRows {
  rows: ReadonlyArray<{ label: string; value: string | number; note?: string }>;
}

/** A panel of your own, rendered at the end of one of the dashboard's screens. */
export interface HackerpotDashboardPanel {
  id: string;
  screen: HackerpotDashboardTabId;
  title: string;
  /**
   * A same-origin URL answering `{ rows: [{ label, value, note? }] }`, or a function
   * returning the same. Rendered as text, always: a value containing a tag shows the tag.
   */
  source: string | (() => Promise<HackerpotDashboardRows> | HackerpotDashboardRows);
  /** Refresh interval in milliseconds, at least one second. Omit to load once. */
  refreshMs?: number;
}

export interface HackerpotDashboardTheme {
  /**
   * Token overrides by custom-property name, with or without the leading dashes:
   * `{ accent: "#7c3aed", panel: "#fff" }`. Applied to the host, so they cascade into the
   * shadow root the same way the built-in tokens do. The contrast the built-in palette was
   * measured for is yours to keep once you replace it.
   */
  tokens?: Record<string, string>;
  /** Force a scheme instead of following the viewer's own setting. */
  scheme?: "light" | "dark";
  /** `compact` tightens table rows and panel padding. */
  density?: "comfortable" | "compact";
}

export interface HackerpotDashboardView {
  /** The screen to open on. Must be one that survives `tabs` and `hide`. */
  tab?: HackerpotDashboardTabId;
  /** Pre-fill the Incidents screen's address filter. */
  ip?: string;
  /** Pre-fill the Incidents screen's detector filter. */
  detector?: string;
}

export interface HackerpotDashboardConfig {
  /** Where `createDashboardHandler` is mounted, e.g. `"/_hackerpot"`. Also settable as the `src` attribute. */
  src?: string;
  /** Which screens appear, in which order, under which labels. */
  tabs?: readonly HackerpotDashboardTab[];
  /** Panels of your own. */
  panels?: readonly HackerpotDashboardPanel[];
  theme?: HackerpotDashboardTheme;
  /**
   * Hide screens the server is still serving. Cosmetic: the data stays on the wire. The
   * handler's `sections` option is the one that keeps it in the process.
   */
  hide?: Partial<Record<HackerpotDashboardTabId, boolean>>;
  /**
   * Where the dashboard opens. The standalone page keeps its tab in the URL fragment;
   * embedded, the address bar belongs to the host page, so this stands in for it. A
   * starting point, not a restriction: everything here can be changed on screen.
   */
  view?: HackerpotDashboardView;
}

function isTabId(value: unknown): value is HackerpotDashboardTabId {
  return typeof value === "string" && (TAB_IDS as readonly string[]).includes(value);
}

/**
 * Which sections the client is booted with, and what to say about the config.
 *
 * Three inputs, in order: what the server offered, what `hide` removes, what `tabs` narrows
 * to. A screen the server withheld cannot be brought back from here and the warning says
 * where it was switched off, because a developer who lists two screens and is given one
 * deserves to be told which file to look in.
 */
export function resolveSections(
  fromServer: Readonly<Record<string, boolean>> | undefined,
  config: Pick<HackerpotDashboardConfig, "hide" | "tabs">,
): { sections: Record<HackerpotDashboardTabId, boolean>; warnings: string[] } {
  const warnings: string[] = [];
  const sections = Object.fromEntries(TAB_IDS.map((id) => [id, fromServer?.[id] !== false])) as Record<HackerpotDashboardTabId, boolean>;

  for (const [key, value] of Object.entries(config.hide ?? {})) {
    if (!isTabId(key)) {
      warnings.push(`hide.${key} is not a screen, so it did nothing. The screens are: ${TAB_IDS.join(", ")}.`);
      continue;
    }
    if (value === true) sections[key] = false;
  }

  const wanted = config.tabs;
  if (wanted !== undefined && wanted.length > 0) {
    const keep = new Set<HackerpotDashboardTabId>();
    for (const tab of wanted) {
      if (!isTabId(tab?.id)) {
        warnings.push(`tabs lists "${String(tab?.id)}", which is not a screen. The screens are: ${TAB_IDS.join(", ")}.`);
        continue;
      }
      keep.add(tab.id);
      if (fromServer?.[tab.id] === false) {
        warnings.push(`tabs lists "${tab.id}", but this dashboard's server has the "${tab.id}" section switched off, so that screen does not exist. That is the \`sections\` option on createDashboardHandler, and it is enforced there rather than here.`);
      } else if (config.hide?.[tab.id] === true) {
        warnings.push(`tabs lists "${tab.id}" and hide.${tab.id} is true; hide wins, so the screen is not shown.`);
      }
    }
    if (keep.size > 0) for (const id of TAB_IDS) if (!keep.has(id)) sections[id] = false;
  }
  return { sections, warnings };
}

/** The order and labels `tabs` asks for, restricted to screens that exist. */
export function tabOrder(config: Pick<HackerpotDashboardConfig, "tabs">, sections: Readonly<Record<HackerpotDashboardTabId, boolean>>): HackerpotDashboardTab[] {
  return (config.tabs ?? []).filter((tab) => isTabId(tab?.id) && sections[tab.id]);
}

/** The view the client will read, with anything unusable dropped and said out loud. */
export function resolveView(view: HackerpotDashboardView | undefined, sections: Readonly<Record<HackerpotDashboardTabId, boolean>>): { view: HackerpotDashboardView | undefined; warnings: string[] } {
  if (view === undefined) return { view: undefined, warnings: [] };
  const warnings: string[] = [];
  const out: HackerpotDashboardView = {};
  if (view.tab !== undefined) {
    if (isTabId(view.tab) && sections[view.tab]) out.tab = view.tab;
    else {
      const shown = TAB_IDS.filter((id) => sections[id]);
      warnings.push(`view.tab is "${String(view.tab)}", which is not one of the screens this dashboard shows (${shown.join(", ") || "none"}). Opening on the first one instead.`);
    }
  }
  if (typeof view.ip === "string" && view.ip.trim() !== "") out.ip = view.ip.trim();
  if (typeof view.detector === "string" && view.detector.trim() !== "") out.detector = view.detector.trim();
  if ((out.ip !== undefined || out.detector !== undefined) && !sections.incidents) {
    warnings.push("view.ip and view.detector filter the Incidents screen, which this dashboard does not show, so they do nothing.");
  }
  return { view: Object.keys(out).length === 0 ? undefined : out, warnings };
}

/**
 * Where the handler is mounted, from a raw `src`. A trailing slash, a query string and a
 * fragment are dropped: the element appends `/api/bootstrap`, so nothing after the path
 * could survive that, and a `?token=` in particular must not be quietly carried along.
 */
export function parseMount(raw: string): { base: string; warning?: string } {
  const trimmed = raw.trim();
  const cut = trimmed.search(/[?#]/);
  const path = (cut === -1 ? trimmed : trimmed.slice(0, cut)).replace(/\/+$/, "");
  if (cut === -1) return { base: path };
  return {
    base: path,
    warning: `src "${raw}" has a ${trimmed[cut] === "?" ? "query string" : "fragment"} on it. The element asks for \`<src>/api/bootstrap\`, so only the path can mean anything here; the rest was ignored. Authentication belongs in the handler's \`auth\` (a cookie or the page's own session), not in the URL.`,
  };
}

/**
 * Why a `src` cannot work, when it cannot. The dashboard sends no CORS headers (that is
 * what stops another site reading your attackers through a logged-in browser), so an
 * absolute URL on another origin is a configuration mistake rather than something to retry.
 */
export function crossOriginProblem(base: string, pageOrigin: string): string | undefined {
  if (!/^[a-z][a-z0-9+.-]*:/i.test(base) && !base.startsWith("//")) return undefined;
  let origin: string;
  try {
    origin = new URL(base, pageOrigin).origin;
  } catch {
    return `src "${base}" is not a URL or a path.`;
  }
  if (origin === pageOrigin) return undefined;
  return `src points at ${origin}, which is not this page's origin (${pageOrigin}). The dashboard is same-origin only: it sends no CORS headers, which is what stops another site reading it through a logged-in browser. Mount createDashboardHandler under this origin and use a path, e.g. src="/_hackerpot".`;
}

/** What a refusal from the handler means to whoever has to fix it. */
export function explainStatus(status: number, base: string): string {
  const where = base === "" ? "this page's own origin" : base;
  if (status === 401) {
    return `it answered 401 Unauthorized. The handler has \`auth\` configured, and the element fetches in the background, where a browser cannot show the sign-in prompt it would show for a navigation. Open ${base === "" ? "the dashboard" : `${base}/`} directly and sign in once (the browser then sends those credentials with the element's requests too), or use an \`authorize\` check that reads the session this page already has.`;
  }
  if (status === 403) return "it answered 403 Forbidden: the handler refused this client or origin rather than its credentials. Check `allowedClients`, and that this page is on the same origin as `src`.";
  if (status === 421) return "it answered 421 Misdirected Request: the handler's `allowedHosts` does not include this page's host name.";
  if (status === 404) return `it answered 404 at ${where}/api/bootstrap. Is createDashboardHandler mounted at ${where}?`;
  if (status === 429) return "it answered 429: too many failed sign-ins from this address. Wait, then reload.";
  return `it answered ${status}`;
}

/**
 * The same release on both sides, or a warning. The element is compiled into the host
 * page's bundle and the handler into the server's, and nothing makes them match. Skew does
 * not look like an error: it looks like a panel that stays empty because a field was renamed.
 */
export function versionSkew(elementVersion: string, served: unknown, base: string): string | undefined {
  const where = base === "" ? "/" : base;
  if (typeof served !== "string" || served === "") return `the handler at ${where} did not say which version it is, so this element (${elementVersion}) cannot check them against each other.`;
  if (served === elementVersion) return undefined;
  return `this element is @osqd/hackerpot ${elementVersion} and the handler at ${where} is ${served}. They are separate bundles, so an empty panel here may be that difference rather than a fault. Install the same version in both.`;
}

/** A theme token's property name, or `undefined` for one that is not a plain custom-property name. */
export function tokenName(token: string): string | undefined {
  const name = token.startsWith("--") ? token : `--${token}`;
  return /^--[A-Za-z0-9_-]+$/.test(name) ? name : undefined;
}

export function checkScheme(value: string | null | undefined): { value?: "light" | "dark"; warning?: string } {
  if (value === null || value === undefined || value === "") return {};
  if (value === "light" || value === "dark") return { value };
  return { warning: `scheme "${value}" is not "light" or "dark", so it was ignored. Leave it unset to follow the viewer's own setting.` };
}

export function checkDensity(value: string | null | undefined): { value?: "comfortable" | "compact"; warning?: string } {
  if (value === null || value === undefined || value === "") return {};
  if (value === "comfortable" || value === "compact") return { value };
  return { warning: `density "${value}" is not "comfortable" or "compact", so it was ignored.` };
}

/**
 * What of a config decides the rendered screens: tabs, hides and panel placement. Not the
 * panel `source` functions: a framework rebuilds those on every render, and counting them
 * would report a change every time.
 */
export function shapeOf(config: HackerpotDashboardConfig): string {
  const tabs = (config.tabs ?? []).map((tab) => `${tab.id}:${tab.label ?? ""}`).join(",");
  const hide = Object.entries(config.hide ?? {})
    .filter(([, v]) => v === true)
    .map(([k]) => k)
    .sort()
    .join(",");
  const panels = (config.panels ?? []).map((panel) => `${panel.id}@${panel.screen}:${panel.title}`).join(",");
  return `${tabs}|${hide}|${panels}`;
}

/** A panel cell, as text and never as markup, and never longer than a cell should be. */
export function cellText(value: unknown): string {
  if (typeof value === "string") return value.slice(0, 200);
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (value === null || value === undefined) return "";
  try {
    return (JSON.stringify(value) ?? "").slice(0, 200);
  } catch {
    return "";
  }
}

/** Most rows one panel may put on the page; the rest are counted, not drawn. */
export const MAX_PANEL_ROWS = 200;

/** The rows a panel source returned, validated. `undefined` when it returned something that is not rows. */
export function panelRows(data: unknown): { rows: Array<{ label: string; value: string; note?: string }>; more: number } | undefined {
  const rows = (data as { rows?: unknown } | null | undefined)?.rows;
  if (!Array.isArray(rows)) return undefined;
  const usable = rows.filter((row): row is { label: unknown; value: unknown; note?: unknown } => typeof row === "object" && row !== null && (row as { label?: unknown }).label !== undefined && (row as { value?: unknown }).value !== undefined);
  return {
    rows: usable.slice(0, MAX_PANEL_ROWS).map((row) => ({ label: cellText(row.label), value: cellText(row.value), ...(row.note === undefined ? {} : { note: cellText(row.note) }) })),
    more: Math.max(0, usable.length - MAX_PANEL_ROWS),
  };
}
