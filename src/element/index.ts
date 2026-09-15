/**
 * `<hackerpot-dashboard>`: the operator dashboard as an element you drop into your own page.
 *
 * ```html
 * <hackerpot-dashboard src="/_hackerpot"></hackerpot-dashboard>
 * <script type="module">
 *   import { defineHackerpotDashboard } from "@osqd/hackerpot/element";
 *   defineHackerpotDashboard();
 * </script>
 * ```
 *
 * The data still comes from a mounted handler, `createDashboardHandler(engine, { basePath:
 * "/_hackerpot", auth })`, because there is nowhere else for it to come from. What the
 * element removes is having to build, style and route a page around it: it fetches
 * `${src}/api/bootstrap` and runs the same client the standalone page runs, inside a shadow
 * root.
 *
 * ## What running it in your page costs you
 *
 * A shadow root is a styling boundary and **not a security boundary**. Any script that can
 * run on the host page can reach into it, read every attacker address and captured request
 * on screen, and call the dashboard's API with the viewer's credentials. On the standalone
 * page, which carries its own CSP and `frame-ancestors 'none'`, an injected script in your
 * application could do none of that. Mount the element only on a page already behind your
 * admin authentication, and treat an XSS there as handing over the dashboard. If you would
 * rather have the isolation than the layout, link to the standalone page instead; the same
 * handler serves it.
 */

import { cssEscape } from "../dashboard/client/css.js";
import { DASHBOARD_CSS, DASHBOARD_MARKUP } from "../dashboard/page.js";
import { VERSION } from "../version.js";
import {
  checkDensity,
  checkScheme,
  crossOriginProblem,
  explainStatus,
  panelRows,
  parseMount,
  resolveSections,
  resolveView,
  shapeOf,
  tabOrder,
  tokenName,
  versionSkew,
} from "./config.js";
import type { HackerpotDashboardConfig, HackerpotDashboardPanel, HackerpotDashboardRows, HackerpotDashboardTab, HackerpotDashboardTabId, HackerpotDashboardTheme, HackerpotDashboardView } from "./config.js";

export type { HackerpotDashboardConfig, HackerpotDashboardPanel, HackerpotDashboardRows, HackerpotDashboardTab, HackerpotDashboardTabId, HackerpotDashboardTheme, HackerpotDashboardView };

/**
 * What the page's `<body>` carries on the standalone page. A shadow root has no body, so
 * without this every element inherits the host page's colour and type, which on a dark
 * page is near-black text on a near-black panel.
 */
const EXTRA_CSS = `
:host { display: block; position: relative; background: var(--page); color: var(--text); font: 14px/1.5 var(--sans); -webkit-font-smoothing: antialiased; }
:host([hidden]) { display: none; }
.hp-notice { font: 14px/1.5 system-ui, sans-serif; padding: 14px; margin: 0; color: var(--bad-text, #b02525); }
.hp-extra { display: grid; gap: 8px; }
.hp-extra .row { display: flex; justify-content: space-between; gap: 12px; align-items: baseline; }
.hp-extra .row b { font-weight: 600; font-variant-numeric: tabular-nums; }
.hp-extra .row span { color: var(--muted); font-size: 12px; }
.hp-extra-panel { margin-top: 14px; }
`;

const LOG = "hackerpot-dashboard:";

/**
 * The rendered subtree, kept across mounts.
 *
 * A router unmounts and remounts the element on navigation. The client is a module graph
 * that evaluates once and holds its own state, so it cannot simply be started again; the
 * subtree it drew is re-parented into the new element's shadow root instead, which keeps
 * every element reference the client holds valid and keeps what it had loaded.
 */
let container: HTMLElement | undefined;
let owner: HackerpotDashboardElement | undefined;
/** The theme most recently applied, for a remounted element whose framework never re-sets it. */
let lastTheme: HackerpotDashboardTheme | undefined;
let registered = false;
const clashed = new Set<string>();

/**
 * Registers `<hackerpot-dashboard>`, or the name you give. Safe to call more than once, and
 * a no-op without a custom-element registry (on a server, during rendering).
 */
export function defineHackerpotDashboard(name = "hackerpot-dashboard"): void {
  if (typeof customElements === "undefined") return;
  const taken = customElements.get(name);
  if (taken !== undefined) {
    if (taken !== HackerpotDashboardElement && !(taken.prototype instanceof HackerpotDashboardElement) && !clashed.has(name)) {
      clashed.add(name);
      console.warn(`${LOG} <${name}> is already registered on this page by something else, so this did nothing. Register the dashboard under a name of your own: defineHackerpotDashboard("ops-hackerpot").`);
    }
    return;
  }
  // A constructor may be registered under one name only, so a second name gets a subclass.
  customElements.define(name, registered ? class extends HackerpotDashboardElement {} : HackerpotDashboardElement);
  registered = true;
}

/**
 * `HTMLElement`, or a stand-in where there is none. `class X extends HTMLElement` runs when
 * the module loads, so without this a server-rendering framework importing the element
 * threw `ReferenceError` before any of its own code ran.
 */
const ElementBase: typeof HTMLElement = typeof HTMLElement === "undefined" ? (class {} as unknown as typeof HTMLElement) : HTMLElement;

export class HackerpotDashboardElement extends ElementBase {
  private settings: HackerpotDashboardConfig = {};
  private booted = false;
  /** Booted and drawn; distinct from `booted`, which is set on the way in. */
  private rendered = false;
  private timers: Array<ReturnType<typeof setInterval>> = [];
  private appliedTokens = new Set<string>();
  private warned = new Set<string>();

  static get observedAttributes(): string[] {
    return ["src", "scheme", "density"];
  }

  /**
   * Set before or after the element is attached. An accessor rather than a field: a page
   * that assigns `el.config` before `defineHackerpotDashboard()` puts an own property on
   * the instance, and a field initialiser would overwrite it at upgrade.
   */
  get config(): HackerpotDashboardConfig {
    return this.settings;
  }

  set config(value: HackerpotDashboardConfig) {
    const before = this.rendered && this.isConnected ? shapeOf(this.settings) : undefined;
    this.settings = value ?? {};
    if (this.booted && this.isConnected) {
      this.applyTheme();
      if (before !== undefined && shapeOf(this.settings) !== before) {
        this.warnOnce(`${LOG} \`tabs\`, \`hide\` and \`panels\` are read once, when the element first mounts. Changing them afterwards has no effect; remount the element instead. (\`theme\` does update live.)`);
      }
    }
  }

  connectedCallback(): void {
    if (this.booted) return;
    this.booted = true;
    if (Object.hasOwn(this, "config")) {
      const preset = (this as unknown as { config: HackerpotDashboardConfig }).config;
      Reflect.deleteProperty(this, "config");
      this.config = preset;
    }
    void this.boot();
  }

  disconnectedCallback(): void {
    for (const timer of this.timers) clearInterval(timer);
    this.timers = [];
    if (owner === this) owner = undefined;
    // The stream goes with it: left open it holds one of the handler's viewer slots and
    // draws into a tree nobody can see. A remount reconnects and reloads.
    void import("../dashboard/client/index.js").then((client) => {
      if (!this.isConnected && owner === undefined) client.suspendDashboard();
    });
    this.booted = false;
    this.rendered = false;
  }

  attributeChangedCallback(attribute: string, previous: string | null, value: string | null): void {
    if (attribute === "scheme") this.applyScheme(this.config.theme?.scheme ?? value);
    if (attribute === "density") this.applyDensity(this.config.theme?.density ?? value);
    if (attribute === "src" && previous !== null && previous !== value && this.rendered) {
      this.warnOnce(`${LOG} \`src\` is read once, when the element first mounts. Changing it afterwards has no effect; replace the element instead.`);
    }
  }

  /** Gives up on this attempt without giving up on the element: a remount may succeed. */
  private standDown(): void {
    if (owner === this) owner = undefined;
    this.booted = false;
    this.rendered = false;
  }

  private fail(shadow: ShadowRoot, why: string): void {
    shadow.append(notice(`The HackerPot dashboard could not start: ${why}`));
    console.error(LOG, why);
    this.standDown();
  }

  private async boot(): Promise<void> {
    const { base, warning } = parseMount(this.config.src ?? this.getAttribute("src") ?? "");
    if (warning !== undefined) this.warnOnce(`${LOG} ${warning}`);
    const shadow = this.shadowRoot ?? this.attachShadow({ mode: "open" });
    // A retry after a failed attempt: drop that attempt's message. Direct children only, so a
    // panel's own "could not load" line inside a re-parented subtree is left alone.
    for (const child of Array.from(shadow.children)) if (child.classList.contains("hp-notice")) child.remove();

    // One at a time. Two live clients would share one module graph, one store and one feed.
    // Sequentially is fine, and is what a router does.
    if (owner !== undefined && owner !== this && owner.isConnected) {
      shadow.append(notice("A HackerPot dashboard is already running on this page. Only one can be."));
      this.standDown();
      return;
    }
    owner = this;

    if (container !== undefined) {
      adoptStyles(shadow);
      this.applyTheme();
      shadow.append(container);
      this.renderPanels(container);
      const client = await import("../dashboard/client/index.js");
      client.resumeDashboard(this);
      this.rendered = true;
      this.dispatchEvent(new CustomEvent("hackerpot-dashboard-ready", { bubbles: true }));
      return;
    }

    const crossOrigin = crossOriginProblem(base, location.origin);
    if (crossOrigin !== undefined) return this.fail(shadow, crossOrigin);

    let boot: Record<string, unknown>;
    try {
      const response = await fetch(`${base}/api/bootstrap`, { credentials: "same-origin", cache: "no-store", headers: { accept: "application/json" } });
      if (!response.ok) throw new Error(explainStatus(response.status, base));
      // Checked before parsing: with no `src` the element asks this page's own origin, is
      // handed HTML, and the parser's "Unexpected token '<'" helps nobody.
      const type = response.headers.get("content-type") ?? "";
      if (!type.includes("json")) {
        throw new Error(
          base === ""
            ? 'no `src` was given, so it asked this page\'s own origin and got something other than JSON back. Point `src` at where createDashboardHandler is mounted, e.g. src="/_hackerpot".'
            : `it answered ${type || "no content type"} rather than JSON. Is createDashboardHandler mounted at ${base}?`,
        );
      }
      boot = (await response.json()) as Record<string, unknown>;
    } catch (error) {
      return this.fail(shadow, error instanceof Error ? error.message : String(error));
    }
    // Removed during the round trip (a route change): somebody else may own the page by now.
    if (!this.isConnected || owner !== this) {
      this.standDown();
      return;
    }

    // The element knows where it is pointing; the server's own idea of its mount path may be
    // the other side of a proxy that strips a prefix.
    boot["base"] = base;
    const skew = versionSkew(VERSION, boot["version"], base);
    if (skew !== undefined) this.warnOnce(`${LOG} ${skew}`);
    const { sections, warnings } = resolveSections(boot["sections"] as Record<string, boolean> | undefined, this.config);
    for (const message of warnings) this.warnOnce(`${LOG} ${message}`);
    boot["sections"] = sections;
    const view = resolveView(this.config.view, sections);
    for (const message of view.warnings) this.warnOnce(`${LOG} ${message}`);
    if (view.view !== undefined) boot["view"] = view.view;

    adoptStyles(shadow);
    const frame = document.createElement("div");
    frame.className = "hp-root";
    // The markup is this package's own template, with no interpolation of anything a request
    // supplied; the one placeholder, the title, is replaced below through text nodes. Parsed
    // with DOMParser, which runs no scripts and creates inert nodes, then imported: the
    // client bundle itself never contains an HTML sink.
    const parsed = new DOMParser().parseFromString(`<!doctype html><html><body>${DASHBOARD_MARKUP}</body></html>`, "text/html");
    for (const node of Array.from(parsed.body.childNodes)) frame.append(document.importNode(node, true));
    const title = typeof boot["title"] === "string" ? boot["title"] : "hackerpot";
    for (const node of Array.from(frame.querySelectorAll("*"))) {
      for (const child of Array.from(node.childNodes)) {
        if (child.nodeType === 3 && child.nodeValue?.includes("__TITLE__") === true) child.nodeValue = child.nodeValue.replace(/__TITLE__/g, title);
      }
    }
    // Inside somebody else's page, a second <main> and a second banner are duplicate
    // landmarks. The main becomes a labelled region; the header gives up its banner role.
    const main = frame.querySelector("main");
    if (main !== null) {
      const region = document.createElement("div");
      for (const attribute of Array.from(main.attributes)) region.setAttribute(attribute.name, attribute.value);
      region.setAttribute("role", "region");
      region.setAttribute("aria-label", `${title} HackerPot dashboard`);
      while (main.firstChild !== null) region.append(main.firstChild);
      main.replaceWith(region);
    }
    frame.querySelector("header")?.setAttribute("role", "none");
    shadow.append(frame);
    container = frame;

    this.applyTheme();
    const client = await import("../dashboard/client/index.js");
    client.mountDashboard({ root: frame, host: this, boot: boot as unknown as Parameters<typeof client.mountDashboard>[0]["boot"] });
    this.relabelTabs(frame, sections);
    this.renderPanels(frame);
    warnIfFramed();
    this.rendered = true;
    this.dispatchEvent(new CustomEvent("hackerpot-dashboard-ready", { bubbles: true }));
  }

  private applyTheme(): void {
    const theme = this.config.theme ?? lastTheme ?? {};
    if (this.config.theme !== undefined) lastTheme = this.config.theme;
    this.applyScheme(theme.scheme ?? this.getAttribute("scheme"));
    this.applyDensity(theme.density ?? this.getAttribute("density"));
    const next = new Set<string>();
    for (const [token, value] of Object.entries(theme.tokens ?? {})) {
      const name = tokenName(token);
      if (name === undefined) {
        this.warnOnce(`${LOG} theme token "${token}" is not a custom-property name, so it was ignored.`);
        continue;
      }
      next.add(name);
      this.style.setProperty(name, String(value));
    }
    // Removed one by one rather than clearing the style attribute: the client keeps its own
    // measurements there (`--header-h`).
    for (const name of this.appliedTokens) if (!next.has(name)) this.style.removeProperty(name);
    this.appliedTokens = next;
  }

  private applyScheme(value: string | null | undefined): void {
    const checked = checkScheme(value);
    if (checked.warning !== undefined) this.warnOnce(`${LOG} ${checked.warning}`);
    if (checked.value !== undefined) this.setAttribute("data-theme", checked.value);
  }

  private applyDensity(value: string | null | undefined): void {
    const checked = checkDensity(value);
    if (checked.warning !== undefined) this.warnOnce(`${LOG} ${checked.warning}`);
    if (checked.value !== undefined) this.setAttribute("data-density", checked.value);
  }

  private warnOnce(message: string): void {
    if (this.warned.has(message)) return;
    this.warned.add(message);
    console.warn(message);
  }

  /** Reorders and relabels the strip. Which screens exist was settled before the client ran. */
  private relabelTabs(within: ParentNode, sections: Readonly<Record<HackerpotDashboardTabId, boolean>>): void {
    const strip = within.querySelector("[role='tablist']");
    if (strip === null) return;
    for (const tab of tabOrder(this.config, sections)) {
      const node = within.querySelector(`#tab-${cssEscape(tab.id)}`);
      if (node === null) continue;
      if (tab.label !== undefined) {
        // The first text node is the label; the count pill beside it stays.
        const text = Array.from(node.childNodes).find((child) => child.nodeType === 3);
        if (text !== undefined) text.nodeValue = tab.label;
        else node.prepend(tab.label);
      }
      strip.append(node);
    }
  }

  private renderPanels(within: ParentNode): void {
    const panels = this.config.panels ?? [];
    // The subtree outlives the element that built it, so panels this config does not ask for go.
    const wanted = new Set(panels.map((panel) => `${panel.id}@${panel.screen}`));
    for (const section of Array.from(within.querySelectorAll("[data-hp-panel]"))) {
      if (!wanted.has(`${section.getAttribute("data-hp-panel")}@${section.getAttribute("data-hp-screen")}`)) section.remove();
    }
    const drawn = new Set<string>();
    for (const panel of panels) {
      const key = `${panel.id}@${panel.screen}`;
      if (drawn.has(key)) {
        this.warnOnce(`${LOG} two panels share the id "${panel.id}" on screen "${panel.screen}"; the second was ignored.`);
        continue;
      }
      drawn.add(key);
      const host = within.querySelector(`#pane-${cssEscape(String(panel.screen))}`);
      if (host === null) {
        const known = Array.from(within.querySelectorAll("[id^='pane-']"))
          .map((node) => node.id.slice("pane-".length))
          .join(", ");
        this.warnOnce(`${LOG} panel "${panel.id}" asks for screen "${panel.screen}", which this dashboard does not show. It shows: ${known || "nothing"}.`);
        continue;
      }
      if (typeof panel.source === "string" && crossOriginProblem(panel.source, location.origin) !== undefined) {
        this.warnOnce(`${LOG} panel "${panel.id}" has a source on another origin, which the dashboard will not fetch. Use a same-origin path or a function.`);
        continue;
      }
      let body = host.querySelector<HTMLElement>(`[data-hp-panel="${cssEscape(panel.id)}"] .hp-extra`);
      if (body === null) {
        const section = document.createElement("div");
        section.className = "panel hp-extra-panel";
        section.setAttribute("data-hp-panel", panel.id);
        section.setAttribute("data-hp-screen", String(panel.screen));
        const heading = document.createElement("h3");
        heading.textContent = panel.title;
        body = document.createElement("div");
        body.className = "hp-extra";
        section.append(heading, body);
        host.append(section);
      }
      const target = body;
      const paint = async (): Promise<void> => {
        let data: HackerpotDashboardRows | unknown;
        try {
          data = typeof panel.source === "string" ? await (await fetch(panel.source, { credentials: "same-origin", cache: "no-store" })).json() : await panel.source();
        } catch {
          target.replaceChildren(notice(`Could not load ${panel.title}.`));
          return;
        }
        const rows = panelRows(data);
        if (rows === undefined) {
          target.replaceChildren(notice(`${panel.title} returned no rows.`));
          return;
        }
        const lines: HTMLElement[] = rows.rows.map((row) => {
          const line = document.createElement("div");
          line.className = "row";
          const label = document.createElement("span");
          label.textContent = row.label;
          const value = document.createElement("b");
          value.textContent = row.value;
          line.append(label, value);
          if (row.note !== undefined) {
            const note = document.createElement("span");
            note.textContent = row.note;
            line.append(note);
          }
          return line;
        });
        if (rows.more > 0) {
          const more = document.createElement("div");
          more.className = "row";
          const label = document.createElement("span");
          label.textContent = `${rows.more} more not shown`;
          more.append(label);
          lines.push(more);
        }
        target.replaceChildren(...lines);
      };
      void paint();
      if (panel.refreshMs !== undefined && panel.refreshMs > 0) this.timers.push(setInterval(() => void paint(), Math.max(1000, panel.refreshMs)));
    }
  }
}

/**
 * The stylesheet, built once and adopted by every shadow root. A constructable stylesheet
 * rather than a `<style>` element because of CSP: an injected `<style>` is inline style, which
 * a host page with `style-src 'self'` blocks; a sheet built by script that already satisfied
 * `script-src` is not.
 */
let sheet: CSSStyleSheet | undefined;

function adoptStyles(shadow: ShadowRoot): void {
  if (typeof CSSStyleSheet !== "undefined" && "replaceSync" in CSSStyleSheet.prototype && "adoptedStyleSheets" in shadow) {
    if (sheet === undefined) {
      sheet = new CSSStyleSheet();
      sheet.replaceSync(`${DASHBOARD_CSS}\n${EXTRA_CSS}`);
    }
    if (!shadow.adoptedStyleSheets.includes(sheet)) shadow.adoptedStyleSheets = [...shadow.adoptedStyleSheets, sheet];
    return;
  }
  if (shadow.querySelector("style[data-hp]") !== null) return;
  const style = document.createElement("style");
  style.setAttribute("data-hp", "");
  style.textContent = `${DASHBOARD_CSS}\n${EXTRA_CSS}`;
  shadow.append(style);
}

let framingWarned = false;

/**
 * The one protection that does not survive being embedded: the standalone page refuses to
 * be framed, and a page you serve decides that for itself. A warning, not a refusal, and
 * only for a cross-origin ancestor.
 */
function warnIfFramed(): void {
  if (framingWarned || globalThis.top === globalThis.self) return;
  try {
    void (globalThis.top as Window).location.origin;
  } catch {
    framingWarned = true;
    console.warn(`${LOG} this page is framed by another origin. The standalone dashboard refuses framing with \`frame-ancestors 'none'\`; a page you serve yourself has to send that header, or \`X-Frame-Options: DENY\`, itself.`);
  }
}

function notice(text: string): HTMLElement {
  const node = document.createElement("p");
  node.className = "hp-notice";
  node.textContent = text;
  return node;
}

declare global {
  interface HTMLElementTagNameMap {
    "hackerpot-dashboard": HackerpotDashboardElement;
  }
}
