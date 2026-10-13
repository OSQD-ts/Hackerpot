// Kept identical in hackerpot and bothandlerjs. Change both, or neither.

/**
 * The page's only way of putting something into the document, and of finding it again.
 *
 * `textContent`, always. Every string that reaches this file — a path, a User-Agent, a request
 * body, a password somebody tried, a rule id typed into an editor — was written by somebody
 * else, and one `innerHTML` anywhere turns a request into script running in an operator's
 * browser. `scripts/build-client.mjs` refuses to bundle any of the four ways to do that, and a
 * test checks the built bundle again.
 *
 * Every lookup goes through a root rather than through `document`, so the same client drives
 * both the standalone page (which owns the whole document) and the embeddable element (which
 * owns a subtree inside a shadow root in somebody else's).
 */
import { cssEscape } from "./css.js";

let root: Document | ShadowRoot | HTMLElement = typeof document === "undefined" ? (undefined as never) : document;

/**
 * The element the theme tokens and `data-theme` hang off: the document element on the page, the
 * host element when embedded, because custom properties inherit *into* a shadow root from its
 * host and `:root` matches nothing in there.
 */
let themeHost: HTMLElement = typeof document === "undefined" ? (undefined as never) : document.documentElement;

let embedded = false;

/** Points the client at the subtree it owns. Called before anything draws. */
export function setRoot(node: Document | ShadowRoot | HTMLElement, host?: HTMLElement): void {
  root = node;
  embedded = typeof document === "undefined" || node !== document;
  if (host !== undefined) themeHost = host;
}

/** A remount carries the same subtree to a new host element. */
export function setThemeHost(host: HTMLElement): void {
  themeHost = host;
}

/**
 * True inside somebody else's page. Three things the standalone page may do and an embedded one
 * may not: write the tab into `location.hash` (the host's URL, and the host's back button), read
 * the hash to decide where to open, and rely on fragment navigation, which does not cross a
 * shadow boundary.
 */
export function isEmbedded(): boolean {
  return embedded;
}

export function rootNode(): Document | ShadowRoot | HTMLElement {
  return root;
}

/** The element carrying `data-theme` and the custom properties. */
export function themeElement(): HTMLElement {
  return themeHost;
}

/**
 * Where pointer and keyboard listeners go: the window when the page is ours, the owned subtree
 * when it is not, so a key pressed on the host's own page is the host's business.
 */
export function eventTarget(): EventTarget {
  return embedded ? (root as unknown as EventTarget) : (globalThis as unknown as EventTarget);
}

export function maybe<T extends HTMLElement = HTMLElement>(id: string): T | null {
  return root.querySelector<T>(`#${cssEscape(id)}`);
}

/**
 * An element the page's own markup declares. A miss is a rename that went wrong, not a
 * condition, so it fails loudly here rather than as a null dereference three frames later.
 */
export function $(id: string): HTMLElement {
  const node = maybe(id);
  if (node === null) throw new Error(`dashboard: no element #${id}`);
  return node;
}

export function byId<T extends HTMLElement>(id: string): T {
  return $(id) as T;
}

export function all<T extends Element = HTMLElement>(selector: string, within: ParentNode = root): T[] {
  return Array.from(within.querySelectorAll<T>(selector));
}

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, className?: string | null, text?: string | number | null): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className !== undefined && className !== null && className !== "") node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

const SVG = "http://www.w3.org/2000/svg";

export function svgEl<K extends keyof SVGElementTagNameMap>(name: K, attributes: Record<string, string | number> = {}): SVGElementTagNameMap[K] {
  const node = document.createElementNS(SVG, name);
  for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
  return node;
}

export function svgText(attributes: Record<string, string | number>, text: string | number): SVGTextElement {
  const node = svgEl("text", attributes);
  node.textContent = String(text);
  return node;
}

export function clear(node: Node): void {
  while (node.firstChild !== null) node.removeChild(node.firstChild);
}

export function setText(id: string, text: string): void {
  const node = maybe(id);
  if (node !== null) node.textContent = text;
}

/** A `<strong>` inline, for the facts and tooltips that bold one figure in a sentence. */
export function strong(text: string): HTMLElement {
  return el("b", null, text);
}

/** Nodes and strings as one list of nodes, strings becoming text nodes. */
export function nodes(parts: ReadonlyArray<Node | string>): Node[] {
  return parts.map((part) => (typeof part === "string" ? document.createTextNode(part) : part));
}

/** A CSS custom property's value, for the charts — which draw in the theme's own colours. */
export function css(name: string): string {
  return getComputedStyle(themeHost).getPropertyValue(name).trim();
}

/**
 * Whether somebody is typing into something inside `node`.
 *
 * Panels are drawn by clearing them and building them again, which is fine for a list of numbers
 * and destructive for a text box: a panel rebuilt whenever traffic arrives takes any input inside
 * it — and whatever had been typed — about a second after it was opened.
 *
 * Typing, specifically, rather than focus of any kind. Clicking a button in a panel focuses it,
 * and a panel that froze on any focus would refuse to redraw in response to its own controls.
 * What must survive a rebuild is text somebody entered and cannot get back.
 *
 * `activeElement` is read from the root this client was pointed at, because embedded that is a
 * shadow root and the document's `activeElement` is the host element rather than anything in it.
 */
const TYPED_INTO = new Set(["text", "search", "url", "tel", "email", "password", "number", "datetime-local", "date", "time", "month", "week"]);

export function holdsTextEntry(node: Element): boolean {
  const active = (root as Document | ShadowRoot).activeElement;
  if (active === null || active === undefined || !node.contains(active)) return false;
  if (active.tagName === "TEXTAREA") return true;
  if ((active as HTMLElement).isContentEditable) return true;
  return active.tagName === "INPUT" && TYPED_INTO.has(((active as HTMLInputElement).type || "text").toLowerCase());
}

let sequence = 0;

/**
 * Ties a `<label>` to the control it names.
 *
 * A label sitting next to an input is a label to a reader who can see the layout and nothing at
 * all to a screen reader: it announces "edit, blank" and moves on. Only for the controls a label
 * can point at — a group of chips is several buttons, and those carry their own names.
 */
export function label(text: string, control: HTMLElement | HTMLElement[]): HTMLLabelElement {
  const node = el("label", null, text);
  const single = Array.isArray(control) ? (control.length === 1 ? control[0] : undefined) : control;
  if (single !== undefined && /^(input|select|textarea)$/i.test(single.tagName)) {
    if (single.id === "") single.id = `field-${++sequence}`;
    node.htmlFor = single.id;
  } else {
    // Nothing to point at, so the group gets the name instead and the text becomes decoration
    // rather than a promise the page does not keep.
    for (const member of Array.isArray(control) ? control : [control]) if (!member.hasAttribute("aria-label")) member.setAttribute("aria-label", text);
  }
  return node;
}

/** Re-exported so the rest of the client reads unchanged; it lives apart for the element's sake. */
export { cssEscape };
