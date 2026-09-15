/**
 * The page's only way of putting something into the document, and of finding it again.
 *
 * `textContent`, always. Every string that reaches this file (a path, a User-Agent, a
 * request body, a password somebody tried over SSH) was written by the attacker the page
 * is describing, and one `innerHTML` anywhere turns their request into script running in
 * an operator's browser. `scripts/build-client.mjs` refuses to bundle any of the four ways
 * to do that, and `tests/dashboard-page.test.ts` checks the bundle again.
 *
 * Every lookup goes through a root rather than through `document`, so the same client
 * drives both the standalone page (which owns the whole document) and
 * `<hackerpot-dashboard>` (which owns a subtree inside a shadow root in somebody else's).
 */
import { cssEscape } from "./css.js";

let root: Document | ShadowRoot | HTMLElement = typeof document === "undefined" ? (undefined as never) : document;

/**
 * The element the theme tokens and `data-theme` hang off: the document element on the
 * page, the host element when embedded, because custom properties inherit *into* a shadow
 * root from its host and `:root` matches nothing in there.
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
 * True inside somebody else's page. Three things the standalone page may do and an
 * embedded one may not: write the tab into `location.hash` (the host's URL, and the host's
 * back button), read the hash to decide where to open, and rely on fragment navigation,
 * which does not cross a shadow boundary.
 */
export function isEmbedded(): boolean {
  return embedded;
}

export function rootNode(): Document | ShadowRoot | HTMLElement {
  return root;
}

export function themeElement(): HTMLElement {
  return themeHost;
}

/**
 * Where pointer and keyboard listeners go: the window when the page is ours, the owned
 * subtree when it is not, so moving the mouse over the host's own page is none of this
 * dashboard's business.
 */
export function eventTarget(): EventTarget {
  return embedded ? root : (globalThis as unknown as EventTarget);
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
