/**
 * Selector escaping, in a leaf module with nothing behind it.
 *
 * The embeddable element assembles selectors from panel ids a developer supplied, before
 * the client's module graph has been pointed at a root, so it needs this without loading
 * `dom.ts`. Every id the client itself looks up is one the page's markup declares.
 */
export function cssEscape(value: string): string {
  return typeof CSS !== "undefined" && typeof CSS.escape === "function" ? CSS.escape(value) : String(value).replace(/[^\w-]/g, "\\$&");
}
