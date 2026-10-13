// Kept identical in hackerpot and bothandlerjs. Change both, or neither.

/**
 * Selector escaping, in a leaf module with nothing behind it.
 *
 * `dom.ts` is the client's entry into the document and carries module state that has to be
 * initialised in order, which is why the embeddable element imports it lazily. But the element
 * also assembles selectors from panel ids a developer supplied *synchronously*, before any of
 * that has happened — so the escape lives here rather than being duplicated or dragging the
 * client's module graph in early. Every id the client itself looks up is one the page declares.
 */
export function cssEscape(value: string): string {
  return typeof CSS !== "undefined" && typeof CSS.escape === "function" ? CSS.escape(value) : String(value).replace(/[^\w-]/g, "\\$&");
}
