import { el, maybe } from "./dom.js";

/** A short confirmation in the corner, as bothandlerjs's dashboard gives one. Gone after six seconds. */
export function toast(kind: "ok" | "bad" | "warn", title: string, detail = ""): void {
  const host = maybe("toasts");
  if (host === null) return;
  const node = el("div", `toast ${kind}`);
  node.append(el("b", null, title));
  if (detail !== "") node.append(el("span", null, detail));
  host.append(node);
  setTimeout(() => node.remove(), 6000);
}
