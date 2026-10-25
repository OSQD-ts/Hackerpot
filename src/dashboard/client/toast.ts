import { el, maybe } from "./dom.js";

const TOAST_INTENT = { ok: "oq-success", bad: "oq-danger", warn: "oq-warning" } as const;

/** A short confirmation in the corner, as bothandlerjs's dashboard gives one. Gone after six seconds. */
export function toast(kind: "ok" | "bad" | "warn", title: string, detail = ""): void {
  const host = maybe("toasts");
  if (host === null) return;
  // The UI kit's toast: an intent class colours its edge, title above the detail.
  const node = el("div", `toast oq-toast ${kind} ${TOAST_INTENT[kind]}`);
  const body = el("div", "oq-toast__body");
  body.append(el("b", "oq-toast__title", title));
  if (detail !== "") body.append(el("span", "oq-toast__message", detail));
  node.append(body);
  host.append(node);
  setTimeout(() => node.remove(), 6000);
}
