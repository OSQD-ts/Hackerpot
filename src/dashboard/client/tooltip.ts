import { $, clear, el, eventTarget } from "./dom.js";

/**
 * One shared tooltip for every chart.
 *
 * The old page stored each tooltip as an HTML string in a `data-tip` attribute and wrote it
 * with `innerHTML` on hover, which meant every User-Agent and path on the Statistics screen
 * was escaped exactly once, by hand, on its way into markup that was then parsed again.
 * Here a mark carries a structured description in a `WeakMap`, and the tooltip is built
 * out of text nodes. There is nothing to escape because nothing is ever parsed.
 *
 * The tooltip is decoration over data that is also available as text: every chart has a
 * table view, and the tooltip element is hidden from assistive technology.
 */

export type TipPart = string | { strong: string } | { swatch: string };

export interface Tip {
  title: string;
  lines: ReadonlyArray<readonly TipPart[]>;
}

const tips = new WeakMap<Element, Tip>();

export function setTip(node: Element, tip: Tip): void {
  tips.set(node, tip);
}

function findTip(event: Event): Tip | undefined {
  const path = typeof event.composedPath === "function" ? event.composedPath() : [];
  let node: Element | null = (path[0] ?? event.target) instanceof Element ? ((path[0] ?? event.target) as Element) : null;
  while (node !== null) {
    const tip = tips.get(node);
    if (tip !== undefined) return tip;
    node = node.parentElement;
  }
  return undefined;
}

let shown: Tip | undefined;

export function initTooltip(): void {
  const box = $("tip");
  const hide = (): void => {
    shown = undefined;
    box.classList.remove("on");
  };
  eventTarget().addEventListener("pointermove", (event) => {
    const pointer = event as PointerEvent;
    const tip = findTip(pointer);
    if (tip === undefined) {
      if (shown !== undefined) hide();
      return;
    }
    if (tip !== shown) {
      shown = tip;
      clear(box);
      box.append(el("div", "t", tip.title));
      for (const line of tip.lines) {
        const row = el("div", "r");
        for (const part of line) {
          if (typeof part === "string") row.append(part);
          else if ("strong" in part) row.append(el("b", null, part.strong));
          else row.append(el("span", `sw bg-${part.swatch}`));
        }
        box.append(row);
      }
      box.classList.add("on");
    }
    // Placed through the CSSOM: a style attribute would be inline style, which the CSP blocks.
    const rect = box.getBoundingClientRect();
    let left = pointer.clientX + 14;
    let top = pointer.clientY + 14;
    if (left + rect.width > innerWidth - 8) left = pointer.clientX - rect.width - 14;
    if (top + rect.height > innerHeight - 8) top = pointer.clientY - rect.height - 14;
    box.style.left = `${Math.max(8, left)}px`;
    box.style.top = `${Math.max(8, top)}px`;
  });
  eventTarget().addEventListener("pointerleave", hide);
  addEventListener("scroll", hide, { passive: true });
}
