// Kept identical in hackerpot and bothandlerjs. Change both, or neither.

import { clear, el } from "./dom.js";
import { fmtInt } from "./format.js";

/**
 * The pager over and under a table.
 *
 * One renderer rather than one per table, because a table may page in the browser or on the
 * server and *neither of those facts belongs in the control*. What it needs to know is where you
 * are and what to do when you press something.
 *
 * Rendered twice per table. Fifty rows are taller than the window on most screens, and a pager
 * only at the bottom means scrolling to the end to go back to the top of the next page.
 *
 * Rebuilt only when what it says changes: a table redraws on every arriving request, and
 * replacing the nodes somebody is reaching for closes an open select mid-choice and lands a click
 * on a node that has just been detached.
 */
export interface PagerModel {
  /** Zero-based. */
  page: number;
  /** What the range reads: `1–50 of 212`. The total is omitted where it is not known. */
  from: number;
  to: number;
  total?: number;
  atStart: boolean;
  atEnd: boolean;
  /** Shown beside the range when the list is being held still. */
  held?: string;
  go: (page: number) => void;
  size?: {
    current: number;
    choices: readonly number[];
    set: (size: number) => void;
  };
}

const painted = new WeakMap<HTMLElement, string>();

export function renderPager(host: HTMLElement, model: PagerModel, options: { withSize: boolean }): void {
  const signature = JSON.stringify([model.page, model.from, model.to, model.total, model.atStart, model.atEnd, model.held ?? "", options.withSize, model.size?.current]);
  if (painted.get(host) === signature && host.childElementCount > 0) return;
  painted.set(host, signature);
  clear(host);

  host.append(step("‹", "Previous page", model.atStart, () => model.go(Math.max(0, model.page - 1))));

  const range = model.total === undefined ? `${fmtInt(model.from)}–${fmtInt(model.to)}` : `${fmtInt(model.from)}–${fmtInt(model.to)} of ${fmtInt(model.total)}`;
  const where = el("span", "where", model.total === 0 ? "0 of 0" : range);
  // Announced on change, because the rows themselves are not a live region: somebody paging with
  // the keyboard has to hear that the page moved.
  where.setAttribute("aria-live", "polite");
  host.append(where, step("›", "Next page", model.atEnd, () => model.go(model.page + 1)));

  if (model.held !== undefined) {
    const held = el("span", "held", model.held);
    held.title = "New entries are still arriving and are still counted. They appear when you return to the first page.";
    host.append(held);
  }

  // The size chooser goes on one of the two pagers only. Two of them would be two controls for
  // one setting, which is a thing to keep in sync and a second stop in the tab order doing nothing new.
  if (options.withSize && model.size !== undefined) {
    const size = model.size;
    const label = el("label", "size");
    label.append("Per page");
    const select = el("select");
    for (const choice of size.choices) {
      const option = el("option", null, String(choice));
      option.value = String(choice);
      option.selected = choice === size.current;
      select.append(option);
    }
    select.addEventListener("change", () => {
      const chosen = Number(select.value);
      if (Number.isFinite(chosen) && chosen > 0) size.set(chosen);
    });
    label.append(select);
    host.append(label);
  }
}

function step(glyph: string, label: string, disabled: boolean, go: () => void): HTMLButtonElement {
  const button = el("button", "step", glyph);
  button.type = "button";
  button.disabled = disabled;
  // The glyph is decoration; a button whose accessible name is "›" tells a screen reader nothing.
  button.setAttribute("aria-label", label);
  button.title = label;
  button.addEventListener("click", go);
  return button;
}
