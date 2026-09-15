import { el } from "./dom.js";
import { hue } from "./format.js";
import { responseClass } from "./query.js";

/**
 * The small labelled chips the page puts beside everything.
 *
 * A detector's hue is a custom property set through the CSSOM (`--h`) and the colour is
 * computed in the stylesheet from it, so each theme picks its own lightness for legible
 * text while the hue stays the same detector to detector. The id is always the text; the
 * hue only helps the eye find it again.
 */

export function detectorBadge(id: string): HTMLElement {
  const badge = el("span", "badge det", id);
  badge.style.setProperty("--h", String(hue(id)));
  return badge;
}

export function responseBadge(response: string, label = response): HTMLElement {
  return el("span", `badge ${responseClass(response)}`, label);
}

export function plainBadge(text: string, extra = ""): HTMLElement {
  return el("span", `badge ${extra}`.trim(), text);
}

/** A row of detector badges, the first `limit` of them and a count of the rest. */
export function detectorBadges(ids: Iterable<string>, limit = Number.POSITIVE_INFINITY): HTMLElement {
  const box = el("span", "badges");
  const list = [...new Set(ids)];
  for (const id of list.slice(0, limit)) box.append(detectorBadge(id));
  if (list.length > limit) box.append(plainBadge(`+${list.length - limit}`));
  return box;
}
