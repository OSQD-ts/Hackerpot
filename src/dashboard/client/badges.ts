import { el } from "./dom.js";
import { hue } from "./format.js";
import { responseClass } from "./query.js";

/**
 * The small labelled chips the page puts beside everything.
 *
 * Every badge is the UI kit's chip. A detector's wears one of the kit's twelve hue tags, picked
 * from the same hash of its id every time, so it is the same colour detector to detector; the
 * kit holds each tag to 4.5:1 in every theme. The id is always the text; the hue only helps the
 * eye find it again.
 */

export function detectorBadge(id: string): HTMLElement {
  return el("span", `badge det oq-chip oq-sm oq-hue-${Math.floor(hue(id) / 30)}`, id);
}

export function responseBadge(response: string, label = response): HTMLElement {
  return el("span", `badge oq-chip oq-sm oq-neutral ${responseClass(response)}`, label);
}

export function plainBadge(text: string, extra = ""): HTMLElement {
  return el("span", `badge oq-chip oq-sm oq-neutral ${extra}`.trim(), text);
}

/** A row of detector badges, the first `limit` of them and a count of the rest. */
export function detectorBadges(ids: Iterable<string>, limit = Number.POSITIVE_INFINITY): HTMLElement {
  const box = el("span", "badges");
  const list = [...new Set(ids)];
  for (const id of list.slice(0, limit)) box.append(detectorBadge(id));
  if (list.length > limit) box.append(plainBadge(`+${list.length - limit}`));
  return box;
}
