import { classOf } from "./analysis.js";
import { clear, el, maybe } from "./dom.js";
import { fmtInt, fmtPct } from "./format.js";
import { incidentTotal } from "./incidents.js";
import { state } from "./store.js";
import type { TabName } from "./types.js";

/**
 * The counter strip above the working screens, as bothandlerjs's dashboard keeps one above every
 * view: the number first, what it counts under it, and colour only where the number means
 * something by itself — proof in violet, a block in red, a cost imposed in amber.
 *
 * Not on the Overview or Statistics, which open with counters of their own.
 */
export const TILE_TABS: ReadonlySet<TabName> = new Set<TabName>(["incidents", "sessions", "actors", "intel"]);

interface Tile {
  value: string;
  key: string;
  sub: string;
  tone?: "proven" | "crit" | "warn" | "good";
}

/** What each tile last showed, so a strip redrawn on every live incident only touches what changed. */
let painted = "";

export function renderTiles(): void {
  const host = maybe("tiles");
  if (host === null) return;
  const tiles = compute();
  const signature = JSON.stringify(tiles);
  if (signature === painted) return;
  painted = signature;
  clear(host);
  for (const tile of tiles) {
    // The UI kit's stat tile, as bothandlerjs's dashboard draws its counters.
    const node = el("div", tile.tone === undefined ? "tile oq-stat" : `tile oq-stat ${tile.tone}`);
    node.append(el("div", "v oq-stat__value", tile.value), el("div", "k oq-stat__label", tile.key));
    const sub = el("div", "s oq-stat__delta", tile.sub);
    sub.title = tile.sub;
    node.append(sub);
    host.append(node);
  }
}

function compute(): Tile[] {
  const recorded = incidentTotal() ?? state.all.length;
  const loaded = state.all.length;
  const proven = state.all.filter((incident) => incident.detections.some((detection) => detection.certain === true)).length;
  // By response class, from the store's own counts where it has them: those cover everything it
  // holds, where the loaded incidents are only the most recent.
  const byClass = new Map<string, number>();
  const byResponse = state.stats?.byResponse;
  if (byResponse !== undefined) {
    for (const [response, n] of Object.entries(byResponse)) byClass.set(classOf(response), (byClass.get(classOf(response)) ?? 0) + n);
  } else {
    for (const incident of state.all) byClass.set(classOf(incident.respondedWith), (byClass.get(classOf(incident.respondedWith)) ?? 0) + 1);
  }
  const classTotal = [...byClass.values()].reduce((sum, n) => sum + n, 0);
  const share = (n: number): string => (classTotal === 0 ? "—" : `${fmtPct(n, classTotal, 0)} of incidents`);
  const sources = state.stats?.uniqueIps ?? new Set(state.all.map((incident) => incident.ip)).size;
  const actors = state.actors.length > 0 ? state.actors.length : new Set(state.all.map((incident) => incident.fingerprint).filter((f) => f !== undefined)).size;
  return [
    { value: fmtInt(recorded), key: "Incidents", sub: "recorded" },
    { value: fmtInt(proven), key: "Proven", sub: loaded === 0 ? "no incidents loaded" : `${fmtPct(proven, loaded, 0)} of loaded`, tone: "proven" },
    { value: fmtInt(byClass.get("block") ?? 0), key: "Blocked", sub: share(byClass.get("block") ?? 0), tone: "crit" },
    { value: fmtInt(byClass.get("time cost") ?? 0), key: "Time cost", sub: share(byClass.get("time cost") ?? 0), tone: "warn" },
    { value: fmtInt(byClass.get("decoy") ?? 0), key: "Decoyed", sub: share(byClass.get("decoy") ?? 0), tone: "good" },
    { value: fmtInt(byClass.get("silent 404") ?? 0), key: "Silent 404", sub: share(byClass.get("silent 404") ?? 0) },
    { value: fmtInt(sources), key: "Sources", sub: "distinct addresses" },
    { value: fmtInt(actors), key: "Actors", sub: "client fingerprints" },
  ];
}
