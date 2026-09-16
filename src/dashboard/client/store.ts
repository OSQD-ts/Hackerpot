import type { IpSortKey } from "./analysis.js";
import type { Failure, IncidentFilter } from "./query.js";
import type { ActorGroup, AttackSession, Incident, IocEntry, StatsSummary, TabName } from "./types.js";

/**
 * Everything the page holds, in one place.
 *
 * One mutable record rather than state spread across modules, so a remount of the element
 * carries all of it across in the same subtree and so there is exactly one answer to "what
 * does the page think the corpus is".
 */

export type StreamState = "off" | "connecting" | "live" | "paused" | "down";

/**
 * What `/api/counts` returns.
 *
 * Kept apart from the incidents themselves because the list this page holds is bounded — by
 * retention, by its page size, by what the live feed dropped — so its length answers "how many
 * rows are here" and never "how many happened".
 */
/** One thing the engine said about itself. Mirrors `Notice` in the engine. */
export interface DashboardNotice {
  timestamp: string;
  message: string;
  /** Present when the notice came from a runtime change, and says which part and by whom. */
  change?: { part: string; summary: string; by?: string };
}

export interface FeedCountsSnapshot {
  total: number;
  /** The earliest instant these counts can speak for. */
  oldest?: number;
  series: ReadonlyArray<{ at: number; total: number }>;
}

export interface State {
  /** The analytics corpus: the most recent incidents, oldest first. */
  all: Incident[];
  /** Bumped whenever `all` changes, so derived analyses know they are stale. */
  version: number;
  /** The Incidents screen's filtered list, newest first. */
  incidents: Incident[];
  stats: StatsSummary | undefined;
  /** Incidents heard on the stream since `stats` was fetched, so the headline count keeps moving. */
  liveSinceStats: number;
  /** How many incidents happened, as opposed to how many are held. Undefined until fetched. */
  counts: FeedCountsSnapshot | undefined;
  /** What the engine has said about itself. Empty when this dashboard reads another process. */
  notices: DashboardNotice[];
  sessions: AttackSession[];
  actors: ActorGroup[];
  ioc: IocEntry[];
  metrics: Record<string, number>;
  metricsRaw: string;
  /** Statistics window, milliseconds back from the newest incident. `0` is everything loaded. */
  range: number;
  proto: string;
  iocMin: number;
  tab: TabName;
  filter: IncidentFilter;
  ipSort: { key: IpSortKey; dir: 1 | -1 };
  live: boolean;
  stream: StreamState;
  streamDetail: string;
  /** Frames the server dropped for this viewer, and frames its rate limit skipped. */
  dropped: number;
  skipped: number;
  /** The drop count the operator last dismissed the notice at. */
  acknowledged: number;
  openIncidents: Set<string>;
  openSessions: Set<string>;
  /** The latest failure per endpoint. */
  failures: Map<string, Failure>;
  loadedAt: number;
}

export const state: State = {
  all: [],
  version: 0,
  incidents: [],
  stats: undefined,
  liveSinceStats: 0,
  counts: undefined,
  notices: [],
  sessions: [],
  actors: [],
  ioc: [],
  metrics: {},
  metricsRaw: "",
  range: 0,
  proto: "",
  iocMin: 0,
  tab: "overview",
  filter: { limit: 100, detector: "", ip: "", query: "" },
  ipSort: { key: "score", dir: -1 },
  live: true,
  stream: "off",
  streamDetail: "",
  dropped: 0,
  skipped: 0,
  acknowledged: 0,
  openIncidents: new Set(),
  openSessions: new Set(),
  failures: new Map(),
  loadedAt: 0,
};
