import type { Failure } from "./query.js";
import type { Incident, TabName } from "./types.js";

/**
 * The handful of things any module may ask of the page as a whole.
 *
 * Filled in by `index.ts` at start-up rather than imported from it. The stream calls
 * `ingest`, the incident detail switches tabs, the session list filters the Incidents
 * screen: written as direct imports those are cycles, and a cycle in a bundle is a
 * half-initialised module waiting to be discovered at run time.
 */
export interface App {
  refresh: () => Promise<void>;
  ingest: (incident: Incident) => void;
  /** Re-renders soon, coalescing a burst of live incidents into one frame of work. */
  schedule: () => void;
  showTab: (tab: TabName, options?: { focus?: boolean; push?: boolean }) => void;
  /** Records or clears an endpoint's failure and redraws the error panel and the status. */
  showFailure: (endpoint: string, failure: Failure | undefined) => void;
  drawStatus: () => void;
  drawNotice: () => void;
  /** Opens the Incidents screen filtered to one address. */
  incidentsFor: (ip: string) => void;
}

export const app: App = {
  refresh: async () => {},
  ingest: () => {},
  schedule: () => {},
  showTab: () => {},
  showFailure: () => {},
  drawStatus: () => {},
  drawNotice: () => {},
  incidentsFor: () => {},
};
