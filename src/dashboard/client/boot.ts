import type { Boot } from "./types.js";

/**
 * What the server told the page about itself.
 *
 * The standalone page is handed this as `window.__HACKERPOT_DASHBOARD__`, stamped into its
 * one nonced script; `<hackerpot-dashboard>` fetches the same object from `/api/bootstrap`
 * and passes it to `mountDashboard`. Neither has to ask which sections exist before
 * drawing, so the first frame never shows a tab it is about to remove.
 *
 * The bindings are `let` and `applyBoot` replaces them. ES module bindings are live, and
 * esbuild keeps them live, so every importer reads the current value; being evaluated
 * before the element has fetched its bootstrap costs nothing.
 */
const FALLBACK: Boot = {
  base: "",
  title: "hackerpot",
  instance: "",
  version: "",
  sections: { overview: true, incidents: true, statistics: true, sessions: true, actors: true, intel: true },
  links: [],
  source: "",
  redaction: { credentials: true, maskIp: false },
};

export let BOOT: Boot = (globalThis as { __HACKERPOT_DASHBOARD__?: Boot }).__HACKERPOT_DASHBOARD__ ?? FALLBACK;
export let API = BOOT.base;
export let SECTIONS = BOOT.sections;

export function applyBoot(next: Boot): void {
  BOOT = { ...FALLBACK, ...next, sections: { ...FALLBACK.sections, ...next.sections }, redaction: { ...FALLBACK.redaction, ...next.redaction } };
  API = BOOT.base;
  SECTIONS = BOOT.sections;
}
