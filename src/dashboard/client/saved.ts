// Kept identical in hackerpot and bothandlerjs. Change both, or neither.

import { apiUrl } from "./api.js";
import { isEmbedded } from "./dom.js";

/**
 * Filters somebody saved.
 *
 * Kept by the dashboard's listener, with a copy in this browser.
 *
 * They used to be kept *only* in this browser, as a personal working note that needed no write
 * endpoint. That held in one situation — an ordinary tab, on a dashboard whose address never
 * changed — and failed silently in every other. Embedded, the page never touches the host page's
 * storage, so nothing was kept; and a sandboxed frame such as VS Code's built-in browser blocks
 * `prompt()` outright, so asking for a name did nothing at all. Both looked like "saving does not
 * work".
 *
 * So the listener is the source of truth: a saved filter is there after a reload, in another
 * browser, and inside somebody else's page. This browser keeps a copy anyway, for one reason — a
 * listener with no saved-filter file starts empty after a restart, and the copy is handed back to
 * it, so leaving the file unset loses nothing the browser-only version kept.
 *
 * The requests are made here rather than through the shared JSON helpers, because the two
 * dashboards report a failed POST differently and this file is the same in both.
 */
export interface SavedFilter {
  name: string;
  /** The query text, exactly as typed. */
  query: string;
  /** The chip it was saved with, because a filter is usually both. */
  filter: string;
}

const MIRROR_KEY = "osqd.dashboard.filters";
/* What bothandlerjs kept this under before the two dashboards shared this file. Read when the
   key above holds nothing, and dropped once anything has been written forward, so a dashboard
   somebody had saved filters in does not come back empty after an upgrade. */
const LEGACY_MIRROR_KEY = "bothandler.filters";
const ENDPOINT = "/api/filters";

/** The list as last seen, so drawing it never waits on the network. */
let known: SavedFilter[] = [];

function readMirror(): SavedFilter[] {
  // Embedded, the storage belongs to the page around us and is shared with whatever else that
  // page keeps there. Reading is harmless; writing somebody else's origin is not, so neither happens.
  if (isEmbedded()) return [];
  try {
    const raw = localStorage.getItem(MIRROR_KEY) ?? localStorage.getItem(LEGACY_MIRROR_KEY);
    const parsed: unknown = raw === null ? [] : JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as SavedFilter[]).filter((entry) => typeof entry?.name === "string" && typeof entry?.query === "string") : [];
  } catch {
    return [];
  }
}

function writeMirror(list: readonly SavedFilter[]): void {
  if (isEmbedded()) return;
  try {
    localStorage.setItem(MIRROR_KEY, JSON.stringify(list));
    localStorage.removeItem(LEGACY_MIRROR_KEY);
  } catch {
    /* A full or refused store is not a reason to stop showing traffic. */
  }
}

/** The list as last seen. Synchronous; see `refreshSavedFilters` for fetching it. */
export function savedFilters(): readonly SavedFilter[] {
  return known;
}

async function send(body: unknown): Promise<{ ok: boolean; filters?: SavedFilter[]; error?: string }> {
  try {
    const response = await fetch(apiUrl(ENDPOINT), {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: { accept: "application/json", "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await response.text();
    const parsed: unknown = text === "" ? {} : JSON.parse(text);
    const payload = parsed as { filters?: SavedFilter[]; error?: string };
    if (!response.ok) return payload.error === undefined ? { ok: false } : { ok: false, error: payload.error };
    return { ok: true, ...(payload.filters === undefined ? {} : { filters: payload.filters }) };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}

/**
 * Fetches the listener's list, and hands it this browser's copy if it came up empty.
 *
 * Empty with a copy here means a listener that restarted without a file, which is the case the
 * copy exists for. A dashboard old enough to have no endpoint answers with an error, and then
 * this browser's copy is the list — the behaviour it always had.
 */
export async function refreshSavedFilters(): Promise<readonly SavedFilter[]> {
  const mirror = readMirror();
  try {
    const response = await fetch(apiUrl(ENDPOINT), { credentials: "same-origin", cache: "no-store", headers: { accept: "application/json" } });
    if (!response.ok) throw new Error(String(response.status));
    let filters = ((await response.json()) as { filters?: SavedFilter[] }).filters ?? [];
    if (filters.length === 0 && mirror.length > 0) {
      // Oldest first, so the newest ends up at the top as it was.
      for (const entry of [...mirror].reverse()) {
        const result = await send(entry);
        if (result.filters !== undefined) filters = result.filters;
      }
    }
    known = filters;
    writeMirror(known);
  } catch {
    known = mirror;
  }
  return known;
}

/** Saves under a name, replacing any filter already using it. */
export async function saveFilter(entry: SavedFilter): Promise<{ ok: boolean; error?: string }> {
  const result = await send(entry);
  if (result.ok) {
    known = result.filters ?? [entry, ...known.filter((existing) => existing.name !== entry.name)];
    writeMirror(known);
    return { ok: true };
  }
  // Kept here anyway, so a listener that cannot take it does not cost somebody the filter they
  // just named. It goes to the listener the next time one comes up empty.
  known = [entry, ...known.filter((existing) => existing.name !== entry.name)].slice(0, 50);
  writeMirror(known);
  return result.error === undefined ? { ok: false } : { ok: false, error: result.error };
}

export async function deleteFilter(name: string): Promise<void> {
  const result = await send({ action: "delete", name });
  known = result.filters ?? known.filter((entry) => entry.name !== name);
  writeMirror(known);
}
