// Kept identical in hackerpot and bothandlerjs. Change both, or neither.

import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Filters somebody saved, kept by the dashboard rather than by one browser.
 *
 * In `localStorage` alone a saved filter survives only a normal tab on a dashboard whose address
 * never changes: embedded, the page never touches the host page's storage, and a sandboxed frame
 * refuses it. So the listener keeps them — one list per listener, since a dashboard that
 * masks addresses has a different audience from one that does not — in memory by default and in
 * a file when `savedFilters.file` is set. The page keeps a copy too, and hands it back to a
 * listener that comes up empty, so leaving the file unset loses nothing.
 */
export interface SavedFilter {
  name: string;
  /** The query text, exactly as typed. */
  query: string;
  /** The outcome chip it was saved with — `all`, or a response class — because a filter is usually both. */
  filter: string;
}

/** Enough for a working set; past this it is a list nobody reads. */
const MAX_SAVED = 50;
const MAX_NAME = 60;
/** The same ceiling the page's query parser reads to. */
const MAX_QUERY = 8192;
/** C0 controls and DEL, which have no business in a name printed on everybody's screen. */
const CONTROL = new RegExp(`[${String.fromCharCode(0)}-${String.fromCharCode(31)}${String.fromCharCode(127)}]`, "g");

/**
 * A saved filter as it is kept: bounded, printable, and `undefined` when it is not one.
 *
 * `chips` is the set this dashboard's page can actually show — its own outcome or verdict chips —
 * because a filter saved with a chip nothing draws would come back as a view that cannot be shown.
 */
export function cleanSavedFilter(value: unknown, chips: ReadonlySet<string>): SavedFilter | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const raw = value as Record<string, unknown>;
  if (typeof raw["name"] !== "string" || typeof raw["query"] !== "string") return undefined;
  const name = raw["name"].replace(CONTROL, " ").trim().slice(0, MAX_NAME);
  if (name === "") return undefined;
  const filter = typeof raw["filter"] === "string" && chips.has(raw["filter"]) ? raw["filter"] : "all";
  return { name, query: raw["query"].slice(0, MAX_QUERY), filter };
}

export class SavedFilterStore {
  private entries: SavedFilter[] = [];

  constructor(
    private readonly file: string | undefined,
    private readonly warn: (message: string) => void,
    private readonly chips: ReadonlySet<string>,
  ) {
    if (file !== undefined) this.load(file);
  }

  list(): readonly SavedFilter[] {
    return this.entries;
  }

  /** Saves under a name, replacing any filter already using it, newest first. */
  save(entry: SavedFilter): void {
    this.entries = [entry, ...this.entries.filter((existing) => existing.name !== entry.name)].slice(0, MAX_SAVED);
    this.persist();
  }

  delete(name: string): void {
    const before = this.entries.length;
    this.entries = this.entries.filter((entry) => entry.name !== name);
    if (this.entries.length !== before) this.persist();
  }

  private load(file: string): void {
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch (error) {
      // No file yet is the normal first run. Anything else is worth a word.
      if ((error as { code?: string }).code !== "ENOENT") this.warn(`Saved filters could not be read from ${file}: ${(error as Error).message}. Starting with none.`);
      return;
    }
    try {
      const parsed: unknown = JSON.parse(text);
      const seen = new Set<string>();
      for (const item of Array.isArray(parsed) ? parsed : []) {
        const entry = cleanSavedFilter(item, this.chips);
        if (entry === undefined || seen.has(entry.name)) continue;
        seen.add(entry.name);
        this.entries.push(entry);
        if (this.entries.length >= MAX_SAVED) break;
      }
    } catch (error) {
      this.warn(`Saved filters in ${file} are not valid JSON (${(error as Error).message}). Starting with none; the file will be replaced on the next save.`);
    }
  }

  /**
   * Written whole, to a temporary file first and then renamed over the real one, so a process
   * killed halfway through leaves the previous list rather than half of a new one. A failure
   * keeps the list in memory and says so.
   */
  private persist(): void {
    if (this.file === undefined) return;
    const temporary = `${this.file}.${process.pid}.tmp`;
    try {
      mkdirSync(dirname(this.file), { recursive: true });
      writeFileSync(temporary, `${JSON.stringify(this.entries, null, 2)}\n`, "utf8");
      renameSync(temporary, this.file);
    } catch (error) {
      this.warn(`Saved filters could not be written to ${this.file}: ${(error as Error).message}. They are kept in memory until the process ends.`);
    }
  }
}
