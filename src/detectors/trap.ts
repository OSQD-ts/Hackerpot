import type { Detection, DetectionContext, Detector } from "./types.js";

/**
 * Hidden traps: links and form fields that exist in your HTML but that no person can reach.
 * Adapted from bothandlerjs.
 *
 * A trap link is hidden from layout, hidden from assistive technology, unfocusable, and
 * disallowed in `robots.txt`. No sequence of clicks, keystrokes or screen-reader
 * gestures reaches it, so a client that requests it parsed the markup and followed every
 * link it found. A trap form field is rendered hidden and must arrive empty; a value in it
 * was typed by something that enumerated the form's inputs.
 *
 * That is detection by construction rather than by inference, which is why a trap is
 * proof (`certain`). The guarantee rests on three things that are the deployment's job:
 *
 * 1. The trap is invisible and unfocusable. Use `renderTrapLink` and `renderTrapField`,
 *    which set `aria-hidden`, `tabindex="-1"` and off-screen positioning together.
 * 2. Trap paths are disallowed in `robots.txt` (`trapRobotsEntries`, or `trapPaths` on
 *    `generateRobotsTxt`), so a crawler that obeys it is never caught.
 * 3. A trap path never serves anything real, now or later.
 */

export interface TrapOptions {
  /**
   * Paths linked only from hidden markup. Matched exactly, or as a prefix when the entry
   * ends in `/`. Default `DEFAULT_TRAP_PATHS`.
   */
  paths?: readonly string[];
  /**
   * Names of hidden form fields that must arrive empty. Read from the query string, from
   * a form-encoded or JSON body when the engine has one, and from `formFields` on the
   * facts. In middleware mode the body is read only for requests something already
   * flagged, so for a POST form mount `trapFormGuard` after your body parser.
   */
  formFields?: readonly string[];
  /** A header only trap links carry, if you prefer to mark traps out of band. */
  headerName?: string;
  /** Default 15, like a replayed honeytoken. */
  score?: number;
  respondWith?: string;
}

/** Trap paths used unless you pass your own. Chosen to look worth fetching. */
export const DEFAULT_TRAP_PATHS: readonly string[] = ["/internal/export.csv", "/api/v1/all-users", "/sitemap-index-full.xml"];

/** Longest field value quoted back in a detection. */
const MAX_QUOTED = 80;

/** The submitted fields of a form-encoded or JSON body, or undefined for anything else. */
function bodyFields(body: string | undefined): Record<string, unknown> | undefined {
  if (body === undefined || body === "") return undefined;
  const trimmed = body.trim();
  if (trimmed.startsWith("{")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : undefined;
    } catch {
      return undefined;
    }
  }
  if (!trimmed.includes("=")) return undefined;
  const fields: Record<string, unknown> = Object.create(null);
  for (const [key, value] of new URLSearchParams(trimmed)) fields[key] ??= value;
  return fields;
}

export function trapDetector(options: TrapOptions = {}): Detector {
  const exact = new Set<string>();
  const prefixes: string[] = [];
  for (const path of options.paths ?? DEFAULT_TRAP_PATHS) {
    if (!path.startsWith("/")) throw new TypeError(`A trap path must begin with "/": ${JSON.stringify(path.slice(0, 60))}`);
    if (path.endsWith("/")) prefixes.push(path);
    else exact.add(path);
  }
  const formFields = [...(options.formFields ?? [])];
  const headerName = options.headerName?.toLowerCase();
  const score = options.score ?? 15;

  const detection = (reason: string, metadata: Record<string, unknown>): Detection => ({
    detectorId: "trap",
    reason,
    score,
    // Nothing a person does reaches a trap. See the module comment for what that rests on.
    certain: true,
    metadata,
    ...(options.respondWith ? { respondWith: options.respondWith } : {}),
  });

  return {
    id: "trap",
    description: "A request touched a hidden trap link, form field or header that only markup-parsing automation reaches",
    // Reads a body when one is present, but never asks for one: a trap path is decided on
    // the path, and waiting for a body would defer it to the second pass.
    inspect(ctx: DetectionContext): Detection | undefined {
      if (exact.has(ctx.path) || prefixes.some((prefix) => ctx.path.startsWith(prefix))) {
        return detection(`Requested trap path ${ctx.path}`, { trap: "path", path: ctx.path });
      }

      if (formFields.length > 0) {
        const sources: Array<[string, Record<string, unknown> | undefined]> = [
          ["query", ctx.query],
          ["form", ctx.formFields],
          ["body", bodyFields(ctx.body)],
        ];
        for (const field of formFields) {
          for (const [source, fields] of sources) {
            const value = fields?.[field];
            // Strings only: this feeds proof, and `String(someObject)` is evidence of nothing.
            if (typeof value === "string" && value.length > 0) {
              return detection(`Filled the hidden form field "${field}"`, { trap: "form-field", field, source, sample: value.slice(0, MAX_QUOTED) });
            }
          }
        }
      }

      if (headerName !== undefined && ctx.headers[headerName] !== undefined) {
        return detection(`Sent the trap header ${headerName}`, { trap: "header", header: headerName });
      }
      return undefined;
    },
  };
}

const HIDDEN_STYLE = "position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden";

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => `&#${character.charCodeAt(0)};`);
}

/**
 * A trap link, with every attribute the guarantee needs: `aria-hidden` and `tabindex="-1"`
 * take it out of the accessibility tree and the tab order, so keyboard and screen-reader
 * users, the people most at risk from a careless trap, can never reach it. Emit it once,
 * near the end of `<body>`.
 */
export function renderTrapLink(path: string = DEFAULT_TRAP_PATHS[0]!, label = "Archive index"): string {
  // Also keeps any scheme, `javascript:` included, out of the href.
  if (!path.startsWith("/")) throw new TypeError(`A trap path must begin with "/": ${JSON.stringify(path.slice(0, 60))}`);
  return `<a href="${escapeHtml(path)}" rel="nofollow noindex" aria-hidden="true" tabindex="-1" style="${HIDDEN_STYLE}">${escapeHtml(label)}</a>`;
}

/**
 * A hidden form field. Give it a name a form filler wants to complete (`website`,
 * `email_confirm`) and list that name in `formFields`.
 */
export function renderTrapField(name: string): string {
  const safe = escapeHtml(name);
  return `<div aria-hidden="true" style="${HIDDEN_STYLE}"><label for="${safe}">Leave this field empty</label><input type="text" id="${safe}" name="${safe}" tabindex="-1" autocomplete="off" value=""></div>`;
}

/** `robots.txt` lines excluding the trap paths, so a crawler that obeys it is never caught. */
export function trapRobotsEntries(paths: readonly string[] = DEFAULT_TRAP_PATHS): string {
  return ["User-agent: *", ...paths.map((path) => `Disallow: ${path}`)].join("\n");
}
