import { postJson } from "./api.js";
import { app } from "./app.js";
import { responseBadge } from "./badges.js";
import { BOOT } from "./boot.js";
import { $, byId, clear, el, maybe } from "./dom.js";
import { fmtInt, fmtTime } from "./format.js";
import { state } from "./store.js";
import { toast } from "./toast.js";
import { download } from "./transfer.js";
import type { Incident } from "./types.js";

/**
 * The policy as data, edited here: a rule list, replayed against what this dashboard already
 * holds, and applied to the running engine when the deployment allows it.
 *
 * The same screen bothandlerjs has, against the endpoints this dashboard already served and
 * nothing on the page used. Two guarantees carried over from the server: a preview **reads** —
 * no score moves, no incident is recorded, the running policy is untouched — and applying needs
 * the `editPolicy` control, which needs authentication.
 */

/** One incident a candidate rule list would answer differently. `PreviewChange` on the server. */
interface PreviewChange {
  id: string;
  ip: string;
  path: string;
  was: string;
  now: string;
  rule: string;
  reason: string;
  downgradedFrom?: string;
}

interface PreviewResult {
  total: number;
  changed: PreviewChange[];
  unchanged: number;
  skipped: number;
}

/** Most changed incidents listed; past that it is a list nobody reads, and the count says the rest. */
const MAX_LISTED = 100;

const EXAMPLE = `[
  {
    "id": "block-proven-scanners",
    "match": { "detector": ["scanner-signature"], "certain": true },
    "respondWith": "block",
    "reason": "A self-declared scanner, proven rather than guessed."
  }
]`;

export function canEditPolicy(): boolean {
  return BOOT.controls?.editPolicy === true;
}

export function canPreviewPolicy(): boolean {
  return BOOT.controls?.previewPolicy === true || canEditPolicy();
}

export function initPolicy(): void {
  const editor = maybe<HTMLTextAreaElement>("policy-rules");
  if (editor === null) return;
  if (editor.value === "") editor.value = EXAMPLE;

  const apply = byId<HTMLButtonElement>("policy-apply");
  apply.hidden = !canEditPolicy();

  byId<HTMLButtonElement>("policy-preview").addEventListener("click", () => void run("preview"));
  apply.addEventListener("click", () => void run("apply"));
  byId<HTMLButtonElement>("policy-example").addEventListener("click", () => {
    editor.value = EXAMPLE;
    editor.focus();
  });
  byId<HTMLButtonElement>("policy-export").addEventListener("click", () => {
    download(`${editor.value.trimEnd()}\n`, `hackerpot-policy-${new Date().toISOString().slice(0, 10)}.json`, "application/json");
  });
  renderPolicyChanges();
}

/**
 * What has been replaced in this process since it started, from the notices the engine keeps.
 *
 * The screen above says what a rule set *would* do; this says what somebody already did, which
 * is the question anybody looking at an unexpected answer asks next.
 */
export function renderPolicyChanges(): void {
  const host = maybe("policy-changes");
  if (host === null) return;
  const changes = state.notices.filter((notice) => notice.change !== undefined);
  const count = maybe("policy-change-count");
  if (count !== null) count.textContent = changes.length === 0 ? "" : `${fmtInt(changes.length)} this run`;
  clear(host);
  if (changes.length === 0) {
    host.append(el("p", "sub", "Nothing has been replaced at runtime. The policy, the detectors and the allowlist are as the code that built this honeypot left them."));
    return;
  }
  const list = el("div", "stack-gap");
  for (const notice of [...changes].reverse().slice(0, 20)) {
    const row = el("div", "notice");
    row.append(el("span", "badge oq-chip oq-sm oq-neutral", notice.change?.part ?? "change"));
    const body = el("div");
    body.append(el("div", null, notice.message));
    body.append(el("div", "faint tiny", [fmtTime(notice.timestamp), notice.change?.by === undefined ? undefined : `by ${notice.change.by}`].filter((part) => part !== undefined).join(" · ")));
    row.append(body);
    list.append(row);
  }
  host.append(list);
}

function rules(): unknown[] | undefined {
  const editor = byId<HTMLTextAreaElement>("policy-rules");
  try {
    const parsed: unknown = JSON.parse(editor.value.trim() === "" ? "[]" : editor.value);
    if (!Array.isArray(parsed)) throw new Error("the rules are a JSON array of rule objects");
    return parsed;
  } catch (error) {
    show(el("p", "warn-text", error instanceof Error ? error.message : String(error)));
    return undefined;
  }
}

async function run(what: "preview" | "apply"): Promise<void> {
  const candidate = rules();
  if (candidate === undefined) return;
  const button = byId<HTMLButtonElement>(what === "apply" ? "policy-apply" : "policy-preview");
  button.disabled = true;
  try {
    if (what === "preview") {
      renderPreview(await postJson<PreviewResult>("/api/policy/preview", { rules: candidate }));
      return;
    }
    const result = await postJson<{ applied: number; by: string }>("/api/policy/apply", { rules: candidate });
    toast("ok", `Applied ${fmtInt(result.applied)} rule${result.applied === 1 ? "" : "s"}`, "Every request from now on is answered by these rules; the ladder still decides what they do not match.");
    show(el("p", null, `Applied by ${result.by}. The change is on the Overview's Notices panel, with who made it.`));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    show(el("p", "warn-text", message));
    toast("bad", what === "apply" ? "Not applied" : "Could not preview", message);
  } finally {
    button.disabled = false;
  }
}

function show(...nodes: Node[]): void {
  const host = $("policy-result");
  clear(host);
  host.append(...nodes);
}

function renderPreview(result: PreviewResult): void {
  const summary = el("div", "policy-summary");
  summary.append(
    stat(fmtInt(result.changed.length), "would change"),
    stat(fmtInt(result.unchanged), "answered the same"),
    stat(fmtInt(result.total), "incidents replayed"),
    stat(fmtInt(result.skipped), "skipped, nothing fired"),
  );
  if (result.changed.length === 0) {
    show(summary, el("p", "muted", result.total === 0 ? "No incident loaded has a detection to replay." : "These rules answer every incident on this dashboard exactly as it was answered."));
    return;
  }

  const table = el("table", "plain");
  const head = el("tr");
  for (const column of ["Address", "Path", "Was", "Would be", "Rule"]) head.append(el("th", null, column));
  const thead = el("thead");
  thead.append(head);
  table.append(thead);
  const body = el("tbody");
  for (const change of result.changed.slice(0, MAX_LISTED)) {
    const row = el("tr");
    const was = el("td");
    was.append(responseBadge(change.was));
    const now = el("td");
    now.append(responseBadge(change.now));
    if (change.downgradedFrom !== undefined) now.append(el("div", "faint tiny", `asked for ${change.downgradedFrom}; the proof guard refused it`));
    const rule = el("td");
    rule.append(el("div", "mono small", change.rule));
    if (change.reason !== "") rule.append(el("div", "faint tiny", change.reason));
    row.append(el("td", "ip", change.ip), el("td", "path", change.path), was, now, rule);
    body.append(row);
  }
  table.append(body);
  const wrap = el("div", "tablewrap scroll");
  wrap.append(table);
  const nodes: Node[] = [summary, wrap];
  if (result.changed.length > MAX_LISTED) nodes.push(el("p", "faint small", `${fmtInt(result.changed.length - MAX_LISTED)} more would change; the first ${MAX_LISTED} are listed.`));
  show(...nodes);
}

function stat(value: string, label: string): HTMLElement {
  const node = el("div", "policy-stat");
  node.append(el("div", "v", value), el("div", "k", label));
  return node;
}

/**
 * A rule drafted from one incident, for the button on an opened row.
 *
 * It matches what that incident was: the detector that scored highest and the path it asked for,
 * answering with what the policy already chose. That is deliberately a no-op rule — somebody
 * reading it changes the action, or widens the match, having started from something true rather
 * than from an empty box.
 */
export function draftRuleFor(incident: Incident): void {
  const editor = maybe<HTMLTextAreaElement>("policy-rules");
  if (editor === null) return;
  const detector = incident.detections[0]?.detector;
  const draft = {
    id: `${detector ?? "incident"}-${incident.ip.replaceAll(/[^\w]/g, "-")}`.slice(0, 64),
    match: {
      ...(detector === undefined ? {} : { detector: [detector] }),
      path: [incident.path],
    },
    respondWith: incident.respondedWith,
    reason: `Drafted from ${incident.method} ${incident.path}.`,
  };
  let current: unknown[] = [];
  try {
    // The example is what the box holds until somebody edits it, so a draft replaces it rather
    // than being filed under a rule nobody wrote.
    const parsed: unknown = JSON.parse(editor.value.trim() === "" || editor.value === EXAMPLE ? "[]" : editor.value);
    if (Array.isArray(parsed)) current = parsed;
  } catch {
    // An editor holding something unparseable is not a reason to lose the draft: it goes on its own.
  }
  editor.value = JSON.stringify([...current, draft], null, 2);
  app.showTab("policy");
  editor.focus();
  editor.setSelectionRange(editor.value.length, editor.value.length);
  toast("ok", "Rule drafted", "It answers exactly as this incident was answered. Change the action, then preview it.");
}
