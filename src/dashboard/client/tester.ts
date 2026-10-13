import { postJson } from "./api.js";
import { detectorBadge, responseBadge } from "./badges.js";
import { BOOT } from "./boot.js";
import { $, byId, clear, el, maybe } from "./dom.js";
import { fmtInt } from "./format.js";
import type { Detection } from "./types.js";

/**
 * "Test a request": a pasted request run through the detectors as a dry run, beside the feed
 * where bothandlerjs's dashboard puts the same panel.
 *
 * Nothing is recorded, no score moves and no response is served — the server evaluates with
 * recording, activity tracking and the traffic audit all switched off. The panel exists only
 * when the deployment granted `testRequest`; the server refuses the call otherwise, so hiding
 * it is courtesy rather than the control.
 */

interface TestResult {
  request: { method: string; path: string; ip: string };
  detections: readonly Detection[];
  shadowDetections?: readonly Detection[];
  score: number;
  confidence?: number;
  actionId?: string;
  rule?: string;
  reason?: string;
  downgradedFrom?: string;
}

export function initTester(): void {
  const panel = maybe("tester");
  if (panel === null) return;
  if (BOOT.controls?.testRequest !== true) {
    panel.remove();
    return;
  }
  panel.hidden = false;
  const input = byId<HTMLTextAreaElement>("test-input");
  const run = byId<HTMLButtonElement>("test-run");
  const submit = async (): Promise<void> => {
    const text = input.value;
    if (text.trim() === "") {
      show(el("p", "muted small", "Paste a User-Agent, a curl command, or a request line with its headers."));
      return;
    }
    run.disabled = true;
    try {
      render(await postJson<TestResult>("/api/test", { text }));
    } catch (error) {
      show(el("p", "warn-text small", error instanceof Error ? error.message : String(error)));
    } finally {
      run.disabled = false;
    }
  };
  run.addEventListener("click", () => void submit());
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      void submit();
    }
  });
}

function show(...nodes: Node[]): void {
  const result = $("test-result");
  clear(result);
  result.append(...nodes);
}

function render(result: TestResult): void {
  const verdict = el("div", "test-verdict");
  verdict.append(responseBadge(result.actionId ?? "none", result.actionId ?? "nothing"));
  verdict.append(el("span", "num", ` score ${fmtInt(result.score)}`));
  if (result.confidence !== undefined) verdict.append(el("span", "muted", ` · confidence ${result.confidence.toFixed(2)}`));
  const nodes: Node[] = [el("div", "mono small muted", `${result.request.method} ${result.request.path} from ${result.request.ip}`), verdict];
  if (result.downgradedFrom !== undefined) nodes.push(el("p", "warn-text small", `Asked for ${result.downgradedFrom}; the evidence could not support it, so this ran instead.`));
  if (result.rule !== undefined || result.reason !== undefined) {
    nodes.push(el("p", "small", [result.rule === undefined ? undefined : `rule ${result.rule}`, result.reason].filter((part) => part !== undefined).join(" — ")));
  }
  if (result.detections.length === 0) nodes.push(el("p", "muted small", "No detector fired."));
  for (const detection of result.detections) nodes.push(detectionLine(detection, false));
  for (const detection of result.shadowDetections ?? []) nodes.push(detectionLine(detection, true));
  show(...nodes);
}

function detectionLine(detection: Detection, shadow: boolean): HTMLElement {
  const line = el("div", "test-detection");
  line.append(detectorBadge(detection.detector), el("span", "num muted", shadow ? " shadow" : ` +${fmtInt(detection.score)}`));
  line.append(el("div", "small", detection.summary));
  return line;
}
