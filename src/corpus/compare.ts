import type { CaseResult, Scorecard } from "./runner.js";

/**
 * Comparing one corpus run against an earlier one.
 *
 * The scorecard answers "does this configuration behave?" against expectations written into
 * each case. What it cannot answer is the question asked during an upgrade: **did anything
 * that used to be served stop being served?** A case can meet its expectations before and
 * after a change and still have moved from "answered normally" to "tarpitted", because no
 * expectation ever said which of the two it had to be — the corpus deliberately does not pin
 * every case to an exact action, so that tuning is possible at all.
 *
 * That gap is where a regression hides. A new detector, a lowered threshold or a reordered
 * rule shows up here as traffic that changed side, and nowhere else. Recording a run and
 * comparing the next one against it turns "the corpus still passes" into "and nobody lost
 * service". Adapted from bothandlerjs, whose runner takes a `--baseline` for the same reason.
 */

/** What one case did, reduced to what is worth comparing between runs. */
export interface CorpusCaseRecord {
  id: string;
  audience: string;
  /** True when the honeypot did not answer this case at all: no response action ran. */
  served: boolean;
  /** The action the case's last request received. Empty when none ran. */
  actionId: string;
  /** Detector ids that fired anywhere in the case. */
  fired: string[];
  /** Whether the case met its own expectations. */
  passed: boolean;
}

export interface CorpusBaseline {
  /** Bumped if the record shape ever changes, so an old file is refused rather than misread. */
  version: 1;
  total: number;
  cases: CorpusCaseRecord[];
}

/** One case that behaves differently than it did. */
export interface CorpusChange {
  id: string;
  audience: string;
  was: string;
  now: string;
}

export interface CorpusComparison {
  /** Traffic that lost service, or a case that stopped meeting its expectations. */
  regressions: CorpusChange[];
  /** Traffic that gained service, or a case that started passing. Reported, never failed. */
  improvements: CorpusChange[];
  /** Cases the baseline knew that this run did not exercise — a corpus that shrank, or a filter. */
  missing: string[];
  /** Cases this run exercised that the baseline had never seen. */
  added: string[];
}

/** True when the honeypot answered nothing: the request would have reached the application. */
export function isServed(result: CaseResult): boolean {
  const last = result.requests[result.requests.length - 1];
  return last === undefined || last.actionId === "";
}

/** How a case's behaviour reads in a report. */
function describe(record: Pick<CorpusCaseRecord, "served" | "actionId" | "passed">): string {
  const outcome = record.served ? "served" : record.actionId === "" ? "flagged" : record.actionId;
  return record.passed ? outcome : `${outcome} (expectations unmet)`;
}

/** The record of a run, for writing to a file and comparing a later run against. */
export function baselineOf(scorecard: Scorecard): CorpusBaseline {
  const cases: CorpusCaseRecord[] = [];
  for (const result of scorecard.results) {
    // A skipped case ran nothing, so it has no behaviour to record. Including it would make
    // "not skipped any more" look like a change in how traffic is treated.
    if (result.skipped !== undefined) continue;
    const last = result.requests[result.requests.length - 1];
    cases.push({
      id: result.case.id,
      audience: result.case.audience,
      served: isServed(result),
      actionId: last?.actionId ?? "",
      fired: [...result.fired],
      passed: result.failures.length === 0,
    });
  }
  return { version: 1, total: cases.length, cases };
}

/** Reads a baseline file's parsed contents, or explains why it cannot be used. */
export function parseBaseline(value: unknown): CorpusBaseline {
  const candidate = value as Partial<CorpusBaseline> | null;
  if (candidate === null || typeof candidate !== "object" || !Array.isArray(candidate.cases)) {
    throw new Error("not a corpus baseline: expected the JSON written by `corpus --json`");
  }
  if (candidate.version !== 1) {
    throw new Error(`baseline version ${String(candidate.version)} is not one this build can read; record a fresh one`);
  }
  return candidate as CorpusBaseline;
}

/**
 * What changed between a recorded run and this one.
 *
 * Losing service is the regression that matters and is listed first: a case that was answered
 * normally and is now tarpitted, blocked or fed a decoy is somebody who used to get through.
 * A case that stopped meeting its expectations counts too, because that is the corpus saying
 * the change was not the one intended.
 */
export function compareToBaseline(baseline: CorpusBaseline, scorecard: Scorecard): CorpusComparison {
  const before = new Map(baseline.cases.map((record) => [record.id, record]));
  const now = baselineOf(scorecard);
  const comparison: CorpusComparison = { regressions: [], improvements: [], missing: [], added: [] };

  for (const record of now.cases) {
    const previous = before.get(record.id);
    if (previous === undefined) {
      comparison.added.push(record.id);
      continue;
    }
    before.delete(record.id);
    const change: CorpusChange = { id: record.id, audience: record.audience, was: describe(previous), now: describe(record) };
    if (previous.served && !record.served) comparison.regressions.push(change);
    else if (!previous.served && record.served) comparison.improvements.push(change);
    else if (previous.passed && !record.passed) comparison.regressions.push(change);
    else if (!previous.passed && record.passed) comparison.improvements.push(change);
  }
  comparison.missing = [...before.keys()];
  return comparison;
}
