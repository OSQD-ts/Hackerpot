#!/usr/bin/env tsx
/**
 * Runs the traffic corpus against the default detector set and prints a scorecard.
 *
 *   npx tsx scripts/corpus.ts                       # middleware mode (the proof guard on)
 *   npx tsx scripts/corpus.ts --standalone          # evaluate without the proof guard
 *   npx tsx scripts/corpus.ts --audience human --verbose
 *   npx tsx scripts/corpus.ts --tag verification
 *   npx tsx scripts/corpus.ts --json > before.json
 *   npx tsx scripts/corpus.ts --baseline before.json   # what changed side since that run
 *
 * The section to read first is FALSE POSITIVES. Everything else is diagnostics; that one
 * is benign traffic this configuration would have caught in a decoy.
 */
import { HoneypotEngine } from "../src/core.js";
import { crawlerVerificationDetector, defaultDetectors, honeytokenDetector, trapDetector, verifiableCrawlers } from "../src/detectors/index.js";
import { CrawlerRanges } from "../src/crawler-ranges.js";
import type { DnsResolver } from "../src/internal/dns.js";
import { AUDIENCE_STAKES, CORPUS, CORPUS_CRAWLER_RANGES, CORPUS_HONEYTOKEN, CORPUS_TRAP_FIELD, CORPUS_TRAP_PATH, runCorpus } from "../src/corpus/index.js";
import type { Audience } from "../src/corpus/schema.js";
import type { CaseResult, Scorecard } from "../src/corpus/runner.js";
import { baselineOf, compareToBaseline, parseBaseline } from "../src/corpus/compare.js";
import { readFileSync } from "node:fs";

const flags = new Map<string, string>();
for (let i = 2; i < process.argv.length; i++) {
  const entry = process.argv[i]!;
  if (!entry.startsWith("--")) continue;
  const next = process.argv[i + 1];
  if (next !== undefined && !next.startsWith("--")) {
    flags.set(entry.slice(2), next);
    i++;
  } else flags.set(entry.slice(2), "true");
}

const audienceFilter = flags.get("audience") as Audience | undefined;
const tagFilter = flags.get("tag");
const verbose = flags.has("verbose");
const asJson = flags.has("json");
const standalone = flags.has("standalone");
const baselineFile = flags.get("baseline");

const cases = CORPUS.filter((item) => (audienceFilter === undefined || item.audience === audienceFilter) && (tagFilter === undefined || item.tags?.includes(tagFilter) === true));

const CAPABILITIES = ["honeytoken", "trap", "crawler-verification", "published-ranges"];

function makeCreate() {
  const ranges = new CrawlerRanges();
  for (const [id, prefixes] of Object.entries(CORPUS_CRAWLER_RANGES)) ranges.update(id, prefixes);
  return ({ resolver }: { resolver: DnsResolver }): HoneypotEngine =>
    new HoneypotEngine({
      enricher: null,
      detectors: [
        crawlerVerificationDetector({ resolver, ranges, crawlers: verifiableCrawlers }),
        ...defaultDetectors(),
        honeytokenDetector({ tokens: [CORPUS_HONEYTOKEN] }),
        trapDetector({ paths: [CORPUS_TRAP_PATH], formFields: [CORPUS_TRAP_FIELD] }),
      ],
    });
}

const RULE = "─".repeat(78);
const out = (line = ""): void => void process.stdout.write(`${line}\n`);

function bar(value: number, total: number, width = 22): string {
  if (total === 0) return "";
  return "█".repeat(Math.round((value / total) * width));
}

function describe(result: CaseResult): void {
  const last = result.requests[result.requests.length - 1];
  out(`  ${result.case.id}  (${result.case.audience}/${result.case.category})`);
  out(`    ${result.case.title}`);
  out(`    -> fired: ${result.fired.join(", ") || "nothing"}${last ? `  action: ${last.actionId || "allow"}` : ""}`);
  for (const failure of result.failures) out(`    x ${failure}`);
  if (verbose) out(`    provenance: ${result.case.provenance}`);
  out();
}

function report(scorecard: Scorecard): void {
  out();
  out(RULE);
  out(`  traffic corpus — ${scorecard.total} cases, ${standalone ? "standalone" : "middleware"} mode`);
  out(RULE);

  out();
  if (scorecard.falsePositives.length === 0) {
    out("  FALSE POSITIVES: none. No benign traffic was penalised.");
  } else {
    out(`  FALSE POSITIVES: ${scorecard.falsePositives.length}. Traffic this configuration would have caught in a decoy.`);
    out(RULE);
    for (const result of scorecard.falsePositives) describe(result);
  }

  out();
  out("  by audience");
  const width = Math.max(...Object.keys(scorecard.byAudience).map((key) => key.length));
  for (const [audience, tally] of Object.entries(scorecard.byAudience)) {
    if (tally.total === 0) continue;
    const actions = Object.entries(tally.actions)
      .sort((a, b) => b[1] - a[1])
      .map(([action, count]) => `${action || "allow"} ${count}`)
      .join(", ");
    out(`    ${audience.padEnd(width)}  ${String(tally.passed).padStart(3)}/${String(tally.total).padStart(3)} pass   ${actions}`);
  }

  out();
  out("  detector coverage");
  const coverage = Object.entries(scorecard.detectorCoverage).sort((a, b) => b[1] - a[1]);
  const detectorWidth = Math.max(0, ...coverage.map(([id]) => id.length));
  for (const [detector, count] of coverage) {
    out(`    ${detector.padEnd(detectorWidth)}  ${String(count).padStart(4)} cases  ${bar(count, scorecard.total)}`);
  }
  if (scorecard.unexercisedDetectors.length > 0) {
    out();
    out(`    not exercised by any case: ${scorecard.unexercisedDetectors.join(", ")}`);
    out("    (a gap in the corpus, not the library — an untested detector regresses unnoticed)");
  }

  if (scorecard.knownCosts.length > 0) {
    out();
    out(`  known costs (${scorecard.knownCosts.length}) — people the design knowingly cannot serve cleanly:`);
    for (const result of scorecard.knownCosts) {
      out(`    ${result.case.id} -> ${result.fired.join(", ")}`);
      out(`      ${result.case.notes ?? result.case.title}`);
    }
  }

  if (scorecard.skipped.length > 0) {
    out();
    out(`  skipped (${scorecard.skipped.length}) — the engine under test is not configured for these:`);
    for (const result of scorecard.skipped) out(`    ${result.case.id}: ${result.skipped}`);
  }

  const otherFailures = scorecard.results.filter((result) => result.skipped === undefined && result.failures.length > 0 && !result.falsePositive);
  if (otherFailures.length > 0) {
    out();
    out(RULE);
    out(`  ${otherFailures.length} expectation mismatch(es)`);
    out(RULE);
    for (const result of otherFailures) describe(result);
  }

  out(RULE);
  out(`  ${scorecard.passed}/${scorecard.total} cases pass  ·  ${scorecard.falsePositives.length} false positives  ·  ${scorecard.skipped.length} skipped  ·  ${scorecard.durationMs.toFixed(0)}ms`);
  out(RULE);
  out();
  if (audienceFilter !== undefined) out(`  ${audienceFilter}: ${AUDIENCE_STAKES[audienceFilter]}\n`);
}

const scorecard = await runCorpus({ create: makeCreate(), provides: CAPABILITIES, cases, middleware: !standalone });

if (asJson) {
  const { results, ...summary } = scorecard;
  void results;
  // `cases` is what makes this file usable as a baseline: one record per case, saying which
  // side of the line it came down on. Everything else here is a summary for a human.
  const { cases, version } = baselineOf(scorecard);
  out(
    JSON.stringify(
      {
        version,
        ...summary,
        falsePositives: scorecard.falsePositives.map((r) => r.case.id),
        knownCosts: scorecard.knownCosts.map((r) => r.case.id),
        skipped: scorecard.skipped.map((r) => r.case.id),
        cases,
      },
      null,
      2,
    ),
  );
} else {
  report(scorecard);
}

let regressed = false;
if (baselineFile !== undefined && baselineFile !== "true") {
  let comparison: ReturnType<typeof compareToBaseline>;
  try {
    comparison = compareToBaseline(parseBaseline(JSON.parse(readFileSync(baselineFile, "utf8")) as unknown), scorecard);
  } catch (error) {
    out(`  cannot read baseline ${baselineFile}: ${(error as Error).message}`);
    process.exit(2);
  }
  regressed = comparison.regressions.length > 0;
  if (!asJson) {
    out(RULE);
    out(`  against ${baselineFile}`);
    out(RULE);
    out();
    if (comparison.regressions.length === 0) {
      out("  no regressions: nothing that was served before is refused now.");
    } else {
      out(`  REGRESSIONS: ${comparison.regressions.length}. Traffic that changed side since that run.`);
      for (const change of comparison.regressions) out(`    ${change.id} (${change.audience}): ${change.was} -> ${change.now}`);
    }
    for (const change of comparison.improvements) out(`    + ${change.id} (${change.audience}): ${change.was} -> ${change.now}`);
    if (comparison.missing.length > 0) out(`    baseline had ${comparison.missing.length} case(s) this run did not exercise: ${comparison.missing.slice(0, 5).join(", ")}${comparison.missing.length > 5 ? ", …" : ""}`);
    if (comparison.added.length > 0) out(`    ${comparison.added.length} case(s) the baseline had never seen`);
    out();
  } else {
    out(JSON.stringify(comparison, null, 2));
  }
}

process.exitCode = scorecard.falsePositives.length > 0 || scorecard.failed > 0 || regressed ? 1 : 0;
