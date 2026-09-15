import { describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import { crawlerVerificationDetector, defaultDetectors, honeytokenDetector, trapDetector, verifiableCrawlers } from "../src/detectors/index.js";
import { CrawlerRanges } from "../src/crawler-ranges.js";
import type { DnsResolver } from "../src/internal/dns.js";
import { CORPUS, CORPUS_CRAWLER_RANGES, CORPUS_HONEYTOKEN, CORPUS_TRAP_FIELD, CORPUS_TRAP_PATH, assertCorpusIntegrity, runCorpus } from "../src/corpus/index.js";

/**
 * The whole corpus, run against the default detectors plus the three the defaults leave
 * out — honeytoken, trap and crawler-verification — with a controlled resolver and the
 * fictional crawler ranges loaded. The two assertions that matter are that no benign
 * traffic is penalised and that every attack is caught; the rest guard the corpus itself.
 */

const CAPABILITIES = ["honeytoken", "trap", "crawler-verification", "published-ranges"];

function makeCreate() {
  const ranges = new CrawlerRanges();
  for (const [id, prefixes] of Object.entries(CORPUS_CRAWLER_RANGES)) ranges.update(id, prefixes);
  return ({ resolver }: { resolver: DnsResolver }): HoneypotEngine =>
    new HoneypotEngine({
      enricher: null,
      // crawler-verification runs first so a confirmed crawler's `verifiedCrawler` mark is
      // set before the volume detectors, which then skip it — exactly the ordering the
      // library documents for a deployment that opts into verification.
      detectors: [
        crawlerVerificationDetector({ resolver, ranges, crawlers: verifiableCrawlers }),
        ...defaultDetectors(),
        honeytokenDetector({ tokens: [CORPUS_HONEYTOKEN] }),
        trapDetector({ paths: [CORPUS_TRAP_PATH], formFields: [CORPUS_TRAP_FIELD] }),
      ],
    });
}

describe("traffic corpus", () => {
  it("is importable from src/corpus/index.js and non-trivial", async () => {
    const module = await import("../src/corpus/index.js");
    expect(module.CORPUS).toBe(CORPUS);
    expect(CORPUS.length).toBeGreaterThanOrEqual(150);
  });

  it("passes its own integrity checks", () => {
    expect(() => assertCorpusIntegrity(CORPUS)).not.toThrow();
  });

  it("expects every default detector on at least one hostile case", () => {
    const expected = new Set(CORPUS.filter((item) => item.audience === "hostile").flatMap((item) => item.expect?.detectors ?? []));
    const unexpected = defaultDetectors()
      .map((detector) => detector.id)
      .filter((id) => !expected.has(id));
    expect(unexpected).toEqual([]);
  });

  it("turns nobody away and catches every attack (middleware mode)", async () => {
    const scorecard = await runCorpus({ create: makeCreate(), provides: CAPABILITIES });

    expect(
      scorecard.falsePositives.map((result) => `${result.case.id}: ${result.failures.join(" | ")}`),
      "false positives — benign traffic the honeypot penalised",
    ).toEqual([]);

    expect(
      scorecard.results.filter((result) => result.skipped === undefined && result.failures.length > 0).map((result) => `${result.case.id}: ${result.failures.join(" | ")}`),
      "cases that did not meet their expectations",
    ).toEqual([]);

    // Nothing is skipped, because the test provides every capability the corpus asks for.
    expect(scorecard.skipped).toEqual([]);
    expect(scorecard.passed).toBe(scorecard.total);
  });

  it("catches the same attacks in standalone mode (no proof guard)", async () => {
    const scorecard = await runCorpus({ create: makeCreate(), provides: CAPABILITIES, middleware: false });
    expect(scorecard.falsePositives.map((result) => result.case.id)).toEqual([]);
    expect(scorecard.results.filter((result) => result.skipped === undefined && result.failures.length > 0).map((result) => result.case.id)).toEqual([]);
  });

  it("skips capability-dependent cases when the engine does not provide them", async () => {
    const scorecard = await runCorpus({ create: () => new HoneypotEngine({ enricher: null }), provides: [] });
    // The honeytoken, trap and crawler-verification cases cannot be judged without their
    // configuration, so they are skipped and reported rather than counted as passes.
    expect(scorecard.skipped.length).toBeGreaterThan(0);
    for (const result of scorecard.skipped) expect(result.case.requires?.length).toBeGreaterThan(0);
  });
});
