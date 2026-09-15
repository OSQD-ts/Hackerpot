import { ADVERSARIAL_CASES } from "./adversarial.js";
import { BENIGN_BOT_CASES } from "./benign-bots.js";
import { EXPLOIT_CASES } from "./exploits.js";
import { HUMAN_CASES } from "./humans.js";
import { INFRASTRUCTURE_CASES } from "./infrastructure.js";
import { SCANNER_CASES } from "./scanners.js";
import type { Audience, TrafficCase } from "./schema.js";

export * from "./schema.js";
export * from "./headers.js";
export { runCorpus, addressFor, factsFor, caseResolver, assertCorpusIntegrity } from "./runner.js";
export type { RunnerOptions, Scorecard, CaseResult, RequestResult, AudienceTally } from "./runner.js";
export { HUMAN_CASES } from "./humans.js";
export { BENIGN_BOT_CASES, CORPUS_CRAWLER_RANGES, GOOGLEBOT_IP, GOOGLEBOT_PTR, BINGBOT_IP, BINGBOT_PTR, DUCKDUCKBOT_IP, GPTBOT_IP } from "./benign-bots.js";
export { INFRASTRUCTURE_CASES } from "./infrastructure.js";
export { SCANNER_CASES } from "./scanners.js";
export { EXPLOIT_CASES } from "./exploits.js";
export { ADVERSARIAL_CASES } from "./adversarial.js";

/**
 * The corpus.
 *
 * Order matters only for readability. Every case carries its own address space and its own
 * clock, so no case can influence another — which is what makes it safe to run a subset,
 * or one case on its own while debugging. Frozen so a caller cannot mutate the shared
 * fixture out from under another.
 */
export const CORPUS: readonly TrafficCase[] = Object.freeze([
  ...HUMAN_CASES,
  ...BENIGN_BOT_CASES,
  ...INFRASTRUCTURE_CASES,
  ...SCANNER_CASES,
  ...EXPLOIT_CASES,
  ...ADVERSARIAL_CASES,
]);

/** What each audience means, and what being wrong about it costs. */
export const AUDIENCE_STAKES: Readonly<Record<Audience, string>> = {
  human: "A person. Anything firing here is a customer the honeypot would have caught in a decoy — a hard failure.",
  "benign-bot": "Automation you want: crawlers, unfurlers, monitors, feeds. Being wrong costs ranking, previews, or a monitor that lies about being green.",
  "unwanted-bot": "Automation most sites decline but which is not an attack. How you treat it is a business decision; the library only has to not prove it a threat.",
  infrastructure: "Your own machinery: probes, origin pulls, webhooks. Usually belongs in the allowlist rather than in front of a detector.",
  hostile: "Scanners, exploit payloads, forgeries and credential attacks. Catching these is the point.",
};

/** Cases matching a tag, for reports and CLI filters. */
export function casesByTag(tag: string, cases: readonly TrafficCase[] = CORPUS): TrafficCase[] {
  return cases.filter((item) => item.tags?.includes(tag) === true);
}

/** Cases in one audience. */
export function casesByAudience(audience: Audience, cases: readonly TrafficCase[] = CORPUS): TrafficCase[] {
  return cases.filter((item) => item.audience === audience);
}

/** Every distinct category present, sorted, for reports that group by it. */
export function categories(cases: readonly TrafficCase[] = CORPUS): string[] {
  return [...new Set(cases.map((item) => item.category))].sort();
}
