import type { Rule } from "./rules.js";

/**
 * Rule sets to start from, read, and own.
 *
 * Each is a list you can print, edit and replace one rule of — not a black box. Every rule
 * carries an id, so an incident can name the one that decided it, and a reason, so the
 * dashboard and the log can say why in words rather than in thresholds.
 *
 * None of them can deny anybody on a guess: in middleware mode the proof guard runs after a
 * rule is chosen, so a rule asking to block an unproven request is answered with the
 * fallback instead. Choose a preset for the shape of the policy; the guard decides how far
 * it is allowed to go. Adapted from bothandlerjs.
 */

/**
 * Watch, and do nothing anybody could notice.
 *
 * Every flagged request is passed through to your application, which answers it exactly as it
 * would have, while the incident is still recorded, scored and alerted on. Run this first on a
 * deployment in front of real users: it tells you what your traffic looks like without a
 * single visitor being slowed down, turned away, or shown a 404 for a page that exists.
 *
 * Standalone, where there is no application, a passed request is answered with a plain 404.
 */
export function observe(_thresholds: PresetThresholds = {}): Rule[] {
  return [{ id: "observe-everything", match: {}, respondWith: "pass", reason: "Observation only: recorded and scored, then handed to the application untouched." }];
}

/**
 * In front of a real application.
 *
 * Bait keeps working, proof is dealt with firmly, and everything unproven costs the client
 * time rather than service. Nothing here refuses a request on a score alone, because in
 * front of real users a score is a guess and the person it is wrong about is a customer.
 */
export function protectApp(thresholds: PresetThresholds = {}): Rule[] {
  const tarpitAt = thresholds.tarpitThreshold ?? 25;
  return [
    {
      id: "proof-block",
      match: { certain: true },
      respondWith: "block",
      reason: "Proof, not suspicion: a replayed honeytoken, a hidden trap, a protocol violation no client stack emits, a self-declared attack tool, or a refuted crawler claim.",
    },
    {
      id: "decoy-bait",
      match: { detector: ["decoy-path", "sensitive-file", "web-shell"] },
      respondWith: "@detector",
      fallbackAction: "decoy-content",
      reason: "A probe for something that does not exist: served the bait the decoy defines, so the prober learns nothing from the difference.",
    },
    {
      id: "exploit-tarpit",
      match: { detector: ["payload-injection", "ssrf-probe", "crlf-injection", "nosql-injection", "prototype-pollution", "insecure-deserialization", "jwt-weakness", "graphql-abuse"] },
      respondWith: "tarpit",
      reason: "An exploitation attempt against the application: held, not refused, because the guess could be wrong and a slow page is recoverable.",
    },
    { id: "persistent-tarpit", match: { minTotalScore: tarpitAt }, respondWith: "tarpit", reason: `This address has kept probing (running score ${tarpitAt} or more). Slowed down rather than refused.` },
    { id: "everything-else", match: {}, respondWith: "pass", reason: "Some signal, not enough to act on. Recorded, and answered by the application as normal." },
  ];
}

/**
 * On its own address or ports, where every request is unsolicited.
 *
 * Nothing here can reach a real visitor, so the responses are the expensive ones: the point
 * is to cost an attacker time and bandwidth, and to keep them talking long enough to record
 * what they are trying.
 */
export function standalone(thresholds: PresetThresholds = {}): Rule[] {
  const blockAt = thresholds.blockThreshold ?? 40;
  const tarpitAt = thresholds.tarpitThreshold ?? 15;
  return [
    { id: "confirmed-block", match: { minTotalScore: blockAt }, respondWith: "block", reason: `A confirmed, persistent attacker (running score ${blockAt} or more). Refused outright.` },
    { id: "proof-block", match: { certain: true }, respondWith: "block", reason: "Proof of automation or of a stolen credential being replayed." },
    // Only when the detector named a response: a catch-all here would answer every request and
    // leave the tarpit rung below unreachable, which is how `tarpit_threshold` once did nothing.
    { id: "detector-choice", match: { detectorResponds: true }, respondWith: "@detector", reason: "The detector's own response: bait for a decoy, a convincing failure for a web shell." },
    { id: "repeat-tarpit", match: { minTotalScore: tarpitAt }, respondWith: "tarpit", reason: `This address keeps probing (running score ${tarpitAt} or more): held rather than answered at once.` },
    { id: "first-probe", match: {}, respondWith: "not-found", reason: "A probe with no bait of its own: answered as though nothing is here." },
  ];
}

/**
 * The thresholds a preset is built from. `[policy] block_threshold` and `tarpit_threshold`
 * arrive here when the file sets them, so a preset never silently overrides the numbers an
 * operator wrote; a key left out keeps the preset's own default.
 */
export interface PresetThresholds {
  /** Running score at which `standalone` blocks. Not used by `observe` or `protect-app`, which never block on a score. */
  blockThreshold?: number;
  /** Running score at which `standalone` (default 15) and `protect-app` (default 25) tarpit. Not used by `observe`. */
  tarpitThreshold?: number;
}

export type PresetName = "observe" | "protect-app" | "standalone";

/** The presets by name, for a config file and the command line. */
export const PRESETS: Record<PresetName, (thresholds?: PresetThresholds) => Rule[]> = {
  observe,
  "protect-app": protectApp,
  standalone,
};

export const PRESET_NAMES: readonly PresetName[] = ["observe", "protect-app", "standalone"];

/**
 * Which of the configured thresholds a preset reads. The rest are printed at startup as unused,
 * so a number in the file that decides nothing says so instead of looking active.
 */
export const PRESET_THRESHOLDS: Record<PresetName, ReadonlyArray<keyof PresetThresholds>> = {
  observe: [],
  "protect-app": ["tarpitThreshold"],
  standalone: ["blockThreshold", "tarpitThreshold"],
};
