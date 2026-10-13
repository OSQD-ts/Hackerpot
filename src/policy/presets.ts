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
 * Every probe is answered with an ordinary 404, exactly as an empty path would be, while the
 * incident is still recorded, scored and alerted on. Run this first on a deployment in front
 * of real users: it tells you what your traffic looks like without a single visitor being
 * slowed down or turned away.
 */
export function observe(): Rule[] {
  return [{ id: "observe-everything", match: {}, respondWith: "not-found", reason: "Observation only: recorded and scored, answered as though nothing is here." }];
}

/**
 * In front of a real application.
 *
 * Bait keeps working, proof is dealt with firmly, and everything unproven costs the client
 * time rather than service. Nothing here refuses a request on a score alone, because in
 * front of real users a score is a guess and the person it is wrong about is a customer.
 */
export function protectApp(): Rule[] {
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
    { id: "persistent-tarpit", match: { minTotalScore: 25 }, respondWith: "tarpit", reason: "This address has kept probing. Slowed down rather than refused." },
    { id: "everything-else", match: {}, respondWith: "not-found", reason: "Some signal, not enough to act on. Recorded and answered normally." },
  ];
}

/**
 * On its own address or ports, where every request is unsolicited.
 *
 * Nothing here can reach a real visitor, so the responses are the expensive ones: the point
 * is to cost an attacker time and bandwidth, and to keep them talking long enough to record
 * what they are trying.
 */
export function standalone(): Rule[] {
  return [
    { id: "confirmed-block", match: { minTotalScore: 40 }, respondWith: "block", reason: "A confirmed, persistent attacker. Refused outright." },
    { id: "proof-block", match: { certain: true }, respondWith: "block", reason: "Proof of automation or of a stolen credential being replayed." },
    { id: "detector-choice", match: {}, respondWith: "@detector", fallbackAction: "", reason: "The detector's own response: bait for a decoy, a convincing failure for a web shell." },
  ].map((rule) => (rule.fallbackAction === "" ? { ...rule, fallbackAction: undefined } : rule)) as Rule[];
}

export type PresetName = "observe" | "protect-app" | "standalone";

/** The presets by name, for a config file and the command line. */
export const PRESETS: Record<PresetName, () => Rule[]> = {
  observe,
  "protect-app": protectApp,
  standalone,
};

export const PRESET_NAMES: readonly PresetName[] = ["observe", "protect-app", "standalone"];
