import { TtlLru } from "../internal/lru.js";
import type { Detection, DetectionContext, Detector } from "./types.js";

export interface UaRotationOptions {
  /** Window the User-Agents are counted over, in ms. Default 10000 (10 s). */
  windowMs?: number;
  /** Distinct User-Agents from one address within the window before it fires. Default 3. */
  distinctThreshold?: number;
  /** Addresses remembered at once; least recently seen are dropped past this. Default 50000. */
  maxAddresses?: number;
  score?: number;
  respondWith?: string;
}

/** User-Agents remembered per address. The threshold is single digits, so a saturated list changes no decision. */
const MAX_AGENTS_PER_ADDRESS = 16;
/** Longest User-Agent kept for comparison: attacker-sized, and a prefix is enough to tell two apart. */
const MAX_AGENT_CHARS = 256;

interface Seen {
  agent: string;
  at: number;
}

/**
 * One address presenting several User-Agents within seconds.
 *
 * A scanner that rotates its User-Agent per request to look like several browsers is still
 * one client, and `repeat-actor` cannot see it: that correlates one fingerprint across many
 * addresses, not many User-Agents from one. A person does not switch browsers mid-second.
 *
 * Off by default, and meant for a standalone trap: in front of real users a shared address (an
 * office, a school, a carrier's NAT) carries several browsers at once, and the window has to
 * stay short for exactly that reason. Suspicion, never proof.
 */
export function uaRotationDetector(options: UaRotationOptions = {}): Detector {
  const windowMs = options.windowMs ?? 10_000;
  const threshold = Math.max(2, options.distinctThreshold ?? 3);
  const score = options.score ?? 5;
  // Expiry here only bounds memory; the window itself is measured on request timestamps, so a
  // replayed log is judged by when its requests happened rather than when they were read.
  const seen = new TtlLru<Seen[]>(Math.max(1, options.maxAddresses ?? 50_000), Math.max(windowMs, 1) * 6);

  return {
    id: "ua-rotation",
    description: "One address presented several different User-Agents within seconds",
    inspect(ctx: DetectionContext): Detection | undefined {
      const raw = ctx.headers["user-agent"];
      const value = Array.isArray(raw) ? raw[0] : raw;
      if (!value) return undefined;
      const agent = value.slice(0, MAX_AGENT_CHARS);
      const now = ctx.timestamp.getTime();
      const cutoff = now - windowMs;

      const history = (seen.get(ctx.ip) ?? []).filter((entry) => entry.at >= cutoff && entry.agent !== agent);
      history.push({ agent, at: now });
      if (history.length > MAX_AGENTS_PER_ADDRESS) history.splice(0, history.length - MAX_AGENTS_PER_ADDRESS);
      seen.set(ctx.ip, history);

      if (history.length < threshold) return undefined;
      const detection: Detection = {
        detector: "ua-rotation",
        summary: `${history.length} different User-Agents from one address within ${Math.round(windowMs / 1000)}s`,
        score,
        metadata: { distinctUserAgents: history.length, windowMs, userAgents: history.map((entry) => entry.agent.slice(0, 80)) },
      };
      if (options.respondWith) detection.respondWith = options.respondWith;
      return detection;
    },
  };
}
