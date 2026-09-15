/**
 * Numbers, durations and times as the page shows them.
 *
 * No document in here, so every function can be unit-tested in Node. The locale is the
 * viewer's own: an operator reading `1.234` where they expected `1,234` is reading a
 * different number, and the browser already knows which one they mean.
 */

/** Shown wherever a value does not exist yet, rather than a zero that would be a claim. */
export const DASH = "—";

export function fmtInt(n: number): string {
  return Number.isFinite(n) ? Math.round(n).toLocaleString() : DASH;
}

/** `12.3K`, `4.5M`: for pills and axis ticks, where the exact count is one hover away. */
export function fmtCompact(n: number): string {
  if (!Number.isFinite(n)) return DASH;
  if (Math.abs(n) >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (Math.abs(n) >= 1e4) return `${(n / 1e3).toFixed(1)}K`;
  // Axis ticks can be fractional (a 0.5 step on a chart whose maximum is 2).
  return Number.isInteger(n) ? fmtInt(n) : String(Math.round(n * 100) / 100);
}

export function pct(n: number, d: number): number {
  return d ? (n / d) * 100 : 0;
}

/** A share, or a dash when there is no whole to be a share of. */
export function fmtPct(n: number, d: number, dp = 1): string {
  return d ? `${pct(n, d).toFixed(dp)}%` : DASH;
}

export function fmtNum(n: number | undefined, dp = 1): string {
  return n === undefined || !Number.isFinite(n) ? DASH : n.toFixed(dp);
}

export function plural(n: number, word: string): string {
  return `${fmtInt(n)} ${word}${n === 1 ? "" : "s"}`;
}

/**
 * A duration at the precision a person reads it: `850ms`, `4.2s`, `38s`, `12m`, `3.5h`,
 * `2.1d`. One decimal below ten of a unit, none above, because "38.4s" is noise and
 * "4s" for 4.4 seconds hides a difference that matters at that size.
 */
export function fmtDur(ms: number | undefined): string {
  if (ms === undefined || !Number.isFinite(ms)) return DASH;
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s < 10 ? s.toFixed(1) : Math.round(s)}s`;
  const m = s / 60;
  if (m < 60) return `${m.toFixed(m < 10 ? 1 : 0)}m`;
  const h = m / 60;
  if (h < 48) return `${h.toFixed(h < 10 ? 1 : 0)}h`;
  return `${(h / 24).toFixed(1)}d`;
}

/** Wall-clock time with milliseconds: probes from one scanner land within the same second. */
export function fmtTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return DASH;
  return `${d.toLocaleTimeString()}.${String(d.getMilliseconds()).padStart(3, "0")}`;
}

export function fmtDateTime(msOrIso: number | string): string {
  const d = new Date(msOrIso);
  return Number.isNaN(d.getTime()) ? DASH : d.toLocaleString();
}

export function fmtClock(msOrIso: number | string): string {
  const d = new Date(msOrIso);
  return Number.isNaN(d.getTime()) ? DASH : d.toLocaleTimeString();
}

/**
 * A stable hue per detector id, so the same detector wears the same badge on every screen
 * and after every reload. It is decoration: the id is always printed beside it.
 */
export function hue(s: string): number {
  let h = 0;
  for (const c of s) h = (h * 31 + (c.codePointAt(0) ?? 0)) % 360;
  return h;
}

/** The severity class a cumulative score reads as. The thresholds are the old page's. */
export function sevClass(n: number): "sev-high" | "sev-mid" | "sev-low" {
  return n >= 40 ? "sev-high" : n >= 15 ? "sev-mid" : "sev-low";
}

/** Shortened with an ellipsis, counting code points so a surrogate pair is never split. */
export function truncate(s: string, max: number): string {
  const chars = Array.from(s);
  return chars.length > max ? `${chars.slice(0, Math.max(0, max - 1)).join("")}…` : s;
}
