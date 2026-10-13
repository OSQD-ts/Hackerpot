/**
 * Text-format log rendering for the standalone service.
 *
 * Lives in its own module rather than inside standalone.ts so it can be tested
 * without importing that entrypoint, which runs `main()` on import.
 */

/**
 * Renders one field of a text-format log line.
 *
 * Log values are attacker-controlled — a captured SSH shell command, a request
 * path, a header. A bare newline in one of those would end the line and let the
 * attacker append entirely fabricated log entries; a space or `=` would forge
 * extra fields on this one. So anything not plainly safe is JSON-quoted, which
 * escapes newlines, carriage returns, quotes, and control characters.
 *
 * The JSON log format never had this problem — `JSON.stringify` already escapes.
 */
export function formatValue(value: unknown): string {
  if (typeof value === "object" && value !== null) return JSON.stringify(value);
  const text = String(value);
  return /[\s"=\\]|[\u0000-\u001f\u007f]/.test(text) ? JSON.stringify(text) : text;
}

/**
 * Renders a whole event as a `[timestamp] key=value …` line.
 *
 * `ts` goes through the same escaping as every other field. It was the one value
 * interpolated raw, on the assumption that a timestamp is always ours — but the
 * callers do not all generate it: `SyslogSink` fills it from `hit.timestamp`, a
 * *stored* record, and this codebase already treats the store as something that can
 * hold records it did not write (both `RedisStore.list` and `FileStore.list` are
 * hardened against a foreign writer). A newline there would close the line and let
 * the rest be read as further log entries — the exact forgery `formatValue` exists
 * to prevent, through the one field that skipped it. Today the syslog path strips
 * line breaks again afterwards, so this was reachable only by a future caller; the
 * fix is to not leave that trap lying in the module whose contract is "escape".
 */
export function formatTextLine(event: Record<string, unknown>): string {
  const { ts, ...rest } = event;
  const fields = Object.entries(rest).map(([key, value]) => `${key}=${formatValue(value)}`);
  return `[${formatValue(ts ?? new Date().toISOString())}] ${fields.join(" ")}`;
}
