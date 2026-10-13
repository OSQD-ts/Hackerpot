import { describe, expect, it } from "vitest";
import { formatTextLine } from "../src/internal/logfmt.js";

describe("every field of a text log line is escaped, including the timestamp", () => {
  // `formatValue` exists because log values are attacker-controlled and a newline in one
  // would end the line and let the rest be read as further entries. `ts` was the single
  // field interpolated raw — and `SyslogSink` fills it from a *stored* record, which this
  // codebase already treats as something a foreign writer may have touched.
  it("does not let a timestamp break the line", () => {
    const line = formatTextLine({ ts: "2026-01-01\nkind=hit ip=9.9.9.9", kind: "hit" });
    expect(line.split(/\r|\n/)).toHaveLength(1);
  });

  it("still renders an ordinary timestamp readably", () => {
    expect(formatTextLine({ ts: "2026-01-01T00:00:00.000Z", kind: "hit" })).toBe("[2026-01-01T00:00:00.000Z] kind=hit");
  });
});
