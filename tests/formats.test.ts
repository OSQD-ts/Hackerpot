import { describe, expect, it } from "vitest";
import { cefFormat, syslogLine } from "../src/index.js";
import type { HoneypotHit } from "../src/index.js";

function hit(overrides: Partial<HoneypotHit> = {}): HoneypotHit {
  return {
    id: "abc-123",
    timestamp: "2026-08-27T12:34:56.000Z",
    ip: "203.0.113.7",
    method: "POST",
    path: "/login",
    headers: {},
    detections: [{ detectorId: "nosql-injection", reason: "NoSQL operator injection — operator in query key", score: 9 }],
    score: 9,
    totalScore: 45,
    respondedWith: "block",
    ...overrides,
  };
}

describe("cefFormat", () => {
  it("renders a valid CEF line with the incident's fields", () => {
    const line = cefFormat(hit());
    expect(line).toMatch(/^CEF:0\|hackerpot\|hackerpot\|[\d.]+\|nosql-injection\|/);
    expect(line).toContain("src=203.0.113.7");
    expect(line).toContain("requestMethod=POST");
    expect(line).toContain("request=/login");
    expect(line).toContain("cs1=nosql-injection");
    expect(line).toContain("cn1=45");
    expect(line).toContain("act=block");
    expect(line).toMatch(/\|(?:10|[1-9])\|/); // severity 1-10 in the header
  });

  it("escapes pipes in the header and equals/backslashes in extensions", () => {
    const line = cefFormat(hit({ detections: [{ detectorId: "x", reason: "a|b reason", score: 1 }], path: "/a=b" }));
    expect(line).toContain("a\\|b reason");
    expect(line).toContain("request=/a\\=b");
  });
});

describe("syslogLine", () => {
  it("wraps a CEF message in an RFC 3164 envelope", () => {
    const line = syslogLine(hit(), { host: "sensor1", facility: 13, severity: 4 });
    expect(line).toMatch(/^<108>/); // 13*8 + 4
    expect(line).toContain(" sensor1 hackerpot: CEF:0|");
  });

  it("can carry a custom message instead of CEF", () => {
    expect(syslogLine(hit(), { message: "custom" })).toMatch(/ hackerpot: custom$/);
  });
});
