import { describe, expect, it } from "vitest";
import { cefFormat, syslogLine, type HoneypotHit } from "../src/index.js";

function hit(overrides: Partial<HoneypotHit> = {}): HoneypotHit {
  return {
    id: "abc-123",
    timestamp: "2026-08-27T12:34:56.000Z",
    ip: "203.0.113.7",
    method: "POST",
    path: "/login",
    headers: {},
    detections: [{ detector: "nosql-injection", summary: "NoSQL operator injection — operator in query key", score: 9 }],
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
    const line = cefFormat(hit({ detections: [{ detector: "x", summary: "a|b reason", score: 1 }], path: "/a=b" }));
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

describe("CEF output cannot be used to forge log lines", () => {
  const hit = (overrides: Partial<HoneypotHit> = {}): HoneypotHit => ({
    id: "abc-123",
    timestamp: "2026-08-27T12:34:56.000Z",
    ip: "203.0.113.7",
    method: "GET",
    path: "/",
    headers: {},
    detections: [{ detector: "sensitive-file", summary: "benign", score: 6 }],
    score: 6,
    totalScore: 6,
    respondedWith: "not-found",
    ...overrides,
  });

  // Every value here is attacker-chosen: the path, and the detector reasons that quote
  // it back. CEF is line-oriented, so a raw CR or LF closes our event and opens one the
  // attacker wrote — with a source IP of their choosing — that no SIEM can tell from a
  // real detection.
  it("escapes CR and LF smuggled through the request path", () => {
    const line = cefFormat(hit({ path: "/a\r\nCEF:0|evil|evil|1|forged|forged|10|src=9.9.9.9" }));
    expect(line).not.toMatch(/[\r\n]/);
    expect(line).toContain("\\r\\n");
  });

  it("escapes CR and LF smuggled through a detector reason (the CEF header half)", () => {
    const line = cefFormat(hit({ detections: [{ detector: "x\ny", summary: "boom\r\nCEF:0|evil", score: 1 }] }));
    expect(line).not.toMatch(/[\r\n]/);
  });

  it("strips the remaining control characters rather than emitting them raw", () => {
    const line = cefFormat(hit({ path: "/a\u0001b\u0007c" }));
    expect(line).not.toMatch(/[\u0000-\u001f\u007f]/);
    expect(line).toContain("request=/abc");
  });

  it("keeps the syslog envelope on a single line too", () => {
    const line = syslogLine(hit({ path: "/a\r\n<108>Aug 27 00:00:00 forged hackerpot: CEF:0|evil" }));
    expect(line).not.toMatch(/[\r\n]/);
  });

  it("still escapes pipes and equals, and leaves clean values alone", () => {
    const line = cefFormat(hit({ detections: [{ detector: "x", summary: "a|b reason", score: 1 }], path: "/a=b" }));
    expect(line).toContain("a\\|b reason");
    expect(line).toContain("request=/a\\=b");
  });
});
