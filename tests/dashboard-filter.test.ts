import { describe, expect, it } from "vitest";
import { INCIDENT_VOCABULARY, MAX_QUERY_CHARS, matchesQuery, parseFilter } from "../src/dashboard/client/query.js";
import type { Incident } from "../src/dashboard/client/types.js";

/**
 * The search box. Two properties matter more than the grammar: an ordinary word never
 * silently becomes an operator, and nothing a half-typed expression can contain makes this
 * throw — it backs a box somebody is still typing into.
 */

const incident = (over: Partial<Incident> = {}): Incident =>
  ({
    id: "a",
    timestamp: "2026-09-16T12:00:00.000Z",
    ip: "203.0.113.40",
    method: "GET",
    path: "/wp-login.php",
    headers: { "user-agent": "curl/8.4.0" },
    detections: [{ detectorId: "decoy-path", reason: "probe for a bait path", score: 10 }],
    score: 10,
    totalScore: 25,
    respondedWith: "tarpit",
    ...over,
  }) as Incident;

const matches = (query: string, over: Partial<Incident> = {}): boolean => matchesQuery(incident(over), parseFilter(query, INCIDENT_VOCABULARY), INCIDENT_VOCABULARY);

describe("fielded terms", () => {
  it("matches a field by substring, case-insensitively", () => {
    expect(matches("ip:203.0.113")).toBe(true);
    expect(matches("path:WP-LOGIN")).toBe(true);
    expect(matches("detector:decoy")).toBe(true);
    expect(matches("action:tarpit")).toBe(true);
    expect(matches("ip:198.51")).toBe(false);
  });

  it("searches what somebody is looking at when no field is named", () => {
    expect(matches("wp-login")).toBe(true);
    expect(matches("curl")).toBe(true);
    // `reason` is searchable by name but not by a bare word: it quotes attacker text, and a
    // free word matching it would make half the table match half the time.
    expect(matches("bait")).toBe(false);
    expect(matches("reason:bait")).toBe(true);
  });

  it("treats a name it does not know as an ordinary word", () => {
    // A URL, a timestamp or an IPv6 address contains a colon and is not a field term.
    expect(matches("http://example.com")).toBe(false);
    expect(matches("nonsense:wp-login")).toBe(false);
  });

  it("compares numbers when asked to", () => {
    expect(matches("score:>5")).toBe(true);
    expect(matches("score:>50")).toBe(false);
    expect(matches("total:>=25")).toBe(true);
    expect(matches("total:<25")).toBe(false);
    // A comparison against something that is not a number matches nothing rather than throwing.
    expect(matches("score:>abc")).toBe(false);
    expect(matches("path:>5")).toBe(false);
  });
});

describe("combining terms", () => {
  it("ands adjacent terms, and honours the explicit operators", () => {
    expect(matches("ip:203.0.113 path:wp-login")).toBe(true);
    expect(matches("ip:203.0.113 path:phpmyadmin")).toBe(false);
    expect(matches("path:phpmyadmin $or path:wp-login")).toBe(true);
    expect(matches("$not path:phpmyadmin")).toBe(true);
    expect(matches("$not path:wp-login")).toBe(false);
    expect(matches("path:wp-login $and action:tarpit")).toBe(true);
  });

  it("groups with parentheses, and gives $and tighter precedence than $or", () => {
    expect(matches("(path:phpmyadmin $or path:wp-login) $and action:tarpit")).toBe(true);
    expect(matches("(path:phpmyadmin $or path:wp-login) $and action:block")).toBe(false);
    // Without the parentheses: phpmyadmin, or (wp-login and tarpit).
    expect(matches("path:phpmyadmin $or path:wp-login $and action:tarpit")).toBe(true);
  });

  it("keeps an ordinary word from becoming an operator", () => {
    // A client that says "or" in its User-Agent must not be parsed as a disjunction.
    expect(matches("or", { headers: { "user-agent": "Mozilla/5.0 (Macintosh) or-something/1.0" } })).toBe(true);
    expect(matches("not", { path: "/not-here" })).toBe(true);
  });

  it("reads a quoted phrase as one term", () => {
    expect(matches('reason:"bait path"')).toBe(false);
    expect(matches('"wp-login.php"')).toBe(true);
  });
});

describe("what it refuses to do", () => {
  it("never throws, whatever is half-typed", () => {
    for (const query of ["(((", ")", '"unclosed', "$or", "$not", "$and $or", "path:", ":", "()", "$not ("]) {
      expect(() => parseFilter(query, INCIDENT_VOCABULARY)).not.toThrow();
      expect(() => matches(query)).not.toThrow();
    }
  });

  it("matches everything when nothing was asked", () => {
    expect(matches("")).toBe(true);
    expect(matches("   ")).toBe(true);
    // An operator with nothing to operate on is not a filter either.
    expect(matches("$and")).toBe(true);
  });

  it("stops reading past its limit", () => {
    // Everything past the cap is dropped — including a term that would have excluded this
    // incident. Beyond that length the box holds a paste rather than a query.
    const long = `path:wp-login ${" ".repeat(MAX_QUERY_CHARS)}$and path:phpmyadmin`;
    expect(matches(long)).toBe(true);
    // The same term inside the cap is read, and excludes it.
    expect(matches("path:wp-login $and path:phpmyadmin")).toBe(false);
  });
});
