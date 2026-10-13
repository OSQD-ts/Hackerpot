import { describe, expect, it } from "vitest";
import { MAX_QUERY_CHARS, parseQuery, queryMatcher, suggestFor } from "../src/dashboard/client/query.js";
import type { Incident } from "../src/dashboard/client/types.js";

/**
 * The search box. Two properties matter more than the grammar: an ordinary word never
 * silently becomes an operator, and nothing a half-typed expression can contain makes this
 * throw — it backs a box somebody is still typing into.
 *
 * The grammar is `@osqd/jql`'s text syntax, which has its own suite; what is tested here is
 * this page's vocabulary through it — every field, and each computed one in particular,
 * because those are the ones this project wrote itself.
 */

const incident = (over: Partial<Incident> = {}): Incident =>
  ({
    id: "a",
    timestamp: "2026-09-16T12:00:00.000Z",
    ip: "203.0.113.40",
    method: "GET",
    path: "/wp-login.php",
    headers: { "user-agent": "curl/8.4.0" },
    detections: [{ detector: "decoy-path", summary: "probe for a bait path", score: 10 }],
    score: 10,
    totalScore: 25,
    respondedWith: "tarpit",
    ...over,
  }) as Incident;

const matches = (query: string, over: Partial<Incident> = {}): boolean => queryMatcher(query)(incident(over));

describe("fielded terms", () => {
  it("matches a field by substring, case-insensitively", () => {
    expect(matches("path:WP-LOGIN")).toBe(true);
    expect(matches("detector:decoy")).toBe(true);
    expect(matches("action:tarp")).toBe(true);
    expect(matches("rule:scanner", { rule: "scanner-tarpit" })).toBe(true);
    expect(matches("rule:scanner")).toBe(false);
    expect(matches("actor:crawl", { actor: { name: "Nightly crawler" } })).toBe(true);
    expect(matches("ua:CURL/8")).toBe(true);
    expect(matches("summary:bait")).toBe(true);
  });

  it("matches an address as a whole, so one address never stands for its neighbours", () => {
    expect(matches("ip:203.0.113.40")).toBe(true);
    // A network prefix that ends on a boundary still finds the network.
    expect(matches("ip:203.0.113")).toBe(true);
    expect(matches("ip:203.0.113.")).toBe(true);
    // A substring match would have found .40 for .4, and excluding .4 would have excluded it.
    expect(matches("ip:203.0.113.4")).toBe(false);
    expect(matches("ip:203.0.11")).toBe(false);
    expect(matches("-ip:203.0.113.4")).toBe(true);
    expect(matches("ip:198.51")).toBe(false);
  });

  it("matches a closed set exactly, ignoring case", () => {
    expect(matches("method:get")).toBe(true);
    expect(matches("method:GE")).toBe(false);
    expect(matches("method:$in(POST, GET)")).toBe(true);
    // The outcome is computed from the response, and matches the chip's name, spaces and all.
    expect(matches("outcome:time")).toBe(false);
    expect(matches('outcome:"time cost"')).toBe(true);
    expect(matches("outcome:decoy")).toBe(false);
    expect(matches("OUTCOME:Decoy", { respondedWith: "fake-data" })).toBe(true);
  });

  it("searches what somebody is looking at when no field is named", () => {
    expect(matches("wp-login")).toBe(true);
    expect(matches("curl")).toBe(true);
    // `reason` is searchable by name but not by a bare word: it quotes attacker text, and a
    // free word matching it would make half the table match half the time.
    expect(matches("bait")).toBe(false);
    expect(matches("reason:bait")).toBe(true);
    expect(matches("203.0.113")).toBe(true);
    expect(matches("nightly", { actor: { name: "Nightly crawler" } })).toBe(true);
  });

  it("treats a name it does not know as an ordinary word", () => {
    // A URL, a timestamp or an IPv6 address contains a colon and is not a field term.
    expect(matches("http://example.com")).toBe(false);
    expect(matches("nonsense:wp-login")).toBe(false);
  });

  it("compares numbers", () => {
    expect(matches("score:>5")).toBe(true);
    expect(matches("score:>50")).toBe(false);
    expect(matches("total:>=25")).toBe(true);
    expect(matches("total:<25")).toBe(false);
    expect(matches("total:<=25")).toBe(true);
    expect(matches("score:5..10")).toBe(true);
    expect(matches("score:11..")).toBe(false);
    // A bare number is equality, not a substring: `score:1` used to find a score of 10.
    expect(matches("score:10")).toBe(true);
    expect(matches("score:1")).toBe(false);
    // A value that is not a number matches nothing rather than throwing, or everything.
    expect(matches("score:>abc")).toBe(false);
    expect(matches("score:high")).toBe(false);
    // On a text field a comparison is the characters typed.
    expect(matches("path:>5")).toBe(false);
  });

  it("asks whether a field is set", () => {
    expect(matches("has:rule")).toBe(false);
    expect(matches("has:rule", { rule: "scanner-tarpit" })).toBe(true);
    expect(matches("-has:actor")).toBe(true);
    expect(matches("has:actor", { actor: { name: "Nightly crawler" } })).toBe(true);
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

  it("negates a term with a leading minus or bang", () => {
    expect(matches("-path:phpmyadmin")).toBe(true);
    expect(matches("-path:wp-login")).toBe(false);
    expect(matches("!detector:decoy-path")).toBe(false);
    expect(matches("-curl")).toBe(false);
    // An even run of $not is no negation at all.
    expect(matches("$not $not path:wp-login")).toBe(true);
  });

  it("takes a set of values", () => {
    expect(matches("path:$in(/phpmyadmin, /wp-login)")).toBe(true);
    expect(matches("path:$notin(/phpmyadmin, /wp-login)")).toBe(false);
    expect(matches("detector:$in(sql, decoy)")).toBe(true);
    // A set left half-typed matches nothing, rather than everything while somebody types it.
    expect(matches("path:$in(")).toBe(false);
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
    // A quote after a field name holds the value together.
    expect(matches('reason:"bait path"')).toBe(true);
    expect(matches("reason:'bait path'")).toBe(true);
    expect(matches('reason:"path bait"')).toBe(false);
    expect(matches('"wp-login.php"')).toBe(true);
    // Pasted from something with smart punctuation, a curly quote is still a quote.
    expect(matches("ua:\u201ccurl/8.4.0\u201d")).toBe(true);
    expect(matches('"curl 8"')).toBe(false);
  });
});

describe("what it refuses to do", () => {
  it("never throws, whatever is half-typed", () => {
    for (const query of ["(((", ")", '"unclosed', "$or", "$not", "$and $or", "path:", ":", "()", "$not (", "-", "!", "has:", "path:$in(", "score:>", "score:..", "ip:$notin(", "'", "method:$in(\"a,", "(".repeat(100)]) {
      expect(() => parseQuery(query)).not.toThrow();
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

  it("searches an unknown name before a colon as the text it is", () => {
    expect(parseQuery("nonsense:wp-login")).toEqual({ $text: { $search: "nonsense:wp-login", $fields: ["path", "ip", "detector", "action", "ua", "actor"] } });
  });
});

describe("completion", () => {
  const values = { detector: ["decoy-path", "sql-injection"], action: ["tarpit"], method: ["GET", "POST"] };

  it("offers field names, aliases included, and operators", () => {
    expect(suggestFor("pa", 2, values)).toEqual({ options: ["path:"], from: 0, to: 2 });
    expect(suggestFor("ip:1 -re", 8, values)).toEqual({ options: ["-reason:"], from: 5, to: 8 });
    expect(suggestFor("$o", 2, values).options).toEqual(["$or"]);
  });

  it("offers the values this page has seen, and the set forms", () => {
    expect(suggestFor("detector:s", 10, values).options).toEqual(["detector:sql-injection"]);
    expect(suggestFor("method:", 7, values).options).toEqual(["method:GET", "method:POST"]);
    expect(suggestFor("detector:$", 10, values).options).toEqual(["detector:$in(", "detector:$notin("]);
    // Values it has not been given are not invented.
    expect(suggestFor("path:/", 6, values).options).toEqual([]);
    expect(suggestFor("detector:", 9, {}).options).toEqual([]);
  });

  it("quotes a value with a space, and completes one already opened with a quote", () => {
    expect(suggestFor("outcome:ti", 10, values)).toEqual({ options: ['outcome:"time cost"'], from: 0, to: 10 });
    expect(suggestFor('ip:1 outcome:"ti', 16, values)).toEqual({ options: ['outcome:"time cost"'], from: 5, to: 16 });
  });
});
