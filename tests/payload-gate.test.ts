import { describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import { injectionSignatures, payloadInjectionDetector } from "../src/detectors/index.js";

/**
 * payload-injection skips a value that has none of the characters its signatures need.
 * A gate is a weaker copy of the patterns it guards: widen a pattern later and the gate
 * could silently stop letting it through. So this fuzzes it, over random strings from an
 * alphabet that includes every character class the patterns use, and asserts that nothing
 * the gate rejects matches any signature.
 */
const GATE = /[./\\%\s(=<:;|`${*_]/;
const ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-+!@#^&[]~'\",?>}{)" + "./\\% \t(=<:;|`$*_";

function randomValue(seed: { n: number }): string {
  const next = (): number => {
    seed.n = (seed.n * 1103515245 + 12345) % 2 ** 31;
    return seed.n / 2 ** 31;
  };
  const length = 1 + Math.floor(next() * 40);
  let out = "";
  for (let i = 0; i < length; i++) out += ALPHABET[Math.floor(next() * ALPHABET.length)];
  return out;
}

describe("payload-injection gate", () => {
  it("never rejects a value any signature would match", () => {
    const seed = { n: 42 };
    let rejected = 0;
    for (let i = 0; i < 200_000; i++) {
      const value = randomValue(seed);
      if (GATE.test(value)) continue;
      rejected += 1;
      const matched = injectionSignatures.find((signature) => signature.pattern.test(value));
      expect(matched, `gate rejected "${value}", which matches ${matched?.kind}`).toBeUndefined();
    }
    expect(rejected).toBeGreaterThan(1000);
  });

  it("rejects the keyword-only forms that need no punctuation at all", () => {
    // Every signature's keyword alternatives, stripped of punctuation, must not match on their own.
    for (const word of ["union", "select", "information", "schema", "jndi", "script", "entity", "system", "sleep", "whoami"]) {
      expect(injectionSignatures.some((signature) => signature.pattern.test(word))).toBe(false);
    }
  });

  it("still catches payloads in query values", async () => {
    const engine = new HoneypotEngine({ enricher: null, detectors: [payloadInjectionDetector()] });
    for (const value of ["1 union select 1", "information_schema", "${jndi:ldap://x}", "<script>", "../../etc/passwd", "%3Cscript%3E"]) {
      const result = await engine.evaluate({ method: "GET", path: "/search", query: { q: value }, headers: { host: "x" }, ip: "198.51.100.40" });
      expect(result.detections, value).toHaveLength(1);
    }
  });
});
