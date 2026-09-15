/// <reference path="../scripts/release-scripts.d.mts" />
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { baseVersion, bumpVersion, classify, declaredRelease, nextVersion } from "../scripts/next-version.mjs";
import { setVersion } from "../scripts/set-version.mjs";

describe("next-version", () => {
  it.each([
    ["feat: add a detector", "patch"],
    ["fix(core): normalise the path", "patch"],
    ["perf: skip the body read", "patch"],
    ["feat!: rename the package", "major"],
    ["docs: explain Release-As: 1.0.0", "none"],
    ["Add protocol emulators and syslog output", "none"],
  ])("%s -> %s", (message, expected) => {
    expect(classify(message)).toBe(expected);
  });

  it("reads a BREAKING CHANGE footer as a major bump", () => {
    expect(classify("fix: drop the old option\n\nBREAKING CHANGE: `countOnly` is gone")).toBe("major");
  });

  it("keeps breaking changes on the minor while the major is 0", () => {
    expect(bumpVersion("0.4.2", "major")).toBe("0.5.0");
    expect(bumpVersion("1.4.2", "major")).toBe("2.0.0");
  });

  it("publishes nothing for commits that change nothing", () => {
    expect(nextVersion("0.1.0", ["docs: fix a typo", "Tidy the README"])).toBeUndefined();
  });

  it("honours Release-As, and refuses one that is invalid or goes backwards", () => {
    expect(declaredRelease("docs: note\n\nRelease-As: 1.0.0")).toEqual({ kind: "version", value: "1.0.0" });
    expect(nextVersion("0.1.0", ["chore: stable\n\nRelease-As: 1.0.0"])).toBe("1.0.0");
    expect(nextVersion("0.1.0", ["fix: x\n\nRelease-As: minor"])).toBe("0.2.0");
    expect(() => nextVersion("0.1.0", ["fix: x\n\nRelease-As: soon"])).toThrow(/neither a version nor a bump/);
    expect(() => nextVersion("1.2.0", ["fix: x\n\nRelease-As: 1.0.0"])).toThrow(/not ahead/);
  });

  // A tagged release is not committed back to package.json, so the automatic path must
  // build on the tag or it would publish a version below the one already out.
  it("builds on the newest tag when it is ahead of package.json", () => {
    expect(baseVersion("0.1.0", "v1.2.0")).toBe("1.2.0");
    expect(baseVersion("1.3.0", "v1.2.0")).toBe("1.3.0");
    expect(baseVersion("0.1.0", undefined)).toBe("0.1.0");
    expect(nextVersion(baseVersion("0.1.0", "v1.2.0"), ["fix: after the tagged release"])).toBe("1.2.1");
  });
});

describe("set-version", () => {
  const repo = (): string => {
    const root = mkdtempSync(join(tmpdir(), "hackerpot-version-"));
    mkdirSync(join(root, "src"));
    writeFileSync(join(root, "package.json"), `${JSON.stringify({ name: "@osqd/hackerpot", version: "0.1.0" }, null, 2)}\n`);
    writeFileSync(join(root, "package-lock.json"), `${JSON.stringify({ name: "@osqd/hackerpot", version: "0.1.0", packages: { "": { name: "@osqd/hackerpot", version: "0.1.0" } } }, null, 2)}\n`);
    writeFileSync(join(root, "src", "version.ts"), '/** doc */\nexport const VERSION = "0.1.0";\n');
    return root;
  };

  it("writes the version into package.json, the lockfile and src/version.ts", () => {
    const root = repo();
    setVersion(root, "1.2.3-rc.1");
    expect(JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version).toBe("1.2.3-rc.1");
    const lock = JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8"));
    expect([lock.version, lock.packages[""].version]).toEqual(["1.2.3-rc.1", "1.2.3-rc.1"]);
    expect(readFileSync(join(root, "src", "version.ts"), "utf8")).toContain('export const VERSION = "1.2.3-rc.1";');
  });

  it("refuses a version that is not semver", () => {
    expect(() => setVersion(repo(), "v1.2")).toThrow(/not a semver version/);
  });
});
