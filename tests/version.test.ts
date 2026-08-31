import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { VERSION } from "../src/version.js";

describe("the in-source version", () => {
  // `src/version.ts` cannot import package.json (the build's rootDir is src), so this
  // is what keeps the two from drifting — a stale value here is reported to every SIEM
  // ingesting the CEF feed as the product version.
  it("matches package.json", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
    expect(VERSION).toBe(pkg.version);
  });
});
