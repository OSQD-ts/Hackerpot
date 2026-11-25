import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { Section } from "../src/config/reader.js";
import { parseConfig } from "../src/config/schema.js";

/**
 * The shipped hackerpot.toml says every value in it is the built-in default and that it is the
 * place to find a setting. It went a whole release without one key 0.3.0 added, because
 * nothing compared the two. This reads every key the schema asks for and finds each in the
 * file, set or as a commented example, under its own section.
 */

/** Keys the file documents once for a whole family rather than per section. */
const DOCUMENTED_ONCE: Array<{ section: RegExp; key: string; where: string }> = [
  { section: /^detectors\./, key: "respond_with", where: "the Detectors heading: every detector takes it" },
];
/** Sections documented under another name: top-level [[webhooks]] take [[management.webhooks]]'s keys. */
const SAME_KEYS_AS: Record<string, string> = { webhooks: "management.webhooks" };

const normalize = (path: string): string => path.replace(/\[\d+\]/g, "").replace(/_/g, "-");

function schemaKeys(): Array<[string, string]> {
  const read: Array<[string, string]> = [];
  const proto = Section.prototype as unknown as { take(key: string): unknown };
  const original = proto.take;
  proto.take = function (this: Section, key: string): unknown {
    read.push([this.path, key]);
    return original.call(this, key);
  };
  try {
    // One entry in every array of tables, so their keys are read too.
    parseConfig(
      {
        policy: { rules: [{ id: "r", respond_with: "block" }] },
        actors: [{ name: "a", ip: ["192.0.2.1"] }],
        webhooks: [{ url: "https://example.com/hook" }],
        management: { webhooks: [{ url: "https://example.com/hook" }] },
        detectors: { "decoy-path": { decoys: [{ id: "d", path: "/x" }] } },
      },
      "<reference>",
    );
  } finally {
    proto.take = original;
  }
  return read;
}

function fileBlocks(): Map<string, string[]> {
  const blocks = new Map<string, string[]>();
  let current = "";
  for (const line of readFileSync("hackerpot.toml", "utf8").split("\n")) {
    const header = /^\s*#?\s*\[\[?([A-Za-z0-9_.-]+)\]\]?\s*(#.*)?$/.exec(line);
    if (header) {
      current = normalize(header[1]!);
      continue;
    }
    const lines = blocks.get(current) ?? [];
    lines.push(line);
    blocks.set(current, lines);
  }
  return blocks;
}

describe("the shipped hackerpot.toml", () => {
  const blocks = fileBlocks();
  const headers = [...blocks.keys()];
  const missing = new Set<string>();

  it("names every key the schema reads", () => {
    for (const [path, key] of schemaKeys()) {
      const section = SAME_KEYS_AS[normalize(path)] ?? normalize(path);
      if (DOCUMENTED_ONCE.some((rule) => rule.section.test(section) && rule.key === key)) continue;
      // A key holding a table is a section of its own, documented by its header.
      const nested = normalize(section === "" ? key : `${section}.${key}`);
      const asSection = SAME_KEYS_AS[nested] ?? nested;
      if (headers.some((header) => header === asSection || header.startsWith(`${asSection}.`))) continue;
      const line = new RegExp(`^\\s*#?\\s*${key.replace(/[-_]/g, "[-_]")}\\s*=`);
      if (!(blocks.get(section) ?? []).some((text) => line.test(text))) missing.add(`[${section || "<root>"}] ${key}`);
    }
    expect([...missing].sort()).toEqual([]);
  });
});
