#!/usr/bin/env node
// Moves everything under `## [Unreleased]` in CHANGELOG.md into a section for the release:
//
//   node scripts/cut-changelog.mjs 1.2.3 [2026-11-25]
//
// The publish workflow runs it beside set-version.mjs and commits the result with the release.
// Until it did, every entry since the first release stayed under [Unreleased], so the file
// could not say which version a change shipped in. An empty [Unreleased] heading is left for
// the next change. A release with nothing recorded gets a section saying so, rather than
// none, so the version list has no holes.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const UNRELEASED = /^## \[Unreleased\][^\n]*\n/m;

/** The changelog text with [Unreleased] cut into `version`. Throws when it cannot be done cleanly. */
export function cutChangelog(text, version, date) {
  if (!SEMVER.test(version)) throw new Error(`"${version}" is not a semver version`);
  if (!DATE.test(date)) throw new Error(`"${date}" is not a YYYY-MM-DD date`);
  if (new RegExp(`^## \\[${version.replace(/\./g, "\\.")}\\]`, "m").test(text)) throw new Error(`CHANGELOG.md already has a section for ${version}`);
  const heading = UNRELEASED.exec(text);
  if (!heading) throw new Error("CHANGELOG.md has no `## [Unreleased]` heading to cut");
  const start = heading.index + heading[0].length;
  const next = text.slice(start).search(/^## \[/m);
  const end = next === -1 ? text.length : start + next;
  const body = text.slice(start, end).trim();
  const released = `## [${version}] - ${date}\n\n${body === "" ? "No user-facing changes recorded." : body}\n\n`;
  return `${text.slice(0, start)}\n${released}${text.slice(end)}`;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const path = join(process.cwd(), "CHANGELOG.md");
    const version = process.argv[2] ?? "";
    const date = process.argv[3] ?? new Date().toISOString().slice(0, 10);
    writeFileSync(path, cutChangelog(readFileSync(path, "utf8"), version, date));
    process.stdout.write(`CHANGELOG.md: [Unreleased] cut into [${version}] - ${date}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
}
