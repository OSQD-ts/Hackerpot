#!/usr/bin/env node
// The next version to publish, derived from the commits since the last release tag.
//
//   node scripts/next-version.mjs            → prints the version, or nothing
//   node scripts/next-version.mjs --explain  → also prints the reasoning to stderr
//
// Adapted from bothandlerjs. A push to main publishes only when a commit says what it
// changes:
//
//   feat: / fix: / perf:          → patch
//   `type!:` or BREAKING CHANGE:  → major, or minor while the major is 0
//   anything else                 → nothing (docs, tests, chores, unprefixed commits)
//
// A feature is a patch on purpose. This runs on every push, so if features bumped the
// minor, the minor would measure how often somebody pushed rather than anything about
// the package. A bigger release is said out loud with a footer on any commit in range:
//
//   Release-As: 1.0.0   → exactly that version
//   Release-As: minor   → that bump, whatever the commits imply
//
// The newest footer wins. An override that is not semver, or does not move forwards,
// stops the release with a non-zero exit rather than quietly publishing something else.
//
// A pushed `v*` tag is the other way to release (see .github/workflows/publish.yml): it
// publishes exactly the tagged version and does not commit that version back to
// package.json. So the base here is whichever is higher, package.json or the newest tag.
// Without that, the next automatic release after a tagged 1.2.0 would derive 0.1.1 from a
// stale package.json and publish a version below the one already out.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

/** `type(scope)!: subject` → the parts that decide a version. */
const HEADER = /^(?<type>[a-z]+)(?:\((?<scope>[^)]*)\))?(?<breaking>!)?:\s/;

/** `Release-As:` at the start of a footer line, so describing the mechanism does not invoke it. */
const RELEASE_AS = /^Release[ -]As:\s*(?<value>.+?)\s*$/im;

/** A version this script is willing to publish: semver, with an optional prerelease. */
const SEMVER = /^(?<major>0|[1-9]\d*)\.(?<minor>0|[1-9]\d*)\.(?<patch>0|[1-9]\d*)(?<pre>-[0-9A-Za-z.-]+)?$/;

export const RANK = { none: 0, patch: 1, minor: 2, major: 3 };

/** What one commit does to the version: "none", "patch" or "major". */
export function classify(message) {
  const [header, ...rest] = message.split("\n");
  const body = rest.join("\n");
  if (/^BREAKING[ -]CHANGE:/m.test(body)) return "major";
  const match = HEADER.exec(header ?? "");
  if (match === null) return "none";
  if (match.groups.breaking === "!") return "major";
  if (match.groups.type === "feat" || match.groups.type === "fix" || match.groups.type === "perf") return "patch";
  return "none";
}

/**
 * What one commit declares outright: `{ kind: "version" | "bump" | "invalid", value }`,
 * or undefined. The subject line is ignored, because a subject is not a footer.
 */
export function declaredRelease(message) {
  const body = message.split("\n").slice(1).join("\n");
  const match = RELEASE_AS.exec(body);
  if (match === null) return undefined;
  const value = match.groups.value;
  const named = value.toLowerCase();
  if (named === "major" || named === "minor" || named === "patch") return { kind: "bump", value: named };
  if (SEMVER.test(value)) return { kind: "version", value };
  return { kind: "invalid", value };
}

/** True when `to` is a later version than `from`. A prerelease sorts below its own release. */
export function isForwards(from, to) {
  const parse = (version) => {
    const match = SEMVER.exec(version);
    if (match === null) return undefined;
    return [Number(match.groups.major), Number(match.groups.minor), Number(match.groups.patch), match.groups.pre === undefined ? 1 : 0];
  };
  const a = parse(from);
  const b = parse(to);
  if (a === undefined || b === undefined) return false;
  for (let i = 0; i < 4; i++) {
    if (b[i] > a[i]) return true;
    if (b[i] < a[i]) return false;
  }
  return false;
}

/** Applies a bump. While the major is 0 a breaking change lands on the minor, as SemVer intends for 0.x. */
export function bumpVersion(current, bump) {
  const [major, minor, patch] = current.split("-")[0].split(".").map(Number);
  const effective = bump === "major" && major === 0 ? "minor" : bump;
  if (effective === "major") return `${major + 1}.0.0`;
  if (effective === "minor") return `${major}.${minor + 1}.0`;
  if (effective === "patch") return `${major}.${minor}.${patch + 1}`;
  return current;
}

/** The version releases build on: the higher of package.json and the newest `v*` tag. */
export function baseVersion(packageVersion, tag) {
  const tagged = tag?.startsWith("v") ? tag.slice(1) : undefined;
  return tagged !== undefined && SEMVER.test(tagged) && isForwards(packageVersion, tagged) ? tagged : packageVersion;
}

/**
 * The next version for a list of commit messages (newest first) on top of `current`, or
 * undefined when nothing in them releases. Throws on an unusable `Release-As`.
 */
export function nextVersion(current, commits, say = () => undefined) {
  let bump = "none";
  let declared;
  for (const commit of commits) {
    const kind = classify(commit);
    if (RANK[kind] > RANK[bump]) bump = kind;
    const said = declaredRelease(commit);
    const mark = said === undefined ? "" : `  [Release-As: ${said.value}${declared === undefined ? "" : ", superseded"}]`;
    if (said !== undefined && declared === undefined) declared = said;
    say(`  ${kind.padEnd(5)}  ${commit.split("\n")[0].slice(0, 72)}${mark}`);
  }

  if (declared !== undefined) {
    if (declared.kind === "invalid") {
      throw new Error(`Release-As: ${declared.value} is neither a version nor a bump. Write a semver version like 1.0.0, or one of major, minor, patch.`);
    }
    const next = declared.kind === "version" ? declared.value : bumpVersion(current, declared.value);
    if (!isForwards(current, next)) {
      throw new Error(`Release-As: ${declared.value} asks for ${next}, which is not ahead of ${current}. A published version cannot be replaced.`);
    }
    say(`${current} → ${next}  (declared: Release-As: ${declared.value})`);
    return next;
  }

  if (bump === "none") {
    say(commits.length === 0 ? "nothing new since the last release" : "no commit here changes what the package does");
    return undefined;
  }
  const next = bumpVersion(current, bump);
  say(`${current} → ${next}  (${bump})`);
  return next;
}

function main() {
  const explain = process.argv.includes("--explain");
  const say = (message) => {
    if (explain) process.stderr.write(`${message}\n`);
  };
  const git = (...args) => execFileSync("git", args, { encoding: "utf8" }).trim();

  const tag = git("tag", "--list", "v*", "--sort=-v:refname").split("\n").filter(Boolean)[0];
  const packageVersion = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
  const current = baseVersion(packageVersion, tag);
  say(tag === undefined ? "no v* tag yet, reading every commit" : `commits since ${tag}`);
  if (current !== packageVersion) say(`building on ${tag}, which is ahead of package.json (${packageVersion})`);

  // NUL between commits: a body may contain any text a person can type.
  const range = tag === undefined ? "HEAD" : `${tag}..HEAD`;
  const commits = git("log", range, "--format=%B%x00")
    .split("\0")
    .map((commit) => commit.trim())
    .filter(Boolean);
  return nextVersion(current, commits, say);
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const next = main();
    if (next !== undefined) process.stdout.write(`${next}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
}
