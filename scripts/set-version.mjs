#!/usr/bin/env node
// Writes a release version everywhere this repository records it:
//
//   node scripts/set-version.mjs 1.2.3
//
// package.json, the lockfile's two root entries, and `VERSION` in src/version.ts, which
// is reported as the product version in the CEF feed. The publish workflow runs it before
// building, and so does the Docker release job: a tagged release is not committed back,
// so the tagged tree can carry an older version than the one being published.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$/;
const VERSION_CONSTANT = /export const VERSION = "[^"]*";/;

/** Sets `version` in the repository at `root`. Throws on an invalid version or a missing constant. */
export function setVersion(root, version) {
  if (!SEMVER.test(version)) throw new Error(`"${version}" is not a semver version`);

  const pkgPath = join(root, "package.json");
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
  pkg.version = version;
  writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);

  const lockPath = join(root, "package-lock.json");
  const lock = JSON.parse(readFileSync(lockPath, "utf8"));
  lock.version = version;
  if (lock.packages?.[""]) lock.packages[""].version = version;
  writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);

  const sourcePath = join(root, "src", "version.ts");
  const source = readFileSync(sourcePath, "utf8");
  if (!VERSION_CONSTANT.test(source)) throw new Error("src/version.ts has no `export const VERSION = \"…\";` to update");
  writeFileSync(sourcePath, source.replace(VERSION_CONSTANT, `export const VERSION = "${version}";`));
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    setVersion(process.cwd(), process.argv[2] ?? "");
    process.stdout.write(`version set to ${process.argv[2]}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
}
