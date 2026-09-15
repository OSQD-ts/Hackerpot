#!/usr/bin/env node
// Every local link in the repository's markdown, checked: the file exists, and an anchor
// names a heading that exists. Adapted from bothandlerjs.
//
// The README is long and edited often. A heading renamed in one place leaves a table of
// contents entry, or a link from another section, pointing at nothing, and it reads
// perfectly right in a diff. External URLs are not followed: whether the internet still
// hosts something is a different job, and it would fail builds for reasons unrelated to
// the change under test.

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const IGNORED = new Set(["node_modules", "dist", "coverage", ".git", ".claude", "nginx", "data"]);

/** Every markdown file in the tree, found rather than listed, so a new page is checked the day it is written. */
function markdownUnder(directory) {
  const found = [];
  for (const entry of readdirSync(directory)) {
    if (IGNORED.has(entry)) continue;
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) found.push(...markdownUnder(path));
    else if (entry.endsWith(".md")) found.push(path);
  }
  return found;
}

/** GitHub's heading anchor: lower-case, punctuation removed, spaces to hyphens, repeats numbered. */
function anchorsOf(markdown) {
  const anchors = new Set();
  const seen = new Map();
  let fenced = false;
  for (const line of markdown.split("\n")) {
    if (/^\s*(```|~~~)/.test(line)) fenced = !fenced;
    if (fenced) continue;
    const heading = /^#{1,6}\s+(.+?)\s*#*\s*$/.exec(line);
    if (!heading) continue;
    const text = heading[1]
      .replace(/`([^`]*)`/g, "$1")
      .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
      .replace(/<[^>]+>/g, "");
    const base = text
      .toLowerCase()
      .replace(/[^\p{L}\p{N}\s_-]/gu, "")
      .replace(/\s/g, "-");
    const count = seen.get(base) ?? 0;
    seen.set(base, count + 1);
    anchors.add(count === 0 ? base : `${base}-${count}`);
  }
  // Explicit anchors: <a id="..."> or <a name="...">.
  for (const match of markdown.matchAll(/<a\s+(?:id|name)="([^"]+)"/g)) anchors.add(match[1]);
  return anchors;
}

/** Links outside fenced code and inline code. */
function linksOf(markdown) {
  const links = [];
  let fenced = false;
  for (const [index, line] of markdown.split("\n").entries()) {
    if (/^\s*(```|~~~)/.test(line)) fenced = !fenced;
    if (fenced) continue;
    const text = line.replace(/`[^`]*`/g, "");
    for (const match of text.matchAll(/\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)) links.push({ target: match[1], line: index + 1 });
  }
  return links;
}

const failures = [];
const anchorCache = new Map();
const anchorsFor = (file) => {
  if (!anchorCache.has(file)) anchorCache.set(file, anchorsOf(readFileSync(file, "utf8")));
  return anchorCache.get(file);
};

const files = markdownUnder(root);
let checked = 0;
for (const file of files) {
  for (const { target, line } of linksOf(readFileSync(file, "utf8"))) {
    if (/^[a-z][a-z0-9+.-]*:/i.test(target)) continue; // http:, https:, mailto:
    checked += 1;
    const [pathPart, anchor] = target.split("#");
    const destination = pathPart === "" ? file : resolve(dirname(file), decodeURIComponent(pathPart));
    const where = `${relative(root, file)}:${line}`;
    if (!existsSync(destination)) {
      failures.push(`${where}  ${target}  (no such file)`);
      continue;
    }
    if (anchor === undefined || anchor === "") continue;
    if (!destination.endsWith(".md")) continue;
    if (!anchorsFor(destination).has(decodeURIComponent(anchor).toLowerCase())) failures.push(`${where}  ${target}  (no such heading)`);
  }
}

if (failures.length > 0) {
  console.error(`${failures.length} broken link(s):\n${failures.map((failure) => `  ${failure}`).join("\n")}`);
  process.exit(1);
}
console.log(`${checked} local link(s) in ${files.length} markdown file(s), all resolve.`);
