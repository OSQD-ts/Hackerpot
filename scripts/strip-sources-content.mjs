// Drops `sourcesContent` from every sourcemap under dist/. The mappings stay, so a stack
// trace still names the line of the source it came from; only the embedded copy of that
// source goes, and it is in the repository. Without this the maps alone hold the whole
// source tree several times over and take the tarball past the size CI holds it to.
import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

async function* walk(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(path);
    else if (entry.name.endsWith(".map")) yield path;
  }
}

let stripped = 0;
for await (const path of walk(new URL("../dist", import.meta.url).pathname)) {
  const map = JSON.parse(await readFile(path, "utf8"));
  if (map.sourcesContent === undefined) continue;
  delete map.sourcesContent;
  await writeFile(path, JSON.stringify(map));
  stripped += 1;
}
console.log(`stripped sourcesContent from ${stripped} sourcemaps`);
