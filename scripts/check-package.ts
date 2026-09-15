import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Packs the tarball, installs it into an empty project, and loads it the way a consumer
 * does: `import` and `require` of every entry in `exports` (the root, `/adapters`, `/cli`,
 * `/corpus`, `/element`), each in its own process, plus every binary with `--help`.
 *
 * `/element` is loaded under Node on purpose. A custom element class is evaluated when its
 * module loads, so an element that extends `HTMLElement` directly throws on import in any
 * framework that renders on the server — present in the package, listed in `exports`,
 * type-checked, and unusable. bothandlerjs shipped exactly that once.
 *
 *   npm run check:package
 *
 * CI already checks which files are in the package. None of that proves they load: every
 * test here imports `src/` directly, so a broken `exports` map, a CommonJS build that
 * throws while loading a runtime dependency, or a binary pointing at a file the build
 * stopped emitting would leave the whole suite green. Adapted from bothandlerjs.
 */

function run(command: string, args: readonly string[], cwd: string): string {
  return execFileSync(command, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

function firstErrorLine(error: unknown): string {
  const stderr = error instanceof Error && "stderr" in error ? String((error as { stderr: unknown }).stderr) : String(error);
  return stderr.split("\n").filter(Boolean)[0] ?? "";
}

const repo = process.cwd();
const pkg = JSON.parse(readFileSync(join(repo, "package.json"), "utf8")) as { name: string; bin?: Record<string, string>; exports: Record<string, unknown> };
/**
 * Every import path the package declares, as a consumer would write it, and whether it is
 * published for `require` at all. `/element` is ESM only on purpose (browser code), so it is
 * loaded with `import` and a `require` of it is not something the package promises.
 */
const entries = Object.entries(pkg.exports)
  .filter(([key]) => key !== "./package.json")
  .map(([key, conditions]) => ({
    name: key === "." ? pkg.name : `${pkg.name}/${key.slice(2)}`,
    requirable: typeof conditions === "object" && conditions !== null && "require" in conditions,
  }));
const scratch = mkdtempSync(join(tmpdir(), "hackerpot-package-"));
let failures = 0;
let tarball: string | undefined;

try {
  process.stdout.write("packing…\n");
  tarball = run("npm", ["pack", "--silent"], repo).trim().split("\n").pop() as string;

  writeFileSync(join(scratch, "package.json"), JSON.stringify({ name: "consumer", private: true, type: "module" }));
  process.stdout.write(`installing ${tarball} into an empty project…\n`);
  // --ignore-scripts, as the Docker runtime stage does: ssh2's install script only builds
  // an optional native accelerator, and the pure-JS path is what has to work everywhere.
  run("npm", ["install", "--no-audit", "--no-fund", "--silent", "--ignore-scripts", join(repo, tarball)], scratch);

  // The root must carry the engine; every other entry must carry something.
  const check = (entry: string): string =>
    entry === pkg.name ? `if (typeof m.HoneypotEngine !== "function") throw new Error("HoneypotEngine is missing");` : `if (Object.keys(m).length === 0) throw new Error("no exports");`;
  for (const { name: entry, requirable } of entries) {
    const probes = [
      ["import", `import * as m from ${JSON.stringify(entry)}; ${check(entry)} console.log(Object.keys(m).length);`],
      ...(requirable ? ([["require", `const m = require(${JSON.stringify(entry)}); ${check(entry)} console.log(Object.keys(m).length);`]] as const) : []),
    ] as const;
    for (const [kind, source] of probes) {
      // Each in its own process: ESM and CommonJS resolve through different halves of `exports`.
      const file = join(scratch, `probe-${kind}.${kind === "import" ? "mjs" : "cjs"}`);
      writeFileSync(file, source);
      try {
        const count = run(process.execPath, [file], scratch).trim();
        process.stdout.write(`  ok    ${kind.padEnd(8)} ${entry}  (${count} exports)\n`);
      } catch (error) {
        failures += 1;
        process.stdout.write(`  FAIL  ${kind.padEnd(8)} ${entry}  ${firstErrorLine(error)}\n`);
      }
    }
  }

  for (const [command, target] of Object.entries(pkg.bin ?? {})) {
    try {
      const help = run(process.execPath, [join(scratch, "node_modules", pkg.name, target), "--help"], scratch);
      if (!help.includes("hackerpot")) throw new Error("--help printed nothing recognisable");
      process.stdout.write(`  ok    bin      ${command} --help\n`);
    } catch (error) {
      failures += 1;
      process.stdout.write(`  FAIL  bin      ${command} --help  ${firstErrorLine(error)}\n`);
    }
  }
} finally {
  if (tarball !== undefined) rmSync(join(repo, tarball), { force: true });
  rmSync(scratch, { recursive: true, force: true });
}

if (failures > 0) {
  process.stdout.write(`\n${failures} check(s) failed against the packed tarball.\n`);
  process.exitCode = 1;
} else {
  process.stdout.write("\nThe packed tarball installs and loads, as ESM, as CommonJS, and as a command.\n");
}
