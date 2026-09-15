import { defineConfig } from "tsup";

const shared = {
  format: ["esm", "cjs"] as const,
  dts: false,
  sourcemap: true,
  target: "es2022",
  splitting: false,
};

// One entry per import path, the way bothandlerjs lays its package out:
//
// - `src/index.ts`           → `@osqd/hackerpot`
// - `src/adapters/index.ts`  → `@osqd/hackerpot/adapters`: an edge deployment that imports
//                               only the Fetch adapter need not name the rest.
// - `src/corpus/index.ts`    → `@osqd/hackerpot/corpus`: traffic fixtures and their runner, its own
//                               entry so importing the library never loads a case of it.
// - `src/cli.ts`             → `@osqd/hackerpot/cli`, and `bin/hackerpot.mjs` imports it.
// - `src/element/index.ts`   → `@osqd/hackerpot/element`, `<hackerpot-dashboard>`.
//
// Then `src/standalone.ts`, which runs the command line when executed and is what the
// container image starts. It gets a shebang so `node dist/standalone.js` and a direct
// execution both work.
//
// LOAD-BEARING ORDERING: `clean: true` on the first config only. tsup runs array configs
// sequentially, so the first cleans dist/ before the second writes. If that ever ran
// concurrently the clean could wipe the standalone entry, intermittently shipping a
// package with no executable. Keep clean on exactly the first config.
export default defineConfig([
  { entry: ["src/index.ts", "src/adapters/index.ts", "src/corpus/index.ts", "src/cli.ts"], clean: true, ...shared },
  { entry: ["src/standalone.ts"], clean: false, banner: { js: "#!/usr/bin/env node" }, ...shared },
  // `@osqd/hackerpot/element`: browser code, so ESM only and type-checked against the DOM.
  // Kept off the root entry, which must never pull in anything that needs a document.
  { entry: { element: "src/element/index.ts" }, format: ["esm"], platform: "browser", target: "es2020", dts: false, sourcemap: true, splitting: false, clean: false },
]);
