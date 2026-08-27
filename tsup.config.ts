import { defineConfig } from "tsup";

const shared = {
  format: ["esm", "cjs"] as const,
  dts: false,
  sourcemap: true,
  target: "es2022",
  splitting: false,
};

// Two builds: the library entry, and the standalone CLI which gets a shebang so
// `npx hackerpot` / the package `bin` can execute it directly.
//
// LOAD-BEARING ORDERING: `clean: true` on the first only, `clean: false` on the
// second. tsup runs these sequentially, so the first cleans dist/ before the second
// writes standalone.js. If tsup ever ran array configs concurrently, the first's
// clean could race and wipe the standalone entry — intermittently shipping a package
// with no CLI. If you touch this, keep clean on exactly the first config.
export default defineConfig([
  { entry: ["src/index.ts"], clean: true, ...shared },
  { entry: ["src/standalone.ts"], clean: false, banner: { js: "#!/usr/bin/env node" }, ...shared },
]);
