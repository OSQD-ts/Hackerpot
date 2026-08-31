import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      // Source only. Scripts are developer tooling exercised by hand, and the
      // entrypoints run `main()` on import, which a coverage run must not trigger.
      include: ["src/**/*.ts"],
      exclude: ["src/standalone.ts", "src/**/index.ts", "src/**/types.ts"],
      reporter: ["text-summary", "text", "json-summary"],
    },
  },
});
