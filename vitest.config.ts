import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      // Source only. Scripts are developer tooling exercised by hand, and the
      // entrypoints run `main()` on import, which a coverage run must not trigger.
      include: ["src/**/*.ts"],
      exclude: [
        // The executable and the command line run in child processes: `tests/cli.test.ts`,
        // `explain.test.ts` and `replay.test.ts` spawn them and assert on what they print, and
        // a coverage run instruments only this process. `service.ts` is what `standalone.ts`
        // used to contain before the command line was split out, excluded for the same reason.
        "src/standalone.ts",
        "src/service.ts",
        "src/cli.ts",
        "src/**/index.ts",
        "src/**/types.ts",
        // The generated bundle is a string, and the page is markup asserted on as text.
        "src/dashboard/client.generated.ts",
        // The browser half needs a document; its pure modules (format, analysis, decode,
        // query, palette, knowledge) are unit-tested and stay counted.
        "src/element/**",
        "src/dashboard/client/{dom,boot,api,store,app,tooltip,charts,badges,volume,overview,statistics,incidents,detail,lists,stream,css}.ts",
      ],
      reporter: ["text-summary", "text", "json-summary"],
      // A point under what the suite measures, so a change that drops coverage fails CI.
      thresholds: { lines: 91, statements: 87, functions: 89, branches: 81 },
    },
  },
});
