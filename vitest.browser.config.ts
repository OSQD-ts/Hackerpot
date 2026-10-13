import { defineConfig } from "vitest/config";

// The browser suite, kept apart from `npm test` on purpose.
//
// It needs a Chromium binary that a fresh checkout does not have, and a default suite that
// fails until somebody runs `npx playwright install` is a suite people learn to skip. Run it
// with `npm run test:browser`; CI runs it in a job that installs the browser first.
//
// Single-threaded and unbounded in time because each test drives a real page: parallel workers
// would fight over the one dashboard they share, and a cold browser launch is slower than
// vitest's default patience.
export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/browser/**/*.test.ts"],
    testTimeout: 30_000,
    hookTimeout: 120_000,
    pool: "forks",
    isolate: false,
    fileParallelism: false,
  },
});
