/**
 * The executable entry point. Everything lives in `cli.ts`, so the command, the published
 * `hackerpot` bin and the container image share one implementation.
 */
import { main } from "./cli.js";

main(process.argv.slice(2)).then(
  (code) => {
    if (code !== 0) process.exitCode = code;
  },
  (error: unknown) => {
    console.error(`hackerpot: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  },
);
