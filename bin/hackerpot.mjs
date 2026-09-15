#!/usr/bin/env node
// Thin launcher. Everything lives in the build, so the command and the library share one
// implementation: a CLI that reimplements the service is a CLI that drifts from it.
import { main } from "../dist/cli.js";

main(process.argv.slice(2)).then(
  (code) => {
    if (code !== 0) process.exitCode = code;
  },
  (error) => {
    console.error(`hackerpot: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  },
);
