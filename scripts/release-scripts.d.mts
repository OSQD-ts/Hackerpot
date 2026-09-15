// Types for the two release scripts, so tests can import them. The scripts stay plain
// .mjs because the publish workflow runs them with node before dependencies matter.

declare module "*next-version.mjs" {
  export const RANK: { none: 0; patch: 1; minor: 2; major: 3 };
  export function classify(message: string): "none" | "patch" | "major";
  export function declaredRelease(message: string): { kind: "version" | "bump" | "invalid"; value: string } | undefined;
  export function isForwards(from: string, to: string): boolean;
  export function bumpVersion(current: string, bump: "none" | "patch" | "minor" | "major"): string;
  export function baseVersion(packageVersion: string, tag: string | undefined): string;
  export function nextVersion(current: string, commits: readonly string[], say?: (message: string) => void): string | undefined;
}

declare module "*set-version.mjs" {
  export function setVersion(root: string, version: string): void;
}
