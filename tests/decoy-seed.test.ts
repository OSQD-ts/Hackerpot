import { describe, expect, it } from "vitest";
import { buildDetectors } from "../src/config/build.js";
import { parseConfig } from "../src/config/schema.js";
import { HoneypotEngine } from "../src/core.js";
import { DEFAULT_DECOY_SEED, decoyHoneytokens, decoyPathDetector, decoyPathsFor, decoySecrets, defaultDecoyPaths, honeytokenDetector } from "../src/detectors/index.js";
import { facts } from "./helpers.js";

/**
 * The built-in decoys' secrets are seeded per install, never the well-known example values
 * every install used to share, and the same seed always serves the same file.
 */

const SEED = "0123456789abcdef0123456789abcdef";

const bodyOf = (decoys: ReturnType<typeof decoyPathsFor>, id: string): string => decoys.find((decoy) => decoy.id === id)?.payload?.body ?? "";

describe("seeded decoy secrets", () => {
  it("serves no well-known example value", () => {
    const all = defaultDecoyPaths.map((decoy) => decoy.payload?.body ?? "").join("\n");
    expect(all).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(all).not.toContain("EXAMPLEKEY");
    expect(all).not.toContain("github.com/example");
  });

  it("is stable for one seed and different for another", () => {
    expect(decoySecrets(SEED)).toEqual(decoySecrets(SEED));
    expect(bodyOf(decoyPathsFor(SEED), "dotenv")).toBe(bodyOf(decoyPathsFor(SEED), "dotenv"));
    expect(bodyOf(decoyPathsFor(SEED), "dotenv")).not.toBe(bodyOf(decoyPathsFor(`${SEED}x`), "dotenv"));
  });

  it("looks like the real thing and points at nobody else", () => {
    const secrets = decoySecrets(SEED);
    expect(secrets.awsAccessKeyId).toMatch(/^AKIA[A-Z2-7]{16}$/);
    expect(secrets.awsSecretAccessKey).toHaveLength(40);
    expect(secrets.appKey).toMatch(/^base64:[A-Za-z0-9+/]{43}=$/);
    expect(new URL(secrets.gitRemote).hostname).toMatch(/\.internal$/);
    expect(bodyOf(decoyPathsFor(SEED), "dotenv")).toContain(`DB_PASSWORD=${secrets.dbPassword}`);
    expect(bodyOf(decoyPathsFor(SEED), "git-config")).toContain(secrets.gitRemote);
  });

  it("takes its seed from the file, and refuses one short enough to guess", () => {
    const config = parseConfig({ detectors: { "decoy-path": { seed: SEED } } }, "<test>");
    expect(config.detectors["decoy-path"].seed).toBe(SEED);
    expect(() => parseConfig({ detectors: { "decoy-path": { seed: "short" } } }, "<test>")).toThrow(/seed/);
  });
});

describe("decoys at any depth", () => {
  const detector = decoyPathDetector(decoyPathsFor(SEED));
  const inspect = (path: string) => detector.inspect({ ...facts({ path }), tracker: undefined as never, timestamp: new Date(), fingerprint: "", fingerprintRegistry: undefined as never });

  it("serves the .env and .git bait below the root too", () => {
    for (const path of ["/.env", "/laravel/.env", "/backup/.env.production", "/public/.git/config", "/old/.git/HEAD", "/html/.git/index", "/blog/wp-config.php.bak"]) {
      expect(inspect(path), path).toBeDefined();
    }
  });

  it("still respects the boundary", () => {
    for (const path of ["/environment", "/docs/.envelope", "/x/.github/workflows", "/legit/page"]) expect(inspect(path), path).toBeUndefined();
  });

  it("accepts match = \"anywhere\" on a custom decoy, and refuses it on a pattern", () => {
    const config = parseConfig({ detectors: { "decoy-path": { decoys: [{ id: "lock", path: "/composer.lock", match: "anywhere" }] } } }, "<test>");
    expect(config.detectors["decoy-path"].decoys[0]!.match).toBe("anywhere");
    expect(() => parseConfig({ detectors: { "decoy-path": { decoys: [{ id: "x", pattern: "^/x$", match: "prefix" }] } } }, "<test>")).toThrow(/match/);
  });
});

describe("planted secrets are honeytokens", () => {
  const replay = (detectors: ReturnType<typeof buildDetectors>, value: string) =>
    new HoneypotEngine({ enricher: null, detectors }).evaluate(facts({ path: "/api/me", headers: { authorization: `Bearer ${value}` } }));

  it("proves a replay of what the decoy .env handed out", async () => {
    const config = parseConfig({ detectors: { "decoy-path": { seed: SEED } } }, "<test>");
    const result = await replay(buildDetectors(config), decoySecrets(SEED).dbPassword);
    const found = result.detections.find((detection) => detection.detector === "honeytoken");
    expect(found?.certain).toBe(true);
    expect(found?.summary).toContain("DB_PASSWORD");
  });

  it("keeps the file's own tokens beside the planted ones", async () => {
    const config = parseConfig({ detectors: { "decoy-path": { seed: SEED }, honeytoken: { tokens: ["my-own-token-value-123"] } } }, "<test>");
    expect((await replay(buildDetectors(config), "my-own-token-value-123")).detections.some((d) => d.detector === "honeytoken")).toBe(true);
    expect((await replay(buildDetectors(config), decoySecrets(SEED).awsAccessKeyId)).detections.some((d) => d.detector === "honeytoken")).toBe(true);
  });

  it("can be switched off, and is off when the built-in decoys are replaced", () => {
    const off = parseConfig({ detectors: { "decoy-path": { honeytokens: false } } }, "<test>");
    expect(buildDetectors(off).map((d) => d.id)).not.toContain("honeytoken");
    const replaced = parseConfig({ detectors: { "decoy-path": { replace_defaults: true, decoys: [{ id: "x", path: "/x" }] } } }, "<test>");
    expect(buildDetectors(replaced).map((d) => d.id)).not.toContain("honeytoken");
  });

  it("lets an extra honeytoken detector replace the default one instead of scoring twice", () => {
    const engine = new HoneypotEngine({ enricher: null, extraDetectors: [honeytokenDetector({ tokens: ["abcdefghijklmnop", ...decoyHoneytokens(DEFAULT_DECOY_SEED)] })] });
    expect(engine.detectors.filter((detector) => detector.id === "honeytoken")).toHaveLength(1);
  });
});
