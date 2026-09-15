import { describe, expect, it } from "vitest";
import { honeytokenDetector } from "../src/index.js";
import type { DetectionContext } from "../src/detectors/types.js";

const TOKEN = "hp_seeded_db_password_7f3a";
const detector = honeytokenDetector({ tokens: [{ value: TOKEN, label: "decoy-db-password" }] });

const ctx = (headers: Record<string, string>, query: Record<string, string> = {}): DetectionContext =>
  ({
    method: "GET",
    path: "/admin",
    query,
    headers,
    ip: "203.0.113.20",
    timestamp: new Date(),
    fingerprint: "",
    tracker: undefined as never,
    fingerprintRegistry: undefined as never,
  }) as DetectionContext;

const basic = (credential: string): string => `Basic ${Buffer.from(credential).toString("base64")}`;

describe("honeytokens replayed inside HTTP Basic credentials", () => {
  // A harvested password is most naturally tried as a Basic credential, where it only
  // ever appears base64-encoded. A raw `includes()` over the header could not see it.
  it("fires when the token is the Basic password", async () => {
    const hit = await detector.inspect(ctx({ authorization: basic(`admin:${TOKEN}`) }));
    expect(hit?.detectorId).toBe("honeytoken");
    expect(hit?.metadata?.["location"]).toBe("header.authorization (basic, decoded)");
  });

  it("fires when the token is the Basic username", async () => {
    expect(await detector.inspect(ctx({ authorization: basic(`${TOKEN}:x`) }))).toBeDefined();
  });

  it("fires on Proxy-Authorization and on a lowercase scheme", async () => {
    expect(await detector.inspect(ctx({ "proxy-authorization": basic(`u:${TOKEN}`) }))).toBeDefined();
    expect(await detector.inspect(ctx({ authorization: basic(`u:${TOKEN}`).replace("Basic", "basic") }))).toBeDefined();
  });

  it("stays quiet for Basic credentials that do not carry the token", async () => {
    expect(await detector.inspect(ctx({ authorization: basic("admin:hunter2") }))).toBeUndefined();
    expect(await detector.inspect(ctx({ authorization: "Basic !!!not-base64!!!" }))).toBeUndefined();
  });

  // Scope pin: only the credential headers are decoded. Base64 elsewhere is arbitrary
  // application data, and guessing inside it is the false-positive risk that kept this
  // out of the detector originally.
  it("does not decode base64 anywhere else", async () => {
    const encoded = Buffer.from(TOKEN).toString("base64");
    expect(await detector.inspect(ctx({ cookie: `session=${encoded}` }, { key: encoded }))).toBeUndefined();
  });

  it("still catches the raw token in a Bearer header", async () => {
    const hit = await detector.inspect(ctx({ authorization: `Bearer ${TOKEN}` }));
    expect(hit?.metadata?.["location"]).toBe("header.authorization");
  });
});
