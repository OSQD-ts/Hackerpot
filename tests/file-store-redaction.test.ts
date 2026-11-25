import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createStore } from "../src/config/build.js";
import { parseConfig } from "../src/config/schema.js";
import { FileStore } from "../src/stores/index.js";
import { hit } from "./helpers.js";

/** What reaches the disk: scanners send credentials, often somebody else's, and a file keeps them for weeks. */

const withCredentials = () =>
  hit({
    headers: { authorization: "Basic dXNlcjpodW50ZXIy", cookie: "session=abcdef123456", "x-acme-automation-token": "tok_9f8e7d6c5b4a", "user-agent": "curl/8.4.0" },
    body: "username=admin&password=hunter2hunter2",
    detections: [{ detector: "credential-bruteforce", summary: "tried password hunter2hunter2", score: 5 }],
  });

async function written(options: Partial<ConstructorParameters<typeof FileStore>[0]>): Promise<Record<string, unknown>> {
  const path = join(mkdtempSync(join(tmpdir(), "hp-redact-")), "hits.jsonl");
  const store = new FileStore({ path, ...options });
  await store.record(withCredentials());
  await store.close();
  return JSON.parse(readFileSync(path, "utf8").trim()) as Record<string, unknown>;
}

describe("the file store", () => {
  it("redacts credentials by default, headers, body and the detector's quote of them alike", async () => {
    const line = JSON.stringify(await written({}));
    for (const secret of ["dXNlcjpodW50ZXIy", "abcdef123456", "tok_9f8e7d6c5b4a", "hunter2hunter2"]) expect(line).not.toContain(secret);
    expect(line).toContain("[redacted]");
    expect(line).toContain("curl/8.4.0");
  });

  it("writes everything when redaction is explicitly off", async () => {
    expect(JSON.stringify(await written({ redact: false }))).toContain("hunter2hunter2");
  });

  it("can leave headers and the body out entirely", async () => {
    const record = await written({ includeHeaders: false, includeBody: false });
    expect(record["headers"]).toEqual({});
    expect(record["body"]).toBeUndefined();
  });

  it("does not change the hit the engine goes on to hand everybody else", async () => {
    const path = join(mkdtempSync(join(tmpdir(), "hp-redact-")), "hits.jsonl");
    const store = new FileStore({ path });
    const original = withCredentials();
    await store.record(original);
    await store.close();
    expect(original.headers["authorization"]).toBe("Basic dXNlcjpodW50ZXIy");
  });

  it("reads the settings from [store.file] and says so in the store description", () => {
    const dir = mkdtempSync(join(tmpdir(), "hp-redact-"));
    const config = parseConfig({ store: { file: { path: join(dir, "hits.jsonl"), include_body: false, secret_headers: ["x-custom"] } } }, "<test>");
    expect(config.store.file).toMatchObject({ redact: true, includeHeaders: true, includeBody: false, secretHeaders: ["x-custom"] });
    const built = createStore(config);
    expect(built.describe).toContain("redacted");
    void built.close();
  });
});
