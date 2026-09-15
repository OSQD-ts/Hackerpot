import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import { formatExplanation, parseRequestText } from "../src/explain.js";

describe("parseRequestText", () => {
  it("reads a bare User-Agent with the headers a browser sends alongside it", () => {
    const facts = parseRequestText("sqlmap/1.7.2#stable (https://sqlmap.org)");
    expect(facts).toMatchObject({ method: "GET", path: "/", headers: { "user-agent": "sqlmap/1.7.2#stable (https://sqlmap.org)", accept: expect.any(String) } });
  });

  it("reads a curl command copied from developer tools", () => {
    const facts = parseRequestText(`curl 'https://shop.example/search?q=%27%20or%201%3D1--' \\\n  -H 'Accept: text/html' \\\n  -H "Cookie: sid=abc" -A 'Mozilla/5.0' --data-raw 'a=1'`);
    expect(facts).toMatchObject({ method: "POST", path: "/search", query: { q: "' or 1=1--" }, body: "a=1", headers: { host: "shop.example", accept: "text/html", cookie: "sid=abc", "user-agent": "Mozilla/5.0" } });
  });

  it("reads a raw request with a request line, headers and a body", () => {
    const facts = parseRequestText("POST /login?next=//evil.example HTTP/1.1\nHost: shop.example\nUser-Agent: python-requests/2.31\n\nuser=admin&password=x");
    expect(facts).toMatchObject({ method: "POST", path: "/login", query: { next: "//evil.example" }, body: "user=admin&password=x", headers: { host: "shop.example" } });
  });

  it("lets flags override what the text says, and refuses empty input", () => {
    expect(parseRequestText("curl/8.4.0", { url: "/.env", method: "head", ip: "192.0.2.1" })).toMatchObject({ method: "HEAD", path: "/.env", ip: "192.0.2.1" });
    expect(() => parseRequestText("  ")).toThrow(/nothing to explain/);
  });
});

describe("formatExplanation", () => {
  it("lists what fired, with proof marked, and the response", async () => {
    const facts = parseRequestText("sqlmap/1.7.2#stable (https://sqlmap.org)", { url: "/.env" });
    const result = await new HoneypotEngine({ enricher: null }).evaluate(facts);
    const text = formatExplanation(facts, result);
    expect(text).toContain("decoy-path");
    expect(text).toContain("scanner-signature");
    expect(text).toMatch(/\[proof/);
    expect(text).toContain("Response");
  });

  it("says so when nothing fired", async () => {
    const facts = parseRequestText("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36");
    const result = await new HoneypotEngine({ enricher: null }).evaluate(facts);
    expect(formatExplanation(facts, result)).toContain("No detector fired");
  });
});

describe("hackerpot --explain", () => {
  it("explains a request from the command line and from stdin", () => {
    const run = (args: string[], input?: string) =>
      execFileSync(process.execPath, ["--import", "tsx", "src/standalone.ts", "--config", "hackerpot.toml", ...args], { encoding: "utf8", timeout: 60_000, ...(input !== undefined ? { input } : {}) });
    const json = JSON.parse(run(["--explain", "nikto/2.5.0", "--url", "/.git/config", "--json"]));
    expect(json.detections.map((d: { detectorId: string }) => d.detectorId)).toEqual(expect.arrayContaining(["decoy-path", "scanner-signature"]));
    expect(run(["--explain"], "GET /wso.php HTTP/1.1\nHost: x\nUser-Agent: curl/8.4.0\n")).toContain("web-shell");
  }, 90_000);
});
