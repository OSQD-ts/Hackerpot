import { describe, expect, it } from "vitest";
import { generateRobotsTxt } from "../src/index.js";

describe("generateRobotsTxt", () => {
  it("advertises decoy paths as Disallow with a wildcard user-agent", () => {
    const txt = generateRobotsTxt();
    expect(txt).toContain("User-agent: *");
    expect(txt).toContain("Disallow: /.env");
    expect(txt).toContain("Disallow: /wp-login.php");
    expect(txt.endsWith("\n")).toBe(true);
  });

  it("includes extra disallows and a sitemap, only string (non-regex) decoys, deduped and sorted", () => {
    const txt = generateRobotsTxt({
      decoys: [
        { id: "a", description: "", path: "/secret-a", score: 5 },
        { id: "b", description: "", path: /^\/regex-only/, score: 5 }, // regex decoy: not a robots rule
        { id: "c", description: "", path: "/secret-a", score: 5 }, // duplicate
      ],
      extraDisallow: ["/admin", "/internal"],
      sitemap: "https://example.com/sitemap.xml",
    });
    expect(txt).toContain("Disallow: /secret-a");
    expect(txt).toContain("Disallow: /admin");
    expect(txt).not.toContain("regex-only");
    expect(txt).toContain("Sitemap: https://example.com/sitemap.xml");
    // deduped: /secret-a appears exactly once
    expect(txt.match(/Disallow: \/secret-a$/gm)).toHaveLength(1);
  });
});
