import { describe, expect, it } from "vitest";
import { HoneypotEngine } from "../src/core.js";
import { decoyPathDetector, defaultDecoyPaths } from "../src/detectors/index.js";
import type { RequestFacts } from "../src/detectors/types.js";

const CHROME = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
let next = 0;
const facts = (path: string): RequestFacts => ({
  method: "GET",
  path,
  query: {},
  headers: { host: "shop.example", "user-agent": CHROME, accept: "text/html", "accept-language": "en", "accept-encoding": "gzip" },
  ip: `10.77.${Math.floor(++next / 250)}.${next % 250}`,
});

async function decoyIdFor(path: string): Promise<string | undefined> {
  const engine = new HoneypotEngine({ enricher: null, detectors: [decoyPathDetector()] });
  const result = await engine.evaluate(facts(path));
  return result.detections[0]?.metadata?.["decoyId"] as string | undefined;
}

describe("decoy path variants", () => {
  // Each of these went undetected when decoys matched only their exact path.
  it.each([
    ["/.env.production", "dotenv"],
    ["/.env.local", "dotenv"],
    ["/.ENV", "dotenv"],
    ["/.git/index", "git-dir"],
    ["/.git/logs/HEAD", "git-dir"],
    ["/.aws/config", "aws-dir"],
    ["/.ssh/authorized_keys", "ssh-dir"],
    ["/.npmrc", "package-credentials"],
    ["/actuator/heapdump", "spring-actuator-heapdump"],
    ["/actuator/env/spring.datasource.password", "spring-actuator-env"],
    ["/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php", "phpunit-eval-rce"],
    ["/_all_dbs", "couchdb-all-dbs"],
    ["/cgi-bin/luci", "router-rce"],
    ["/wp-config.php.save", "wp-config"],
    ["/remote/fgt_lang", "fortinet-traversal"],
  ])("catches %s", async (path, id) => {
    expect(await decoyIdFor(path)).toBe(id);
  });

  it("keeps the more specific decoy, and its bait, ahead of the prefix that covers it", async () => {
    expect(await decoyIdFor("/.git/config")).toBe("git-config");
    expect(await decoyIdFor("/.aws/credentials")).toBe("aws-credentials");
  });

  // A prefix only matches at a `/` or `.` boundary.
  it.each(["/.environment-guide", "/.gitignore-explained", "/vendor/phpunitish", "/actuator/environment-docs", "/solr/administrators-handbook"])("leaves %s alone", async (path) => {
    expect(await decoyIdFor(path)).toBeUndefined();
  });

  it("keeps a custom string decoy exact unless it asks for prefix matching", async () => {
    const exact = new HoneypotEngine({ enricher: null, detectors: [decoyPathDetector([{ id: "a", description: "a", path: "/admin", score: 5 }])] });
    expect((await exact.evaluate(facts("/admin/users"))).detections).toEqual([]);
    const prefix = new HoneypotEngine({ enricher: null, detectors: [decoyPathDetector([{ id: "a", description: "a", path: "/admin", match: "prefix", score: 5 }])] });
    expect((await prefix.evaluate(facts("/admin/users"))).detections).toHaveLength(1);
  });

  it("gives every built-in decoy a unique id", () => {
    const ids = defaultDecoyPaths.map((decoy) => decoy.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
