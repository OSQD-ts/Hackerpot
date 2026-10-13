import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CLIENT_SCRIPT } from "../src/dashboard/client.generated.js";
import { DASHBOARD_CSS, DASHBOARD_MARKUP, renderDashboardPage } from "../src/dashboard/page.js";
import type { DashboardBootstrap } from "../src/dashboard/types.js";

/**
 * The served page, as a string: what the CSP relies on and what the client relies on.
 *
 * The page renders attacker-written text under `default-src 'none'` with a per-response
 * nonce, so every script and style must carry that nonce, no element may carry an inline
 * style, and the bundle may contain no HTML sink. A title is operator configuration, but it
 * is interpolated into both HTML and a script, so it is the one value here that could
 * break out of either.
 */

const bootstrap: DashboardBootstrap = {
  base: "/_hackerpot",
  title: 'ops </script><script>alert("x")</script> $& honeypot',
  instance: "edge-1",
  version: "0.1.0",
  sections: { overview: true, incidents: true, statistics: true, sessions: true, actors: true, intel: true },
  controls: { testRequest: false, previewPolicy: false, editPolicy: false },
  links: [{ label: "Runbook", href: "https://runbook.example" }],
  source: "this process",
  redaction: { credentials: true, maskIp: false },
};

const NONCE = "bm9uY2UtdmFsdWUtMTIzNA==";

function render(): string {
  return renderDashboardPage(bootstrap)(NONCE);
}

/** The page with the contents of every script and style removed, so only markup is left. */
function markupOnly(html: string): string {
  return html.replace(/(<script\b[^>]*>)[\s\S]*?<\/script>/gi, "$1</script>").replace(/(<style\b[^>]*>)[\s\S]*?<\/style>/gi, "$1</style>");
}

describe("dashboard page", () => {
  it("carries the bundle", () => {
    expect(CLIENT_SCRIPT.length).toBeGreaterThan(10_000);
    expect(render()).toContain(CLIENT_SCRIPT);
  });

  it("stamps the nonce on every script and style, and has nothing else that runs", () => {
    const html = markupOnly(render());
    const tags = html.match(/<(script|style)\b[^>]*>/gi) ?? [];
    expect(tags).toHaveLength(3);
    for (const tag of tags) expect(tag).toContain(`nonce="${NONCE}"`);
    expect(html).not.toMatch(/<link\b/i);
    expect(html).not.toMatch(/\son[a-z]+\s*=/i);
    expect(html).not.toMatch(/(src|href)\s*=\s*"(?:https?:)?\/\//i);
    // A fresh nonce per call, not a cached page.
    expect(renderDashboardPage(bootstrap)("other")).toContain('nonce="other"');
    expect(renderDashboardPage(bootstrap)("other")).not.toContain(NONCE);
  });

  it("ships its stylesheet whole", () => {
    // The CSS is a template literal, so a stray backtick in a comment ends it early and the
    // page renders unstyled while every other test passes. Balanced braces and the last rules
    // of the file being present catch that.
    const opens = (DASHBOARD_CSS.match(/\{/g) ?? []).length;
    const closes = (DASHBOARD_CSS.match(/\}/g) ?? []).length;
    expect(opens).toBe(closes);
    expect(DASHBOARD_CSS).toContain(".search kbd");
    expect(DASHBOARD_CSS).toContain(".tile.proven .v");
    expect(DASHBOARD_CSS).toContain(".panel:has(> h3:first-child)");
  });

  it("has no inline style attributes anywhere", () => {
    expect(markupOnly(render())).not.toMatch(/\sstyle\s*=/i);
    expect(DASHBOARD_MARKUP).not.toMatch(/\sstyle\s*=/i);
  });

  it("ships the request tester hidden, for the client to show only when the control is granted", () => {
    // Hidden in the markup rather than revealed by default: a deployment that never granted
    // `testRequest` must not show a box whose every submission the server refuses.
    expect(DASHBOARD_MARKUP).toMatch(/<section class="panel" id="tester"[^>]*\shidden>/);
    expect(CLIENT_SCRIPT).toContain("/api/test");
    expect(CLIENT_SCRIPT).toContain("testRequest");
  });

  it("ships the Policy screen, which the client shows only when a policy control is granted", async () => {
    expect(DASHBOARD_MARKUP).toContain('id="pane-policy"');
    expect(DASHBOARD_MARKUP).toContain('id="policy-rules"');
    // Apply is hidden in the markup: editPolicy is the control that reveals it, and it needs auth.
    expect(DASHBOARD_MARKUP).toMatch(/<button id="policy-apply"[^>]*\shidden>/);
    expect(CLIENT_SCRIPT).toContain("/api/policy/preview");
    expect(CLIENT_SCRIPT).toContain("/api/policy/apply");
  });

  it("ships the Reference screen, which needs nothing from the server", async () => {
    expect(DASHBOARD_MARKUP).toContain('id="pane-reference"');
    const { detectorList, responseList } = await import("../src/dashboard/client/knowledge.js");
    // Every detector the library ships is explained, so a rule or an alert naming one has a page
    // to send somebody to.
    const { defaultDetectors } = await import("../src/index.js");
    const explained = new Set(detectorList().map(([id]) => id));
    const missing = defaultDetectors().map((detector) => detector.id).filter((id) => !explained.has(id));
    expect(missing, "detectors with no entry on the Reference screen").toEqual([]);
    expect(responseList().length).toBeGreaterThan(0);
  });

  it("exports the shown incidents in a format hackerpot replay reads", async () => {
    // The export is a JSON line per incident; replay's JSON reader takes ip, method, path,
    // timestamp and headers from exactly that shape, so the round trip needs no converter.
    expect(DASHBOARD_MARKUP).toContain('id="f-export"');
    const { parseLogLine } = await import("../src/replay.js");
    const line = JSON.stringify({ id: "x", timestamp: "2026-09-16T10:00:00.000Z", ip: "203.0.113.9", method: "GET", path: "/.env", headers: { "user-agent": "curl/8.4.0" }, detections: [], score: 0, totalScore: 0, respondedWith: "not-found" });
    expect(parseLogLine(line)).toMatchObject({ ip: "203.0.113.9", method: "GET", target: "/.env", headers: { "user-agent": "curl/8.4.0" } });
  });

  it("ships no HTML sink in the client bundle", () => {
    for (const sink of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"]) expect(CLIENT_SCRIPT).not.toContain(sink);
    expect(CLIENT_SCRIPT.toLowerCase()).not.toContain("</script");
  });

  it("keeps a title containing </script> escaped in both the title and the bootstrap", () => {
    const html = render();
    // Exactly the page's own two closing tags: the title opened none.
    expect(html.match(/<\/script>/gi)).toHaveLength(2);
    expect(html).toContain("<title>ops &#60;/script&#62;&#60;script&#62;alert(&#34;x&#34;)&#60;/script&#62; $&#38; honeypot</title>");
    const boot = /window\.__HACKERPOT_DASHBOARD__ = JSON\.parse\((.*)\);<\/script>/.exec(html)?.[1];
    expect(boot).toBeDefined();
    expect(boot).not.toContain("<");
    expect(JSON.parse(JSON.parse(boot as string) as string)).toEqual(bootstrap);
  });

  it("writes theme tokens for light and dark, for both the page and a shadow host", () => {
    expect(DASHBOARD_CSS).toContain(":root, :host {");
    expect(DASHBOARD_CSS).toContain(':root:not([data-theme="light"]), :host(:not([data-theme="light"]))');
    expect(DASHBOARD_CSS).toContain(':root[data-theme="dark"], :host([data-theme="dark"])');
    expect(DASHBOARD_CSS).toContain("prefers-color-scheme: dark");
    for (const slot of ["s1", "s8", "so", "q0", "q12", "o5"]) expect(DASHBOARD_CSS).toContain(`--${slot}:`);
  });

  it("declares every element id the client looks up by name", () => {
    const dir = join(import.meta.dirname, "..", "src", "dashboard", "client");
    const ids = new Set<string>();
    for (const file of readdirSync(dir).filter((name) => name.endsWith(".ts"))) {
      const source = readFileSync(join(dir, file), "utf8");
      for (const match of source.matchAll(/\b(?:\$|maybe|byId(?:<[^>]+>)?|setText|maybe<[^>]+>)\("([a-z][a-z0-9-]*)"/g)) ids.add(match[1] as string);
    }
    expect(ids.size).toBeGreaterThan(40);
    const missing = [...ids].filter((id) => !DASHBOARD_MARKUP.includes(`id="${id}"`));
    expect(missing).toEqual([]);
    for (const tab of ["overview", "incidents", "statistics", "sessions", "actors", "intel"]) {
      expect(DASHBOARD_MARKUP).toContain(`id="tab-${tab}"`);
      expect(DASHBOARD_MARKUP).toContain(`id="pane-${tab}"`);
    }
  });

  it("makes every tab a keyboard-reachable tab bound to its panel", () => {
    const tabs = DASHBOARD_MARKUP.match(/<button[^>]*role="tab"[^>]*>/g) ?? [];
    // One per screen: the six sections, plus Policy and Reference, which the client removes when
    // no policy control was granted and never, respectively.
    expect(tabs).toHaveLength(8);
    for (const tab of tabs) {
      expect(tab).toMatch(/aria-controls="pane-[a-z]+"/);
      expect(tab).toMatch(/type="button"/);
    }
    expect(DASHBOARD_MARKUP).toContain('role="tablist"');
    expect(DASHBOARD_MARKUP.match(/role="tabpanel"/g)).toHaveLength(8);
  });
});
