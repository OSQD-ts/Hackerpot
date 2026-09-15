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

  it("has no inline style attributes anywhere", () => {
    expect(markupOnly(render())).not.toMatch(/\sstyle\s*=/i);
    expect(DASHBOARD_MARKUP).not.toMatch(/\sstyle\s*=/i);
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
    expect(tabs).toHaveLength(6);
    for (const tab of tabs) {
      expect(tab).toMatch(/aria-controls="pane-[a-z]+"/);
      expect(tab).toMatch(/type="button"/);
    }
    expect(DASHBOARD_MARKUP).toContain('role="tablist"');
    expect(DASHBOARD_MARKUP.match(/role="tabpanel"/g)).toHaveLength(6);
  });
});
