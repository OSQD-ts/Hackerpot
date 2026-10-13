import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { chromium, firefox, webkit } from "playwright";
import type { Browser, Page } from "playwright";
import { HoneypotEngine } from "../../src/core.js";
import { startDashboard } from "../../src/dashboard/index.js";
import type { DashboardServer } from "../../src/dashboard/index.js";
import { decoyPathDetector, payloadInjectionDetector, scannerSignatureDetector, suspiciousMethodDetector } from "../../src/detectors/index.js";

/**
 * The dashboard page, in a real browser.
 *
 * Everything else here can be tested by calling a function. This cannot: the page is DOM work
 * whose job is to behave under a keyboard, a scroll and a narrow viewport, and none of those
 * exist in Node. Until this file existed the page's coverage was string matching — "the bundle
 * contains the word ArrowDown" — which passes just as happily against a handler wired to the
 * wrong element, and which let a stylesheet ship truncated with every test green.
 *
 * Kept out of `npm test` on purpose: it needs a browser binary a fresh checkout does not have.
 * `npm run test:browser` runs it, and `BROWSER_ENGINE` picks the engine — the same knob
 * bothandlerjs's suite has, for the same reason. A page this size is mostly CSS, and CSS is
 * where engines differ.
 */

const ENGINES = { chromium, firefox, webkit } as const;
const ENGINE = ENGINES[(process.env["BROWSER_ENGINE"] ?? "chromium") as keyof typeof ENGINES] ?? chromium;
/** axe, read once and evaluated into whichever page is being audited. */
const axeSource = readFileSync(createRequire(import.meta.url).resolve("axe-core/axe.min.js"), "utf8");

let browser: Browser;
let dashboard: DashboardServer;
let url: string;

beforeAll(async () => {
  const engine = new HoneypotEngine({
    enricher: null,
    detectors: [decoyPathDetector(), payloadInjectionDetector(), scannerSignatureDetector(), suspiciousMethodDetector()],
  });
  // Enough traffic for a feed, a pager and side panels that have something to count.
  const paths = ["/.env", "/wp-config.php.bak", "/admin", "/api/items?q=1' OR 1=1--", "/.git/config"];
  for (let i = 0; i < 60; i += 1) {
    await engine.evaluate({
      method: i % 7 === 0 ? "MKCOL" : "GET",
      path: paths[i % paths.length] as string,
      query: {},
      headers: { host: "shop.example", "user-agent": i % 3 === 0 ? "sqlmap/1.7" : "curl/8.4.0" },
      ip: `203.0.113.${10 + (i % 6)}`,
    });
  }
  dashboard = await startDashboard(engine, { port: 0, title: "browser test", instance: "test", controls: { testRequest: true, previewPolicy: true } });
  url = dashboard.url;
  browser = await ENGINE.launch();
}, 120_000);

afterAll(async () => {
  await browser?.close();
  await dashboard?.close();
});

async function open(width = 1440): Promise<Page> {
  const page = await browser.newPage({ viewport: { width, height: 900 }, colorScheme: "dark" });
  const failures: string[] = [];
  page.on("pageerror", (error) => failures.push(String(error)));
  page.on("console", (message) => {
    if (message.type() === "error") failures.push(message.text());
  });
  (page as Page & { failures: string[] }).failures = failures;
  await page.goto(url);
  // The rows live in the Incidents pane, which is hidden until that tab is chosen, so this waits
  // for them to exist rather than to be visible.
  await page.waitForSelector("tbody tr.row", { state: "attached" });
  return page;
}

const failuresOf = (page: Page): string[] => (page as Page & { failures?: string[] }).failures ?? [];

/**
 * What the two dashboards agreed on: the tokens and metrics the shared look is made of.
 *
 * These are read off the page as the browser computes them, so a rule that stops applying — a
 * selector renamed, a stylesheet truncated, a token dropped — fails here rather than being
 * noticed in a screenshot months later. The values are bothandlerjs's.
 */
const CONTRACT: ReadonlyArray<readonly [label: string, selector: string, property: string, expected: string]> = [
  ["body type", "body", "fontFamily", 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif'],
  ["body line height", "body", "lineHeight", "21.7px"],
  ["page background", "body", "backgroundColor", "rgb(13, 15, 18)"],
  ["panel surface", ".feed-panel", "backgroundColor", "rgb(22, 24, 29)"],
  ["panel border", ".feed-panel", "borderTopColor", "rgb(39, 43, 51)"],
  ["panel radius", ".feed-panel", "borderRadius", "12px"],
  ["panel heading", ".feed-panel > h2", "fontSize", "11.5px"],
  ["panel heading weight", ".feed-panel > h2", "fontWeight", "620"],
  ["toolbar padding", "#pane-incidents .toolbar", "paddingLeft", "15px"],
  ["toolbar gap", "#pane-incidents .toolbar", "gap", "8px"],
  ["button size", "#f-export", "fontSize", "12.5px"],
  ["button radius", "#f-export", "borderRadius", "8px"],
  ["chip shape", "#pane-incidents .filters button", "borderRadius", "999px"],
  ["chip size", "#pane-incidents .filters button", "fontSize", "11.5px"],
  ["search field", '.search input[type="search"]', "fontSize", "12.5px"],
  ["tile value", ".tiles .tile .v", "fontSize", "21px"],
  ["tile label", ".tiles .tile .k", "fontSize", "10.5px"],
  ["table header", "table.feed thead th", "paddingLeft", "15px"],
  ["bar row type", "#pane-incidents .barrow", "fontSize", "12.5px"],
  ["bars gap", "#pane-incidents .bars", "gap", "8px"],
];

const computed = (page: Page, selector: string, property: string): Promise<string | null> =>
  page.evaluate(
    ({ selector, property }) => {
      const node = document.querySelector(selector);
      return node === null ? null : (getComputedStyle(node) as unknown as Record<string, string>)[property] ?? null;
    },
    { selector, property },
  );

describe("the dashboard in a browser", () => {
  it("draws the feed, its counters and its side panels", async () => {
    const page = await open();
    await page.getByRole("tab", { name: /^Incidents/ }).click();
    expect(await page.locator("tbody tr.row").count()).toBeGreaterThan(5);
    // The counter strip belongs to the incident-shaped screens, and is drawn when one is chosen.
    expect(await page.locator(".tiles .tile").count()).toBe(8);
    expect(await page.locator("#side-detectors .barrow").count()).toBeGreaterThan(0);
    expect(failuresOf(page)).toEqual([]);
    await page.close();
  });

  // Engines serialise the same computed style differently: WebKit drops the quotes around a font
  // name and prints 21.699999px for 21.7px. Those are the same value, so compare them as one.
  const normalised = (value: string) => value.replace(/"/g, "").replace(/(\d+\.\d+)px/g, (_, n: string) => `${Number(Number(n).toFixed(2))}px`);

  it("keeps the shared visual contract", async () => {
    const page = await open();
    await page.getByRole("tab", { name: /^Incidents/ }).click();
    await page.waitForTimeout(300);
    const wrong: string[] = [];
    for (const [label, selector, property, expected] of CONTRACT) {
      const actual = await computed(page, selector, property);
      if (actual === null || normalised(actual) !== normalised(expected)) wrong.push(`${label} (${selector} ${property}): ${actual ?? "no such element"} — expected ${expected}`);
    }
    expect(wrong).toEqual([]);
    await page.close();
  });

  it("filters by outcome chip, by search, and clears with Escape", async () => {
    const page = await open();
    await page.getByRole("tab", { name: /^Incidents/ }).click();
    const all = await page.locator("tbody tr.row").count();
    await page.locator('#f-outcome button[data-outcome="decoy"]').click();
    const decoys = await page.locator("tbody tr.row").count();
    expect(decoys).toBeGreaterThan(0);
    expect(decoys).toBeLessThan(all);
    expect(await page.locator("tbody tr.row:not(.c-decoy)").count()).toBe(0);
    await page.locator('#f-outcome button[data-outcome=""]').click();
    // One of the six addresses the fixture sends from: narrow, and true of no other row.
    await page.locator("#f-query").fill("ip:203.0.113.10");
    await page.waitForTimeout(250);
    expect(await page.locator("tbody tr.row").count()).toBeLessThan(all);
    await page.locator("#f-query").press("Escape");
    await page.waitForTimeout(250);
    expect(await page.locator("tbody tr.row").count()).toBe(all);
    await page.close();
  });

  it("opens a row with the keyboard and explains it", async () => {
    const page = await open();
    await page.getByRole("tab", { name: /^Incidents/ }).click();
    const row = page.locator("tbody tr.row").first();
    const toggle = row.locator("button.row-toggle");
    await toggle.focus();
    await page.keyboard.press("Enter");
    await page.waitForTimeout(200);
    expect(await toggle.getAttribute("aria-expanded")).toBe("true");
    const detail = page.locator("tr.detail").first();
    expect(await detail.isVisible()).toBe(true);
    expect(await detail.innerText()).toContain("WHY THIS FIRED");
    expect(await detail.locator(".ex-actions button").count()).toBeGreaterThanOrEqual(3);
    await page.keyboard.press("Enter");
    await page.waitForTimeout(200);
    expect(await toggle.getAttribute("aria-expanded")).toBe("false");
    await page.close();
  });

  it("opens a detector's reference entry from the incident that named it", async () => {
    const page = await open();
    await page.getByRole("tab", { name: /^Incidents/ }).click();
    await page.locator("tbody tr.row button.row-toggle").first().click();
    await page.waitForTimeout(300);
    const link = page.locator("tr.detail .ex-card .ref-link").first();
    const named = await link.locator(".badge.det").innerText();
    await link.click();
    await page.waitForTimeout(400);
    expect(await page.locator("#ref-article h2").innerText()).toBe(named);
    expect(await page.locator('#ref-index .ref-item[aria-current="true"] .ref-id').innerText()).toBe(named);
    await page.close();
  });

  it("groups, rolls up and pages the feed", async () => {
    const page = await open();
    await page.getByRole("tab", { name: /^Incidents/ }).click();
    await page.locator("#feed-group").selectOption("ip");
    await page.waitForTimeout(250);
    expect(await page.locator("tbody tr.grp").count()).toBeGreaterThan(1);
    await page.locator("#feed-roll").click();
    await page.waitForTimeout(200);
    expect(await page.locator("tbody tr.row").count()).toBe(0);
    await page.locator("#feed-roll").click();
    await page.locator("#feed-group").selectOption("none");
    await page.locator("#feed-pager-top select").selectOption("25");
    await page.waitForTimeout(250);
    expect(await page.locator("tbody tr.row").count()).toBe(25);
    await page.locator("#feed-pager-top button[aria-label='Next page']").click();
    await page.waitForTimeout(250);
    expect(await page.locator("#feed-pager-top .where").innerText()).toContain("26–");
    await page.close();
  });

  it("saves a filter, reloads it, and deletes it", async () => {
    const page = await open();
    await page.getByRole("tab", { name: /^Incidents/ }).click();
    await page.locator("#f-query").fill("detector:decoy-path");
    await page.waitForTimeout(200);
    await page.locator("#saved-filters button", { hasText: "Save" }).click();
    await page.locator("#saved-filters input.saved-name").fill("decoys");
    await page.keyboard.press("Enter");
    await page.waitForTimeout(400);
    // Kept by the dashboard, not by this browser: a fresh page finds it.
    const second = await open();
    await second.getByRole("tab", { name: /^Incidents/ }).click();
    await second.waitForTimeout(400);
    await second.locator("#saved-filters select").selectOption("decoys");
    await second.waitForTimeout(300);
    expect(await second.locator("#f-query").inputValue()).toBe("detector:decoy-path");
    await second.locator("#saved-filters button", { hasText: "Delete" }).click();
    await second.waitForTimeout(300);
    expect(await second.locator("#saved-filters select option").count()).toBe(1);
    await page.close();
    await second.close();
  });

  it("tests a pasted request and previews a policy without recording anything", async () => {
    const page = await open();
    await page.getByRole("tab", { name: /^Incidents/ }).click();
    const before = await page.locator("tbody tr.row").count();
    await page.locator("#test-input").fill("GET /.env\nuser-agent: sqlmap/1.7\nhost: shop.example");
    await page.locator("#test-run").click();
    await page.waitForTimeout(600);
    expect(await page.locator("#test-result").innerText()).toContain("decoy-path");
    expect(await page.locator("tbody tr.row").count()).toBe(before);

    await page.getByRole("tab", { name: "Policy" }).click();
    await page.locator("#policy-rules").fill('[{"id":"block-scanners","match":{"detector":["scanner-signature"]},"respondWith":"block","reason":"Test."}]');
    await page.locator("#policy-preview").click();
    await page.waitForTimeout(600);
    expect(await page.locator("#policy-result").innerText()).toContain("WOULD CHANGE");
    // Apply needs editPolicy, which this dashboard did not grant.
    expect(await page.locator("#policy-apply").isHidden()).toBe(true);
    await page.close();
  });

  it("explains every detector on the Reference screen", async () => {
    const page = await open();
    await page.getByRole("tab", { name: "Reference" }).click();
    await page.waitForTimeout(300);
    expect(await page.locator("#ref-index .ref-item").count()).toBeGreaterThan(30);
    await page.locator("#ref-filter").fill("honeytoken");
    await page.waitForTimeout(250);
    expect(await page.locator("#ref-index .ref-item").count()).toBe(1);
    await page.locator("#ref-index .ref-item").click();
    await page.waitForTimeout(250);
    expect(await page.locator("#ref-article h2").innerText()).toBe("honeytoken");
    expect(await page.locator("#ref-article .ref-body").innerText()).toContain("How it is recognised");
    await page.close();
  });

  it("remembers the colour scheme across a reload", async () => {
    const page = await open();
    const scheme = (): Promise<string | null> => page.evaluate(() => document.documentElement.getAttribute("data-theme"));
    await page.locator("#theme").click();
    const chosen = await scheme();
    expect(["light", "dark"]).toContain(chosen);
    await page.reload();
    await page.waitForSelector("tbody tr.row", { state: "attached" });
    expect(await scheme()).toBe(chosen);
    await page.close();
  });

  it("fits a phone without scrolling sideways", async () => {
    const page = await open(390);
    for (const tab of ["Overview", "Incidents", "Statistics", "Reference"]) {
      await page.getByRole("tab", { name: new RegExp(`^${tab}`) }).click();
      await page.waitForTimeout(400);
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
      expect(overflow, `${tab} overflows at 390px`).toBe(false);
    }
    await page.close();
  });

  it("has no serious accessibility violations on any screen", async () => {
    const page = await open();
    const found: string[] = [];
    for (const tab of ["Overview", "Incidents", "Statistics", "Sessions", "Actors", "Threat intel", "Policy", "Reference"]) {
      await page.getByRole("tab", { name: new RegExp(`^${tab}`) }).click();
      await page.waitForTimeout(500);
      await page.evaluate(axeSource);
      const violations = await page.evaluate(async () => {
        const result = await (globalThis as unknown as { axe: { run: (context: unknown, options: unknown) => Promise<{ violations: Array<{ id: string; impact: string | null; nodes: unknown[] }> }> } }).axe.run(document, {
          runOnly: { type: "tag", values: ["wcag2a", "wcag2aa"] },
        });
        return result.violations.filter((violation) => violation.impact === "serious" || violation.impact === "critical").map((violation) => `${violation.id} (${violation.nodes.length})`);
      });
      for (const violation of violations) found.push(`${tab}: ${violation}`);
    }
    expect(found).toEqual([]);
    await page.close();
  });
});
