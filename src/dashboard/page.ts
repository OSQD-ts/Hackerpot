import { CLIENT_SCRIPT } from "./client.generated.js";
import type { DashboardBootstrap } from "./types.js";

/**
 * The dashboard page.
 *
 * Shipped as a template rather than a file on disk: a bundled library cannot assume anything
 * sits next to its JavaScript. The markup and CSS are here; the behaviour is the TypeScript
 * under `client/`, bundled into `CLIENT_SCRIPT` by `scripts/build-client.mjs`.
 *
 * Three rules, all because the page renders attacker-written text:
 *
 * 1. Nothing is assembled into HTML. Values reach the document through `textContent`; the
 *    client bundle contains no `innerHTML`, and the build refuses one.
 * 2. No `style` attributes. The CSP blocks inline styles; geometry goes through the CSSOM.
 * 3. No network access beyond the dashboard's own API: `default-src 'none'`.
 *
 * `DASHBOARD_CSS` and `DASHBOARD_MARKUP` are exported on their own so
 * `<hackerpot-dashboard>` can adopt them into a shadow root. That is why every selector that
 * would reach for the document is written `:root, :host`: `:root` matches nothing inside a
 * shadow tree, where the host element is what the tokens hang off.
 */

/**
 * The dark scheme's tokens, written once and used twice: under `prefers-color-scheme: dark`
 * (unless `data-theme="light"` says otherwise) and under an explicit `data-theme="dark"`, so
 * the theme button wins in both directions.
 *
 * The series slots are the same eight hues as the light scheme stepped for the dark surface,
 * not an automatic inversion; the sequential ramp runs the other way round (near zero recedes
 * toward the surface, which on a dark page means darker).
 */
const DARK = `
  color-scheme: dark;
  --page: #0d0f12; --panel: #16181d; --panel-2: #1b1e24; --border: #272b33; --row-line: #202329;
  --text: #f2f4f7; --text-2: #c4cad3; --muted: #8b929c; --faint: #7d838c;
  --accent: #3987e5; --accent-solid: #2364b4; --link: #86b6ef; --focus: #86b6ef;
  --ok: #3fb950; --warn: #d29922; --bad: #f85149;
  --ok-text: #4ec97a; --warn-text: #fab219; --bad-text: #ff8078; --info-text: #86b6ef; --violet-text: #b3a4f5; --payload-text: #ffd9a0;
  --ok-tint: rgba(63,185,80,.25); --bad-tint: rgba(248,81,73,.15); --bad-edge: rgba(248,81,73,.5);
  --warn-tint: rgba(210,153,34,.15); --warn-edge: rgba(210,153,34,.5); --info-tint: rgba(88,166,255,.15); --info-edge: rgba(88,166,255,.45);
  --violet-tint: rgba(163,113,247,.14); --violet-edge: rgba(163,113,247,.45);
  --header-bg: #16181d; --tabs-bg: #16181d; --tip-bg: #0d0f12; --pre-bg: #0d0f12; --detail-bg: #0d0f12;
  --hover: rgba(88,166,255,.06); --flash: rgba(245,166,35,.28); --shadow: 0 8px 26px rgba(0,0,0,.55);
  /* A panel on a dark page is separated by its own surface and border; a shadow under it
     only muddies the page. In light it does the separating, as it does in bothandlerjs. */
  --panel-shadow: none;
  --surface: #16181d; --grid: #23272e;
  --s1: #3987e5; --s2: #d95926; --s3: #199e70; --s4: #c98500; --s5: #d55181; --s6: #008300; --s7: #9085e9; --s8: #e66767; --so: #566173;
  --q0: #1b1e24; --q1: #104281; --q2: #184f95; --q3: #1c5cab; --q4: #256abf; --q5: #2a78d6; --q6: #3987e5;
  --q7: #5598e7; --q8: #6da7ec; --q9: #86b6ef; --q10: #9ec5f4; --q11: #b7d3f6; --q12: #cde2fb;
  --o1: #184f95; --o2: #256abf; --o3: #3987e5; --o4: #6da7ec; --o5: #9ec5f4;
  --meter-track: #184f95; --meter-fill: #6da7ec;
  --det-sat: 70%; --det-light: 72%;
`;

const SLOT_RULES = ["s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "so"]
  .map((s) => `.fill-${s} { fill: var(--${s}); } .stroke-${s} { stroke: var(--${s}); } .bg-${s} { background: var(--${s}); }`)
  .concat(Array.from({ length: 13 }, (_, i) => `.fill-q${i} { fill: var(--q${i}); } .bg-q${i} { background: var(--q${i}); }`))
  .concat(["o1", "o2", "o3", "o4", "o5"].map((o) => `.bg-${o} { background: var(--${o}); }`))
  .join("\n");

export const DASHBOARD_CSS = String.raw`/* ---------------------------------------------------------------------------
   Tokens.

   Light first, dark below. The categorical slots are a validated eight-hue palette,
   stepped separately for each surface: adjacent slots stay apart under the common
   colour-vision deficiencies, and every multi-series chart also carries a legend and a
   table view, so hue is never the only thing telling two things apart. Text never wears
   a series colour; the ink tokens are for text.
--------------------------------------------------------------------------- */
:root, :host {
  color-scheme: light;
  --page: #f4f5f7; --panel: #ffffff; --panel-2: #f3f4f6; --border: #e4e6ea; --row-line: #eef0f3;
  --text: #0b0d12; --text-2: #3c414b; --muted: #5f646e; --faint: #676d77;
  --accent: #2a78d6; --accent-solid: #1b5fb0; --link: #1b5fb0; --focus: #2a78d6;
  --ok: #0ca30c; --warn: #b07800; --bad: #d03b3b;
  --ok-text: #006300; --warn-text: #6d4700; --bad-text: #b02525; --info-text: #1c5cab; --violet-text: #5b34a8; --payload-text: #7a3e00;
  --ok-tint: rgba(12,163,12,.14); --bad-tint: rgba(208,59,59,.09); --bad-edge: rgba(208,59,59,.38);
  --warn-tint: rgba(201,133,0,.12); --warn-edge: rgba(201,133,0,.45); --info-tint: rgba(42,120,214,.09); --info-edge: rgba(42,120,214,.38);
  --violet-tint: rgba(91,52,168,.08); --violet-edge: rgba(91,52,168,.32);
  --header-bg: #ffffff; --tabs-bg: #fafbfc; --tip-bg: #ffffff; --pre-bg: #f6f8fa; --detail-bg: #f7f8fa;
  --hover: rgba(42,120,214,.06); --flash: rgba(237,161,0,.26); --shadow: 0 8px 26px rgba(11,13,18,.14);
  --panel-shadow: 0 1px 2px rgba(11,13,18,.06), 0 1px 8px rgba(11,13,18,.04);
  --surface: #ffffff; --grid: #eceef1;
  --s1: #2a78d6; --s2: #eb6834; --s3: #1baf7a; --s4: #eda100; --s5: #e87ba4; --s6: #008300; --s7: #4a3aa7; --s8: #e34948; --so: #8a9099;
  --q0: #eef0f3; --q1: #cde2fb; --q2: #b7d3f6; --q3: #9ec5f4; --q4: #86b6ef; --q5: #6da7ec; --q6: #5598e7;
  --q7: #3987e5; --q8: #2a78d6; --q9: #256abf; --q10: #1c5cab; --q11: #184f95; --q12: #104281;
  --o1: #86b6ef; --o2: #5598e7; --o3: #2a78d6; --o4: #1c5cab; --o5: #104281;
  --meter-track: #cde2fb; --meter-fill: #2a78d6;
  --det-sat: 55%; --det-light: 32%;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  /* bothandlerjs's token names, as aliases of these, so a rule carried over from its dashboard
     reads the same colours here without being rewritten. */
  --line: var(--border); --line-soft: var(--row-line); --ink: var(--text); --ink-2: var(--text-2);
  --surface-2: var(--panel-2); --raised: var(--panel); --good-text: var(--ok-text); --crit-text: var(--bad-text);
  --crit: var(--bad); --proven-text: var(--violet-text);
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]), :host(:not([data-theme="light"])) {${DARK}}
}
:root[data-theme="dark"], :host([data-theme="dark"]) {${DARK}}

* { box-sizing: border-box; }
[hidden] { display: none !important; }
body { margin: 0; background: var(--page); color: var(--text); font: 14px/1.55 var(--sans); -webkit-font-smoothing: antialiased; }
a { color: var(--link); }
code, .mono { font-family: var(--mono); }
.num { font-variant-numeric: tabular-nums; }
.small { font-size: 12px; }
.tiny { font-size: 11px; }
.muted { color: var(--muted); }
.faint { color: var(--faint); }
.warn-text { color: var(--warn-text); }
.breakall { word-break: break-all; white-space: pre-wrap; }
.spacer { flex: 1; }
.gap-top { margin-top: 12px; }
.gap-bottom { margin-bottom: 8px; }
:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0; }
/* Clipped rather than pushed off the top: inside <hackerpot-dashboard> "off the top" is the host
   page's own heading, and the link sat on top of it. */
.skip { position: absolute; left: 8px; top: 8px; z-index: 50; background: var(--panel); color: var(--text); padding: 6px 10px; border-radius: 6px; border: 1px solid var(--border); }
.skip:not(:focus) { width: 1px; height: 1px; padding: 0; border: 0; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }

/* --- header -------------------------------------------------------------
   Two rows, the same split bothandlerjs's dashboard uses. The first carries identity,
   connection state and everything you can press; the second carries the tab strip and, at its
   far end, the facts about this instance as plain text, so nothing that is not a control wears
   a control's border. The whole header sticks, tabs included, so there is no second sticky
   offset to measure.
------------------------------------------------------------------------- */
.hp-header {
  position: sticky; top: 0; z-index: 30; padding: 0 20px;
  background: color-mix(in srgb, var(--header-bg) 92%, transparent);
  backdrop-filter: saturate(180%) blur(8px);
  border-bottom: 1px solid var(--border);
}
.head-row { display: flex; align-items: center; gap: 10px 14px; min-height: 54px; flex-wrap: wrap; padding: 7px 0; }
.brand { display: flex; align-items: baseline; gap: 8px; min-width: 0; }
.brand h1 { font-size: 15px; font-weight: 640; letter-spacing: -.015em; margin: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.brand span { color: var(--muted); font-size: 12.5px; white-space: nowrap; }
.grow { flex: 1 1 auto; min-width: 8px; }
.links { display: flex; gap: 6px; flex-wrap: wrap; }
.linkbtn { font-size: 12.5px; padding: 6px 11px; border: 1px solid var(--border); border-radius: 8px; text-decoration: none; }
/* A hairline between "somewhere else" and "do something here". */
.head-actions { display: flex; gap: 6px; align-items: center; }
.links:not([hidden]) + .head-actions { padding-left: 12px; border-left: 1px solid var(--border); }
button[aria-pressed="true"] { background: color-mix(in srgb, var(--s1) 12%, var(--surface)); border-color: color-mix(in srgb, var(--s1) 45%, var(--line)); color: var(--ink); }

/* Status, not a control: a filled pill with no border, so it never reads as pressable. */
.status { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 520; color: var(--text-2);
  padding: 3px 10px 3px 8px; border-radius: 999px; background: color-mix(in srgb, var(--text) 5%, transparent); white-space: nowrap; }
.dot { width: 7px; height: 7px; border-radius: 50%; background: var(--faint); flex: none; }
.status.online .dot { background: var(--ok); box-shadow: 0 0 0 3px color-mix(in srgb, var(--ok) 22%, transparent); }
.status.offline .dot { background: var(--bad); box-shadow: 0 0 0 3px color-mix(in srgb, var(--bad) 20%, transparent); }
.status.auth .dot, .status.connecting .dot { background: var(--warn); }
@media (prefers-reduced-motion: reduce) { tr.flash { animation: none; } }

.nav-row { display: flex; align-items: flex-end; gap: 20px; }
.facts { display: flex; gap: 14px; flex-wrap: wrap; margin: 0 0 0 auto; padding-bottom: 9px; font-size: 11.5px; color: var(--muted); min-width: 0; }
.facts div { display: flex; gap: 4px; align-items: baseline; min-width: 0; }
.facts dd { margin: 0; font-weight: 600; color: var(--text-2); font-variant-numeric: tabular-nums; max-width: 28ch; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.facts dd.warn-text { color: var(--warn-text); }
/* Secondary by definition, so it is the first thing to go when room runs out. */
@media (max-width: 900px) { .facts { display: none; } }
@media (max-width: 560px) { .brand span { display: none; } }

/* --- tabs --------------------------------------------------------------- */
.tabs { display: flex; gap: 2px; margin-bottom: -1px; flex: none; }
.tabs [role="tab"] { background: none; border: none; border-bottom: 2px solid transparent; border-radius: 0;
  padding: 9px 12px; color: var(--muted); font-weight: 500; font-size: 13px; cursor: pointer; white-space: nowrap; }
.tabs [role="tab"]:hover { color: var(--text); background: none; }
.tabs [role="tab"][aria-selected="true"] { color: var(--text); border-bottom-color: var(--accent); }
/* Six tabs are wider than a phone. Tightened first, and past that the strip scrolls on its own
   rather than pushing the whole document sideways. */
@media (max-width: 640px) {
  .tabs { flex: 0 1 auto; min-width: 0; overflow-x: auto; scrollbar-width: none; }
  .tabs::-webkit-scrollbar { display: none; }
  .tabs [role="tab"] { padding: 9px 7px; font-size: 12.5px; flex: none; }
}
.pill { display: inline-block; margin-left: 6px; padding: 1px 7px; border-radius: 999px; font-size: 10.5px;
  border: 1px solid var(--border); color: var(--muted); font-variant-numeric: tabular-nums; }

.hp-main { padding: 28px 20px 64px; max-width: 1680px; margin: 0 auto; }
/* The width every layout below asks about, taken one level down from the window.
   Embedded in a 320px sidebar on a 1280px screen a media query reads the window, never
   fires, and the feed is squeezed to nothing beside a side column holding its minimum.
   A container query reads this box, which is the one the layout actually has. */
/* One column, stacked, with the gap between panels declared once here rather than as a
   margin on each thing that can sit in it — the same grid bothandlerjs's <main> is. */
.hp-main { display: grid; gap: 16px; align-content: start; container: dash / inline-size; }
/* A grid item's min-width is auto, so a panel wrapping a wide table refuses to shrink and
   pushes the document sideways instead. The grids below say minmax(0, ...) for the same
   reason; the panes stacked here need the same permission. */
.hp-main > * { min-width: 0; }
.toolbar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 18px; }
.toolbar label.field { display: inline-flex; gap: 6px; align-items: center; font-size: 12px; color: var(--muted); }
input, select, button { font: inherit; color: var(--text); }
input[type="text"], input[type="number"], select {
  font: inherit; font-size: 12.5px; padding: 5px 9px; border-radius: 7px;
  border: 1px solid var(--line); background: var(--surface); color: var(--ink); min-width: 0;
}
select { cursor: pointer; }
input[type="search"] {
  font: inherit; font-size: 12.5px; padding: 5px 10px; min-width: 180px; flex: 1 1 180px;
  border: 1px solid var(--line); border-radius: 8px; background: var(--surface-2); color: var(--ink);
}
input::placeholder { color: color-mix(in srgb, var(--muted) 80%, transparent); }
input[type="search"]::placeholder { color: var(--muted); }
input[type=text], input[type=search] { width: 150px; }
input:focus, select:focus { border-color: var(--link); }
button { font: inherit; font-size: 12.5px; line-height: 1.4; padding: 6px 11px; border-radius: 8px;
  border: 1px solid var(--border); background: var(--panel); color: var(--text-2);
  cursor: pointer; white-space: nowrap; }
button:hover { background: var(--panel-2); color: var(--text); border-color: color-mix(in srgb, var(--text) 22%, var(--border)); }
button.sm { padding: 4px 10px; font-size: 12px; }
/* One button per panel may be the one you came for. bothandlerjs marks the same ones. */
/* A solid of its own rather than --accent: white on the accent itself measures 3.6:1,
   which is under the floor for text this size. bothandlerjs carries the same token. */
button.primary { background: var(--accent-solid); border-color: var(--accent-solid); color: #fff; font-weight: 560; }
button.primary:hover { background: color-mix(in srgb, var(--accent-solid) 86%, #000); border-color: transparent; color: #fff; }
/* Prose inside a panel: the legend below the feed, and anywhere a screen has to say what
   the reader is looking at rather than count it. */
.note { padding: 13px 15px; font-size: 12.5px; color: var(--text-2); }
.note p { margin: 0 0 9px; }
.note p:last-child { margin: 0; }
.note b { color: var(--text); }
/* The legend names the edge colours, so it has to wear them. The lighter *-text tokens
   rather than the edge hues themselves: three of the four are borders, sized for a 3px
   line rather than for reading a word in. */
.lg-decoy { color: var(--info-text); }
.lg-time-cost { color: var(--warn-text); }
.lg-block { color: var(--bad-text); }
.lg-protocol-capture { color: var(--payload-text); }
/* A choice of one, as a row of pills: bothandlerjs's range chips. */
.seg { display: inline-flex; gap: 4px; flex-wrap: wrap; }
.seg button { font-size: 11px; padding: 2px 8px; border-radius: 999px; color: var(--ink-2); }
.seg button[aria-pressed="true"] { background: color-mix(in srgb, var(--s1) 14%, var(--surface)); border-color: color-mix(in srgb, var(--s1) 50%, var(--line)); color: var(--ink); font-weight: 560; }
.switch { display: inline-flex; align-items: center; gap: 8px; user-select: none; cursor: pointer; font-weight: 500; font-size: 12.5px; position: relative; }
.switch input { position: absolute; opacity: 0; width: 40px; height: 22px; margin: 0; cursor: pointer; }
.track { width: 40px; height: 22px; border-radius: 20px; background: var(--panel-2); border: 1px solid var(--border); position: relative; transition: background .15s; flex: none; }
.track::after { content: ""; position: absolute; top: 2px; left: 2px; width: 16px; height: 16px; border-radius: 50%; background: var(--faint); transition: transform .15s, background .15s; }
.switch input:checked + .track { background: var(--ok-tint); border-color: var(--ok); }
.switch input:checked + .track::after { transform: translateX(18px); background: var(--ok); }
.switch input:focus-visible + .track { outline: 2px solid var(--focus); outline-offset: 2px; }

.banner { padding: 11px 15px; border-radius: 8px; margin-bottom: 18px; font-size: 13px; display: flex; gap: 8px 12px; flex-wrap: wrap; align-items: baseline; }
.banner.err { background: var(--bad-tint); border: 1px solid var(--bad-edge); color: var(--bad-text); }
.banner.warn { background: var(--warn-tint); border: 1px solid var(--warn-edge); color: var(--warn-text); }
.banner ul { margin: 0; padding-left: 18px; flex-basis: 100%; }
.banner .grow { flex: 1; }

/* --- tiles -------------------------------------------------------------- */
/* The same tiles the other screens draw, at the same spacing — wider only because a
   statistic's label is a phrase where a counter's is a word. */
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(178px, 1fr)); gap: 10px; margin-bottom: 16px; }
/* The number first, then what it counts — bothandlerjs's tile. Reordered here rather than in the
   markup, because the label still reads first to a screen reader, which is the right way round
   for somebody who cannot glance at the number. */
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 8px 12px 9px; min-width: 0; display: flex; flex-direction: column; }
.card .value { order: 1; }
.card .label { order: 2; margin-top: 2px; }
.card .sub { order: 3; }
.card .spark { order: 4; }
.card .label { font-size: 10.5px; text-transform: uppercase; letter-spacing: .055em; color: var(--muted); font-weight: 560; }
.card .value { font-size: 21px; font-weight: 620; letter-spacing: -.025em; line-height: 1.15; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.card .value.small { font-size: 17px; font-family: var(--mono); }
.card .sub { font-size: 11px; color: var(--muted); margin-top: 1px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.card .spark { margin-top: 8px; height: 26px; }
.hero { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 18px 20px;
  display: flex; align-items: center; gap: 26px; flex-wrap: wrap; margin-bottom: 14px; }
.hero .big { font-size: 48px; font-weight: 620; letter-spacing: -.03em; line-height: 1; }
.hero .caption { font-size: 10.5px; color: var(--muted); text-transform: uppercase; letter-spacing: .055em; font-weight: 560; }
.hero .facts-row { display: flex; gap: 26px; flex-wrap: wrap; margin-left: auto; }
.hero .k { font-size: 10.5px; text-transform: uppercase; letter-spacing: .055em; color: var(--muted); font-weight: 560; }
.hero .v { font-size: 15px; font-weight: 600; font-variant-numeric: tabular-nums; }

/* --- panels ------------------------------------------------------------- */
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 18px; }
.grid3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-bottom: 18px; }
@container dash (max-width: 1080px) { .grid3 { grid-template-columns: 1fr 1fr; } }
@container dash (max-width: 780px) { .grid2, .grid3 { grid-template-columns: 1fr; } }
/* The page's own gutters are the window's business, not the column's. */
@media (max-width: 780px) { .hp-header, .hp-main { padding-left: 16px; padding-right: 16px; } }
.panel { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 16px 18px; min-width: 0; box-shadow: var(--panel-shadow); }
.panel.wide { margin-bottom: 14px; }
.panel h3 { margin: 0 0 4px; font-size: 11.5px; text-transform: uppercase; letter-spacing: .055em; color: var(--muted); font-weight: 620; display: flex; align-items: center; gap: 8px; }
.panel h3 .hint { font-weight: 400; text-transform: none; letter-spacing: 0; color: var(--muted); font-size: 11.5px; margin-left: auto; }
/* A panel that opens with its title gets bothandlerjs's header strip: the title and whatever
   describes its scope on one ruled line, the content below it. A panel without a title (an
   actor card, a session) keeps plain padding. */
.panel:has(> h3:first-child) { padding: 0; overflow: clip; }
.panel > h3:first-child { margin: 0; padding: 9px 14px; border-bottom: 1px solid var(--border); gap: 10px; }
.panel:has(> h3:first-child) > :not(h3) { margin: 12px 15px 14px; }
.panel .sub, .sub { font-size: 12px; color: var(--muted); margin: 0 0 12px; }
.sec-title { margin: 26px 0 12px; font-size: 12px; font-weight: 620; text-transform: uppercase; letter-spacing: .055em; display: flex; align-items: baseline; gap: 10px; }
.sec-title span { font-weight: 400; font-size: 12.5px; text-transform: none; letter-spacing: 0; color: var(--muted); }
.tabletoggle { margin-left: auto; flex: none; font-weight: 400; text-transform: none; letter-spacing: 0; font-size: 11px; color: var(--muted); background: none; border: none; padding: 0; }
.tabletoggle:hover { color: var(--link); }
.panel h3 .hint ~ .tabletoggle { margin-left: 10px; }
.datatable { margin-top: 12px; }
.datatable table, table.plain { font-size: 12px; }
.datatable td, .datatable th { padding: 5px 9px; }
.datatable thead th { background: transparent; }
.scrollx { overflow-x: auto; }
.nodata { font-size: 12px; color: var(--faint); padding: 14px 0; }
.empty { text-align: center; padding: 44px; color: var(--faint); }
.foot { margin: 20px 4px; color: var(--faint); font-size: 12px; }

/* --- bars and charts ------------------------------------------------------ */
/* The name sits inside a tinted track, the same bar bothandlerjs draws. The fill is the series
   hue at low opacity so the name over it keeps its contrast, in either scheme. */
.bars { display: grid; gap: 8px; padding: 12px 15px 14px; }
.panel:has(> h3:first-child) > .bars { margin: 0; }
/* A note brings its own padding, the same padding bothandlerjs gives it. */
.panel:has(> h3:first-child) > .note { margin: 0; }
.barrow { display: grid; grid-template-columns: minmax(0, 1fr) 46px; gap: 10px; align-items: center; font-size: 12.5px; }
.barrow .bar { position: relative; height: 20px; border-radius: 6px; overflow: hidden; background: color-mix(in srgb, var(--text) 5%, transparent); }
.barrow .bar > span { position: absolute; inset: 0 auto 0 0; border-radius: 0 5px 5px 0; opacity: .3; }
.barrow .name { position: relative; padding: 0 8px; line-height: 20px; font-size: 12.5px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.barrow .n { text-align: right; font-variant-numeric: tabular-nums; color: var(--ink-2); font-size: 12px; }
.barrow .n em { font-style: normal; color: var(--faint); font-size: 11px; }
.chart { width: 100%; display: block; overflow: visible; }
.chart .gridline { stroke: var(--grid); stroke-width: 1; shape-rendering: crispEdges; }
.chart .axis { fill: var(--faint); font-size: 10px; font-family: var(--sans); }
.chart .axis.mono { font-family: var(--mono); }
.chart .area { fill-opacity: .10; }
.chart .line { fill: none; stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }
.chart .ring { stroke: var(--surface); stroke-width: 2; }
.chart .hit { fill: transparent; cursor: crosshair; }
.chart .cross { stroke: var(--faint); stroke-width: 1; opacity: 0; pointer-events: none; }
.chart .mark { stroke: var(--violet-text); stroke-width: 1.5; stroke-dasharray: 3 2; opacity: .55; }
.chart .mark:hover { opacity: 1; }
.chart .marker { opacity: 0; pointer-events: none; }
.chart .cross.on, .chart .marker.on { opacity: 1; }
.heat .cell { stroke: var(--surface); stroke-width: 2; }
.heat .cell:hover { stroke: var(--text); }
.spark-svg { display: block; }
.spark-area { fill-opacity: .12; }
.spark-line { fill: none; stroke-width: 1.5; stroke-linejoin: round; }
.legend { display: flex; gap: 14px; flex-wrap: wrap; margin-top: 10px; font-size: 12px; color: var(--ink-2); }
.legend .key { display: inline-flex; align-items: center; gap: 6px; }
.sw { display: inline-block; width: 10px; height: 10px; border-radius: 3px; flex: none; vertical-align: middle; margin-right: 4px; }
.stackbar { display: flex; height: 26px; border-radius: 5px; overflow: hidden; background: var(--panel-2); gap: 2px; }
.stackbar > div { min-width: 2px; }
.stack-gap { margin-top: 14px; }
.scale { display: flex; align-items: center; gap: 8px; margin-top: 10px; font-size: 10px; color: var(--faint); }
.scale .ramp { display: flex; height: 9px; border-radius: 2px; overflow: hidden; width: 130px; }
.scale .ramp i { flex: 1; }
.scale-note { margin-left: 6px; }
.meter-head { display: flex; align-items: baseline; gap: 10px; margin-bottom: 8px; }
.meter-value { font-size: 34px; font-weight: 620; letter-spacing: -.025em; line-height: 1; }
.meter-track { height: 10px; border-radius: 5px; background: var(--meter-track); overflow: hidden; }
.meter-fill { height: 100%; background: var(--meter-fill); border-radius: 0 4px 4px 0; }
.meter-note { margin: 9px 0 0; }
.stage { margin-bottom: 10px; }
.stage-head { display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px; }
.stage-track { height: 14px; border-radius: 2px; background: var(--panel-2); }
.stage-fill { height: 100%; border-radius: 0 4px 4px 0; }
.kv { display: grid; grid-template-columns: auto 1fr; gap: 4px 14px; font-size: 12px; margin: 0; }
.kv dt { color: var(--muted); }
.kv dt.help { cursor: help; text-decoration: underline dotted var(--faint); }
.kv dd { margin: 0; font-variant-numeric: tabular-nums; }
.cadence-facts { margin-top: 12px; }

#tip { position: fixed; z-index: 100; pointer-events: none; opacity: 0; transition: opacity .08s; left: 0; top: 0;
  background: var(--tip-bg); color: var(--text); border: 1px solid var(--border); border-radius: 8px; padding: 8px 11px;
  font-size: 12px; max-width: 340px; box-shadow: var(--shadow); overflow-wrap: anywhere; }
#tip.on { opacity: 1; }
#tip .t { font-weight: 700; margin-bottom: 3px; }
#tip .r { color: var(--muted); font-variant-numeric: tabular-nums; }
#tip .r b { color: var(--text); font-weight: 600; }

/* --- tables ------------------------------------------------------------- */
/* Separate borders rather than collapsed, so a sticky header keeps its bottom border —
   collapsing hands that border to the table, which does not travel with the cell. Every
   border here is a bottom border on the cell plus the left accent on td.edge, so nothing
   is shared between two cells and separating merges or doubles nothing. bothandlerjs's
   tables are built the same way, for the same reason. */
table { width: 100%; border-collapse: separate; border-spacing: 0; }
.tablewrap { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; box-shadow: var(--panel-shadow); }
.tablewrap.scroll { overflow-x: auto; }
thead th { text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: var(--muted);
  padding: 9px 15px; background: var(--panel); border-bottom: 1px solid var(--border); white-space: nowrap; font-weight: 600; }
tbody td, tbody th { padding: 7px 14px; border-bottom: 1px solid var(--row-line); font-size: 13px; vertical-align: middle; text-align: left; }
td.r, th.r { text-align: right; font-variant-numeric: tabular-nums; }
/* Narrow, quiet, and never the reason a row wraps: the time is for scanning down, not for
   reading across. The date sits above the time rather than beside it, because one line of
   "13-09-2026 09:14:02.128" pushes the path column into wrapping, and a feed that retains a
   week cannot be read as "today" without it. */
tbody td.when { white-space: nowrap; font-family: var(--mono); font-size: 11.5px; color: var(--muted); width: 1%; padding-right: 4px; }
/* The date is the quieter of the two lines because the time is what gets read; quieter here
   means the muted ink the column already uses, not that ink dimmed further — a second 28% off
   it lands under the contrast floor, which is a real "cannot read this" rather than a taste. */
tbody td.when .when-date { display: block; }
tbody td.when .when-time { display: block; color: var(--text-2); }

/* --- the incident feed ----------------------------------------------------
   Laid out as bothandlerjs lays out its live feed: the table and its filters in one panel,
   and beside it what the rows on screen add up to. Each row reads as a request — method and
   path, then who sent it — with a coloured left edge for what the honeypot did about it, so
   a column of blocks or of tarpits can be seen before a single badge is read.
------------------------------------------------------------------------- */
.feed-layout { display: grid; gap: 16px; grid-template-columns: minmax(0, 1.9fr) minmax(280px, 1fr); align-items: start; }
@container dash (max-width: 1080px) { .feed-layout { grid-template-columns: minmax(0, 1fr); } }
/* What the feed table has to fit inside is this panel, not the window: at a 1400px
   viewport the panel is about 880px wide beside its side column, so a viewport breakpoint
   at 980px never fires and the right-hand columns are clipped on an ordinary desktop. The
   rungs are further down, after the table's own rules — a container query adds no
   specificity, so one written above them would lose. */
.feed-panel { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; min-width: 0; box-shadow: var(--panel-shadow); container: feed / inline-size; }
.feed-head { margin: 0; padding: 9px 14px; font-size: 11.5px; font-weight: 620; color: var(--muted); text-transform: uppercase; letter-spacing: .055em;
  border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 10px; }
.feed-head .hint { margin-left: auto; font-weight: 400; text-transform: none; letter-spacing: 0; font-size: 11.5px; }
.feed-panel .toolbar { margin: 0; padding: 10px 15px; border-bottom: 1px solid var(--line); }
.feed-panel .toolbar + .toolbar { padding-top: 0; margin-top: -1px; border-top: 0; }
.feed-panel .toolbar:has(+ .toolbar) { border-bottom: 0; }
/* One click narrows the feed to what the honeypot did — bothandlerjs's outcome chips. */
.filters { display: flex; gap: 5px; flex-wrap: wrap; }
.filters button { font-size: 11.5px; padding: 3px 10px; border-radius: 999px; }
/* The slash shortcut, shown inside the box it focuses, as bothandlerjs shows it. */
/* ---- the feed toolbar, carried over from bothandlerjs's dashboard rule for rule ---------- */
.search { position: relative; display: flex; flex: 1 1 180px; min-width: 180px; }
.search input[type="search"] { flex: 1 1 auto; width: auto; padding-right: 26px; }
.search kbd {
  position: absolute; right: 7px; top: 50%; transform: translateY(-50%);
  font: 500 10.5px/1 var(--mono); color: var(--muted); background: color-mix(in srgb, var(--ink) 6%, transparent);
  border: 1px solid var(--line); border-radius: 4px; padding: 3px 5px; pointer-events: none;
}
.search input[type="search"]:focus + kbd, .search input[type="search"]:not(:placeholder-shown) + kbd { display: none; }
.suggest {
  position: absolute; top: calc(100% + 4px); left: 0; z-index: 30; margin: 0; padding: 4px;
  list-style: none; min-width: 220px; max-height: 260px; overflow-y: auto;
  background: var(--surface); border: 1px solid var(--line); border-radius: 9px; box-shadow: var(--shadow);
}
.suggest li { padding: 4px 9px; border-radius: 6px; cursor: pointer; font-size: 12px; font-family: var(--mono); }
.suggest li[aria-selected="true"] { background: color-mix(in srgb, var(--focus) 18%, transparent); }
.saved { display: flex; align-items: center; gap: 6px; }
.saved input.saved-name { width: 18ch; flex: 0 0 auto; font: inherit; font-size: 12px; padding: 4px 8px; }
.saved-confirm { border-color: var(--accent); color: var(--accent); }
.timeframe { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; font-size: 11.5px; color: var(--muted); }
.retention { border-left: 1px solid var(--line); padding-left: 10px; }
.retention select { font-size: 11.5px; }
.timeframe label { display: inline-flex; align-items: center; gap: 4px; }
.timeframe input { font: inherit; font-size: 11.5px; padding: 2px 5px; border-radius: 6px; border: 1px solid var(--line); background: var(--surface); color: var(--ink); }
.timeframe button, .saved button { font: inherit; font-size: 11.5px; padding: 3px 9px; border-radius: 7px; border: 1px solid var(--line); background: var(--surface); color: var(--ink); cursor: pointer; }
.saved select { font: inherit; font-size: 11.5px; padding: 3px 6px; border-radius: 7px; border: 1px solid var(--line); background: var(--surface); color: var(--ink); max-width: 170px; }
.saved button:hover { border-color: var(--focus); }
.arrange { display: flex; gap: 6px; align-items: center; }
.arrange label { font-size: 11.5px; color: var(--muted); }
.arrange select { font-size: 12px; padding: 4px 6px; }
tbody tr.grp th {
  text-align: left; padding: 4px 10px 4px 6px; font-size: 11.5px; font-weight: 650; text-transform: none; letter-spacing: 0;
  color: var(--ink-2); background: color-mix(in srgb, var(--ink) 4%, transparent);
  border-top: 1px solid var(--line); border-bottom: 1px solid var(--line-soft);
}
tbody tr.grp:first-child th { border-top: 0; }
.grp-toggle { display: inline-flex; align-items: baseline; gap: 8px; border: 0; background: none; border-radius: 6px; padding: 4px 8px; font: inherit; font-weight: 650; color: var(--ink-2); text-align: left; }
.grp-toggle:hover { background: color-mix(in srgb, var(--ink) 6%, transparent); color: var(--ink); border-color: transparent; }
.grp-toggle .chev { color: var(--muted); width: 9px; display: inline-block; }
.grp-only { border: 0; background: none; padding: 3px 8px; font-size: 11px; color: var(--muted); border-radius: 6px; opacity: 0; }
tr.grp:hover .grp-only, .grp-only:focus-visible { opacity: 1; }
.grp-only:hover { background: color-mix(in srgb, var(--s1) 14%, transparent); color: var(--ink); border-color: transparent; }
.grp-key { font-family: var(--mono); }
.grp-n { color: var(--muted); font-weight: 400; font-variant-numeric: tabular-nums; }
.pager { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; padding: 9px 2px 2px; font-size: 12px; color: var(--muted); }
.pager button { font: inherit; padding: 4px 11px; border-radius: 7px; border: 1px solid var(--line); background: var(--surface); color: var(--ink); cursor: pointer; }
.pager button:hover:not(:disabled) { border-color: var(--focus); }
.pager button:disabled { opacity: .45; cursor: default; }
.pager .where { font-variant-numeric: tabular-nums; }
.pager.pager-inline { padding: 0; margin-left: auto; gap: 8px; }
.pager.pager-inline .size { margin-left: 0; }
.pager.pager-bottom { padding: 10px 14px; border-top: 1px solid var(--line); }
.pager .step { min-width: 30px; font-size: 15px; line-height: 1; padding: 3px 8px 5px; }
.pager .size { display: flex; align-items: center; gap: 6px; margin-left: auto; }
.pager .size select { font: inherit; padding: 3px 6px; border-radius: 6px; border: 1px solid var(--line); background: var(--surface); color: var(--ink); }
.toasts { position: fixed; right: 18px; bottom: 18px; z-index: 60; display: grid; gap: 8px; max-width: 380px; }
.toast { background: var(--raised); border: 1px solid var(--line); border-left: 3px solid var(--s1); border-radius: 9px; padding: 10px 12px; font-size: 12.5px; box-shadow: 0 6px 22px rgba(0,0,0,.18); animation: toast-in .16s ease-out; }
.toast.ok { border-left-color: var(--good-text); }
.toast.bad { border-left-color: var(--crit-text); }
.toast.warn { border-left-color: var(--warn-text); }
.toast b { display: block; margin-bottom: 2px; }
.toast span { color: var(--muted); }
@keyframes toast-in { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }
@media (prefers-reduced-motion: reduce) { .toast { animation: none; } }
.feed-side { display: grid; gap: 16px; min-width: 0; }
/* Sessions, Actors and Indicators sit in the same frame as the feed, the way bothandlerjs frames
   its actor registry: a ruled title with a count, then what the list is, then the list. */
.panel-note { margin: 0; padding: 10px 14px; font-size: 12.5px; color: var(--text-2); border-bottom: 1px solid var(--border); }
.list-body { padding: 12px 14px 2px; }
/* The policy editor: a box of rules, what pressing Preview said about them, and the two buttons. */
#policy-rules { display: block; width: 100%; resize: vertical; min-height: 220px; font: 12.5px/1.55 var(--mono); color: var(--text);
  background: var(--panel-2); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; }
#policy-rules:focus { border-color: var(--link); }
.policy-actions { display: flex; align-items: center; gap: 8px; margin: 10px 0 4px; }
#policy-apply { border-color: color-mix(in srgb, var(--s1) 45%, var(--border)); color: var(--text); }
#policy-result:not(:empty) { margin: 12px 0 14px; display: grid; gap: 12px; }
#policy-result p { margin: 0; }
.policy-summary { display: flex; gap: 22px; flex-wrap: wrap; }
.policy-stat .v { font-size: 21px; font-weight: 620; letter-spacing: -.025em; font-variant-numeric: tabular-nums; }
.policy-stat .k { font-size: 10.5px; color: var(--muted); text-transform: uppercase; letter-spacing: .055em; font-weight: 560; }
/* The reference: the same cards an opened incident uses, one per detector and per action. */
/* The Reference screen, laid out as bothandlerjs lays its own out: an index of every name
   on the left, one entry open on the right. The article is set for reading rather than
   scanning — a longer measure, a larger size and more leading than the panels around it,
   because it is the one place on the page somebody reads paragraphs. */
.policy-layout { display: grid; gap: 16px; grid-template-columns: minmax(0, 1fr) minmax(300px, 400px); align-items: start; }
.policy-layout > * { min-width: 0; }
.policy-side { display: grid; gap: 16px; align-content: start; }
@container dash (max-width: 1080px) { .policy-layout { grid-template-columns: minmax(0, 1fr); } }
/* A note that trails what it explains rather than introducing it. */
.note.aside { font-size: 11.5px; color: var(--muted); padding-top: 0; }
.ref-layout { display: grid; gap: 16px; grid-template-columns: minmax(230px, 300px) minmax(0, 1fr); align-items: start; }
@container dash (max-width: 820px) { .ref-layout { grid-template-columns: minmax(0, 1fr); } }
.ref-search { padding: 10px 15px; border-bottom: 1px solid var(--line-soft); }
.ref-search input { width: 100%; box-sizing: border-box; }
#ref-index { max-height: min(72vh, 900px); overflow: auto; padding-bottom: 8px; }
@container dash (max-width: 820px) { #ref-index { max-height: 40vh; } }
.ref-group h3 { margin: 12px 15px 4px; font-size: 10.5px; font-weight: 650; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); }
.ref-group ul { list-style: none; margin: 0; padding: 0; }
.ref-none { padding: 5px 15px; font-size: 12px; color: var(--muted); }
.ref-item {
  display: flex; align-items: center; gap: 8px; width: 100%; border: 0; border-radius: 0; background: none;
  padding: 5px 15px; text-align: left; font-size: 12px; color: var(--ink-2);
}
.ref-item:hover { background: var(--surface-2); border-color: transparent; }
.ref-item[aria-current="true"] { background: color-mix(in srgb, var(--s1) 12%, var(--surface)); color: var(--ink); box-shadow: inset 2px 0 0 var(--s1); }
.ref-id { font-family: var(--mono); flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; }
.ref-tag { font-size: 10.5px; color: var(--good-text); }
.ref-article header { padding: 18px 22px 14px; border-bottom: 1px solid var(--line-soft); }
.ref-kicker { font-size: 10.5px; font-weight: 650; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); margin-bottom: 4px; }
.ref-article h2 { margin: 0; font-size: 19px; font-weight: 650; color: var(--ink); }
.ref-article h2:focus { outline: none; }
.ref-lede { margin: 8px 0 0; color: var(--ink-2); font-size: 13px; }
.ref-facts { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; margin-top: 10px; }
.ref-fact { font-size: 11px; padding: 2px 9px; border-radius: 999px; background: color-mix(in srgb, var(--ink) 7%, transparent); color: var(--ink-2); }
.ref-fact.on { background: color-mix(in srgb, var(--good-text) 14%, transparent); color: var(--good-text); }
.ref-fact.off { color: var(--muted); }
.ref-body { padding: 6px 22px 18px; font-size: 13.5px; line-height: 1.65; color: var(--ink); max-width: 80ch; }
.ref-body p { margin: 11px 0; }
.ref-body h3 { margin: 22px 0 4px; font-size: 13.5px; font-weight: 650; }
/* A name elsewhere on the page that opens its entry here. Dotted rather than solid so a
   screen full of them still reads as data first. */
.ref-link {
  display: inline; border: 0; border-bottom: 1px dotted color-mix(in srgb, currentColor 55%, transparent); border-radius: 0;
  background: none; padding: 0; margin: 0; font: inherit; line-height: inherit; color: inherit; white-space: inherit; text-align: inherit; cursor: pointer;
}
.ref-link:hover { background: none; color: var(--ink); border-color: transparent transparent currentColor; }
/* The counter strip bothandlerjs keeps above its views, rule for rule. */
.tiles { display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(136px, 1fr)); }
.tile { background: var(--surface); border: 1px solid var(--line); border-radius: 10px; padding: 8px 12px 9px; }
.tile .v { font-size: 21px; font-weight: 620; letter-spacing: -.025em; line-height: 1.15; font-variant-numeric: tabular-nums; }
.tile .k { font-size: 10.5px; color: var(--muted); text-transform: uppercase; letter-spacing: .055em; margin-top: 2px; font-weight: 560; }
.tile .s { font-size: 11px; color: var(--muted); margin-top: 1px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.tile.good .v { color: var(--good-text); }
.tile.warn .v { color: var(--warn-text); }
.tile.crit .v { color: var(--crit-text); }
.tile.proven .v { color: var(--proven-text); }
.list-body .panel.session { background: var(--page); }
.feed-panel .tablewrap { border: 0; border-radius: 0; }
/* Under the page header, which is sticky too: scrolling a long feed keeps the column names.
   The literal is the fallback for the instant before the header is measured. */
table.feed thead th { position: sticky; top: var(--header-h, 91px); z-index: 2; }
@container dash (max-width: 1080px) { .feed-side { grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); } }
table.feed tbody td { vertical-align: top; }
table.feed td.edge { border-left: 3px solid transparent; padding-left: 12px; }
tr.c-block td.edge { border-left-color: var(--bad); }
tr.c-time-cost td.edge { border-left-color: var(--s2); }
tr.c-decoy td.edge { border-left-color: var(--s1); }
tr.c-protocol-capture td.edge { border-left-color: var(--s4); }
/* max-width: 0 lets the column take the room left over and still clip what does not fit,
   rather than a long User-Agent widening the whole table. */
table.feed td.req { width: 36%; max-width: 0; }
table.feed td.score, table.feed td.when { white-space: nowrap; }
table.feed td:nth-child(3) { min-width: 240px; }
/* The column ladder, the same one bothandlerjs's feed climbs down and for the same reasons.
   Three things go, in the order that costs least. First the detectors, which are one tap away
   in the row's detail and are the column a narrow panel can most afford to lose. Then the
   date above the time, because rows on a panel that narrow are all recent. Then the request's
   second line stops ellipsing and wraps, which is what actually buys the room: the cap on that
   one line is most of what the table cannot go below.
   The thresholds are in ch, not pixels, because what the columns need is set by the width of a
   glyph. A pixel breakpoint is only correct for the font it was measured on, and is off by
   whatever the next machine's default face differs by. */
@container feed (max-width: 112ch) {
  table.feed th:nth-child(3), table.feed td:nth-child(3) { display: none; }
  table.feed td.req { width: auto; max-width: none; min-width: 200px; }
}
@container feed (max-width: 92ch) {
  tbody td.when .when-date { display: none; }
}
@container feed (max-width: 76ch) {
  .req-line { flex-wrap: wrap; }
  .req-line .path { white-space: normal; word-break: break-all; }
  .req-sub { white-space: normal; word-break: break-word; }
}
/* The disclosure for a row.
   The whole row used to carry the state and the keys, with the actor link inside it — a control
   nested in a control, which leaves a screen reader with two things to announce and no way to
   say which one Enter belongs to, and which ARIA allows only in a treegrid. The row still opens
   on click, because that is a convenience rather than a role; the keyboard gets this, which is
   one control with one name and one job. */
.row-toggle {
  border: 0; background: none; padding: 0; margin: 0; border-radius: 4px;
  font: inherit; font-size: 12.5px; color: inherit; text-align: left; cursor: pointer; width: 100%;
}
.row-toggle:hover { background: none; color: inherit; border-color: transparent; }
.req-line { display: flex; gap: 8px; align-items: baseline; min-width: 0; font-family: var(--mono); }
.req-line .path { max-width: none; flex: 1 1 auto; min-width: 0; }
.req-sub { font-size: 11.5px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-top: 1px; }
.req-sub .ip { color: var(--text-2); }
.req-sub .actor { color: var(--violet-text); font-weight: 600; }
#tester textarea { display: block; width: 100%; margin-top: 8px; resize: vertical; min-height: 84px; font: 12px/1.5 var(--mono); color: var(--text);
  background: var(--panel-2); border: 1px solid var(--border); border-radius: 8px; padding: 8px 10px; }
#tester textarea:focus { border-color: var(--link); }
.test-actions { display: flex; justify-content: flex-end; align-items: center; gap: 10px; margin-top: 8px; }
#test-result:not(:empty) { margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border); display: grid; gap: 8px; }
#test-result p { margin: 0; }
.test-verdict { display: flex; align-items: baseline; gap: 4px; flex-wrap: wrap; }
.test-detection .small { margin-top: 3px; color: var(--text-2); }
tbody tr.row { cursor: pointer; }
tbody tr.row:hover, tbody tr.row:focus-within { background: var(--hover); }
/* An open row keeps a tint of its own: the detail below it is long, and "which row is this"
   is the question a reader has halfway down it. */
tbody tr.row.open { background: color-mix(in srgb, var(--s1) 7%, transparent); }
tbody tr.row .row-toggle:focus-visible { outline-offset: -1px; }
tbody tr.detail > td { background: var(--detail-bg); padding: 0; }
tr.flash { animation: flash 1.1s ease-out; }
@keyframes flash { 0% { background: var(--flash); } 100% { background: transparent; } }
.sortbtn { background: none; border: none; padding: 0; font: inherit; color: inherit; text-transform: inherit; letter-spacing: inherit; font-weight: 600; }
.sortbtn:hover { color: var(--text); }
.sortbtn .arrow { color: var(--accent); }
.sparkcell { width: 130px; }
.score-total { color: var(--faint); font-weight: 400; }

/* --- incident detail --------------------------------------------------------- */
.detail-inner { padding: 16px 18px; }
.detail-inner pre, .metrics-raw { margin: 0; background: var(--pre-bg); border: 1px solid var(--border); border-radius: 8px; padding: 12px; overflow: auto; font-size: 12px; max-height: 320px; }
.metrics-raw { max-height: 420px; }
.explain-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
@container dash (max-width: 820px) { .explain-grid { grid-template-columns: 1fr; } }
.explain-col > h4, .decode > h4 { margin: 0 0 9px; font-size: 11px; text-transform: uppercase; letter-spacing: .6px; color: var(--muted); font-weight: 600; }
.ex-card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 12px 14px; margin-bottom: 10px; }
.ex-card.shadow { border-style: dashed; }
.ex-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 9px; }
.ex-reason { font-size: 12px; overflow-wrap: anywhere; }
.ex-score { margin-left: auto; font-family: var(--mono); font-size: 11px; color: var(--faint); }
.ex-line { display: flex; gap: 9px; margin: 5px 0; font-size: 12px; line-height: 1.5; }
.ex-k { flex: 0 0 80px; color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: .5px; padding-top: 2px; }
.ex-v { flex: 1; color: var(--text-2); min-width: 0; }
.ex-v b { color: var(--text); }
details.raw { margin-top: 12px; }
.ex-actions { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 14px; }
.ex-foot { margin-top: 12px; padding-top: 10px; border-top: 1px solid var(--border); font-size: 11.5px; color: var(--muted); font-variant-numeric: tabular-nums; }
details.raw > summary { cursor: pointer; color: var(--muted); font-size: 12px; margin-bottom: 8px; }
details.raw > summary:hover { color: var(--text); }
.actor { margin-bottom: 12px; font-size: 12px; color: var(--muted); }
code.fp { color: var(--violet-text); background: var(--violet-tint); border: 1px solid var(--violet-edge); border-radius: 6px; padding: 1px 7px; }
.decode { margin-top: 12px; }
.dec-row { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 9px 12px; margin-bottom: 8px; }
.dec-meta { display: flex; gap: 8px; align-items: center; margin-bottom: 6px; flex-wrap: wrap; }
.dec-src { font-size: 10px; text-transform: uppercase; letter-spacing: .5px; color: var(--muted); }
.dec-enc { font-family: var(--mono); font-size: 10px; padding: 1px 7px; border-radius: 20px; background: var(--info-tint); color: var(--info-text); border: 1px solid var(--info-edge); }
.detail-inner pre.dec-val { font-size: 12px; color: var(--payload-text); word-break: break-all; white-space: pre-wrap; margin: 0; background: none; border: none; padding: 0; max-height: 200px; }
.dec-raw { font-family: var(--mono); font-size: 11px; color: var(--faint); word-break: break-all; margin: 2px 0 0; }

/* --- badges ------------------------------------------------------------- */
.badge { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px; font-weight: 600;
  white-space: nowrap; background: var(--panel-2); color: var(--muted); border: 1px solid var(--border); }
.badge.det { background: hsl(var(--h, 210) 60% 55% / .14); color: hsl(var(--h, 210) var(--det-sat) var(--det-light)); border-color: hsl(var(--h, 210) 60% 55% / .45); }
.badge.rotating { background: var(--bad-tint); color: var(--bad-text); border-color: var(--bad-edge); }
.badge.ipbtn { cursor: pointer; color: var(--text); }
.badge.ipbadge { color: var(--text); }
.badges { display: inline-flex; flex-wrap: wrap; gap: 4px; }
.badges.push { margin-left: auto; }
.ip { font-family: var(--mono); }
.ip.big { font-size: 13.5px; font-weight: 600; }
.path { font-family: var(--mono); max-width: 320px; display: inline-block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: bottom; }
.method { font-family: var(--mono); font-weight: 500; font-size: 12.5px; color: var(--text-2); }
.score { font-variant-numeric: tabular-nums; font-weight: 700; }
.sev-low { color: var(--ok-text); } .sev-mid { color: var(--warn-text); } .sev-high { color: var(--bad-text); }
.resp-block { background: var(--bad-tint); color: var(--bad-text); border-color: var(--bad-edge); }
.resp-tarpit, .resp-rate-limit, .resp-chaos, .resp-gzip-bomb { background: var(--warn-tint); color: var(--warn-text); border-color: var(--warn-edge); }
.resp-decoy-content, .resp-fake-data, .resp-fake-success { background: var(--info-tint); color: var(--info-text); border-color: var(--info-edge); }
.resp-redirect { background: var(--violet-tint); color: var(--violet-text); border-color: var(--violet-edge); }

/* --- sessions, actors ----------------------------------------------------- */
.panel.session { margin-bottom: 12px; }
.session-head { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; width: 100%; background: none; border: none; padding: 0; text-align: left; font-weight: 400; }
.row-flex { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.tl-wrap { margin-top: 14px; }
.timeline { position: relative; padding-left: 18px; }
.timeline::before { content: ""; position: absolute; left: 4px; top: 4px; bottom: 4px; width: 1px; background: var(--border); }
.tl-item { position: relative; padding: 5px 0 5px 4px; font-size: 12px; display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; }
.tl-item::before { content: ""; position: absolute; left: -18px; top: 12px; width: 7px; height: 7px; border-radius: 50%; background: var(--s1); box-shadow: 0 0 0 2px var(--panel); }
.tl-item.hi::before { background: var(--bad); }
.tl-time { font-family: var(--mono); color: var(--faint); font-size: 11px; }

/* --- density ------------------------------------------------------------ */
:root[data-density="compact"] tbody td, :host([data-density="compact"]) tbody td,
:root[data-density="compact"] thead th, :host([data-density="compact"]) thead th { padding-top: 5px; padding-bottom: 5px; }
:root[data-density="compact"] .panel, :host([data-density="compact"]) .panel,
:root[data-density="compact"] .card, :host([data-density="compact"]) .card { padding: 10px 12px; }
:root[data-density="compact"] .hp-main, :host([data-density="compact"]) .hp-main { padding: 14px; }

${SLOT_RULES}
`;

export const DASHBOARD_MARKUP = String.raw`<div id="hp-app" class="hp-app">
<a class="skip" href="#hp-main">Skip to the dashboard</a>
<header class="hp-header">
  <div class="head-row">
    <div class="brand"><h1 id="hp-title">__TITLE__</h1><span>operator dashboard</span></div>
    <div id="status" class="status idle" role="status" aria-live="polite"><span class="dot" aria-hidden="true"></span><span id="status-text">loading</span></div>
    <div class="grow"></div>
    <nav class="links" id="hp-links" aria-label="Links" hidden></nav>
    <div class="head-actions">
      <button id="refresh" type="button">Refresh</button>
      <button id="theme" type="button">Theme</button>
      <button id="live" type="button" aria-pressed="false">Pause</button>
    </div>
  </div>
  <div class="nav-row">
  <div class="tabs" role="tablist" aria-label="Dashboard screens">
    <button type="button" role="tab" id="tab-overview" aria-controls="pane-overview" aria-selected="true">Overview</button>
    <button type="button" role="tab" id="tab-incidents" aria-controls="pane-incidents" aria-selected="false" tabindex="-1">Incidents<span class="pill" id="tc-incidents">0</span></button>
    <button type="button" role="tab" id="tab-statistics" aria-controls="pane-statistics" aria-selected="false" tabindex="-1">Statistics</button>
    <button type="button" role="tab" id="tab-sessions" aria-controls="pane-sessions" aria-selected="false" tabindex="-1">Sessions<span class="pill" id="tc-sessions">0</span></button>
    <button type="button" role="tab" id="tab-actors" aria-controls="pane-actors" aria-selected="false" tabindex="-1">Actors<span class="pill" id="tc-actors">0</span></button>
    <button type="button" role="tab" id="tab-intel" aria-controls="pane-intel" aria-selected="false" tabindex="-1">Threat intel<span class="pill" id="tc-ioc">0</span></button>
    <button type="button" role="tab" id="tab-policy" aria-controls="pane-policy" aria-selected="false" tabindex="-1">Policy</button>
    <button type="button" role="tab" id="tab-reference" aria-controls="pane-reference" aria-selected="false" tabindex="-1">Reference</button>
  </div>
    <dl class="facts">
      <div><dt>instance</dt><dd id="hp-instance"></dd></div>
      <div><dt>source</dt><dd id="hp-source"></dd></div>
      <div><dt>credentials</dt><dd id="hp-redaction"></dd></div>
      <div><dt>updated</dt><dd id="last-refresh">—</dd></div>
    </dl>
  </div>
</header>

<main id="hp-main" class="hp-main">
  <div class="tiles" id="tiles" aria-label="Counts" hidden></div>

  <div id="stream-notice" class="banner warn" role="status" hidden>
    <span id="stream-notice-text" class="grow"></span>
    <button id="stream-notice-reload" type="button" class="sm">Reload</button>
    <button id="stream-notice-dismiss" type="button" class="sm">Dismiss</button>
  </div>
  <div id="banner" class="banner err" role="alert" hidden><strong id="banner-title"></strong><ul id="banner-list"></ul></div>

  <section role="tabpanel" id="pane-overview" aria-labelledby="tab-overview">
    <h2 class="sr-only">Overview</h2>
    <div class="hero">
      <div>
        <div class="caption">Incidents captured</div>
        <div class="big num" id="h-total">&#8212;</div>
        <div class="faint tiny" id="h-total-sub"></div>
      </div>
      <div class="facts-row">
        <div><div class="k">Unique IPs</div><div class="v" id="h-ips">&#8212;</div></div>
        <div><div class="k">Actors</div><div class="v" id="h-actors">&#8212;</div></div>
        <div data-needs="intel"><div class="k">Active blocks</div><div class="v" id="h-blocks">&#8212;</div></div>
        <div data-needs="intel"><div class="k">Tracked IPs</div><div class="v" id="h-tracked">&#8212;</div></div>
        <div><div class="k">Detectors fired</div><div class="v" id="h-dets">&#8212;</div></div>
        <div><div class="k">Observed for</div><div class="v" id="h-span">&#8212;</div></div>
      </div>
    </div>

    <div class="cards">
      <div class="card"><div class="label">Top offender</div><div class="value small" id="c-top">&#8212;</div><div class="sub" id="c-top-sub"></div></div>
      <div class="card"><div class="label">Last seen</div><div class="value small" id="c-last">&#8212;</div><div class="sub" id="c-last-sub"></div></div>
      <div class="card"><div class="label">Peak rate</div><div class="value" id="c-peak">&#8212;</div><div class="sub" id="c-peak-sub"></div></div>
      <div class="card"><div class="label">Median score</div><div class="value" id="c-median">&#8212;</div><div class="sub" id="c-median-sub"></div></div>
      <div class="card"><div class="label">Blocked share</div><div class="value" id="c-blockshare">&#8212;</div><div class="sub" id="c-blockshare-sub"></div></div>
    </div>

    <div class="panel wide">
      <h3>Incident volume<span class="hint" id="ov-bucket"></span><button type="button" class="tabletoggle" data-table="ov-vol-table">table view</button></h3>
      <p class="sub">Every recorded hit, bucketed over the observation window. Hover for the exact count.</p>
      <div id="ov-vol"></div>
      <div class="datatable" id="ov-vol-table" hidden></div>
    </div>

    <div class="grid2">
      <div class="panel"><h3>Detections by type<button type="button" class="tabletoggle" data-table="ov-det-table">table view</button></h3>
        <p class="sub">How many incidents each detector fired on.</p>
        <div id="p-detectors"></div><div class="datatable" id="ov-det-table" hidden></div></div>
      <div class="panel"><h3>Top offenders by score<button type="button" class="tabletoggle" data-table="ov-off-table">table view</button></h3>
        <p class="sub">Cumulative suspicion score per source IP.</p>
        <div id="p-offenders"></div><div class="datatable" id="ov-off-table" hidden></div></div>
    </div>

    <div class="panel wide" data-needs="overview">
      <h3>Notices<span class="hint" id="notice-count"></span></h3>
      <p class="sub">What this honeypot has said about itself: startup warnings, settings that would quietly do nothing, and every runtime change with who made it. Held in memory for this run.</p>
      <div id="p-notices"></div>
    </div>

    <div class="grid2">
      <div class="panel"><h3>Response actions served</h3>
        <p class="sub">What the honeypot answered with: the escalation policy's output.</p>
        <div id="p-responses-mix"></div><div id="p-responses-list" class="stack-gap"></div></div>
      <div class="panel"><h3>Latest activity</h3>
        <p class="sub">The five most recent incidents. The full list is on the Incidents screen.</p>
        <div id="p-recent"></div></div>
    </div>
  </section>

  <section role="tabpanel" id="pane-incidents" aria-labelledby="tab-incidents" hidden>
    <div class="feed-layout">
    <section class="feed-panel" aria-labelledby="feed-title">
    <h2 class="feed-head"><span id="feed-title">Incidents</span><span class="hint" id="feed-summary"></span></h2>
    <div class="toolbar">
      <div class="filters" id="f-outcome" role="group" aria-label="What the honeypot did"></div>
      <div class="search">
        <input type="search" id="f-query" placeholder="ip:198.51.100.7  detector:decoy-path  -action:not-found" spellcheck="false" autocomplete="off"
               role="combobox" aria-expanded="false" aria-controls="f-suggest" aria-autocomplete="list" aria-label="Filter the incidents">
        <kbd aria-hidden="true">/</kbd>
        <ul class="suggest" id="f-suggest" role="listbox" aria-label="Filter suggestions" hidden></ul>
      </div>
      <div class="saved" id="saved-filters"></div>
      <div class="timeframe" id="timeframe">
        <label>From <input type="datetime-local" id="from-at" step="1"></label>
        <label>To <input type="datetime-local" id="to-at" step="1"></label>
        <button type="button" id="timeframe-clear" hidden>Clear</button>
      </div>
      <div class="timeframe retention">
        <label for="f-limit">Load</label>
        <select id="f-limit" title="How many of the most recent incidents to fetch. The filters above search what is loaded."></select>
      </div>
      <div class="arrange">
        <label for="feed-order">Order</label>
        <select id="feed-order">
          <option value="newest">Newest first</option>
          <option value="oldest">Oldest first</option>
          <option value="score-high">Highest score</option>
          <option value="score-low">Lowest score</option>
        </select>
        <label for="feed-group">Group</label>
        <select id="feed-group">
          <option value="none">No grouping</option>
          <option value="ip">Address</option>
          <option value="actor">Actor</option>
          <option value="detector">Detector</option>
          <option value="outcome">Outcome</option>
          <option value="path">Path</option>
        </select>
        <button id="feed-roll" type="button" aria-pressed="false" hidden>Roll up all</button>
      </div>
      <button id="f-export" type="button" title="Download every incident matching this filter as JSON Lines, which hackerpot replay reads">Export</button>
      <div class="pager pager-inline" id="feed-pager-top" hidden></div>
    </div>
    <div class="scroll">
      <table class="feed">
        <thead><tr><th scope="col">Time</th><th scope="col">Request</th><th scope="col">Detectors</th><th scope="col" class="r">Score</th><th scope="col">Response</th></tr></thead>
        <tbody id="rows"><tr><td colspan="5"><div class="empty">Loading incidents.</div></td></tr></tbody>
      </table>
    </div>
    <div class="pager pager-bottom" id="feed-pager-bottom" hidden></div>
    </section>
    <aside class="feed-side" aria-label="What the rows above contain">
      <section class="panel"><h3>Detectors firing <span class="hint" id="side-scope"></span></h3><div id="side-detectors"></div></section>
      <section class="panel"><h3>Busiest sources <span class="hint" id="side-scope-ips"></span></h3><div id="side-sources"></div></section>
      <section class="panel" id="tester" aria-labelledby="tester-title" hidden>
        <h3><span id="tester-title">Test a request</span> <span class="hint">nothing is recorded</span></h3>
        <textarea id="test-input" rows="4" spellcheck="false" autocomplete="off" aria-label="A User-Agent, a curl command, or a request line with headers" placeholder="Paste a User-Agent, a curl command, or a request with its headers"></textarea>
        <div class="test-actions"><span class="faint tiny">Ctrl+Enter</span><button id="test-run" type="button" class="primary">Try it</button></div>
        <div id="test-result" aria-live="polite"></div>
      </section>
      <section class="panel" id="feed-legend" aria-labelledby="feed-legend-title">
        <h3 id="feed-legend-title">Reading this</h3>
        <div class="note">
          <p>The <b>left edge</b> of a row is what the honeypot answered with, in the colours the badges and the
             Overview's bar already use: <b class="lg-decoy">blue</b> served a decoy, <b class="lg-time-cost">amber</b>
             spent the caller's time, <b class="lg-block">red</b> blocked it outright, and
             <b class="lg-protocol-capture">gold</b> captured a protocol session. No edge is a silent 404 — answered
             as if nothing were there.</p>
          <p>The <b>score</b> is this request's out of the address's running total, so a low number beside a high
             one is one probe from somebody already well known here.</p>
          <p>A <b>detector</b> badge names what recognised the request. Open the row for what each one saw, what
             the response did, and anything the payload was hiding behind an encoding.</p>
        </div>
      </section>
    </aside>
    </div>
    <p class="foot">Click a row, or tab to its request and press Enter, to open it. The arrow keys walk the feed from there.</p>
  </section>

  <section role="tabpanel" id="pane-statistics" aria-labelledby="tab-statistics" hidden>
    <h2 class="sr-only">Statistics</h2>
    <div class="toolbar">
      <span class="faint small" id="st-range-label">Window</span>
      <div class="seg" id="st-range" role="group" aria-labelledby="st-range-label">
        <button type="button" data-range="0" aria-pressed="true">all</button>
        <button type="button" data-range="300000" aria-pressed="false">5m</button>
        <button type="button" data-range="900000" aria-pressed="false">15m</button>
        <button type="button" data-range="3600000" aria-pressed="false">1h</button>
        <button type="button" data-range="21600000" aria-pressed="false">6h</button>
        <button type="button" data-range="86400000" aria-pressed="false">24h</button>
      </div>
      <label class="field">Protocol <select id="st-proto"><option value="">all</option></select></label>
      <div class="spacer"></div>
      <label class="switch small"><input id="st-tables" type="checkbox"><span class="track" aria-hidden="true"></span>Data tables</label>
      <span class="faint small" id="st-scope"></span>
    </div>

    <div class="cards" id="st-kpis"></div>

    <h2 class="sec-title">Volume &amp; tempo <span>when the traffic arrived, and how fast</span></h2>
    <div class="panel wide">
      <h3>Incidents over time<span class="hint" id="st-bucket"></span><button type="button" class="tabletoggle" data-table="st-vol-table">table view</button></h3>
      <p class="sub">Incident count per bucket, with the distinct source IPs active in each.</p>
      <div id="st-vol"></div>
      <div class="datatable" id="st-vol-table" hidden></div>
    </div>
    <div class="grid2">
      <div class="panel"><h3>Cumulative reach</h3>
        <p class="sub">Unique source IPs and unique actor fingerprints seen so far. A flat line means one attacker persisting; a climbing one means a widening campaign.</p>
        <div id="st-cum"></div></div>
      <div class="panel"><h3>Request cadence<span class="hint">inter-arrival gaps</span></h3>
        <p class="sub">Time between consecutive requests from the same IP. Tight, low-variance gaps are a machine; human browsing is bursty and irregular.</p>
        <div id="st-cadence-chart"></div><div id="st-cadence-facts" class="cadence-facts"></div></div>
    </div>
    <div class="panel wide">
      <h3>Activity clock<span class="hint">hour of day by day of week, local time</span><button type="button" class="tabletoggle" data-table="st-heat-table">table view</button></h3>
      <p class="sub">Where the attack traffic lands on the clock. Scanners run around the clock; a human operator has a working day.</p>
      <div id="st-heat"></div>
      <div class="datatable" id="st-heat-table" hidden></div>
    </div>

    <h2 class="sec-title">Detections <span>what fired, how often, and what fires together</span></h2>
    <div class="grid2">
      <div class="panel"><h3>Detector frequency<button type="button" class="tabletoggle" data-table="st-det-table">table view</button></h3>
        <p class="sub">Incidents each detector fired on, and the share of all incidents.</p>
        <div id="st-det"></div><div class="datatable" id="st-det-table" hidden></div></div>
      <div class="panel"><h3>Score contribution by detector</h3>
        <p class="sub">Total points each detector added. A rare high-confidence detector can outweigh a noisy one.</p>
        <div id="st-detscore"></div></div>
    </div>
    <div class="panel wide">
      <h3>Detector co-occurrence<span class="hint">how often two detectors fire on the same request</span><button type="button" class="tabletoggle" data-table="st-cooc-table">table view</button></h3>
      <p class="sub">Corroboration map. A cell is the number of incidents where both detectors fired; the diagonal is each detector's own total.</p>
      <div id="st-cooc"></div>
      <div class="datatable" id="st-cooc-table" hidden></div>
    </div>

    <h2 class="sec-title">Severity <span>how dangerous the traffic was, and how the honeypot answered</span></h2>
    <div class="grid2">
      <div class="panel"><h3>Per-incident score distribution<button type="button" class="tabletoggle" data-table="st-hist-table">table view</button></h3>
        <p class="sub">Points added by each single request. The long tail on the right is where the real exploitation attempts live.</p>
        <div id="st-hist"></div><div class="datatable" id="st-hist-table" hidden></div></div>
      <div class="panel"><h3>Score percentiles</h3>
        <p class="sub">Per-incident score and per-IP cumulative score, side by side.</p>
        <div id="st-pct"></div></div>
    </div>
    <div class="grid2">
      <div class="panel"><h3>Response mix</h3>
        <p class="sub">Share of incidents by the action served.</p>
        <div id="st-resp-mix"></div><div id="st-resp-list" class="stack-gap"></div></div>
      <div class="panel"><h3>Escalation funnel<span class="hint">by source IP</span></h3>
        <p class="sub">How far each IP got up the escalation ladder: the honeypot's policy in one picture.</p>
        <div id="st-funnel"></div></div>
    </div>

    <h2 class="sec-title">Attack surface <span>what they went after</span></h2>
    <div class="grid3">
      <div class="panel"><h3>Most-probed paths<button type="button" class="tabletoggle" data-table="st-path-table">table view</button></h3><div id="st-paths"></div><div class="datatable" id="st-path-table" hidden></div></div>
      <div class="panel"><h3>HTTP methods</h3><div id="st-methods"></div></div>
      <div class="panel"><h3>Protocol split</h3><p class="sub">HTTP against the SSH, SMTP, FTP and Telnet honeypots.</p><div id="st-protos"></div></div>
    </div>
    <div class="grid2">
      <div class="panel"><h3>Client identities<span class="hint">User-Agent</span><button type="button" class="tabletoggle" data-table="st-ua-table">table view</button></h3>
        <p class="sub">Self-declared and trivially spoofed: read it as tooling fashion, not identity.</p>
        <div id="st-uas"></div><div class="datatable" id="st-ua-table" hidden></div></div>
      <div class="panel"><h3>Request shape</h3>
        <p class="sub">Structural traits of the captured requests.</p>
        <div id="st-shape"></div></div>
    </div>

    <h2 class="sec-title">Sources <span>who the traffic came from</span></h2>
    <div class="grid3">
      <div class="panel"><h3>Address class</h3><p class="sub">Special-use classification of the source IP. A private or loopback source on a public honeypot means a proxy is leaking internal clients.</p><div id="st-cats"></div></div>
      <div class="panel"><h3>Country</h3><p class="sub">Only when a data-backed enricher is configured.</p><div id="st-countries"></div></div>
      <div class="panel"><h3>Network / ASN</h3><p class="sub">Only when a data-backed enricher is configured.</p><div id="st-asns"></div></div>
    </div>
    <div class="panel wide">
      <h3>Source IP breakdown<span class="hint">sort by any column</span></h3>
      <p class="sub">Every IP seen in the window, with its activity over the observation period.</p>
      <div id="st-iptable"></div>
    </div>

    <h2 class="sec-title">Obfuscation <span>what they tried to hide</span></h2>
    <div class="grid2">
      <div class="panel"><h3>Encoding layers observed</h3>
        <p class="sub">Encodings peeled off request values across the window: URL-, base64- and hex-encoding, often layered.</p>
        <div id="st-enc"></div></div>
      <div class="panel"><h3>Payload obfuscation rate</h3>
        <p class="sub">Share of incidents carrying at least one value that decoded to something different.</p>
        <div id="st-encrate"></div></div>
    </div>
  </section>

  <section role="tabpanel" id="pane-sessions" aria-labelledby="tab-sessions" hidden>
    <section class="feed-panel list-panel" aria-labelledby="sessions-title">
      <h2 class="feed-head"><span id="sessions-title">Sessions</span><span class="hint" id="sessions-count"></span></h2>
      <p class="panel-note">Each source IP's incidents in order: the attack as a narrative. Open a session to read its timeline.</p>
      <div id="sessions-list" class="list-body"><div class="empty">Loading sessions.</div></div>
    </section>
  </section>

  <section role="tabpanel" id="pane-actors" aria-labelledby="tab-actors" hidden>
    <section class="feed-panel list-panel" aria-labelledby="actors-title">
      <h2 class="feed-head"><span id="actors-title">Actors</span><span class="hint" id="actors-count"></span></h2>
      <p class="panel-note">Incidents grouped by <b>actor fingerprint</b> (header order and User-Agent family) instead of by IP, so one attacker rotating through addresses collapses into a single actor. Sorted by how many IPs each used.</p>
      <div id="actors-list" class="list-body"><div class="empty">Loading actors.</div></div>
    </section>
  </section>

  <section role="tabpanel" id="pane-reference" aria-labelledby="tab-reference" hidden>
    <div class="ref-layout">
      <section class="feed-panel ref-index-panel" aria-labelledby="reference-title">
        <h2 class="feed-head"><span id="reference-title">Detectors and actions</span><span class="hint" id="ref-count"></span></h2>
        <div class="ref-search"><input type="search" id="ref-filter" placeholder="Filter by name or by what it does" aria-label="Filter detectors and actions" autocomplete="off" spellcheck="false"></div>
        <nav id="ref-index" aria-label="Detectors and actions"></nav>
        <div class="note" id="ref-empty" hidden>Nothing here matches that filter.</div>
      </section>
      <article class="feed-panel ref-article" id="ref-article"></article>
    </div>
  </section>

  <section role="tabpanel" id="pane-policy" aria-labelledby="tab-policy" hidden>
    <div class="policy-layout">
      <section class="feed-panel" aria-labelledby="policy-title">
        <h2 class="feed-head"><span id="policy-title">Policy rules</span><span class="hint">the policy as data</span></h2>
        <div class="toolbar">
          <button id="policy-example" type="button">Example</button>
          <button id="policy-export" type="button" title="Download these rules as JSON">Export</button>
          <div class="spacer"></div>
          <button id="policy-preview" type="button">Preview</button>
          <button id="policy-apply" type="button" class="primary" hidden>Apply</button>
        </div>
        <p class="panel-note">Rules are read in order; the first whose match fits decides. Anything they do not match falls through to the shipped ladder. <strong>Preview replays them</strong> against the incidents this dashboard holds — nothing is recorded and the running policy is untouched until you apply.</p>
        <div class="list-body">
          <textarea id="policy-rules" rows="14" spellcheck="false" autocomplete="off" aria-label="Policy rules as JSON"></textarea>
          <div id="policy-result" aria-live="polite"></div>
        </div>
      </section>
      <div class="policy-side">
        <section class="panel" id="policy-changes-panel" aria-labelledby="policy-changes-title">
          <h3 id="policy-changes-title">Changes <span class="hint" id="policy-change-count"></span></h3>
          <div id="policy-changes"></div>
          <div class="note aside">What was replaced in this process at runtime, and by whom where the dashboard's
               authentication could say. Bounded and in memory: the durable record is the honeypot's own log.</div>
        </section>
        <section class="panel" id="policy-running-panel">
          <h3>Running now</h3>
          <div class="note aside" id="policy-running">The policy this process runs is whatever the code that built this
               honeypot passed it — a function, not a list — so it cannot be printed here. What a rule set would do
               instead is what Preview answers.</div>
        </section>
      </div>
    </div>
  </section>

  <section role="tabpanel" id="pane-intel" aria-labelledby="tab-intel" hidden>
    <section class="feed-panel" aria-labelledby="ioc-title">
    <h2 class="feed-head"><span id="ioc-title">Indicators</span><span class="hint" id="ioc-count"></span></h2>
    <div class="toolbar">
      <span class="faint small" id="ioc-min-label">Minimum score</span>
      <div class="seg" id="ioc-min" role="group" aria-labelledby="ioc-min-label">
        <button type="button" data-min="0" aria-pressed="true">0</button><button type="button" data-min="10" aria-pressed="false">10</button>
        <button type="button" data-min="25" aria-pressed="false">25</button><button type="button" data-min="50" aria-pressed="false">50</button><button type="button" data-min="100" aria-pressed="false">100</button>
      </div>
      <div class="spacer"></div>
      <button type="button" class="sm" id="ioc-copy-txt">Copy IP list</button>
      <button type="button" class="sm" id="ioc-copy-json">Copy JSON</button>
    </div>
    <div id="ioc-list"><div class="empty">Loading indicators.</div></div>
    </section>
    <div class="panel wide gap-top">
      <h3>Prometheus metrics<span class="hint">/api/metrics</span></h3>
      <p class="sub">The exposition this dashboard's source serves, verbatim.</p>
      <pre id="metrics-raw" class="metrics-raw" tabindex="0" role="group" aria-label="Prometheus exposition">&#8212;</pre>
    </div>
  </section>

  <p class="foot">Everything on this page is read from this dashboard's own API and live feed; nothing here talks to the attacker-facing honeypot. <span id="hp-version"></span></p>
</main>
<div class="toasts" id="toasts" aria-live="polite"></div>
<div id="tip" aria-hidden="true"></div>
</div>`;

/**
 * Builds the page once and returns a function stamping a per-response nonce into it. The
 * bootstrap is JSON inside a JSON string, escaped so a title containing `</script>` cannot
 * close the element.
 */
export function renderDashboardPage(bootstrap: DashboardBootstrap): (nonce: string) => string {
  const boot = escapeForScript(JSON.stringify(JSON.stringify(bootstrap)));
  // Function replacements: a string replacement would read `$&` out of the bundle or a title.
  const html = PAGE.replace("__BOOT_JSON__", () => boot)
    .replace("__CSS__", () => DASHBOARD_CSS)
    .replace("__MARKUP__", () => DASHBOARD_MARKUP)
    .replace("__SCRIPT__", () => CLIENT_SCRIPT)
    .replace(/__TITLE__/g, () => escapeHtml(bootstrap.title));
  return (nonce) => html.replace(/__NONCE__/g, () => nonce);
}

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>__TITLE__</title>
<style nonce="__NONCE__">__CSS__</style>
</head>
<body>
__MARKUP__
<script nonce="__NONCE__">window.__HACKERPOT_DASHBOARD__ = JSON.parse(__BOOT_JSON__);</script>
<script nonce="__NONCE__">__SCRIPT__</script>
</body>
</html>`;

function escapeForScript(json: string): string {
  return json.replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => `&#${character.charCodeAt(0)};`);
}
