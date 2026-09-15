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
  --page: #0e1116; --panel: #161b22; --panel-2: #1c2230; --border: #2a3140; --row-line: rgba(42,49,64,.55);
  --text: #e6edf3; --text-2: #c6d0dc; --muted: #8b97a7; --faint: #7d8896;
  --accent: #f5a623; --link: #58a6ff; --focus: #58a6ff;
  --ok: #3fb950; --warn: #d29922; --bad: #f85149;
  --ok-text: #3fb950; --warn-text: #f0cd7a; --bad-text: #ff9d97; --info-text: #8cc2ff; --violet-text: #c9a6ff; --payload-text: #ffd9a0;
  --ok-tint: rgba(63,185,80,.25); --bad-tint: rgba(248,81,73,.15); --bad-edge: rgba(248,81,73,.5);
  --warn-tint: rgba(210,153,34,.15); --warn-edge: rgba(210,153,34,.5); --info-tint: rgba(88,166,255,.15); --info-edge: rgba(88,166,255,.45);
  --violet-tint: rgba(163,113,247,.14); --violet-edge: rgba(163,113,247,.45);
  --header-bg: #141920; --tabs-bg: #12161d; --tip-bg: #0a0d12; --pre-bg: #0a0d12; --detail-bg: #0e1116;
  --hover: rgba(88,166,255,.06); --flash: rgba(245,166,35,.28); --shadow: 0 8px 26px rgba(0,0,0,.55);
  --surface: #161b22; --grid: #232b39;
  --s1: #3987e5; --s2: #d95926; --s3: #199e70; --s4: #c98500; --s5: #d55181; --s6: #008300; --s7: #9085e9; --s8: #e66767; --so: #566173;
  --q0: #1c2230; --q1: #104281; --q2: #184f95; --q3: #1c5cab; --q4: #256abf; --q5: #2a78d6; --q6: #3987e5;
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
  --page: #f4f5f7; --panel: #ffffff; --panel-2: #eef1f4; --border: #dde1e6; --row-line: #e9ecf0;
  --text: #0b0d12; --text-2: #3c414b; --muted: #555b65; --faint: #676d77;
  --accent: #c27c00; --link: #1b5fb0; --focus: #1b5fb0;
  --ok: #0ca30c; --warn: #b07800; --bad: #d03b3b;
  --ok-text: #006300; --warn-text: #6d4700; --bad-text: #b02525; --info-text: #1c5cab; --violet-text: #5b34a8; --payload-text: #7a3e00;
  --ok-tint: rgba(12,163,12,.14); --bad-tint: rgba(208,59,59,.09); --bad-edge: rgba(208,59,59,.38);
  --warn-tint: rgba(201,133,0,.12); --warn-edge: rgba(201,133,0,.45); --info-tint: rgba(42,120,214,.09); --info-edge: rgba(42,120,214,.38);
  --violet-tint: rgba(91,52,168,.08); --violet-edge: rgba(91,52,168,.32);
  --header-bg: #ffffff; --tabs-bg: #fafbfc; --tip-bg: #ffffff; --pre-bg: #f6f8fa; --detail-bg: #f7f8fa;
  --hover: rgba(42,120,214,.06); --flash: rgba(237,161,0,.26); --shadow: 0 8px 26px rgba(11,13,18,.14);
  --surface: #ffffff; --grid: #eceef1;
  --s1: #2a78d6; --s2: #eb6834; --s3: #1baf7a; --s4: #eda100; --s5: #e87ba4; --s6: #008300; --s7: #4a3aa7; --s8: #e34948; --so: #8a9099;
  --q0: #eef0f3; --q1: #cde2fb; --q2: #b7d3f6; --q3: #9ec5f4; --q4: #86b6ef; --q5: #6da7ec; --q6: #5598e7;
  --q7: #3987e5; --q8: #2a78d6; --q9: #256abf; --q10: #1c5cab; --q11: #184f95; --q12: #104281;
  --o1: #86b6ef; --o2: #5598e7; --o3: #2a78d6; --o4: #1c5cab; --o5: #104281;
  --meter-track: #cde2fb; --meter-fill: #2a78d6;
  --det-sat: 55%; --det-light: 32%;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]), :host(:not([data-theme="light"])) {${DARK}}
}
:root[data-theme="dark"], :host([data-theme="dark"]) {${DARK}}

* { box-sizing: border-box; }
[hidden] { display: none !important; }
body { margin: 0; background: var(--page); color: var(--text); font: 14px/1.5 var(--sans); -webkit-font-smoothing: antialiased; }
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

/* --- header ------------------------------------------------------------- */
.hp-header {
  display: flex; align-items: center; gap: 10px 18px; flex-wrap: wrap;
  padding: 12px 22px; background: var(--header-bg); border-bottom: 1px solid var(--border);
  position: sticky; top: 0; z-index: 30;
}
.brand h1 { font-size: 17px; font-weight: 700; margin: 0; letter-spacing: .2px; }
.brand small { display: block; font-size: 11px; color: var(--muted); }
.facts { display: flex; gap: 4px 18px; flex-wrap: wrap; margin: 0; font-size: 12px; }
.facts div { display: flex; gap: 6px; align-items: baseline; min-width: 0; }
.facts dt { color: var(--muted); }
.facts dd { margin: 0; font-family: var(--mono); max-width: 36ch; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.links { display: flex; gap: 6px; flex-wrap: wrap; }
.linkbtn { font-size: 12px; padding: 4px 10px; border: 1px solid var(--border); border-radius: 8px; text-decoration: none; }
.status { display: inline-flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 600;
  padding: 5px 12px; border-radius: 20px; background: var(--panel-2); white-space: nowrap; }
.dot { width: 9px; height: 9px; border-radius: 50%; background: var(--faint); }
.status.online .dot { background: var(--ok); animation: pulse 2s infinite; }
.status.offline .dot { background: var(--bad); }
.status.auth .dot { background: var(--warn); }
.status.connecting .dot { background: var(--warn); }
@keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(63,185,80,.5); } 70% { box-shadow: 0 0 0 7px rgba(63,185,80,0); } 100% { box-shadow: 0 0 0 0 rgba(63,185,80,0); } }
@media (prefers-reduced-motion: reduce) { .status.online .dot, tr.flash { animation: none; } }

/* --- tabs --------------------------------------------------------------- */
.tabs { display: flex; gap: 2px; padding: 0 22px; background: var(--tabs-bg); border-bottom: 1px solid var(--border);
  position: sticky; top: var(--header-h, 0px); z-index: 20; overflow-x: auto; }
.tabs [role="tab"] { background: none; border: none; border-bottom: 2px solid transparent; border-radius: 0;
  padding: 11px 15px; color: var(--muted); font-weight: 600; font-size: 13px; cursor: pointer; white-space: nowrap; }
.tabs [role="tab"]:hover { color: var(--text); background: var(--hover); }
.tabs [role="tab"][aria-selected="true"] { color: var(--text); border-bottom-color: var(--accent); }
.pill { display: inline-block; margin-left: 7px; padding: 0 6px; border-radius: 10px; font-size: 11px;
  background: var(--panel-2); color: var(--muted); font-variant-numeric: tabular-nums; }

.hp-main { padding: 22px; max-width: 1400px; margin: 0 auto; }
.toolbar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 18px; }
.toolbar label.field { display: inline-flex; gap: 6px; align-items: center; font-size: 12px; color: var(--muted); }
input, select, button { font: inherit; color: var(--text); }
input[type=text], input[type=search], select { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 7px 10px; }
input[type=text], input[type=search] { width: 150px; }
input:focus, select:focus { border-color: var(--link); }
button { background: var(--panel-2); border: 1px solid var(--border); border-radius: 8px; padding: 7px 14px; cursor: pointer; font-weight: 600; }
button:hover { border-color: var(--muted); }
button.sm { padding: 4px 10px; font-size: 12px; }
.seg { display: inline-flex; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
.seg button { border: none; border-radius: 0; background: none; padding: 6px 12px; font-size: 12px; color: var(--muted); }
.seg button[aria-pressed="true"] { background: var(--panel-2); color: var(--text); }
.switch { display: inline-flex; align-items: center; gap: 8px; user-select: none; cursor: pointer; font-weight: 600; font-size: 13px; position: relative; }
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
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(178px, 1fr)); gap: 14px; margin-bottom: 18px; }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 14px 16px; min-width: 0; }
.card .label { font-size: 11px; text-transform: uppercase; letter-spacing: .6px; color: var(--muted); }
.card .value { font-size: 28px; font-weight: 700; margin-top: 4px; line-height: 1.15; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.card .value.small { font-size: 17px; font-family: var(--mono); }
.card .sub { font-size: 11px; color: var(--faint); margin-top: 3px; min-height: 1.5em; }
.card .spark { margin-top: 8px; height: 26px; }
.hero { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 18px 20px;
  display: flex; align-items: center; gap: 26px; flex-wrap: wrap; margin-bottom: 14px; }
.hero .big { font-size: 52px; font-weight: 700; line-height: 1; }
.hero .caption { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .6px; }
.hero .facts-row { display: flex; gap: 26px; flex-wrap: wrap; margin-left: auto; }
.hero .k { font-size: 10px; text-transform: uppercase; letter-spacing: .6px; color: var(--muted); }
.hero .v { font-size: 15px; font-weight: 600; font-variant-numeric: tabular-nums; }

/* --- panels ------------------------------------------------------------- */
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 18px; }
.grid3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-bottom: 18px; }
@media (max-width: 1080px) { .grid3 { grid-template-columns: 1fr 1fr; } }
@media (max-width: 780px) { .grid2, .grid3 { grid-template-columns: 1fr; } .hp-header, .tabs, .hp-main { padding-left: 16px; padding-right: 16px; } }
.panel { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 16px 18px; min-width: 0; }
.panel.wide { margin-bottom: 14px; }
.panel h3 { margin: 0 0 4px; font-size: 12px; text-transform: uppercase; letter-spacing: .6px; color: var(--muted); font-weight: 600; display: flex; align-items: center; gap: 8px; }
.panel h3 .hint { font-weight: 400; text-transform: none; letter-spacing: 0; color: var(--faint); font-size: 11px; }
.panel .sub, .sub { font-size: 12px; color: var(--faint); margin: 0 0 12px; }
.sec-title { margin: 26px 0 12px; font-size: 13px; font-weight: 700; letter-spacing: .4px; display: flex; align-items: baseline; gap: 10px; }
.sec-title span { font-weight: 400; font-size: 12px; color: var(--faint); }
.sec-title::before { content: ""; width: 3px; height: 15px; background: var(--accent); border-radius: 2px; align-self: center; }
.tabletoggle { margin-left: auto; font-weight: 400; text-transform: none; letter-spacing: 0; font-size: 11px; color: var(--faint); background: none; border: none; padding: 0; }
.tabletoggle:hover { color: var(--link); }
.datatable { margin-top: 12px; }
.datatable table, table.plain { font-size: 12px; }
.datatable td, .datatable th { padding: 5px 9px; }
.datatable thead th { background: transparent; }
.scrollx { overflow-x: auto; }
.nodata { font-size: 12px; color: var(--faint); padding: 14px 0; }
.empty { text-align: center; padding: 44px; color: var(--faint); }
.foot { margin: 20px 4px; color: var(--faint); font-size: 12px; }

/* --- bars and charts ------------------------------------------------------ */
.barrow { display: flex; align-items: center; gap: 10px; margin: 7px 0; }
.barrow .name { width: 168px; font-size: 12px; font-family: var(--mono); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.barrow.wide .name { width: 260px; }
.barrow .bar { flex: 1; height: 9px; border-radius: 2px; background: var(--panel-2); overflow: hidden; min-width: 20px; }
.barrow .bar > span { display: block; height: 100%; border-radius: 0 4px 4px 0; }
.barrow .n { width: 70px; text-align: right; font-variant-numeric: tabular-nums; color: var(--muted); font-size: 12px; }
.barrow .n em { font-style: normal; color: var(--faint); font-size: 11px; }
@media (max-width: 520px) { .barrow .name, .barrow.wide .name { width: 110px; } }
.chart { width: 100%; display: block; overflow: visible; }
.chart .gridline { stroke: var(--grid); stroke-width: 1; shape-rendering: crispEdges; }
.chart .axis { fill: var(--faint); font-size: 10px; font-family: var(--sans); }
.chart .axis.mono { font-family: var(--mono); }
.chart .area { fill-opacity: .10; }
.chart .line { fill: none; stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }
.chart .ring { stroke: var(--surface); stroke-width: 2; }
.chart .hit { fill: transparent; cursor: crosshair; }
.chart .cross { stroke: var(--faint); stroke-width: 1; opacity: 0; pointer-events: none; }
.chart .marker { opacity: 0; pointer-events: none; }
.chart .cross.on, .chart .marker.on { opacity: 1; }
.heat .cell { stroke: var(--surface); stroke-width: 2; }
.heat .cell:hover { stroke: var(--text); }
.spark-svg { display: block; }
.spark-area { fill-opacity: .12; }
.spark-line { fill: none; stroke-width: 1.5; stroke-linejoin: round; }
.legend { display: flex; flex-wrap: wrap; gap: 4px 14px; margin-top: 10px; font-size: 11px; color: var(--muted); }
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
.meter-value { font-size: 34px; font-weight: 700; line-height: 1; }
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
table { width: 100%; border-collapse: collapse; }
.tablewrap { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
.tablewrap.scroll { overflow-x: auto; }
thead th { text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: .5px; color: var(--muted);
  padding: 10px 14px; background: var(--panel-2); border-bottom: 1px solid var(--border); white-space: nowrap; font-weight: 600; }
tbody td, tbody th { padding: 9px 14px; border-bottom: 1px solid var(--row-line); font-size: 13px; vertical-align: middle; text-align: left; }
td.r, th.r { text-align: right; font-variant-numeric: tabular-nums; }
td.when { white-space: nowrap; font-family: var(--mono); font-size: 12px; color: var(--faint); }
tbody tr.row { cursor: pointer; }
tbody tr.row:hover, tbody tr.row[aria-expanded="true"] { background: var(--hover); }
tbody tr.row:focus-visible { outline-offset: -2px; }
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
@media (max-width: 820px) { .explain-grid { grid-template-columns: 1fr; } }
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
.badge { display: inline-block; padding: 2px 8px; border-radius: 20px; font-size: 11px; font-weight: 600; font-family: var(--mono);
  white-space: nowrap; background: var(--panel-2); color: var(--muted); border: 1px solid var(--border); }
.badge.det { background: hsl(var(--h, 210) 60% 55% / .14); color: hsl(var(--h, 210) var(--det-sat) var(--det-light)); border-color: hsl(var(--h, 210) 60% 55% / .45); }
.badge.rotating { background: var(--bad-tint); color: var(--bad-text); border-color: var(--bad-edge); }
.badge.ipbtn { cursor: pointer; color: var(--text); }
.badge.ipbadge { color: var(--text); }
.badges { display: inline-flex; flex-wrap: wrap; gap: 4px; }
.badges.push { margin-left: auto; }
.ip { font-family: var(--mono); }
.ip.big { font-size: 15px; font-weight: 700; }
.path { font-family: var(--mono); max-width: 320px; display: inline-block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: bottom; }
.method { font-family: var(--mono); font-weight: 700; font-size: 12px; color: var(--muted); }
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
  <div class="brand"><h1 id="hp-title">__TITLE__</h1><small>HackerPot operator dashboard</small></div>
  <dl class="facts">
    <div><dt>Instance</dt><dd id="hp-instance"></dd></div>
    <div><dt>Source</dt><dd id="hp-source"></dd></div>
    <div><dt>Credentials</dt><dd id="hp-redaction"></dd></div>
  </dl>
  <div class="spacer"></div>
  <nav class="links" id="hp-links" aria-label="Links" hidden></nav>
  <div id="status" class="status idle" role="status" aria-live="polite"><span class="dot" aria-hidden="true"></span><span id="status-text">loading</span></div>
  <button id="theme" type="button" class="sm">Theme</button>
</header>

<div class="tabs" role="tablist" aria-label="Dashboard screens">
  <button type="button" role="tab" id="tab-overview" aria-controls="pane-overview" aria-selected="true">Overview</button>
  <button type="button" role="tab" id="tab-incidents" aria-controls="pane-incidents" aria-selected="false" tabindex="-1">Incidents<span class="pill" id="tc-incidents">0</span></button>
  <button type="button" role="tab" id="tab-statistics" aria-controls="pane-statistics" aria-selected="false" tabindex="-1">Statistics</button>
  <button type="button" role="tab" id="tab-sessions" aria-controls="pane-sessions" aria-selected="false" tabindex="-1">Sessions<span class="pill" id="tc-sessions">0</span></button>
  <button type="button" role="tab" id="tab-actors" aria-controls="pane-actors" aria-selected="false" tabindex="-1">Actors<span class="pill" id="tc-actors">0</span></button>
  <button type="button" role="tab" id="tab-intel" aria-controls="pane-intel" aria-selected="false" tabindex="-1">Threat intel<span class="pill" id="tc-ioc">0</span></button>
</div>

<main id="hp-main" class="hp-main">
  <div class="toolbar">
    <button id="refresh" type="button">Refresh</button>
    <label class="switch" id="live-label"><input id="live" type="checkbox" checked><span class="track" aria-hidden="true"></span>Live feed</label>
    <span class="faint small" id="last-refresh"></span>
  </div>

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
    <h2 class="sr-only">Incidents</h2>
    <div class="toolbar">
      <label class="field">Detector <select id="f-detector"></select></label>
      <label class="field">Source IP <input id="f-ip" type="text" autocomplete="off" spellcheck="false" placeholder="any"></label>
      <label class="field">Show <select id="f-limit"></select></label>
      <button id="f-clear" type="button" class="sm">Clear filter</button>
    </div>
    <div class="tablewrap scroll">
      <table>
        <thead><tr><th scope="col">Time</th><th scope="col">Source IP</th><th scope="col">Method</th><th scope="col">Path</th><th scope="col">Detectors</th><th scope="col">Score</th><th scope="col">Response</th></tr></thead>
        <tbody id="rows"><tr><td colspan="7"><div class="empty">Loading incidents.</div></td></tr></tbody>
      </table>
    </div>
    <p class="foot">Select a row (or focus it and press Enter) to see why each detector fired, what the response did, and any payload the request hid behind an encoding.</p>
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
    <h2 class="sr-only">Sessions</h2>
    <p class="foot">Each source IP's incidents in order: the attack as a narrative. Open a session to read its timeline.</p>
    <div id="sessions-list"><div class="empty">Loading sessions.</div></div>
  </section>

  <section role="tabpanel" id="pane-actors" aria-labelledby="tab-actors" hidden>
    <h2 class="sr-only">Actors</h2>
    <p class="foot">Incidents grouped by <b>actor fingerprint</b> (header order and User-Agent family) instead of by IP, so one attacker rotating through addresses collapses into a single actor. Sorted by how many IPs each used.</p>
    <div id="actors-list"><div class="empty">Loading actors.</div></div>
  </section>

  <section role="tabpanel" id="pane-intel" aria-labelledby="tab-intel" hidden>
    <h2 class="sr-only">Threat intel</h2>
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
    <div class="panel wide gap-top">
      <h3>Prometheus metrics<span class="hint">/api/metrics</span></h3>
      <p class="sub">The exposition this dashboard's source serves, verbatim.</p>
      <pre id="metrics-raw" class="metrics-raw">&#8212;</pre>
    </div>
  </section>

  <p class="foot">Everything on this page is read from this dashboard's own API and live feed; nothing here talks to the attacker-facing honeypot. <span id="hp-version"></span></p>
</main>
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
