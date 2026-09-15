import { niceScale } from "./analysis.js";
import { clear, el, nodes, svgEl, svgText } from "./dom.js";
import { fmtCompact, fmtInt, fmtPct } from "./format.js";
import { SEQUENTIAL_STEPS, sequentialStep, slot } from "./palette.js";
import { setTip, type TipPart } from "./tooltip.js";

/**
 * The chart primitives, built out of elements.
 *
 * SVG through `createElementNS`, labels through `textContent`, geometry through
 * attributes and colours through classes the theme defines. The only style the client
 * ever sets is a width or a flex share, and it sets those through the CSSOM, which the
 * page's CSP permits and a `style="..."` attribute would not be.
 *
 * Charts are drawn at their container's real pixel width so text never scales with the
 * plot, and redrawn when the window resizes or a hidden screen is shown (a hidden
 * container is zero pixels wide, so whatever was drawn into it is drawn again).
 */

type Render = (width: number) => Node[];

const charts = new Map<HTMLElement, Render>();

function paint(target: HTMLElement, render: Render): void {
  const width = Math.max(240, Math.floor(target.clientWidth || target.parentElement?.clientWidth || 600));
  clear(target);
  target.append(...render(width));
}

/** Registers a width-dependent chart and draws it. */
export function draw(target: HTMLElement, render: Render): void {
  charts.set(target, render);
  paint(target, render);
}

/** Replaces a container's content with something that does not depend on width. */
export function replace(target: HTMLElement, ...content: Node[]): void {
  charts.delete(target);
  clear(target);
  target.append(...content);
}

export function repaintVisible(): void {
  for (const [target, render] of charts) {
    if (!target.isConnected) continue;
    if (target.getClientRects().length > 0) paint(target, render);
  }
}

export function noData(message = "no data in this window"): HTMLElement {
  return el("div", "nodata", message);
}

function chartSvg(width: number, height: number, label: string, extra = ""): SVGSVGElement {
  const svg = svgEl("svg", { class: `chart ${extra}`.trim(), width, height, viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": label });
  return svg;
}

function legend(entries: ReadonlyArray<{ name: string; slot: number; note?: string }>): HTMLElement {
  const box = el("div", "legend");
  for (const entry of entries) {
    const key = el("span", "key");
    key.append(el("span", `sw bg-${slot(entry.slot)}`), entry.name);
    if (entry.note !== undefined) key.append(" ", el("span", "faint num", entry.note));
    box.append(key);
  }
  return box;
}

function gridlines(svg: SVGSVGElement, scale: { step: number; ticks: number; max: number }, left: number, right: number, y: (v: number) => number): void {
  for (let t = 0; t <= scale.ticks; t++) {
    const value = scale.step * t;
    const yy = y(value).toFixed(1);
    svg.append(svgEl("line", { class: "gridline", x1: left, y1: yy, x2: right, y2: yy }));
    svg.append(svgText({ class: "axis", x: left - 7, y: Number(yy) + 3, "text-anchor": "end" }, fmtCompact(Math.round(value * 100) / 100)));
  }
}

export interface Series {
  name: string;
  values: readonly number[];
  slot: number;
}

/**
 * Time-bucketed chart. One series is an area (a 10% wash under a 2px line); two or more
 * are lines with a legend, so identity is never colour alone. A crosshair and a marker per
 * series follow the hovered bucket, and the tooltip reads every series at once.
 */
export function timeChart(target: HTMLElement, buckets: ReadonlyArray<{ label: string; full: string }>, series: readonly Series[], options: { height?: number; label: string }): void {
  draw(target, (W) => {
    if (buckets.length === 0) return [noData()];
    const H = options.height ?? 190;
    const P = { l: 46, r: 14, t: 12, b: 24 };
    const iw = W - P.l - P.r;
    const ih = H - P.t - P.b;
    const scale = niceScale(Math.max(1, ...series.flatMap((s) => s.values)));
    const n = buckets.length;
    const x = (i: number): number => P.l + (n === 1 ? iw / 2 : (i / (n - 1)) * iw);
    const y = (v: number): number => P.t + ih - (v / scale.max) * ih;
    const svg = chartSvg(W, H, options.label);
    gridlines(svg, scale, P.l, W - P.r, y);

    for (const s of series) {
      const cls = slot(s.slot);
      const points = s.values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`);
      if (series.length === 1) {
        svg.append(svgEl("path", { class: `area fill-${cls}`, d: `M ${P.l},${P.t + ih} L ${points.join(" L ")} L ${x(n - 1).toFixed(1)},${P.t + ih} Z` }));
      }
      svg.append(svgEl("polyline", { class: `line stroke-${cls}`, points: points.join(" ") }));
      if (n === 1) svg.append(svgEl("circle", { class: `fill-${cls} ring`, cx: x(0), cy: y(s.values[0] ?? 0), r: 4 }));
    }

    const label = (i: number): void => {
      const anchor = i === 0 ? "start" : i === n - 1 ? "end" : "middle";
      svg.append(svgText({ class: "axis mono", x: x(i).toFixed(1), y: H - 7, "text-anchor": anchor }, buckets[i]?.label ?? ""));
    };
    label(0);
    if (n > 2) label(Math.floor((n - 1) / 2));
    if (n > 1) label(n - 1);

    const cross = svgEl("line", { class: "cross", x1: 0, x2: 0, y1: P.t, y2: P.t + ih });
    const markers = series.map((s) => svgEl("circle", { class: `marker ring fill-${slot(s.slot)}`, r: 4, cx: 0, cy: 0 }));
    const column = n > 1 ? iw / (n - 1) : iw;
    buckets.forEach((bucket, i) => {
      const left = Math.max(P.l, x(i) - column / 2);
      const right = Math.min(W - P.r, x(i) + column / 2);
      const hit = svgEl("rect", { class: "hit", x: left.toFixed(1), y: P.t, width: Math.max(1, right - left).toFixed(1), height: ih });
      setTip(hit, { title: bucket.full, lines: series.map((s): TipPart[] => [{ swatch: slot(s.slot) }, `${s.name} `, { strong: fmtInt(s.values[i] ?? 0) }]) });
      hit.addEventListener("pointerenter", () => {
        cross.setAttribute("x1", x(i).toFixed(1));
        cross.setAttribute("x2", x(i).toFixed(1));
        cross.classList.add("on");
        markers.forEach((marker, si) => {
          marker.setAttribute("cx", x(i).toFixed(1));
          marker.setAttribute("cy", y(series[si]?.values[i] ?? 0).toFixed(1));
          marker.classList.add("on");
        });
      });
      svg.append(hit);
    });
    svg.append(cross, ...markers);
    svg.addEventListener("pointerleave", () => {
      cross.classList.remove("on");
      for (const marker of markers) marker.classList.remove("on");
    });

    return series.length > 1 ? [svg, legend(series)] : [svg];
  });
}

export interface Column {
  label: string;
  axis: string;
  value: number;
  note?: string;
}

/** Vertical columns for a distribution, each with a 4px rounded cap and a square base. */
export function columnChart(target: HTMLElement, items: readonly Column[], options: { height?: number; unit?: string; xTitle?: string; label: string }): void {
  draw(target, (W) => {
    if (items.length === 0) return [noData()];
    const H = options.height ?? 190;
    const P = { l: 42, r: 12, t: 14, b: options.xTitle === undefined ? 22 : 34 };
    const iw = W - P.l - P.r;
    const ih = H - P.t - P.b;
    const scale = niceScale(Math.max(1, ...items.map((d) => d.value)));
    const y = (v: number): number => P.t + ih - (v / scale.max) * ih;
    const slotWidth = iw / items.length;
    const bw = Math.min(24, Math.max(3, slotWidth - 6));
    const svg = chartSvg(W, H, options.label);
    gridlines(svg, scale, P.l, W - P.r, y);
    const every = items.length <= 14 ? 1 : Math.ceil(items.length / 10);
    items.forEach((item, i) => {
      const cx = P.l + slotWidth * i + slotWidth / 2;
      const h = (item.value / scale.max) * ih;
      if (h > 0) {
        const top = P.t + ih - h;
        const r = Math.min(4, h, bw / 2);
        const l = cx - bw / 2;
        const rt = cx + bw / 2;
        const base = P.t + ih;
        svg.append(svgEl("path", { class: "fill-s1", d: `M ${l},${base} L ${l},${top + r} Q ${l},${top} ${l + r},${top} L ${rt - r},${top} Q ${rt},${top} ${rt},${top + r} L ${rt},${base} Z` }));
      }
      const hit = svgEl("rect", { class: "hit", x: (P.l + slotWidth * i).toFixed(1), y: P.t, width: slotWidth.toFixed(1), height: ih });
      const line: TipPart[] = [{ strong: fmtInt(item.value) }, ` ${options.unit ?? "incidents"}`];
      if (item.note !== undefined) line.push(` · ${item.note}`);
      setTip(hit, { title: item.label, lines: [line] });
      svg.append(hit);
      if (i % every === 0) svg.append(svgText({ class: "axis", x: cx.toFixed(1), y: H - (options.xTitle === undefined ? 7 : 18), "text-anchor": "middle" }, item.axis));
    });
    if (options.xTitle !== undefined) svg.append(svgText({ class: "axis", x: P.l + iw / 2, y: H - 3, "text-anchor": "middle" }, options.xTitle));
    return [svg];
  });
}

export interface RankedOptions {
  total?: number;
  unit?: string;
  share?: boolean;
  wide?: boolean;
  slot?: number;
  emptyText?: string;
}

/** Ranked horizontal bars: magnitude in one hue, biggest first. Width-independent, so plain HTML. */
export function rankedBars(target: HTMLElement, entries: ReadonlyArray<readonly [name: string, n: number, note?: string]>, options: RankedOptions = {}): void {
  if (entries.length === 0) {
    replace(target, noData(options.emptyText));
    return;
  }
  const total = options.total ?? entries.reduce((sum, entry) => sum + entry[1], 0);
  const max = Math.max(1, ...entries.map((entry) => entry[1]));
  const rows = entries.map(([name, n, note]) => {
    const row = el("div", options.wide === true ? "barrow wide" : "barrow");
    const label = el("div", "name", name);
    label.title = name;
    const bar = el("div", "bar");
    const fill = el("span", `bg-${slot(options.slot ?? 0)}`);
    fill.style.width = `${Math.max(1, (n / max) * 100).toFixed(2)}%`;
    bar.append(fill);
    const count = el("div", "n", fmtCompact(n));
    if (options.share !== false) count.append(" ", el("em", null, fmtPct(n, total, 0)));
    row.append(label, bar, count);
    const line: TipPart[] = [{ strong: fmtInt(n) }, ` ${options.unit ?? "incidents"}`];
    if (total) line.push(` · ${fmtPct(n, total)} of ${fmtInt(total)}`);
    setTip(row, { title: name, lines: note === undefined ? [line] : [line, [note]] });
    return row;
  });
  replace(target, ...rows);
}

/** Part-to-whole: one stacked bar with a 2px surface gap between segments, and a legend with the numbers. */
export function stackBar(target: HTMLElement, entries: ReadonlyArray<readonly [string, number]>, options: { slotFor?: (name: string, index: number) => number; emptyText?: string } = {}): void {
  const total = entries.reduce((sum, entry) => sum + entry[1], 0);
  if (!total) {
    replace(target, noData(options.emptyText));
    return;
  }
  const bar = el("div", "stackbar");
  const keys: Array<{ name: string; slot: number; note: string }> = [];
  entries.forEach(([name, n], i) => {
    const s = options.slotFor?.(name, i) ?? i;
    const segment = el("div", `bg-${slot(s)}`);
    segment.style.flex = `${n} 0 0`;
    setTip(segment, { title: name, lines: [[{ strong: fmtInt(n) }, ` · ${fmtPct(n, total)}`]] });
    bar.append(segment);
    keys.push({ name, slot: s, note: `${fmtInt(n)} · ${fmtPct(n, total, 0)}` });
  });
  replace(target, bar, legend(keys));
}

/** A sequential heat grid, one hue, with the ramp and its maximum printed underneath. */
export function heatGrid(
  target: HTMLElement,
  rows: ReadonlyArray<{ label: string }>,
  columns: ReadonlyArray<{ label: string; full?: string }>,
  get: (row: number, column: number) => number,
  options: { labelWidth?: number; cellHeight?: number; unit?: string; scaleNote?: string; label: string },
): void {
  let max = 0;
  for (let r = 0; r < rows.length; r++) for (let c = 0; c < columns.length; c++) max = Math.max(max, get(r, c));
  draw(target, (W) => {
    if (max <= 0) return [noData()];
    const L = options.labelWidth ?? 42;
    const T = 16;
    const cw = Math.max(6, (W - L - 8) / columns.length);
    const ch = options.cellHeight ?? 22;
    const H = T + rows.length * ch + 6;
    const svg = chartSvg(W, H, options.label, "heat");
    columns.forEach((column, ci) => {
      if (column.label !== "" && (columns.length <= 26 || ci % 2 === 0)) svg.append(svgText({ class: "axis", x: (L + ci * cw + cw / 2).toFixed(1), y: T - 5, "text-anchor": "middle" }, column.label));
    });
    rows.forEach((row, ri) => {
      svg.append(svgText({ class: "axis", x: L - 8, y: T + ri * ch + ch / 2 + 3, "text-anchor": "end" }, row.label));
      columns.forEach((column, ci) => {
        const value = get(ri, ci);
        const cell = svgEl("rect", { class: `cell fill-q${sequentialStep(value, max)}`, x: (L + ci * cw).toFixed(1), y: T + ri * ch, width: cw.toFixed(1), height: ch, rx: 3 });
        setTip(cell, { title: `${row.label} · ${column.full ?? column.label}`, lines: [[{ strong: fmtInt(value) }, ` ${options.unit ?? "incidents"}`]] });
        svg.append(cell);
      });
    });
    const scale = el("div", "scale");
    const ramp = el("span", "ramp");
    for (let step = 0; step <= SEQUENTIAL_STEPS; step++) ramp.append(el("i", `bg-q${step}`));
    scale.append(el("span", null, "0"), ramp, el("span", "num", fmtInt(max)));
    if (options.scaleNote !== undefined) scale.append(el("span", "scale-note", options.scaleNote));
    return [svg, scale];
  });
}

/** A tiny inline trend: no axes, no labels, for a tile or a table cell. */
export function sparkline(values: readonly number[], width: number, height: number, slotIndex = 0): SVGSVGElement {
  const svg = svgEl("svg", { class: "spark-svg", width, height, viewBox: `0 0 ${width} ${height}`, "aria-hidden": "true" });
  if (values.length === 0) return svg;
  const max = Math.max(1, ...values);
  const x = (i: number): number => (values.length === 1 ? width / 2 : (i / (values.length - 1)) * width);
  const y = (v: number): number => height - 1 - (v / max) * (height - 2);
  const points = values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`);
  const cls = slot(slotIndex);
  svg.append(svgEl("path", { class: `spark-area fill-${cls}`, d: `M 0,${height} L ${points.join(" L ")} L ${width},${height} Z` }));
  svg.append(svgEl("polyline", { class: `spark-line stroke-${cls}`, points: points.join(" ") }));
  return svg;
}

export interface Fact {
  key: string;
  value: ReadonlyArray<Node | string>;
  help?: string;
}

/** A key/value list: the right form when the data is a handful of numbers. */
export function factList(target: HTMLElement, facts: readonly Fact[]): void {
  const list = el("dl", "kv");
  for (const fact of facts) {
    const term = el("dt", fact.help === undefined ? null : "help", fact.key);
    if (fact.help !== undefined) {
      term.title = fact.help;
      setTip(term, { title: fact.key, lines: [[fact.help]] });
    }
    const value = el("dd");
    value.append(...nodes(fact.value));
    list.append(term, value);
  }
  replace(target, list);
}

/** The table under a chart, so nothing on the page is gated behind colour or a pointer. */
export function dataTable(target: HTMLElement | null, headers: readonly string[], rows: ReadonlyArray<ReadonlyArray<Node | string>>): void {
  if (target === null) return;
  if (rows.length === 0) {
    replace(target);
    return;
  }
  const table = el("table");
  const head = el("thead");
  const headRow = el("tr");
  headers.forEach((header, i) => {
    const th = el("th", i === 0 ? null : "r", header);
    th.scope = "col";
    headRow.append(th);
  });
  head.append(headRow);
  const body = el("tbody");
  for (const row of rows) {
    const tr = el("tr");
    row.forEach((cell, i) => {
      const td = el("td", i === 0 ? null : "r num");
      td.append(...nodes([cell]));
      tr.append(td);
    });
    body.append(tr);
  }
  table.append(head, body);
  const wrap = el("div", "scrollx");
  wrap.append(table);
  replace(target, wrap);
}

/** One ratio against its whole: a meter, not a two-slice pie. */
export function meter(target: HTMLElement, value: number, total: number, options: { unit?: string; note?: string } = {}): void {
  const head = el("div", "meter-head");
  head.append(el("div", "meter-value num", fmtPct(value, total, 1)), el("div", "faint small", `${fmtInt(value)} of ${fmtInt(total)} ${options.unit ?? "incidents"}`));
  const track = el("div", "meter-track");
  const fill = el("div", "meter-fill");
  fill.style.width = `${total ? ((value / total) * 100).toFixed(2) : "0"}%`;
  track.append(fill);
  track.setAttribute("role", "meter");
  track.setAttribute("aria-valuemin", "0");
  track.setAttribute("aria-valuemax", String(total));
  track.setAttribute("aria-valuenow", String(value));
  const content: Node[] = [head, track];
  if (options.note !== undefined) content.push(el("p", "sub meter-note", options.note));
  replace(target, ...content);
}
