/**
 * Canvas plots.
 *
 * Every chart here draws a MEASURED series. There is no decorative motion and
 * no idle animation anywhere in this lab: a plot changes only when the learner
 * changes something, which is the only kind of motion §2 permits.
 *
 * Accessibility. A canvas has no text nodes, so the arithmetic contrast oracle
 * cannot see inside one, and a reader using a screen reader cannot either. So
 * every chart is drawn under three rules:
 *   1. it carries `role="img"` and an `aria-label` REWRITTEN on each redraw to
 *      describe what is currently plotted, in numbers;
 *   2. the numbers it shows are always ALSO printed as text beside it (a legend
 *      entry, a readout row, or a table), so nothing is available only as a
 *      picture;
 *   3. its series colours are taken from the palette tokens chosen to clear
 *      3:1 against the plot's own background (WCAG 1.4.11), and each series is
 *      additionally distinguished in the legend by name, so no meaning rests
 *      on hue alone.
 */

export interface Series {
  readonly label: string;
  readonly colorVar: string;
  readonly values: ArrayLike<number>;
  /** Draw as vertical bars rather than a line — used for the sample scan. */
  readonly bars?: boolean;
  readonly dashed?: boolean;
}

export interface AxisSpec {
  readonly title: string;
  readonly xLabel: string;
  readonly yLabel: string;
  /** Tick label for x position i. */
  readonly xTick: (i: number) => string | null;
  readonly yMin?: number;
  readonly yMax?: number;
  /** Draw a horizontal rule at these y values (e.g. zero, or a threshold). */
  readonly rules?: readonly { y: number; label: string }[];
  /** Highlight one x position — the sample under attack, say. */
  readonly markX?: number | null;
  readonly markLabel?: string;
  /** Log-scaled x axis, for the trace-count curves. */
  readonly xValues?: readonly number[];
  readonly logX?: boolean;
}

const PAD = { top: 24, right: 18, bottom: 36, left: 58 };

function cssVar(name: string): string {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || '#ffffff';
}

/** Create a canvas already wired for accessibility. */
export function makeChart(width: number, height: number): HTMLCanvasElement {
  const c = document.createElement('canvas');
  c.className = 'chart';
  c.width = width;
  c.height = height;
  c.setAttribute('role', 'img');
  c.setAttribute('aria-label', 'Chart not yet drawn.');
  return c;
}

export function drawChart(
  canvas: HTMLCanvasElement,
  series: readonly Series[],
  axis: AxisSpec,
  ariaLabel: string
): void {
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  const w = canvas.width;
  const h = canvas.height;
  const plotW = w - PAD.left - PAD.right;
  const plotH = h - PAD.top - PAD.bottom;

  const text = cssVar('--text-dim');
  const muted = cssVar('--text-muted');
  const grid = cssVar('--border');
  const axisColor = cssVar('--control-border');

  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = cssVar('--surface-2');
  ctx.fillRect(0, 0, w, h);

  const n = Math.max(...series.map((s) => s.values.length), 1);
  let lo = axis.yMin ?? Infinity;
  let hi = axis.yMax ?? -Infinity;
  if (axis.yMin === undefined || axis.yMax === undefined) {
    for (const s of series) {
      for (let i = 0; i < s.values.length; i++) {
        const v = s.values[i];
        if (!Number.isFinite(v)) continue;
        if (axis.yMin === undefined && v < lo) lo = v;
        if (axis.yMax === undefined && v > hi) hi = v;
      }
    }
    for (const r of axis.rules ?? []) {
      if (axis.yMin === undefined && r.y < lo) lo = r.y;
      if (axis.yMax === undefined && r.y > hi) hi = r.y;
    }
  }
  if (!Number.isFinite(lo) || !Number.isFinite(hi) || lo === hi) {
    lo = lo - 1;
    hi = hi + 1;
  }
  const span = hi - lo;
  lo -= span * 0.08;
  hi += span * 0.08;

  const xValues = axis.xValues;
  // Bars sit in BANDS, lines on points. A bar chart positioned like a line
  // chart puts the first and last bars half outside the plot area, which is
  // exactly what it did before this was split out.
  const banded = series.some((s) => s.bars);
  const bandW = plotW / n;
  const xAt = (i: number): number => {
    if (banded && !axis.logX) return PAD.left + (i + 0.5) * bandW;
    if (xValues && axis.logX) {
      const a = Math.log10(Math.max(xValues[0], 1));
      const b = Math.log10(Math.max(xValues[xValues.length - 1], 10));
      const t = (Math.log10(Math.max(xValues[i], 1)) - a) / (b - a || 1);
      return PAD.left + t * plotW;
    }
    return PAD.left + (n === 1 ? plotW / 2 : (i / (n - 1)) * plotW);
  };
  const yAt = (v: number): number => PAD.top + plotH - ((v - lo) / (hi - lo)) * plotH;

  // Axes and gridlines.
  ctx.strokeStyle = grid;
  ctx.lineWidth = 1;
  ctx.font = '11px ui-monospace, Menlo, monospace';
  ctx.fillStyle = muted;
  const ticks = 4;
  for (let k = 0; k <= ticks; k++) {
    const v = lo + ((hi - lo) * k) / ticks;
    const y = Math.round(yAt(v)) + 0.5;
    ctx.beginPath();
    ctx.moveTo(PAD.left, y);
    ctx.lineTo(PAD.left + plotW, y);
    ctx.stroke();
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    ctx.fillText(formatTick(v, hi - lo), PAD.left - 6, y);
  }

  ctx.strokeStyle = axisColor;
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.moveTo(PAD.left + 0.5, PAD.top);
  ctx.lineTo(PAD.left + 0.5, PAD.top + plotH);
  ctx.lineTo(PAD.left + plotW, PAD.top + plotH);
  ctx.stroke();

  // Named horizontal rules (zero line, noise floor, ...).
  for (const r of axis.rules ?? []) {
    if (r.y < lo || r.y > hi) continue;
    const y = Math.round(yAt(r.y)) + 0.5;
    ctx.save();
    ctx.strokeStyle = axisColor;
    ctx.setLineDash([4, 4]);
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(PAD.left, y);
    ctx.lineTo(PAD.left + plotW, y);
    ctx.stroke();
    ctx.restore();
    ctx.fillStyle = muted;
    ctx.textAlign = 'left';
    ctx.textBaseline = 'bottom';
    ctx.fillText(r.label, PAD.left + 4, y - 3);
  }

  // The marked x position, drawn behind the data.
  if (axis.markX !== null && axis.markX !== undefined && axis.markX >= 0 && axis.markX < n) {
    const x = Math.round(xAt(axis.markX)) + 0.5;
    ctx.save();
    ctx.strokeStyle = cssVar('--alarm');
    ctx.setLineDash([3, 3]);
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(x, PAD.top);
    ctx.lineTo(x, PAD.top + plotH);
    ctx.stroke();
    ctx.restore();
    if (axis.markLabel) {
      ctx.fillStyle = cssVar('--alarm-text');
      ctx.textAlign = x > PAD.left + plotW * 0.6 ? 'right' : 'left';
      ctx.textBaseline = 'top';
      ctx.fillText(axis.markLabel, x + (ctx.textAlign === 'right' ? -4 : 4), PAD.top + 2);
    }
  }

  // The data.
  for (const s of series) {
    const color = cssVar(s.colorVar);
    if (s.bars) {
      ctx.fillStyle = color;
      const bw = Math.max(2, Math.min(bandW * 0.68, 56));
      for (let i = 0; i < s.values.length; i++) {
        const v = s.values[i];
        if (!Number.isFinite(v)) continue;
        const y0 = yAt(Math.max(lo, Math.min(0, hi)));
        const y1 = yAt(v);
        ctx.fillRect(xAt(i) - bw / 2, Math.min(y0, y1), bw, Math.max(1, Math.abs(y1 - y0)));
      }
      continue;
    }
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.setLineDash(s.dashed ? [6, 4] : []);
    ctx.beginPath();
    let started = false;
    for (let i = 0; i < s.values.length; i++) {
      const v = s.values[i];
      if (!Number.isFinite(v)) continue;
      const x = xAt(i);
      const y = yAt(v);
      if (started) ctx.lineTo(x, y);
      else {
        ctx.moveTo(x, y);
        started = true;
      }
    }
    ctx.stroke();
    ctx.setLineDash([]);
    if (s.values.length <= 24) {
      ctx.fillStyle = color;
      for (let i = 0; i < s.values.length; i++) {
        const v = s.values[i];
        if (!Number.isFinite(v)) continue;
        ctx.beginPath();
        ctx.arc(xAt(i), yAt(v), 3, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  }

  // X tick labels.
  ctx.fillStyle = muted;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';
  for (let i = 0; i < n; i++) {
    const t = axis.xTick(i);
    if (t === null) continue;
    ctx.fillText(t, xAt(i), PAD.top + plotH + 6);
  }

  ctx.fillStyle = text;
  ctx.textAlign = 'left';
  ctx.textBaseline = 'top';
  ctx.font = '12px system-ui, sans-serif';
  ctx.fillText(axis.title, PAD.left, 4);
  ctx.textAlign = 'right';
  ctx.fillText(axis.xLabel, PAD.left + plotW, h - 13);
  ctx.save();
  ctx.translate(11, PAD.top + plotH / 2);
  ctx.rotate(-Math.PI / 2);
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';
  ctx.fillText(axis.yLabel, 0, 0);
  ctx.restore();

  canvas.setAttribute('aria-label', ariaLabel);
}

function formatTick(v: number, span: number): string {
  if (span >= 1000) return Math.round(v).toLocaleString('en-US');
  if (span >= 10) return v.toFixed(0);
  if (span >= 1) return v.toFixed(1);
  return v.toFixed(2);
}
