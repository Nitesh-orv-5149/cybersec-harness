// Small dependency-free SVG charts. Mark specs follow the dataviz method: bars <=24px with a 4px
// rounded data-end (square at the baseline), 2px surface gaps between stacked segments, 2px lines,
// >=8px markers with a 2px surface ring, hairline recessive grid, hover tooltip on every chart,
// a legend for >=2 series, and a table view for every chart.
import { type ReactNode, useLayoutEffect, useRef, useState } from 'react';

/** Categorical slots (validated dark-mode steps: blue, orange, aqua). Never cycled. */
export const SERIES = ['#3987e5', '#d95926', '#199e70'];
/** Severity is a status, not a series: fixed status steps, always shown with a text label. */
export const SEVERITY_COLOR: Record<string, string> = { high: '#d03b3b', medium: '#ec835a', low: '#fab219', info: '#8e8e93', unknown: '#48484a' };
export const SEVERITY_ORDER = ['high', 'medium', 'low', 'info', 'unknown'];
const SURFACE = '#26262c';
const GRID = 'rgba(255, 255, 255, 0.08)';

export interface Series { key: string; label: string; color: string }

function useWidth<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const [w, setW] = useState(0);
  useLayoutEffect(() => {
    if (!ref.current) return;
    setW(Math.floor(ref.current.getBoundingClientRect().width));
    const ro = new ResizeObserver(([e]) => setW(Math.floor(e.contentRect.width)));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, w] as const;
}

/** Round the axis max up to 1/2/5 × 10ⁿ so ticks land on clean numbers. */
function niceScale(max: number, ticks = 4) {
  if (max <= 0) return { max: 1, step: 1 };
  const raw = max / ticks;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 5, 10].map((m) => m * mag).find((s) => s >= raw)!;
  const stepInt = Math.max(1, Math.round(step)); // counts are integers
  return { max: Math.ceil(max / stepInt) * stepInt, step: stepInt };
}
const compact = (n: number) => (n >= 1000 ? `${(n / 1000).toFixed(n >= 10000 ? 0 : 1)}K` : String(n));

function topRounded(x: number, y: number, w: number, h: number) {
  const r = Math.min(4, h, w / 2);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}
function rightRounded(x: number, y: number, w: number, h: number) {
  const r = Math.min(4, w, h / 2);
  return `M${x},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h - r}Q${x + w},${y + h} ${x + w - r},${y + h}H${x}Z`;
}

export function Legend({ series, values }: { series: Series[]; values?: Record<string, number | string> }) {
  return (
    <ul className="legend">
      {series.map((s) => (
        <li key={s.key}><i style={{ background: s.color }} />{s.label}{values && values[s.key] !== undefined && <b>{values[s.key]}</b>}</li>
      ))}
    </ul>
  );
}

interface Tip { x: number; y: number; title: string; rows: { label: string; value: ReactNode; color?: string }[] }
function Tooltip({ tip }: { tip: Tip | null }) {
  if (!tip) return null;
  return (
    <div className="chart-tip" style={{ left: tip.x, top: tip.y }} role="status">
      <div className="chart-tip-title">{tip.title}</div>
      {tip.rows.map((r) => (
        <div key={r.label} className="chart-tip-row">{r.color && <i style={{ background: r.color }} />}<span>{r.label}</span><b>{r.value}</b></div>
      ))}
    </div>
  );
}

/** Card frame with a Chart/Table switch so no value is gated behind hover or color. */
export function ChartCard({ title, sub, table, children, wide, action }: {
  title: string; sub?: string; wide?: boolean; action?: ReactNode;
  table: { head: string[]; rows: (string | number)[][] }; children: ReactNode;
}) {
  const [asTable, setAsTable] = useState(false);
  return (
    <section className={`chart-card${wide ? ' wide' : ''}`}>
      <header className="chart-head">
        <div><h3>{title}</h3>{sub && <p className="chart-sub">{sub}</p>}</div>
        <div className="row">
          {action}
          <div className="seg" role="group" aria-label="View as">
            <button aria-pressed={!asTable} onClick={() => setAsTable(false)}>Chart</button>
            <button aria-pressed={asTable} onClick={() => setAsTable(true)}>Table</button>
          </div>
        </div>
      </header>
      {asTable ? (
        <div className="chart-table"><table className="tbl"><thead><tr>{table.head.map((h) => <th key={h}>{h}</th>)}</tr></thead>
          <tbody>{table.rows.map((r, i) => <tr key={i}>{r.map((c, j) => <td key={j}>{c}</td>)}</tr>)}</tbody></table></div>
      ) : children}
    </section>
  );
}

/** Horizontal (optionally stacked) bars: one row per category. */
export function HBars({ rows, series, onSelect }: {
  rows: { key: string; label: string; values: Record<string, number> }[]; series: Series[]; onSelect?: (key: string) => void;
}) {
  const [ref, w] = useWidth<HTMLDivElement>();
  const [tip, setTip] = useState<Tip | null>(null);
  const [hover, setHover] = useState<string | null>(null);
  const labelW = Math.min(150, Math.max(90, w * 0.32));
  const valueW = 36;
  const band = 34, bar = 18;
  const plotW = Math.max(40, w - labelW - valueW - 8);
  const totals = rows.map((r) => series.reduce((a, s) => a + (r.values[s.key] ?? 0), 0));
  const { max } = niceScale(Math.max(1, ...totals));
  const h = rows.length * band + 4;
  return (
    <div ref={ref} className="chart">
      {w > 0 && (
        <svg width={w} height={h} role="img" aria-label={rows.map((r, i) => `${r.label}: ${totals[i]}`).join(', ')}>
          <line x1={labelW} x2={labelW} y1={0} y2={h} stroke={GRID} />
          {rows.map((r, i) => {
            const y = i * band + (band - bar) / 2;
            let x = labelW;
            const segs = series.filter((s) => (r.values[s.key] ?? 0) > 0);
            const active = hover === r.key;
            return (
              <g key={r.key} opacity={hover && !active ? 0.45 : 1} style={{ transition: 'opacity 150ms' }}>
                <text x={labelW - 10} y={y + bar / 2} dy="0.35em" textAnchor="end" className="chart-label">{r.label.length > 22 ? `${r.label.slice(0, 21)}…` : r.label}</text>
                {segs.map((s, si) => {
                  const segW = ((r.values[s.key] ?? 0) / max) * plotW;
                  const last = si === segs.length - 1;
                  const drawW = Math.max(1, last ? segW : segW - 2); // 2px surface gap between segments
                  const d = last ? rightRounded(x, y, drawW, bar) : `M${x},${y}h${drawW}v${bar}h${-drawW}Z`;
                  x += segW;
                  return <path key={s.key} d={d} fill={s.color} />;
                })}
                <text x={labelW + (totals[i] / max) * plotW + 6} y={y + bar / 2} dy="0.35em" className="chart-value">{totals[i]}</text>
                <rect x={0} y={i * band} width={w} height={band} fill="transparent" style={{ cursor: onSelect ? 'pointer' : 'default' }}
                  onMouseEnter={() => setHover(r.key)}
                  onMouseMove={(e) => {
                    const box = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect();
                    setTip({ x: e.clientX - box.left + 12, y: e.clientY - box.top + 12, title: r.label,
                      rows: [...segs.map((s) => ({ label: s.label, value: r.values[s.key], color: s.color })), ...(segs.length > 1 ? [{ label: 'Total', value: totals[i] }] : [])] });
                  }}
                  onMouseLeave={() => { setHover(null); setTip(null); }}
                  onClick={() => onSelect?.(r.key)} />
              </g>
            );
          })}
        </svg>
      )}
      <Tooltip tip={tip} />
      {series.length > 1 && <Legend series={series} />}
    </div>
  );
}

/** Vertical stacked columns over time buckets. */
export function Columns({ buckets, series, height = 190 }: {
  buckets: { key: string; tick: string; title: string; values: Record<string, number> }[]; series: Series[]; height?: number;
}) {
  const [ref, w] = useWidth<HTMLDivElement>();
  const [tip, setTip] = useState<Tip | null>(null);
  const [hover, setHover] = useState<number | null>(null);
  const m = { l: 30, r: 6, t: 8, b: 22 };
  const plotW = Math.max(40, w - m.l - m.r), plotH = height - m.t - m.b;
  const totals = buckets.map((b) => series.reduce((a, s) => a + (b.values[s.key] ?? 0), 0));
  const { max, step } = niceScale(Math.max(1, ...totals));
  const bandW = plotW / Math.max(1, buckets.length);
  const barW = Math.max(3, Math.min(24, bandW * 0.68));
  const yOf = (v: number) => m.t + plotH - (v / max) * plotH;
  const tickEvery = Math.ceil(buckets.length / Math.max(1, Math.floor(plotW / 70)));
  return (
    <div ref={ref} className="chart">
      {w > 0 && (
        <svg width={w} height={height} role="img" aria-label={`${buckets.length} buckets, total ${totals.reduce((a, b) => a + b, 0)}`}>
          {Array.from({ length: max / step + 1 }, (_, i) => i * step).map((v) => (
            <g key={v}>
              <line x1={m.l} x2={w - m.r} y1={yOf(v)} y2={yOf(v)} stroke={GRID} />
              <text x={m.l - 6} y={yOf(v)} dy="0.35em" textAnchor="end" className="chart-axis">{compact(v)}</text>
            </g>
          ))}
          {hover !== null && <rect x={m.l + hover * bandW} y={m.t} width={bandW} height={plotH} fill="rgba(255, 255, 255, 0.05)" rx={4} />}
          {buckets.map((b, i) => {
            const x = m.l + i * bandW + (bandW - barW) / 2;
            let cum = 0;
            const segs = series.filter((s) => (b.values[s.key] ?? 0) > 0);
            return (
              <g key={b.key}>
                {segs.map((s, si) => {
                  const v = b.values[s.key];
                  const y1 = yOf(cum), y2 = yOf(cum + v);
                  cum += v;
                  const last = si === segs.length - 1;
                  const hh = Math.max(1, y1 - y2 - (last ? 0 : 2));
                  return <path key={s.key} d={last ? topRounded(x, y1 - hh, barW, hh) : `M${x},${y1 - hh}h${barW}v${hh}h${-barW}Z`} fill={s.color} />;
                })}
                {i % tickEvery === 0 && <text x={x + barW / 2} y={height - 6} textAnchor="middle" className="chart-axis">{b.tick}</text>}
                <rect x={m.l + i * bandW} y={m.t} width={bandW} height={plotH} fill="transparent"
                  onMouseMove={(e) => {
                    setHover(i);
                    const box = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect();
                    setTip({ x: Math.min(e.clientX - box.left + 12, w - 170), y: e.clientY - box.top + 12, title: b.title,
                      rows: series.map((s) => ({ label: s.label, value: b.values[s.key] ?? 0, color: s.color })) });
                  }}
                  onMouseLeave={() => { setHover(null); setTip(null); }} />
              </g>
            );
          })}
          <line x1={m.l} x2={w - m.r} y1={yOf(0)} y2={yOf(0)} stroke="rgba(255, 255, 255, 0.2)" />
        </svg>
      )}
      <Tooltip tip={tip} />
      {series.length > 1 && <Legend series={series} />}
    </div>
  );
}

/** Lines over an ordered x (e.g. analysis runs), one shared y-axis, crosshair tooltip. */
export function Lines({ points, series, height = 190 }: {
  points: { key: string; tick: string; title: string; values: Record<string, number> }[]; series: Series[]; height?: number;
}) {
  const [ref, w] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const m = { l: 34, r: 56, t: 10, b: 22 };
  const plotW = Math.max(40, w - m.l - m.r), plotH = height - m.t - m.b;
  const all = points.flatMap((p) => series.map((s) => p.values[s.key] ?? 0));
  const { max, step } = niceScale(Math.max(1, ...all));
  const xOf = (i: number) => m.l + (points.length < 2 ? plotW / 2 : (i / (points.length - 1)) * plotW);
  const yOf = (v: number) => m.t + plotH - (v / max) * plotH;
  const tickEvery = Math.ceil(points.length / Math.max(1, Math.floor(plotW / 64)));
  const lastI = points.length - 1;
  const hp = hover !== null ? points[hover] : null;
  // End labels only where they don't collide; converging lines fall back to legend + tooltip.
  const endLabel = new Set<string>();
  [...series].sort((a, b) => yOf(points[lastI]?.values[a.key] ?? 0) - yOf(points[lastI]?.values[b.key] ?? 0))
    .reduce((prevY, s) => { const y = yOf(points[lastI]?.values[s.key] ?? 0); if (y - prevY >= 14) { endLabel.add(s.key); return y; } return prevY; }, -Infinity);
  return (
    <div ref={ref} className="chart">
      {w > 0 && points.length > 0 && (
        <svg width={w} height={height} role="img" aria-label={series.map((s) => `${s.label} latest ${points[lastI].values[s.key]}`).join(', ')}
          onMouseMove={(e) => {
            const box = e.currentTarget.getBoundingClientRect();
            const i = Math.round(((e.clientX - box.left - m.l) / plotW) * (points.length - 1));
            setHover(Math.max(0, Math.min(lastI, i)));
          }}
          onMouseLeave={() => setHover(null)}>
          {Array.from({ length: max / step + 1 }, (_, i) => i * step).map((v) => (
            <g key={v}>
              <line x1={m.l} x2={w - m.r} y1={yOf(v)} y2={yOf(v)} stroke={GRID} />
              <text x={m.l - 6} y={yOf(v)} dy="0.35em" textAnchor="end" className="chart-axis">{compact(v)}</text>
            </g>
          ))}
          {points.map((p, i) => i % tickEvery === 0 && <text key={p.key} x={xOf(i)} y={height - 6} textAnchor="middle" className="chart-axis">{p.tick}</text>)}
          {series.map((s, si) => (
            <g key={s.key}>
              {si === 0 && <path d={`M${xOf(0)},${yOf(0)}${points.map((p, i) => `L${xOf(i)},${yOf(p.values[s.key] ?? 0)}`).join('')}L${xOf(lastI)},${yOf(0)}Z`} fill={s.color} opacity={0.1} />}
              <path d={points.map((p, i) => `${i ? 'L' : 'M'}${xOf(i)},${yOf(p.values[s.key] ?? 0)}`).join('')} fill="none" stroke={s.color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
              <circle cx={xOf(lastI)} cy={yOf(points[lastI].values[s.key] ?? 0)} r={4} fill={s.color} stroke={SURFACE} strokeWidth={2} />
              {endLabel.has(s.key) && <text x={xOf(lastI) + 8} y={yOf(points[lastI].values[s.key] ?? 0)} dy="0.35em" className="chart-value">{points[lastI].values[s.key]}</text>}
            </g>
          ))}
          {hp && (
            <g pointerEvents="none">
              <line x1={xOf(hover!)} x2={xOf(hover!)} y1={m.t} y2={m.t + plotH} stroke="rgba(255, 255, 255, 0.3)" />
              {series.map((s) => <circle key={s.key} cx={xOf(hover!)} cy={yOf(hp.values[s.key] ?? 0)} r={4} fill={s.color} stroke={SURFACE} strokeWidth={2} />)}
            </g>
          )}
        </svg>
      )}
      {hp && <Tooltip tip={{ x: Math.min(xOf(hover!) + 12, w - 170), y: 8, title: hp.title, rows: series.map((s) => ({ label: s.label, value: hp.values[s.key] ?? 0, color: s.color })) }} />}
      {series.length > 1 && <Legend series={series} />}
    </div>
  );
}

/** One stacked bar that shows a whole split (e.g. findings by severity), with a counted legend. */
export function Meter({ parts, label }: { parts: { key: string; label: string; value: number; color: string }[]; label: string }) {
  const total = parts.reduce((a, p) => a + p.value, 0);
  const shown = parts.filter((p) => p.value > 0);
  return (
    <div className="meter" role="img" aria-label={`${label}: ${shown.map((p) => `${p.value} ${p.label}`).join(', ') || 'none'}`}>
      <div className="meter-bar">
        {total === 0 ? <span className="meter-empty" /> : shown.map((p) => (
          <span key={p.key} style={{ flexGrow: p.value, background: p.color }} title={`${p.label}: ${p.value}`} />
        ))}
      </div>
      <Legend series={parts.map((p) => ({ key: p.key, label: p.label, color: p.color }))} values={Object.fromEntries(parts.map((p) => [p.key, p.value]))} />
    </div>
  );
}
