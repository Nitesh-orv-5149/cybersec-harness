import { useEffect, useMemo, useState } from 'react';
import type { Ctx } from '../App';
import { api, SOURCE_NAME, timeAgo, TOOL_LABEL, type Finding } from '../api';
import { ChartCard, Columns, HBars, Lines, Meter, SERIES, SEVERITY_COLOR, SEVERITY_ORDER, type Series } from '../charts';

const SEV_SERIES: Series[] = SEVERITY_ORDER.slice(0, 4).map((k) => ({ key: k, label: k, color: SEVERITY_COLOR[k] }));
const hourLabel = (d: Date) => d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });

export function OverviewView({ ctx, goFindings }: { ctx: Ctx; goFindings: () => void }) {
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [history, setHistory] = useState<any>(null);
  const [tools, setTools] = useState<{ tool: string; area: string; state: string }[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.get<Finding[]>(`/api/projects/${ctx.projectId}/findings`).then((f) => { setFindings(f); setErr(null); }).catch((e) => setErr(e.message));
  }, [ctx.projectId, ctx.ticks.findings]);
  useEffect(() => {
    api.get<any>(`/api/projects/${ctx.projectId}/history`).then(setHistory).catch(() => setHistory(null));
  }, [ctx.projectId, ctx.ticks.history]);
  useEffect(() => {
    Promise.all([
      api.get<any[]>(`/api/projects/${ctx.projectId}/security/scanners`).catch(() => []),
      api.get<any[]>(`/api/projects/${ctx.projectId}/security/kinds`).catch(() => []),
    ]).then(([deps, kinds]) => setTools([
      ...deps.map((s) => ({ tool: s.tool, area: 'Dependency scan', state: s.state })),
      ...kinds.flatMap((k) => (k.tools ?? k.readiness ?? []).map((t: any) => ({ tool: t.tool, area: k.label, state: t.state }))),
    ]));
  }, [ctx.projectId]);

  const open = useMemo(() => (findings ?? []).filter((f) => f.status === 'open'), [findings]);
  const sevCount = useMemo(() => Object.fromEntries(SEVERITY_ORDER.map((s) => [s, open.filter((f) => f.severity === s).length])), [open]);
  const resolved = (findings ?? []).filter((f) => f.status === 'resolved').length;

  const bySource = useMemo(() => {
    const m = new Map<string, Record<string, number>>();
    for (const f of open) { const r = m.get(f.source) ?? {}; r[f.severity] = (r[f.severity] ?? 0) + 1; m.set(f.source, r); }
    return [...m.entries()].map(([k, values]) => ({ key: k, label: SOURCE_NAME[k] ?? k, values }))
      .sort((a, b) => Object.values(b.values).reduce((x, y) => x + y, 0) - Object.values(a.values).reduce((x, y) => x + y, 0));
  }, [open]);

  // 24 hourly buckets ending now (UTC-aligned to match the server's grouping), so quiet hours show as zero.
  const activity = useMemo(() => {
    const byHour = new Map<number, any>((history?.summary?.activity ?? []).map((a: any) => [new Date(a._id).getTime(), a]));
    const now = new Date(); now.setUTCMinutes(0, 0, 0);
    return Array.from({ length: 24 }, (_, i) => {
      const d = new Date(now.getTime() - (23 - i) * 3600_000);
      const a = byHour.get(d.getTime());
      return { key: String(d.getTime()), tick: hourLabel(d), title: d.toLocaleString([], { weekday: 'short', hour: 'numeric', minute: '2-digit' }),
        values: { ok: (a?.events ?? 0) - (a?.failed ?? 0), failed: a?.failed ?? 0 } };
    });
  }, [history]);

  const growth = useMemo(() => (history?.analysisRuns ?? []).filter((r: any) => r.summary).slice().reverse().slice(-30)
    .map((r: any, i: number) => ({ key: r._id, tick: `#${i + 1}`, title: `${new Date(r.startedAt).toLocaleString()} · ${r.trigger}`,
      values: { nodes: r.summary.nodes, edges: r.summary.edges } })), [history]);

  if (err) return <div className="empty"><h2>Overview unavailable</h2><p>{err}</p></div>;
  if (!findings) return <div className="empty muted">Loading…</div>;

  const readyTools = (tools ?? []).filter((t) => t.state === 'ready').length;
  const activitySeries: Series[] = [{ key: 'ok', label: 'Analysed', color: SERIES[0] }, { key: 'failed', label: 'Failed', color: SEVERITY_COLOR.high }];
  const growthSeries: Series[] = [{ key: 'nodes', label: 'Nodes', color: SERIES[0] }, { key: 'edges', label: 'Edges', color: SERIES[1] }];
  const g = ctx.graph?.graph;

  return (
    <div className="scroll">
      <div className="overview">
        <section className="hero glass">
          <div className="hero-main">
            <span className="eyebrow">Security posture · {ctx.status.name}</span>
            <div className="hero-figure">{open.length}</div>
            <p className="hero-sub">open findings{sevCount.high ? <> · <b className="t-bad">{sevCount.high} high severity</b></> : ' · none high severity'}</p>
            <Meter label="Open findings by severity" parts={SEVERITY_ORDER.slice(0, 4).map((k) => ({ key: k, label: k, value: sevCount[k] ?? 0, color: SEVERITY_COLOR[k] }))} />
            <button className="btn primary" onClick={goFindings}>Review findings</button>
          </div>
          <div className="hero-tiles">
            <Tile label="Resolved" value={resolved} hint="findings closed by a later run" />
            <Tile label="Endpoints" value={g?.nodes.filter((n) => n.kind === 'endpoint').length ?? '—'} hint={`${g?.nodes.length ?? 0} nodes in the code graph`} />
            <Tile label="Sensitive sinks" value={g?.nodes.filter((n) => n.kind === 'sink').length ?? '—'} hint="SQL, shell, filesystem, network" />
            <Tile label="Tools ready" value={tools ? `${readyTools}/${tools.length}` : '—'} hint="installed and usable now" />
          </div>
        </section>

        <div className="chart-grid">
          <ChartCard title="Open findings by source" sub="Stacked by severity. Click a row to open Findings."
            table={{ head: ['Source', ...SEV_SERIES.map((s) => s.label), 'Total'], rows: bySource.map((r) => [r.label, ...SEV_SERIES.map((s) => r.values[s.key] ?? 0), Object.values(r.values).reduce((a, b) => a + b, 0)]) }}>
            {bySource.length ? <HBars rows={bySource} series={SEV_SERIES} onSelect={goFindings} /> : <p className="chart-empty">No open findings.</p>}
          </ChartCard>

          <ChartCard title="File activity" sub="Saved-file events per hour, last 24 hours"
            table={{ head: ['Hour', 'Analysed', 'Failed'], rows: activity.filter((a) => a.values.ok + a.values.failed > 0).map((a) => [a.title, a.values.ok, a.values.failed]) }}>
            <Columns buckets={activity} series={activitySeries} />
          </ChartCard>

          <ChartCard title="Code graph size" sub={`Nodes and edges after each analysis run (last ${growth.length})`}
            table={{ head: ['Run', 'When', 'Nodes', 'Edges'], rows: growth.map((p: any) => [p.tick, p.title, p.values.nodes, p.values.edges]) }}>
            {growth.length ? <Lines points={growth} series={growthSeries} /> : <p className="chart-empty">No analysis runs recorded yet.</p>}
          </ChartCard>

          <ChartCard title="Security tool readiness" sub="What can run right now"
            table={{ head: ['Area', 'Tool', 'State'], rows: (tools ?? []).map((t) => [t.area, TOOL_LABEL[t.tool] ?? t.tool, t.state.replace(/_/g, ' ')]) }}>
            {tools ? (
              <div className="readiness">
                <Meter label="Tool readiness" parts={[
                  { key: 'ready', label: 'ready', value: readyTools, color: '#0ca30c' },
                  { key: 'missing', label: 'not available', value: tools.length - readyTools, color: '#48484a' },
                ]} />
                <ul className="tool-list">
                  {tools.map((t) => (
                    <li key={t.area + t.tool}>
                      <span className={`dot ${t.state === 'ready' ? 'on' : 'off'}`} />
                      <span className="tool-name">{TOOL_LABEL[t.tool] ?? t.tool}</span>
                      <span className="faint small">{t.area}</span>
                      <span className={`chip ${t.state === 'ready' ? 'st-completed' : 'st-failed'}`}>{t.state.replace(/_/g, ' ')}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ) : <p className="chart-empty">Checking tools…</p>}
          </ChartCard>
        </div>

        {open.length > 0 && (
          <section className="glass recent">
            <header className="chart-head"><div><h3>Latest open findings</h3></div><button className="btn small" onClick={goFindings}>View all</button></header>
            <ul className="recent-list">
              {open.slice().sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)).slice(0, 5).map((f) => (
                <li key={f._id}>
                  <span className={`chip sev-${f.severity}`}>{f.severity}</span>
                  <span className="recent-title">{f.title}</span>
                  <span className="faint small">{SOURCE_NAME[f.source] ?? f.source} · {timeAgo(f.lastSeenAt)}</span>
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    </div>
  );
}

function Tile({ label, value, hint }: { label: string; value: number | string; hint: string }) {
  return <div className="tile"><div className="tile-label">{label}</div><div className="tile-value">{value}</div><div className="tile-hint">{hint}</div></div>;
}
