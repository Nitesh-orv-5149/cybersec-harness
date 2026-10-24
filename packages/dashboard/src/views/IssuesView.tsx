import { useEffect, useMemo, useState } from 'react';
import type { Ctx } from '../App';
import { api, artifactUrl, timeAgo, type Finding } from '../api';
import { Index } from '../graphUtil';
import { PathChain } from './GraphView';

const CLASS_LABEL: Record<string, string> = {
  security_sensitive_path: 'Security-sensitive path',
  confirmed_test_failure: 'Confirmed test failure',
  observed: 'Observed difference',
  potentially_related: 'Potentially related',
  unverified: 'Unverified',
  inconclusive: 'Inconclusive',
};
const ACTION_LABEL: Record<string, string> = {
  observed: 'First observed', reopened: 'Observed again', verified_fixed: 'Verified fixed by browser run', resolved_by_analysis: 'Resolved: path no longer in graph',
};

export function IssuesView({ ctx }: { ctx: Ctx }) {
  const [status, setStatus] = useState<'open' | 'resolved' | 'all'>('open');
  const [source, setSource] = useState<'all' | 'graph' | 'runtime'>('all');
  const [items, setItems] = useState<Finding[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [current, setCurrent] = useState<string | null>(null);
  const [detail, setDetail] = useState<{ finding: Finding; records: any[] } | null>(null);
  const index = useMemo(() => (ctx.graph?.graph ? new Index(ctx.graph.graph) : null), [ctx.graph]);

  useEffect(() => {
    api.get<Finding[]>(`/api/projects/${ctx.projectId}/findings${status === 'all' ? '' : `?status=${status}`}`)
      .then((r) => { setItems(r); setErr(null); }).catch((e) => setErr(e.message));
  }, [ctx.projectId, status, ctx.ticks.findings]);
  const shown = (items ?? []).filter((f) => source === 'all' || f.source === source);
  const sel = shown.find((f) => f._id === current) ?? shown[0];
  useEffect(() => {
    if (!sel) { setDetail(null); return; }
    api.get<{ finding: Finding; records: any[] }>(`/api/projects/${ctx.projectId}/findings/${sel._id}`).then(setDetail).catch(() => setDetail(null));
  }, [sel?._id, ctx.ticks.findings]);

  if (err) return <div className="empty"><h2>Findings unavailable</h2><p>{err}</p></div>;
  if (!items || !index) return <div className="empty muted">Loading…</div>;

  return (
    <div className="split">
      <div className="master">
        <div className="toolbar">
          <select className="input" style={{ width: 'auto' }} value={status} onChange={(e) => setStatus(e.target.value as any)} aria-label="Status">
            <option value="open">Open</option><option value="resolved">Resolved</option><option value="all">All</option>
          </select>
          <select className="input" style={{ width: 'auto' }} value={source} onChange={(e) => setSource(e.target.value as any)} aria-label="Source">
            <option value="all">Code and website</option><option value="graph">Code analysis</option><option value="runtime">Website runs</option>
          </select>
          <span className="muted small">{shown.length}</span>
        </div>
        {!shown.length && <div className="empty">{status === 'open' ? 'No open findings for this filter.' : 'Nothing here yet.'}</div>}
        {shown.map((f) => (
          <button key={f._id} className="entry" aria-current={sel?._id === f._id} onClick={() => setCurrent(f._id)}>
            <div className="row">
              <span className={`chip sev-${f.severity}`}>{f.severity}</span>
              <span className={`chip st-${f.classification}`}>{CLASS_LABEL[f.classification] ?? f.classification}</span>
              {f.status === 'resolved' && <span className="chip st-resolved">resolved</span>}
            </div>
            <div className="t">{f.title}</div>
            <div className="small faint">{f.source === 'graph' ? 'Code analysis' : 'Website run'} · last seen {timeAgo(f.lastSeenAt)}</div>
          </button>
        ))}
      </div>
      <div className="detail">
        {sel && <FindingDetail f={detail?.finding ?? sel} records={detail?.records ?? []} index={index} ctx={ctx} />}
      </div>
    </div>
  );
}

function FindingDetail({ f, records, index, ctx }: { f: Finding; records: any[]; index: Index; ctx: Ctx }) {
  const changed = new Set(f.correlation?.changedNodes ?? []);
  const paths = f.correlation?.paths?.length ? f.correlation.paths : f.paths;
  return (
    <>
      <div className="section">
        <div className="row"><span className={`chip sev-${f.severity}`}>{f.severity}</span><span className={`chip st-${f.classification}`}>{CLASS_LABEL[f.classification] ?? f.classification}</span><span className="chip">{f.status ?? 'open'}</span><span className="faint small mono">{f._id}</span></div>
        <h2 style={{ marginTop: 8 }}>{f.title}</h2>
        <p className="muted small">First seen {timeAgo(f.firstSeenAt)} · last seen {timeAgo(f.lastSeenAt)} · confidence {f.confidence}</p>
      </div>
      <div className="section">
        <h3>What was found</h3>
        <ul className="explain">{f.explanation.map((e, i) => <li key={i}>{e}</li>)}</ul>
      </div>
      {f.source === 'runtime' && f.evidence.failedAssertions?.length > 0 && (
        <div className="section"><h3>Browser evidence</h3>
          <div className="assert">{f.evidence.failedAssertions.map((a: any, i: number) => <span key={i} style={{ display: 'contents' }}><span className="mark-bad">✗</span><span><span className="mono">{a.step}</span><br /><span className="muted">{a.message}</span></span></span>)}</div>
          {f.lastSeenBrowserRunId && <RunShots ctx={ctx} runId={f.lastSeenBrowserRunId} scenario={f.scenario} />}
        </div>
      )}
      {f.correlation && (
        <div className="section">
          <h3>Connection to code changes</h3>
          <p><span className={`chip ${f.correlation.status === 'potentially_related' ? 'st-observed' : ''}`}>{f.correlation.status === 'potentially_related' ? 'potentially related' : 'no supporting path'}</span></p>
          <p className="muted">{f.correlation.reason}</p>
        </div>
      )}
      {paths.length > 0 && (
        <div className="section">
          <h3>{f.source === 'graph' ? 'Reachability paths' : 'Dependency paths from what the scenario exercised to the changed code'}</h3>
          {paths.map((p, i) => <PathChain key={i} path={p} index={index} ctx={ctx} changed={changed} />)}
          <button className="btn small" onClick={() => ctx.select({ nodeId: paths[0][paths[0].length - 1], path: paths[0], from: 'finding' }, 'graph')}>Show in graph</button>
        </div>
      )}
      {f.locations.length > 0 && <div className="section"><h3>Source locations</h3><ul className="list">{f.locations.map((l, i) => (
        <li key={i}><button onClick={() => api.post(`/api/projects/${ctx.projectId}/open-in-editor`, l)}><span className="lbl">{l.file}:{l.line}</span></button></li>
      ))}</ul></div>}
      <div className="section"><h3>Suggested next step</h3><p>{f.suggestedNextStep}</p></div>
      <div className="section"><h3>Limitations</h3><ul className="explain limit">{f.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul></div>
      <div className="section">
        <h3>Verification history</h3>
        {records.length ? (
          <table className="tbl"><tbody>{records.map((r) => (
            <tr key={r._id}><td className="muted" style={{ whiteSpace: 'nowrap' }}>{new Date(r.at).toLocaleString()}</td><td>{ACTION_LABEL[r.action] ?? r.action}</td><td className="mono small muted">{r.browserRunId ?? r.analysisRunId}</td><td className="muted">{r.result}</td></tr>
          ))}</tbody></table>
        ) : <p className="muted small">No records yet.</p>}
      </div>
    </>
  );
}

function RunShots({ ctx, runId, scenario }: { ctx: Ctx; runId: string; scenario?: Finding['scenario'] }) {
  const [item, setItem] = useState<any>(null);
  useEffect(() => {
    api.get<any>(`/api/projects/${ctx.projectId}/browser-runs/${runId}`).then((d) => setItem(d.comparison?.items.find((i: any) => i.scenarioId === scenario?.id && i.viewport === scenario?.viewport) ?? null)).catch(() => setItem(null));
  }, [runId, scenario?.id, scenario?.viewport]);
  if (!item) return null;
  return (
    <div className="shots" style={{ marginTop: 10 }}>
      {[['Baseline', item.baselineScreenshot], ['Candidate', item.candidateScreenshot], ['Difference', item.visual?.diffImage]].map(([label, src]) => (
        <figure className="shot" key={label} style={{ margin: 0 }}><figcaption>{label}</figcaption><div className="frame" style={{ maxHeight: 260 }}>{src ? <img src={artifactUrl(ctx.projectId, src)} alt={`${label} screenshot`} /> : null}</div></figure>
      ))}
    </div>
  );
}
