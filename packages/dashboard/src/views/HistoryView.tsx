import { useEffect, useState } from 'react';
import type { Ctx } from '../App';
import { api, timeAgo } from '../api';

type Section = 'overview' | 'events' | 'analysis' | 'snapshots' | 'browser' | 'verification';

export function HistoryView({ ctx }: { ctx: Ctx }) {
  const [h, setH] = useState<any>(null);
  const [err, setErr] = useState<string | null>(null);
  const [sec, setSec] = useState<Section>('overview');
  useEffect(() => {
    api.get<any>(`/api/projects/${ctx.projectId}/history`).then((d) => { setH(d); setErr(null); }).catch((e) => setErr(e.message));
  }, [ctx.projectId, ctx.ticks.history]);
  if (err) return <div className="empty"><h2>History unavailable</h2><p>{err}</p></div>;
  if (!h) return <div className="empty muted">Loading…</div>;

  const sev = Object.fromEntries((h.summary.findings?.bySeverity ?? []).map((x: any) => [x._id, x.count]));
  const byStatus = Object.fromEntries((h.summary.findings?.byStatus ?? []).map((x: any) => [x._id, x.count]));
  const runsBy = Object.fromEntries((h.summary.browserRunsByStatus ?? []).map((x: any) => [x._id, x.count]));
  const tabs: [Section, string, number][] = [
    ['overview', 'Overview', 0], ['events', 'File events', h.events.length], ['analysis', 'Analysis runs', h.analysisRuns.length],
    ['snapshots', 'Snapshots', h.snapshots.length], ['browser', 'Browser runs', h.browserRuns.length], ['verification', 'Verification', h.verifications.length],
  ];

  return (
    <div className="scroll">
      <div className="toolbar">
        {tabs.map(([id, label, n]) => <button key={id} className="btn small" aria-pressed={sec === id} style={sec === id ? { borderColor: 'var(--endpoint)' } : undefined} onClick={() => setSec(id)}>{label}{n ? ` (${n})` : ''}</button>)}
        <span className="small faint">Stored in MongoDB; survives restarts.</span>
      </div>
      <div style={{ padding: '16px 20px' }}>
        {sec === 'overview' && (
          <>
            <div className="stats section">
              <div className="stat"><div className="n" style={{ color: 'var(--bad)' }}>{sev.high ?? 0}</div><div className="muted small">open high-severity findings</div></div>
              <div className="stat"><div className="n">{(sev.medium ?? 0) + (sev.low ?? 0)}</div><div className="muted small">open medium and low</div></div>
              <div className="stat"><div className="n" style={{ color: 'var(--ok)' }}>{byStatus.resolved ?? 0}</div><div className="muted small">resolved findings</div></div>
              <div className="stat"><div className="n">{runsBy.completed ?? 0}<span className="muted small"> / {Object.values(runsBy).reduce((a: number, b: any) => a + Number(b), 0)}</span></div><div className="muted small">browser runs completed</div></div>
              <div className="stat"><div className="n">{h.summary.activity.reduce((a: number, b: any) => a + b.events, 0)}</div><div className="muted small">file events in the last 24h</div></div>
            </div>
            <div className="section">
              <h3>Scenario history</h3>
              <p className="small muted">Aggregated from every candidate browser result. Each bar is one run, oldest first.</p>
              {h.scenarioHistory.length ? (
                <table className="tbl"><thead><tr><th>Scenario</th><th>Viewport</th><th>Recent runs</th><th>Passed</th><th>Failed</th><th>Latest</th></tr></thead>
                  <tbody>{h.scenarioHistory.map((s: any) => (
                    <tr key={s.scenarioId + s.viewport}>
                      <td>{s.scenarioName}</td><td className="muted">{s.viewport}</td>
                      <td><span className="spark">{s.recent.map((r: any, i: number) => <i key={i} className={r.status} title={`${r.status} · ${r.runId}`} />)}</span></td>
                      <td>{s.passed}</td><td style={{ color: s.failed ? 'var(--bad)' : undefined }}>{s.failed}</td>
                      <td><span className={`chip st-${s.lastStatus}`}>{s.lastStatus}</span> <span className="faint small">{timeAgo(s.lastAt)}</span></td>
                    </tr>
                  ))}</tbody></table>
              ) : <p className="muted">No browser results yet.</p>}
            </div>
            <div className="section">
              <h3>Recent comparisons</h3>
              {h.comparisons.length ? <table className="tbl"><thead><tr><th>When</th><th>Baseline → current</th><th>Outcome</th><th>Confidence</th></tr></thead><tbody>{h.comparisons.map((c: any) => (
                <tr key={c._id}><td className="muted">{timeAgo(c.createdAt)}</td><td className="mono small">{c.baselineSnapshotId.slice(5, 13)} → {c.candidateSnapshotId.slice(5, 13)}</td>
                  <td>{Object.entries(c.summary).map(([k, v]) => <span key={k} className={`chip st-${k}`} style={{ marginRight: 4 }}>{String(v)} {k.replace(/_/g, ' ')}</span>)}</td><td className="muted">{c.confidence}</td></tr>
              ))}</tbody></table> : <p className="muted">None yet.</p>}
            </div>
          </>
        )}
        {sec === 'events' && <table className="tbl"><thead><tr><th>Received</th><th>File</th><th>Event</th><th>Source</th><th>Content</th><th>Status</th><th>Run</th></tr></thead><tbody>{h.events.map((e: any) => (
          <tr key={e._id}><td className="muted" style={{ whiteSpace: 'nowrap' }}>{new Date(e.receivedAt).toLocaleTimeString()}</td><td className="mono small">{e.path}</td><td>{e.type}</td><td className="muted">{e.source}{e.bufferState === 'unsaved' ? ' (unsaved)' : ''}</td><td className="mono small faint">{e.contentHash ?? '—'}</td>
            <td><span className={`chip st-${e.status === 'analyzed' ? 'completed' : e.status}`}>{e.status}</span>{e.error && <div className="small" style={{ color: 'var(--bad)' }}>{e.error}</div>}{e.occurrences > 1 && <div className="small faint">deduplicated ×{e.occurrences}</div>}</td><td className="mono small faint">{e.analysisRunId}</td></tr>
        ))}</tbody></table>}
        {sec === 'analysis' && <table className="tbl"><thead><tr><th>Started</th><th>Trigger</th><th>Status</th><th>Files</th><th>Graph</th><th>Changes</th><th>Source hash</th></tr></thead><tbody>{h.analysisRuns.map((r: any) => (
          <tr key={r._id}><td className="muted" style={{ whiteSpace: 'nowrap' }}>{new Date(r.startedAt).toLocaleTimeString()}</td><td>{r.trigger}{r.fullScan ? ' (full)' : ''}</td><td><span className={`chip st-${r.status}`}>{r.status}</span>{r.error && <div className="small" style={{ color: 'var(--bad)' }}>{r.error}</div>}</td>
            <td className="mono small">{(r.files ?? []).join(', ') || '—'}</td><td className="small">{r.summary ? `${r.summary.nodes} nodes, ${r.summary.edges} edges` : '—'}</td>
            <td className="small">{r.summary ? `${r.summary.changedNodes} changed, +${r.summary.addedNodes}/−${r.summary.removedNodes} nodes, ${r.summary.affectedEndpoints} endpoints affected` : '—'}</td><td className="mono small faint">{r.sourceHash?.slice(0, 10)}</td></tr>
        ))}</tbody></table>}
        {sec === 'snapshots' && <table className="tbl"><thead><tr><th>Created</th><th>Snapshot</th><th>Used as</th><th>Files</th><th>Size</th><th>Content hash</th></tr></thead><tbody>{h.snapshots.map((s: any) => (
          <tr key={s._id}><td className="muted">{new Date(s.createdAt).toLocaleString()}</td><td className="mono small">{s._id}</td><td>{(s.labels ?? []).join(', ')}</td><td>{s.fileCount}</td><td className="muted">{(s.totalBytes / 1024).toFixed(1)} KB</td><td className="mono small faint">{s.contentHash.slice(0, 16)}</td></tr>
        ))}</tbody></table>}
        {sec === 'browser' && <table className="tbl"><thead><tr><th>Started</th><th>Status</th><th>Trigger</th><th>Baseline → current</th><th>Result</th></tr></thead><tbody>{h.browserRuns.map((r: any) => (
          <tr key={r._id}><td className="muted">{new Date(r.startedAt).toLocaleString()}</td><td><span className={`chip st-${r.status}`}>{r.status}</span></td><td className="muted">{r.trigger}</td><td className="mono small">{r.baselineSnapshotId?.slice(5, 13)} → {r.candidateSnapshotId?.slice(5, 13)}</td>
            <td className="small">{r.summary ? Object.entries(r.summary).map(([k, v]) => `${v} ${k.replace(/_/g, ' ')}`).join(', ') : <span style={{ color: 'var(--bad)' }}>{r.error}</span>}</td></tr>
        ))}</tbody></table>}
        {sec === 'verification' && <table className="tbl"><thead><tr><th>When</th><th>Finding</th><th>Action</th><th>Result</th><th>Evidence run</th></tr></thead><tbody>{h.verifications.map((v: any) => (
          <tr key={v._id}><td className="muted" style={{ whiteSpace: 'nowrap' }}>{new Date(v.at).toLocaleString()}</td><td>{v.notes}<div className="mono small faint">{v.findingId}</div></td><td>{v.action.replace(/_/g, ' ')}</td><td className="muted">{v.result}</td><td className="mono small faint">{v.browserRunId ?? v.analysisRunId}</td></tr>
        ))}</tbody></table>}
      </div>
    </div>
  );
}
