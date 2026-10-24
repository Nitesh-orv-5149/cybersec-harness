import { useEffect, useState } from 'react';
import type { Ctx } from '../App';
import { api, artifactUrl, timeAgo, ApiError } from '../api';

const STATUS_TEXT: Record<string, string> = {
  pending: 'Preparing snapshots', building: 'Building and starting', browser_running: 'Running browser scenarios', comparing: 'Comparing results',
  completed: 'Completed', failed: 'Failed', inconclusive: 'Inconclusive', cancelled: 'Cancelled',
};
const CLASS_TEXT: Record<string, string> = {
  confirmed_test_failure: 'Regression: passed on baseline, fails now', observed: 'Difference observed', fixed: 'Fixed: failed on baseline, passes now',
  pre_existing_failure: 'Fails on both', inconclusive: 'Could not be compared', unchanged: 'No difference',
};

export function CompareView({ ctx }: { ctx: Ctx }) {
  const [runs, setRuns] = useState<any[] | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const s = ctx.status;
  const job = s.browser.job;

  useEffect(() => {
    api.get<any[]>(`/api/projects/${ctx.projectId}/browser-runs`).then((r) => { setRuns(r); }).catch(() => setRuns([]));
  }, [ctx.projectId, ctx.ticks.browser]);
  useEffect(() => { if (job?.runId) setRunId(job.runId); }, [job?.runId]);

  const act = async (fn: () => Promise<any>, ok?: (r: any) => string) => {
    setBusy(true); setMsg(null);
    try { const r = await fn(); if (ok) setMsg(ok(r)); ctx.refreshStatus(); }
    catch (e) { const ae = e as ApiError; setMsg(ae.body?.reasons ? `${ae.message}: ${ae.body.reasons.join('; ')}` : ae.message); }
    finally { setBusy(false); }
  };

  const current = runs?.find((r) => r._id === runId) ?? runs?.[0];
  return (
    <div className="split">
      <div className="master">
        <div style={{ padding: 14, borderBottom: '1px solid var(--line)', display: 'grid', gap: 12 }}>
          <div>
            <h3 style={{ marginTop: 0 }}>Baseline</h3>
            {s.baseline
              ? <p className="small">Snapshot <span className="mono">{s.baseline.snapshotId.slice(5, 17)}</span>, {s.baseline.fileCount} files, set {timeAgo(s.baseline.createdAt)}</p>
              : <p className="small muted">Not set. Mark a known-good state of your files as the baseline; later runs compare your current files against it.</p>}
            <button className="btn small" disabled={busy} onClick={() => {
              if (s.baseline && !confirm('Replace the baseline with the current files on disk? Earlier runs keep their original baseline.')) return;
              void act(() => api.post(`/api/projects/${ctx.projectId}/baseline`), (r) => `Baseline set to ${r.snapshotId.slice(5, 17)}${r.reused ? ' (identical to an existing snapshot)' : ''}${r.unsavedBuffersExcluded.length ? `. Unsaved buffers were not included: ${r.unsavedBuffersExcluded.join(', ')}` : ''}`);
            }}>{s.baseline ? 'Replace baseline with current files' : 'Mark current files as baseline'}</button>
          </div>
          {s.config.run && !s.config.runApproved && (
            <div className="box">
              <h3 style={{ marginTop: 0 }}>Approve run commands</h3>
              <p className="small muted">These commands come from <span className="mono">workbench.config.json</span>. They run in isolated copies of your snapshots, never in your working folder.</p>
              <dl className="kv small">
                {s.config.run.build && <><dt>Build</dt><dd className="mono">{s.config.run.build}</dd></>}
                <dt>Start</dt><dd className="mono">{s.config.run.start}</dd>
                <dt>Ready when</dt><dd className="mono">GET {s.config.run.healthPath}</dd>
              </dl>
              <button className="btn small primary" style={{ marginTop: 8 }} disabled={busy} onClick={() => void act(() => api.post(`/api/projects/${ctx.projectId}/approve-run`, { hash: s.config.runHash }), () => 'Run commands approved')}>Approve these commands</button>
            </div>
          )}
          <div className="row">
            {job
              ? <button className="btn danger" onClick={() => void act(() => api.post(`/api/projects/${ctx.projectId}/verify/cancel`), () => 'Cancelling')}>Cancel run</button>
              : <button className="btn primary" disabled={busy || !s.verification.ok} onClick={() => void act(() => api.post(`/api/projects/${ctx.projectId}/verify`), (r) => r.queued ? 'Queued after the current run' : 'Run started')}>Compare current files with baseline</button>}
            {s.browser.queued && <span className="small muted">one more run queued</span>}
          </div>
          {!s.verification.ok && !job && <ul className="explain small muted">{s.verification.reasons.map((r: string) => <li key={r}>{r}</li>)}</ul>}
          {msg && <p className="small" role="status">{msg}</p>}
        </div>
        {runs && !runs.length && <div className="empty small">No runs yet.</div>}
        {runs?.map((r) => (
          <button key={r._id} className="entry" aria-current={current?._id === r._id} onClick={() => setRunId(r._id)}>
            <div className="row"><span className={`chip st-${r.status}`}>{STATUS_TEXT[r.status] ?? r.status}</span><span className="small faint">{timeAgo(r.startedAt)}</span></div>
            <div className="small" style={{ marginTop: 4 }}>
              {r.summary ? Object.entries(r.summary).map(([k, v]) => <span key={k} className={`chip st-${k}`} style={{ marginRight: 4 }}>{String(v)} {k.replace(/_/g, ' ')}</span>) : <span className="muted">{r.error ?? 'in progress'}</span>}
            </div>
            <div className="mono small faint" style={{ marginTop: 4 }}>{r.baselineSnapshotId?.slice(5, 13)} → {r.candidateSnapshotId?.slice(5, 13)} · {r.trigger}</div>
          </button>
        ))}
      </div>
      <div className="detail">{current ? <RunDetail ctx={ctx} runId={current._id} live={job?.runId === current._id} /> : <div className="empty">Run a comparison to see baseline and current pages side by side.</div>}</div>
    </div>
  );
}

function Pipeline({ run }: { run: any }) {
  const side = (n: 'baseline' | 'candidate') => run.sides?.[n]?.status ?? 'pending';
  const stage = (label: string, st: string) => {
    const cls = st === 'completed' || st === 'ready' ? 'done' : st === 'failed' ? 'failed' : st === 'pending' ? '' : 'active';
    return <span className={`stage ${cls}`}>{label}: {st}</span>;
  };
  return (
    <div className="pipeline">
      {stage('Snapshot', run.candidateSnapshotId ? 'completed' : 'pending')}
      {stage('Baseline app', side('baseline'))}
      {stage('Current app', side('candidate'))}
      {stage('Compare', run.comparisonId ? 'completed' : run.status === 'comparing' ? 'running' : 'pending')}
    </div>
  );
}

function RunDetail({ ctx, runId, live }: { ctx: Ctx; runId: string; live: boolean }) {
  const [d, setD] = useState<any>(null);
  const [vp, setVp] = useState('all');
  const [onlyDiff, setOnlyDiff] = useState(false);
  useEffect(() => { api.get<any>(`/api/projects/${ctx.projectId}/browser-runs/${runId}`).then(setD).catch(() => setD(null)); }, [runId, ctx.ticks.browser]);
  if (!d?.run) return <div className="empty muted">Loading…</div>;
  const run = d.run;
  const cmp = d.comparison;
  const results: any[] = d.results;
  const currentHash = ctx.status.live?.sourceHash;
  const items = (cmp?.items ?? []).filter((i: any) => (vp === 'all' || i.viewport === vp) && (!onlyDiff || i.classification !== 'unchanged'));
  const viewports = [...new Set((cmp?.items ?? []).map((i: any) => i.viewport))] as string[];
  const failedSide = (['baseline', 'candidate'] as const).find((n) => run.sides?.[n]?.status === 'failed');

  return (
    <>
      <div className="section cmp-head">
        <div className="row"><span className={`chip st-${run.status}`}>{STATUS_TEXT[run.status] ?? run.status}</span><span className="mono small faint">{run._id}</span>{run.browserVersion && <span className="small faint">Chromium {run.browserVersion}</span>}</div>
        <p className="small">
          Baseline <span className="mono">{run.baselineSnapshotId?.slice(5, 17)}</span> compared with your files as of <span className="mono">{run.candidateSnapshotId?.slice(5, 17)}</span>, captured {new Date(run.startedAt).toLocaleTimeString()}.
          {run.filesChanged && <> {run.filesChanged.modified.length} modified, {run.filesChanged.added.length} added, {run.filesChanged.removed.length} removed file{run.filesChanged.removed.length === 1 ? '' : 's'}.</>}
        </p>
        {(live || !run.finishedAt) && <Pipeline run={run} />}
        {run.staleAtFinish && <div className="banner warn" style={{ borderRadius: 4 }}>Your files changed while this run was executing. These results describe snapshot {run.candidateSnapshotId?.slice(5, 17)}, not the current source ({currentHash?.slice(0, 8)}).</div>}
        {run.coverageNotes?.map((n: string) => <div key={n} className="banner warn" style={{ borderRadius: 4 }}>{n}</div>)}
        {run.error && <div className="banner" style={{ borderRadius: 4 }}>{run.error}</div>}
        {failedSide && run.sides[failedSide].log && <details open><summary className="small muted">{failedSide} {run.sides[failedSide].failedStep} output</summary><pre className="log">{run.sides[failedSide].log}</pre></details>}
      </div>
      {cmp && (
        <>
          <div className="toolbar" style={{ marginLeft: -20, marginRight: -20, paddingLeft: 20 }}>
            <select className="input" style={{ width: 'auto' }} value={vp} onChange={(e) => setVp(e.target.value)} aria-label="Viewport">
              <option value="all">All viewports</option>{viewports.map((v) => <option key={v}>{v}</option>)}
            </select>
            <label className="row small"><input type="checkbox" checked={onlyDiff} onChange={(e) => setOnlyDiff(e.target.checked)} /> Only scenarios with differences</label>
          </div>
          {items.map((it: any) => <Case key={it.scenarioId + it.viewport} it={it} ctx={ctx} b={results.find((r) => r.side === 'baseline' && r.scenarioId === it.scenarioId && r.viewport === it.viewport)} c={results.find((r) => r.side === 'candidate' && r.scenarioId === it.scenarioId && r.viewport === it.viewport)} />)}
          {!items.length && <p className="muted">No scenarios match this filter.</p>}
          <div className="section"><h3>Limitations</h3><ul className="explain limit">{cmp.limitations.map((l: string) => <li key={l}>{l}</li>)}</ul></div>
        </>
      )}
    </>
  );
}

function Case({ it, b, c, ctx }: { it: any; b: any; c: any; ctx: Ctx }) {
  const bad = it.classification === 'confirmed_test_failure';
  const [open, setOpen] = useState(it.classification !== 'unchanged');
  const v = it.visual;
  return (
    <section className={`case ${bad ? 'bad' : ''}`}>
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <div>
          <h3>{it.scenarioName} <span className="muted small">· {it.viewport}</span></h3>
          <div className="row small" style={{ marginTop: 4 }}>
            <span className={`chip st-${it.classification}`}>{CLASS_TEXT[it.classification]}</span>
            {v && <span className="chip">{(v.ratio * 100).toFixed(2)}% pixels differ</span>}
            <span className="muted">baseline {it.baselineStatus}, current {it.candidateStatus}</span>
          </div>
        </div>
        <button className="btn small" onClick={() => setOpen(!open)} aria-expanded={open}>{open ? 'Hide' : 'Show'} screenshots</button>
      </div>
      {it.notes.length > 0 && <ul className="explain small muted" style={{ marginTop: 6 }}>{it.notes.map((n: string) => <li key={n}>{n}</li>)}</ul>}
      {open && (
        <div className="shots" style={{ marginTop: 10 }}>
          <Shot label="Baseline" src={artifactUrl(ctx.projectId, it.baselineScreenshot)} />
          <Shot label="Current" src={artifactUrl(ctx.projectId, it.candidateScreenshot)} />
          <Shot label="Difference" src={artifactUrl(ctx.projectId, v?.diffImage)} regions={v?.regions} size={v ? [v.width, v.height] : undefined} />
        </div>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginTop: 10 }}>
        {[['Baseline', b], ['Current', c]].map(([label, r]: any) => (
          <div key={label}>
            <div className="small muted" style={{ marginBottom: 4 }}>{label} assertions {r && <span className="faint">· {r.durationMs}ms</span>}</div>
            {r ? <div className="assert">{r.assertions.map((a: any, i: number) => <span key={i} style={{ display: 'contents' }}><span className={a.ok ? 'mark-ok' : 'mark-bad'}>{a.ok ? '✓' : '✗'}</span><span><span className="mono small">{a.step}</span>{!a.ok && <><br /><span className="muted small">{a.message}</span></>}</span></span>)}{r.error && <><span className="mark-bad">!</span><span className="small">{r.error}</span></>}</div> : <span className="small faint">not run</span>}
            {r?.consoleErrors?.length > 0 && <p className="small" style={{ color: 'var(--bad)', marginTop: 6 }}>Console: {r.consoleErrors.join(' | ')}</p>}
            {r?.failedRequests?.length > 0 && <p className="small" style={{ color: 'var(--warn)', marginTop: 4 }}>Requests: {r.failedRequests.map((f: any) => `${f.status ?? f.error} ${f.url}`).join(', ')}</p>}
            {r?.apiRequests?.length > 0 && <p className="small faint" style={{ marginTop: 4 }}>API calls: {r.apiRequests.map((q: any) => `${q.method} ${q.path} → ${q.status}`).join(', ')}</p>}
          </div>
        ))}
      </div>
    </section>
  );
}

function Shot({ label, src, regions, size }: { label: string; src: string; regions?: any[]; size?: [number, number] }) {
  return (
    <figure className="shot" style={{ margin: 0 }}>
      <figcaption><span>{label}</span>{regions?.length ? <span>{regions.length} changed region{regions.length > 1 ? 's' : ''}</span> : null}</figcaption>
      <div className="frame">
        <div style={{ position: 'relative' }}>
          {src ? <img src={src} alt={`${label} screenshot`} loading="lazy" /> : <div className="empty small">No screenshot</div>}
          {size && regions?.map((r, i) => (
            <span key={i} className="region" style={{ left: `${(r.x / size[0]) * 100}%`, top: `${(r.y / size[1]) * 100}%`, width: `${(r.width / size[0]) * 100}%`, height: `${(r.height / size[1]) * 100}%` }} />
          ))}
        </div>
      </div>
    </figure>
  );
}
