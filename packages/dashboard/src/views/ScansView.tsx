// Security tools other than dependency scanning: API testing, dynamic web scanning, template scanning,
// source-code analysis, secrets detection and infrastructure checks. One panel per scan kind.
import { useEffect, useState } from 'react';
import type { Ctx } from '../App';
import { api, artifactUrl, timeAgo, TOOL_LABEL, type Finding } from '../api';
import { WebSecurityPanel } from './WebSecurityPanel';

/** Nuclei has its own service (it can scan the baseline and current snapshots side by side), so it is listed here
 *  with its own panel instead of as a generic scan kind. Same panel and history as Website comparison → Security changes. */
const WEB_ENTRY = '__web_nuclei';

export const STATE_LABEL: Record<string, string> = {
  ready: 'ready', not_installed: 'not installed', not_functional: 'not working', needs_network: 'needs network permission', unreachable: 'service unreachable', disabled: 'disabled',
};
export const STATE_CLASS: Record<string, string> = { ready: 'st-completed', not_installed: 'st-failed', not_functional: 'st-failed', unreachable: 'st-failed', needs_network: 'st-inconclusive', disabled: '' };
const RUN_CLASS: Record<string, string> = { completed: 'st-completed', partial: 'st-inconclusive', running: 'st-analyzing', failed: 'st-failed', unavailable: 'st-failed', cancelled: 'st-cancelled', not_run: '', not_applicable: '', timed_out: 'st-failed', inconclusive: 'st-inconclusive', skipped: '' };
const RUN_LABEL: Record<string, string> = { not_applicable: 'not applicable', not_run: 'not run', timed_out: 'timed out' };
const COVERAGE_LABEL: Record<string, string> = {
  covered: 'covered', partial: 'partly covered', not_applicable: 'not applicable (nothing this tool can scan)', unavailable: 'not scanned: no usable tool', failed: 'not scanned: scan failed', not_run: 'not run',
};

interface KindStatus {
  kind: string; category: string; label: string; description: string; dynamic: boolean; modes: string[]; activeModes: string[]; enabled: boolean;
  blockers: string[]; activeBlockers: string[]; job: { runId: string; tool: string | null } | null; lastRun: any; tools: any[];
}

export function ScansView({ ctx }: { ctx: Ctx }) {
  const [kinds, setKinds] = useState<KindStatus[] | null>(null);
  const [current, setCurrent] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const load = (refresh = false) => {
    setChecking(true);
    api.get<KindStatus[]>(`/api/projects/${ctx.projectId}/security/kinds${refresh ? '?refresh=1' : ''}`).then((k) => { setKinds(k); setErr(null); }).catch((e) => setErr(e.message)).finally(() => setChecking(false));
  };
  useEffect(() => { load(); }, [ctx.projectId, ctx.ticks.security]);
  if (err) return <div className="empty"><h2>Security tools unavailable</h2><p>{err}</p></div>;
  if (!kinds) return <div className="empty muted">Checking installed tools…</div>;
  const sel = kinds.find((k) => k.kind === current) ?? kinds[0]!;
  const web = ctx.status.security?.web ?? null;
  const webSelected = current === WEB_ENTRY;
  return (
    <div className="split">
      <div className="master">
        <div className="toolbar"><button className="btn small" disabled={checking} onClick={() => load(true)}>{checking ? 'Checking…' : 'Re-check tools'}</button><span className="small faint">Tools are never downloaded or installed by the workbench.</span></div>
        {kinds.map((k) => {
          const ready = k.tools.filter((t) => t.state === 'ready').length;
          return (
            <button key={k.kind} className="entry" aria-current={!webSelected && sel.kind === k.kind} onClick={() => setCurrent(k.kind)}>
              <div className="row">
                {k.job ? <span className="chip st-analyzing">running</span> : k.lastRun ? <span className={`chip ${RUN_CLASS[k.lastRun.status] ?? ''}`}>{RUN_LABEL[k.lastRun.status] ?? k.lastRun.status}</span> : <span className="chip">never run</span>}
                {k.dynamic && <span className="chip">dynamic</span>}
                <span className={`chip ${ready ? 'st-completed' : 'st-failed'}`}>{ready}/{k.tools.length} tool{k.tools.length > 1 ? 's' : ''} ready</span>
              </div>
              <div className="t">{k.label}</div>
              <div className="small faint">{k.tools.map((t) => t.displayName).join(', ')}{k.lastRun?.counts ? ` · ${k.lastRun.counts.total} finding(s) in last run` : ''}</div>
            </button>
          );
        })}
        {web && (
          <button className="entry" aria-current={webSelected} onClick={() => setCurrent(WEB_ENTRY)}>
            <div className="row">
              {web.job ? <span className="chip st-analyzing">running</span> : web.lastRun ? <span className={`chip ${RUN_CLASS[web.lastRun.status] ?? ''}`}>{RUN_LABEL[web.lastRun.status] ?? web.lastRun.status}</span> : <span className="chip">never run</span>}
              <span className="chip">dynamic</span>
              {web.readiness
                ? <span className={`chip ${web.readiness.state === 'ready' && web.readiness.templates === 'ready' ? 'st-completed' : 'st-failed'}`}>{web.readiness.state === 'ready' ? (web.readiness.templates === 'ready' ? 'nuclei + templates ready' : 'templates not ready') : STATE_LABEL[web.readiness.state] ?? web.readiness.state}</span>
                : <span className="chip">not checked yet</span>}
            </div>
            <div className="t">Web scanning</div>
            <div className="small faint">Nuclei{web.enabled ? '' : ' · disabled in config'}</div>
          </button>
        )}
      </div>
      <div className="detail">{webSelected
        ? <div className="section" style={{ maxWidth: 'none' }}>
            <h3>Web scanning (Nuclei)</h3>
            <p className="small muted">Nuclei sends HTTP requests to a running copy of the app (or an authorised URL) and checks the responses against vetted templates. The same scan, with a baseline vs current comparison, is under Website comparison → Security changes; results and history are shared.</p>
            <WebSecurityPanel ctx={ctx} />
          </div>
        : <KindPanel k={sel} ctx={ctx} reload={() => load()} />}</div>
    </div>
  );
}

function KindPanel({ k, ctx, reload }: { k: KindStatus; ctx: Ctx; reload: () => void }) {
  const [runs, setRuns] = useState<any[] | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [mode, setMode] = useState(k.modes[0] ?? '');
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const storeUp = ctx.status.store.available;
  useEffect(() => { setMode(k.modes[0] ?? ''); setConfirm(false); setErr(null); }, [k.kind]);
  useEffect(() => {
    if (!storeUp) { setRuns(null); setFindings(null); return; }
    api.get<any[]>(`/api/projects/${ctx.projectId}/security/kinds/${k.kind}/runs`).then(setRuns).catch((e) => setErr(e.message));
    api.get<Finding[]>(`/api/projects/${ctx.projectId}/findings?status=open`).then((f) => setFindings(f.filter((x) => x.category === k.category))).catch(() => setFindings(null));
  }, [ctx.projectId, k.kind, ctx.ticks.security, ctx.ticks.findings, storeUp]);

  const active = k.activeModes.includes(mode);
  const blockers = (active ? k.activeBlockers : k.blockers).filter((b) => !/confirm in the dashboard/.test(b));
  const start = async () => {
    setBusy(true); setErr(null);
    try { await api.post(`/api/projects/${ctx.projectId}/security/kinds/${k.kind}/runs`, { mode: mode || undefined, confirmActive: active ? confirm : undefined }); reload(); ctx.refreshStatus(); }
    catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };
  const cancel = () => api.post(`/api/projects/${ctx.projectId}/security/kinds/${k.kind}/cancel`).then(() => { reload(); ctx.refreshStatus(); });
  const last = runs?.find((r) => r.status !== 'running') ?? null;

  return (
    <>
      <div className="section">
        <h2>{k.label}</h2>
        <p className="muted">{k.description}</p>
        {err && <div className="banner" style={{ marginTop: 8 }}>{err}</div>}
        <div className="row" style={{ marginTop: 10, gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          {k.modes.length > 1 && (
            <select className="input" style={{ width: 'auto' }} value={mode} onChange={(e) => { setMode(e.target.value); setConfirm(false); }} aria-label="Mode">
              {k.modes.map((m) => <option key={m} value={m}>{m}{k.activeModes.includes(m) ? ' (sends attack-style requests)' : ''}</option>)}
            </select>
          )}
          {k.job
            ? <><span className="chip st-analyzing">running{k.job.tool ? ` ${TOOL_LABEL[k.job.tool] ?? k.job.tool}` : ''}</span><button className="btn small danger" onClick={cancel}>Cancel</button></>
            : <button className="btn primary" disabled={busy || !storeUp || blockers.length > 0 || (active && !confirm)} onClick={start}>Run {k.label}</button>}
        </div>
        {active && !k.job && (
          <label className="small" style={{ display: 'block', marginTop: 8 }}>
            <input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} /> I am authorised to test this application. The workbench only targets a local copy it starts itself{k.kind === 'template' || k.kind === 'web' ? ' or a target listed in the project configuration' : ''}.
          </label>
        )}
        {blockers.length > 0 && <ul className="explain limit" style={{ marginTop: 8 }}>{blockers.map((b, i) => <li key={i}>{b}</li>)}</ul>}
      </div>

      <div className="section">
        <h3>Tools</h3>
        <table className="tbl">
          <thead><tr><th>Tool</th><th>Status</th><th>Version</th><th>Executable</th><th>Contacts</th></tr></thead>
          <tbody>{k.tools.map((t) => (
            <tr key={t.tool}>
              <td><b>{t.displayName}</b></td>
              <td><span className={`chip ${STATE_CLASS[t.state] ?? ''}`}>{STATE_LABEL[t.state] ?? t.state}</span>{t.reason && <div className="small muted" style={{ marginTop: 4 }}>{t.reason}</div>}</td>
              <td className="mono small">{t.version ?? '—'}</td>
              <td className="mono small">{t.binary ?? '—'}</td>
              <td className="small">{t.networkHosts.length ? t.networkHosts.join(', ') : <span className="muted">local only</span>}</td>
            </tr>
          ))}</tbody>
        </table>
        <details style={{ marginTop: 8 }}><summary className="small muted">Known limitations</summary>{k.tools.map((t) => <div key={t.tool} style={{ marginTop: 6 }}><b className="small">{t.displayName}</b><ul className="explain limit">{t.limitations.map((l: string, i: number) => <li key={i}>{l}</li>)}</ul></div>)}</details>
      </div>

      {!storeUp && <div className="empty">MongoDB is unavailable, so results cannot be stored or shown.</div>}
      {storeUp && last && <RunSummary run={last} ctx={ctx} />}
      {storeUp && runs && !runs.length && !k.job && <p className="muted" style={{ padding: '0 20px' }}>No {k.label.toLowerCase()} run yet.</p>}

      {storeUp && findings && (
        <div className="section">
          <h3>Open findings <span className="muted small">({findings.length})</span></h3>
          {findings.length ? (
            <table className="tbl">
              <thead><tr><th>Severity</th><th>Finding</th><th>Where</th><th>Rule</th><th>Tools</th><th>Code link</th></tr></thead>
              <tbody>{findings.map((f) => (
                <tr key={f._id} className="clickable" onClick={() => ctx.select({ nodeId: null, path: null, from: `finding:${f._id}` }, 'issues')}>
                  <td><span className={`chip sev-${f.severity}`}>{f.severity}</span></td>
                  <td>{f.title}{f.potentialRegression && <span className="chip st-failed" style={{ marginLeft: 4 }}>potential regression</span>}</td>
                  <td className="mono small">{whereOf(f)}</td>
                  <td className="mono small">{(f.ruleIds ?? []).map((r) => r.split(':').slice(1).join(':')).join(', ')}</td>
                  <td className="small">{(f.scanners ?? []).map((t) => TOOL_LABEL[t] ?? t).join(', ')}</td>
                  <td className="small">{(f.labels ?? []).includes('reaches_sensitive_sink') ? <span className="chip st-failed">reaches sensitive call</span> : (f.labels ?? []).includes('graph_linked') ? <span className="chip">linked</span> : <span className="muted">none</span>}</td>
                </tr>
              ))}</tbody>
            </table>
          ) : last?.counts ? <p className="muted">No open findings from the tools that ran.</p>
            : last?.status === 'not_applicable' ? <p className="muted">Not applicable to this project: {last.coverage?.reason ?? 'nothing for these tools to check'}. This is not a clean result.</p>
            : <p className="muted">No completed run, so there are no results (this is not the same as "no issues").</p>}
        </div>
      )}

      {storeUp && runs && runs.length > 0 && (
        <div className="section">
          <h3>History</h3>
          <table className="tbl"><thead><tr><th>Started</th><th>Mode</th><th>Status</th><th>Tools completed</th><th>Findings</th><th>New</th><th>Not currently observed</th><th>Run</th></tr></thead>
            <tbody>{runs.map((r) => (
              <tr key={r._id}>
                <td className="muted">{timeAgo(r.startedAt)}</td>
                <td className="small">{r.mode ?? '—'}{r.active ? <span className="chip st-inconclusive" style={{ marginLeft: 4 }}>active</span> : null}</td>
                <td><span className={`chip ${RUN_CLASS[r.status] ?? ''}`}>{RUN_LABEL[r.status] ?? r.status}</span></td>
                <td className="small">{(r.tools ?? []).filter((t: any) => t.status === 'completed').map((t: any) => TOOL_LABEL[t.tool] ?? t.tool).join(', ') || <span className="muted">none</span>}</td>
                <td>{r.counts ? r.counts.total : <span className="muted">not scanned</span>}</td>
                <td>{r.counts?.new ?? '—'}</td>
                <td>{r.counts?.notCurrentlyObserved ?? '—'}</td>
                <td className="mono small muted">{r._id}</td>
              </tr>
            ))}</tbody></table>
        </div>
      )}
    </>
  );
}

export function whereOf(f: Finding): string {
  const l = f.location;
  if (!l) return '—';
  if (l.operation) return l.operation;
  if (l.url) return `${l.method ? `${l.method} ` : ''}${l.url}`;
  if (l.file) return `${l.file}${l.line ? `:${l.line}` : ''}${l.resource ? ` (${l.resource})` : ''}${l.commit ? ` @ ${l.commit.slice(0, 10)}` : ''}`;
  return '—';
}

function DetailValue({ v }: { v: unknown }) {
  if (Array.isArray(v)) {
    if (!v.length) return <span className="muted">none</span>;
    if (v.every((x) => typeof x !== 'object' || x === null)) return <span className="mono small">{v.slice(0, 30).join(', ')}{v.length > 30 ? ` … (+${v.length - 30})` : ''}</span>;
    return <ul className="explain">{v.slice(0, 15).map((x, i) => <li key={i} className="small mono">{typeof x === 'object' ? Object.values(x as object).join(' — ') : String(x)}</li>)}</ul>;
  }
  if (v && typeof v === 'object') return <span className="mono small">{Object.entries(v as object).map(([a, b]) => `${a}: ${typeof b === 'object' ? JSON.stringify(b) : b}`).join(' · ')}</span>;
  return <span className="mono small">{v === null || v === undefined ? '—' : String(v)}</span>;
}

function RunSummary({ run, ctx }: { run: any; ctx: Ctx }) {
  const c = run.counts;
  const sev = c?.bySeverity ?? {};
  const dur = run.finishedAt ? Math.round((new Date(run.finishedAt).getTime() - new Date(run.startedAt).getTime()) / 100) / 10 : null;
  const detail = Object.entries(run.coverage?.detail ?? {});
  return (
    <div className="section">
      <h3>Latest run <span className={`chip ${RUN_CLASS[run.status] ?? ''}`}>{RUN_LABEL[run.status] ?? run.status}</span> <span className="small muted">{timeAgo(run.startedAt)}{dur !== null ? ` · ${dur}s` : ''}{run.mode ? ` · mode ${run.mode}` : ''}</span></h3>
      <dl className="kv wide">
        <dt>Coverage</dt><dd>{COVERAGE_LABEL[run.coverage?.status] ?? run.coverage?.status}{run.coverage?.reason && <div className="small muted">{run.coverage.reason}</div>}</dd>
        {run.target && <><dt>Target</dt><dd className="mono small">{run.target.url} <span className="muted">(local copy of snapshot {String(run.target.snapshotId).slice(0, 18)})</span></dd></>}
        {run.active && <><dt>Authorisation</dt><dd className="small">active mode, confirmed in the dashboard at {new Date(run.authorization?.at ?? run.startedAt).toLocaleString()}</dd></>}
        {detail.map(([key, v]) => <span key={key} style={{ display: 'contents' }}><dt>{key}</dt><dd><DetailValue v={v} /></dd></span>)}
      </dl>
      {c ? (
        <div className="stats" style={{ margin: '12px 0' }}>
          <div className="stat"><div className="n" style={{ color: 'var(--bad)' }}>{sev.high ?? 0}</div><div className="muted small">high</div></div>
          <div className="stat"><div className="n">{sev.medium ?? 0}</div><div className="muted small">medium</div></div>
          <div className="stat"><div className="n">{(sev.low ?? 0) + (sev.info ?? 0)}</div><div className="muted small">low / info</div></div>
          <div className="stat"><div className="n">{sev.unknown ?? 0}</div><div className="muted small">severity not supplied</div></div>
          <div className="stat"><div className="n">{c.new}</div><div className="muted small">new · {c.recurring} recurring</div></div>
          <div className="stat"><div className="n">{c.graphLinked}</div><div className="muted small">linked to code</div></div>
          <div className="stat"><div className="n">{c.notCurrentlyObserved}</div><div className="muted small">not currently observed</div></div>
          <div className="stat"><div className="n" style={{ color: c.regressions ? 'var(--bad)' : undefined }}>{c.regressions}</div><div className="muted small">potential regressions</div></div>
        </div>
      ) : <p className="muted" style={{ margin: '12px 0' }}>No counts: nothing was scanned successfully in this run.</p>}
      {(run.notes ?? []).length > 0 && <ul className="explain limit">{run.notes.map((n: string, i: number) => <li key={i}>{n}</li>)}</ul>}
      <table className="tbl">
        <thead><tr><th>Tool</th><th>Result</th><th>Exit</th><th>Time</th><th>Findings</th><th>Notes</th></tr></thead>
        <tbody>{(run.tools ?? []).map((t: any, i: number) => (
          <tr key={i}>
            <td>{t.displayName} <span className="faint small">{t.version ?? ''}</span></td>
            <td><span className={`chip ${RUN_CLASS[t.status] ?? ''}`}>{RUN_LABEL[t.status] ?? t.status}</span>{t.reason && <div className="small muted" style={{ marginTop: 4 }}>{t.reason}</div>}</td>
            <td className="mono small">{t.exitCode ?? '—'}</td>
            <td className="small">{t.durationMs != null ? `${(t.durationMs / 1000).toFixed(1)}s` : '—'}</td>
            <td>{t.observationCount ?? <span className="muted">—</span>}</td>
            <td className="small">
              {t.notes.map((n: string, k: number) => <div key={k} className="muted" style={{ wordBreak: 'break-all' }}>{n}</div>)}
              {t.reportRef && <a href={artifactUrl(ctx.projectId, t.reportRef)} target="_blank" rel="noreferrer">raw report</a>}
              {t.stderrTail && <details><summary className="muted">stderr</summary><pre className="log">{t.stderrTail}</pre></details>}
            </td>
          </tr>
        ))}</tbody>
      </table>
    </div>
  );
}
