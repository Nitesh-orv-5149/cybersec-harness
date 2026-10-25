import { useEffect, useState } from 'react';
import type { Ctx } from '../App';
import { api, artifactUrl, timeAgo, TOOL_LABEL, type Finding } from '../api';
import { ChartCard, Columns, HBars, SERIES, SEVERITY_COLOR, SEVERITY_ORDER } from '../charts';
import { Icon } from '../icons';

const STATE_LABEL: Record<string, string> = {
  ready: 'ready', not_installed: 'not installed', not_functional: 'not working', needs_network: 'needs network permission', unreachable: 'service unreachable', disabled: 'disabled',
};
const STATE_CLASS: Record<string, string> = { ready: 'st-completed', not_installed: 'st-failed', not_functional: 'st-failed', unreachable: 'st-failed', needs_network: 'st-inconclusive', disabled: '' };
const COVERAGE_LABEL: Record<string, string> = { covered: 'covered', partial: 'partly covered', unavailable: 'not scanned: no usable scanner', failed: 'not scanned: scanner failed', not_run: 'not run' };
const COVERAGE_CLASS: Record<string, string> = { covered: 'st-completed', partial: 'st-inconclusive', unavailable: 'st-failed', failed: 'st-failed', not_run: '' };
const RUN_CLASS: Record<string, string> = { completed: 'st-completed', partial: 'st-inconclusive', running: 'st-analyzing', failed: 'st-failed', unavailable: 'st-failed', cancelled: 'st-cancelled', not_run: '' };
const USE_SHORT: Record<string, string> = {
  called_from_analysed_code: 'called by app code', imported_by_analysed_code: 'imported, no resolved call', transitive: 'transitive', declared_not_imported: 'declared, not imported', not_in_lockfile: 'not in lockfile',
};

export function SecurityView({ ctx }: { ctx: Ctx }) {
  const [scanners, setScanners] = useState<any[] | null>(null);
  const [runs, setRuns] = useState<any[] | null>(null);
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [checking, setChecking] = useState(false);
  const dep = ctx.status.security?.dependencies;
  const storeUp = ctx.status.store.available;

  const loadScanners = (refresh = false) => {
    setChecking(true);
    api.get<any[]>(`/api/projects/${ctx.projectId}/security/scanners${refresh ? '?refresh=1' : ''}`).then(setScanners).catch((e) => setErr(e.message)).finally(() => setChecking(false));
  };
  useEffect(() => { loadScanners(); }, [ctx.projectId]);
  useEffect(() => {
    if (!storeUp) { setRuns(null); setFindings(null); return; }
    api.get<any[]>(`/api/projects/${ctx.projectId}/security/dependency-scans`).then(setRuns).catch((e) => setErr(e.message));
    api.get<Finding[]>(`/api/projects/${ctx.projectId}/findings`).then((f) => setFindings(f.filter((x) => x.source === 'dependency'))).catch(() => setFindings(null));
  }, [ctx.projectId, ctx.ticks.security, ctx.ticks.findings, storeUp]);

  const start = async () => {
    setBusy(true);
    setErr(null);
    try { await api.post(`/api/projects/${ctx.projectId}/security/dependency-scans`); ctx.refreshStatus(); }
    catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };
  const cancel = () => api.post(`/api/projects/${ctx.projectId}/security/dependency-scans/cancel`).then(ctx.refreshStatus);

  const last = runs?.find((r) => r.status !== 'running') ?? null;
  const running = dep?.job;
  const open = (findings ?? []).filter((f) => f.status === 'open');

  return (
    <div className="scroll">
      <div className="toolbar">
        {running
          ? <><span className="chip st-analyzing">scanning{running.tool ? ` with ${TOOL_LABEL[running.tool] ?? running.tool}` : ''}</span><button className="btn small danger" onClick={cancel}>Cancel</button></>
          : <button className="btn primary" disabled={busy || !storeUp || !dep?.enabled} onClick={start} title={!storeUp ? 'MongoDB is required to store scan results' : undefined}>Run dependency scan</button>}
        <button className="btn small" disabled={checking} onClick={() => loadScanners(true)}>{checking ? 'Checking…' : 'Re-check scanners'}</button>
        <span className="small muted">Mode <b>{dep?.mode}</b> · order {dep?.order?.map((t: string) => TOOL_LABEL[t] ?? t).join(' → ')} · network {dep?.allowNetwork ? <b>allowed</b> : <b>not allowed</b>}</span>
        <span className="small faint">Manual only. Tools are never downloaded or installed by the workbench.</span>
      </div>
      <div style={{ padding: '16px 20px' }}>
        {err && <div className="banner" style={{ marginBottom: 12 }}>{err}</div>}
        {dep?.lockfileChangedSinceLastScan && <div className="banner warn" style={{ marginBottom: 12 }}>The lockfile changed since the last dependency scan. Its results describe the previous lockfile.</div>}
        {!dep?.allowNetwork && <p className="small muted">Network permission is off (<span className="mono">security.allowNetwork</span>). Scanners that query an advisory service or download a database are shown as needing network permission and will not run.</p>}

        <div className="section">
          <h3>Scanner availability</h3>
          {!scanners ? <p className="muted">Checking installed tools…</p> : (
            <table className="tbl">
              <thead><tr><th>Tool</th><th>Status</th><th>Version</th><th>Executable</th><th>Contacts</th><th>Last run</th><th>Advisories</th></tr></thead>
              <tbody>{scanners.map((s) => {
                const t = last?.tools?.find((x: any) => x.tool === s.tool);
                return (
                  <tr key={s.tool}>
                    <td><b>{s.displayName}</b><div className="faint small">{s.outputFormat}</div></td>
                    <td><span className={`chip ${STATE_CLASS[s.state] ?? ''}`}>{STATE_LABEL[s.state] ?? s.state}</span>{s.reason && <div className="small muted" style={{ marginTop: 4 }}>{s.reason}</div>}</td>
                    <td className="mono small">{s.version ?? '—'}</td>
                    <td className="mono small">{s.binary ?? '—'}</td>
                    <td className="small">{s.networkHosts.length ? s.networkHosts.join(', ') : <span className="muted">nothing (offline)</span>}</td>
                    <td>{t ? <span className={`chip ${RUN_CLASS[t.status] ?? ''}`}>{t.status.replace('_', ' ')}</span> : <span className="muted">—</span>}</td>
                    <td>{t?.observationCount ?? <span className="muted">—</span>}</td>
                  </tr>
                );
              })}</tbody>
            </table>
          )}
          {scanners && <details style={{ marginTop: 8 }}><summary className="small muted">Known limitations of each tool</summary>{scanners.map((s) => <div key={s.tool} style={{ marginTop: 6 }}><b className="small">{s.displayName}</b><ul className="explain limit">{s.limitations.map((l: string, i: number) => <li key={i}>{l}</li>)}</ul></div>)}</details>}
        </div>

        {!storeUp && <div className="empty">MongoDB is unavailable, so scan history and findings cannot be shown or stored. Scanner availability above is still checked live.</div>}

        {storeUp && runs && runs.some((r) => r.status !== 'running') && <DependencyCharts runs={runs} open={open} />}

        {storeUp && last && <LastRun run={last} ctx={ctx} />}
        {storeUp && runs && !runs.length && !running && <p className="muted">No dependency scan has run for this project yet.</p>}

        {storeUp && findings && (
          <div className="section">
            <h3>Open dependency findings <span className="muted small">({open.length})</span></h3>
            <p className="small muted">Each row is an installed package version with a published advisory. Use evidence comes from the existing code graph; it does not show whether the vulnerable function itself is called.</p>
            {open.length ? (
              <table className="tbl">
                <thead><tr><th>Severity</th><th>Package</th><th>Advisory</th><th>Published</th><th>Use in this app</th><th>Scanners</th><th /></tr></thead>
                <tbody>{open.map((f) => (
                  <tr key={f._id} className="clickable" onClick={() => ctx.select({ nodeId: null, path: null, from: `finding:${f._id}` }, 'issues')}>
                    <td><span className={`chip sev-${f.severity}`}>{f.severity}</span></td>
                    <td className="mono small">{f.pkg?.name}@{f.pkg?.version ?? '?'}{f.pkg?.devOnly ? <span className="faint"> dev</span> : ''}</td>
                    <td className="mono small">{f.canonicalId}</td>
                    <td className="small">{(f.evidence.severityByTool ?? []).map((s: any) => s.original ?? '?').join(' / ')}</td>
                    <td className="small">{f.pkg?.use ? USE_SHORT[f.pkg.use.evidence] ?? f.pkg.use.evidence : <span className="muted">unknown</span>}</td>
                    <td className="small">{(f.scanners ?? []).map((t) => TOOL_LABEL[t] ?? t).join(', ')}</td>
                    <td>{f.potentialRegression && <span className="chip st-failed">potential regression</span>}</td>
                  </tr>
                ))}</tbody>
              </table>
            ) : last?.counts ? <p className="muted">No open dependency findings from the scanners that ran.</p> : <p className="muted">No completed dependency scan, so there are no results to show (this is not the same as having no vulnerabilities).</p>}
          </div>
        )}

        <p className="small muted" style={{ padding: '0 20px' }}>Website vulnerability scanning (Nuclei) is under <b>Security tools → Web scanning</b> and <b>Website comparison → Security changes</b>.</p>

        {storeUp && runs && runs.length > 0 && (
          <div className="section">
            <h3>Scan history</h3>
            <table className="tbl"><thead><tr><th>Started</th><th>Status</th><th>Tools that completed</th><th>Advisories</th><th>New</th><th>Not currently observed</th><th>Run</th></tr></thead>
              <tbody>{runs.map((r) => (
                <tr key={r._id}>
                  <td className="muted">{timeAgo(r.startedAt)}</td>
                  <td><span className={`chip ${RUN_CLASS[r.status] ?? ''}`}>{r.status}</span>{r.staleAtFinish && <span className="chip st-inconclusive" style={{ marginLeft: 4 }}>stale</span>}</td>
                  <td className="small">{(r.tools ?? []).filter((t: any) => t.status === 'completed').map((t: any) => TOOL_LABEL[t.tool] ?? t.tool).join(', ') || <span className="muted">none</span>}</td>
                  <td>{r.counts ? r.counts.total : <span className="muted">not scanned</span>}</td>
                  <td>{r.counts?.new ?? '—'}</td>
                  <td>{r.counts?.notCurrentlyObserved ?? '—'}</td>
                  <td className="mono small muted">{r._id}</td>
                </tr>
              ))}</tbody></table>
          </div>
        )}
      </div>
    </div>
  );
}

function LastRun({ run, ctx }: { run: any; ctx: Ctx }) {
  const c = run.counts;
  const sev = c?.bySeverity ?? {};
  const dur = run.finishedAt ? Math.round((new Date(run.finishedAt).getTime() - new Date(run.startedAt).getTime()) / 100) / 10 : null;
  return (
    <div className="section">
      <h3>Latest scan <span className={`chip ${RUN_CLASS[run.status] ?? ''}`}>{run.status}</span> <span className="small muted">{timeAgo(run.startedAt)}{dur !== null ? ` · ${dur}s` : ''}</span></h3>
      {run.staleAtFinish && <p className="small" style={{ color: 'var(--warn)' }}>The lockfile changed while this scan was running; results describe the lockfile as it was when the scan started.</p>}
      <table className="tbl" style={{ marginBottom: 12 }}>
        <thead><tr><th>Lockfile</th><th>Coverage</th><th>Scanned by</th><th>Why</th></tr></thead>
        <tbody>{(run.coverage ?? []).map((cv: any, i: number) => (
          <tr key={i}><td className="mono small">{cv.lockfile} <span className="faint">({cv.ecosystem})</span></td><td><span className={`chip ${COVERAGE_CLASS[cv.status] ?? ''}`}>{COVERAGE_LABEL[cv.status] ?? cv.status}</span></td><td className="small">{cv.by.map((t: string) => TOOL_LABEL[t] ?? t).join(', ') || '—'}</td><td className="small muted">{cv.reason ?? ''}</td></tr>
        ))}</tbody>
      </table>
      {c ? (
        <div className="stats" style={{ marginBottom: 12 }}>
          <div className="stat"><div className="n" style={{ color: 'var(--bad)' }}>{sev.high ?? 0}</div><div className="muted small">high</div></div>
          <div className="stat"><div className="n">{sev.medium ?? 0}</div><div className="muted small">medium</div></div>
          <div className="stat"><div className="n">{(sev.low ?? 0) + (sev.info ?? 0)}</div><div className="muted small">low / info</div></div>
          <div className="stat"><div className="n">{sev.unknown ?? 0}</div><div className="muted small">severity not supplied</div></div>
          <div className="stat"><div className="n">{c.new}</div><div className="muted small">new · {c.recurring} recurring</div></div>
          <div className="stat"><div className="n">{c.notCurrentlyObserved}</div><div className="muted small">not currently observed</div></div>
          <div className="stat"><div className="n" style={{ color: c.regressions ? 'var(--bad)' : undefined }}>{c.regressions}</div><div className="muted small">potential regressions</div></div>
          <div className="stat"><div className="n" style={{ color: 'var(--ok)' }}>{c.resolvedVersionRemoved}</div><div className="muted small">resolved (version removed)</div></div>
        </div>
      ) : <p className="muted">No vulnerability counts: no lockfile was scanned successfully in this run.</p>}
      {c?.notRechecked > 0 && <p className="small muted">{c.notRechecked} earlier finding(s) were not re-checked because the scanner that reported them did not run this time; they stay open.</p>}
      <table className="tbl">
        <thead><tr><th>Tool</th><th>Result</th><th>Exit</th><th>Time</th><th>Advisories</th><th>Notes</th></tr></thead>
        <tbody>{(run.tools ?? []).map((t: any, i: number) => (
          <tr key={i}>
            <td>{t.displayName} <span className="faint small">{t.version ?? ''}</span></td>
            <td><span className={`chip ${RUN_CLASS[t.status] ?? ''}`}>{t.status.replace('_', ' ')}</span>{t.reason && <div className="small muted" style={{ marginTop: 4 }}>{t.reason}</div>}</td>
            <td className="mono small">{t.exitCode ?? '—'}</td>
            <td className="small">{t.durationMs != null ? `${Math.round(t.durationMs)}ms` : '—'}</td>
            <td>{t.observationCount ?? <span className="muted">—</span>}</td>
            <td className="small">
              {t.notes.map((n: string, k: number) => <div key={k} className="muted">{n}</div>)}
              {t.reportRef && <a href={artifactUrl(ctx.projectId, t.reportRef)} target="_blank" rel="noreferrer">raw report</a>}
              {t.stderrTail && <details><summary className="muted">stderr</summary><pre className="log">{t.stderrTail}</pre></details>}
            </td>
          </tr>
        ))}</tbody>
      </table>
    </div>
  );
}

/** Advisories per scanner on the latest run, and advisories found per run over time. */
function DependencyCharts({ runs, open }: { runs: any[]; open: Finding[] }) {
  const done = runs.filter((r) => r.status !== 'running');
  const last = done[0];
  const perTool = (last?.tools ?? []).map((t: any) => ({ key: t.tool, label: TOOL_LABEL[t.tool] ?? t.tool, values: { n: t.observationCount ?? 0 } }));
  const sev = SEVERITY_ORDER.map((k) => ({ key: k, label: k, color: SEVERITY_COLOR[k] }));
  const sevRows = [{ key: 'open', label: 'Open findings', values: Object.fromEntries(SEVERITY_ORDER.map((k) => [k, open.filter((f) => f.severity === k).length])) }];
  const timeline = done.slice(0, 20).reverse().map((r) => ({
    key: r._id, tick: new Date(r.startedAt).toLocaleDateString([], { month: 'short', day: 'numeric' }), title: new Date(r.startedAt).toLocaleString(),
    values: { n: (r.tools ?? []).reduce((a: number, t: any) => a + (t.observationCount ?? 0), 0) },
  }));
  if (timeline.every((t) => t.values.n === 0) && !open.length) {
    return (
      <div className="clean-state glass">
        <span className="clean-icon"><Icon.check /></span>
        <div>
          <b>No advisories in the last {timeline.length} completed scan{timeline.length === 1 ? '' : 's'}</b>
          <p className="small muted">{perTool.length} scanner{perTool.length === 1 ? '' : 's'} ran on the latest scan ({perTool.map((t: any) => t.label).join(', ')}), {timeAgo(last?.startedAt)}. Charts appear here once a scan reports an advisory.</p>
        </div>
      </div>
    );
  }
  return (
    <div className="charts-row">
      <ChartCard title="Advisories per scanner" sub={`Latest run · ${timeAgo(last?.startedAt)}`}
        table={{ head: ['Scanner', 'Advisories'], rows: perTool.map((t: any) => [t.label, t.values.n]) }}>
        {perTool.length ? <HBars rows={perTool} series={[{ key: 'n', label: 'Advisories', color: SERIES[0] }]} /> : <p className="chart-empty">No scanner results on the latest run.</p>}
      </ChartCard>
      <ChartCard title="Advisories found per run" sub={`Last ${timeline.length} completed scans, oldest first`}
        table={{ head: ['When', 'Advisories'], rows: timeline.map((t) => [t.title, t.values.n]) }}>
        <Columns buckets={timeline} series={[{ key: 'n', label: 'Advisories', color: SERIES[0] }]} height={160} />
      </ChartCard>
      {open.length > 0 && (
        <ChartCard title="Open dependency findings by severity" wide table={{ head: ['Severity', 'Count'], rows: SEVERITY_ORDER.map((k) => [k, sevRows[0].values[k]]) }}>
          <HBars rows={sevRows} series={sev} />
        </ChartCard>
      )}
    </div>
  );
}
