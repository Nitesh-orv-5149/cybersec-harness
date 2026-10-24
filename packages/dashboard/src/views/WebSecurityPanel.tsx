// Security changes: nuclei scans of the baseline/current snapshots or an authorized running app, with a live view of
// what nuclei is doing, and the comparison of findings between scans. Kept separate from the visual comparison on
// purpose: a visual difference is not a vulnerability, and nuclei does not compare screenshots.
// Used in Website comparison (next to the website changes) and in the Dependency scan tab.
import { useEffect, useState } from 'react';
import type { Ctx } from '../App';
import { api, artifactUrl, timeAgo, ApiError, type Finding } from '../api';

export const RUN_TEXT: Record<string, string> = {
  running: 'Running', completed: 'Completed', incomplete: 'Incomplete', failed: 'Failed', cancelled: 'Cancelled', unavailable: 'Unavailable',
};
export const RUN_CLASS: Record<string, string> = {
  running: 'st-analyzing', completed: 'st-completed', incomplete: 'st-inconclusive', failed: 'st-failed', cancelled: 'st-cancelled', unavailable: 'st-failed',
  pending: '', starting: 'st-building', scanning: 'st-analyzing', timed_out: 'st-inconclusive',
};
const SIDE_LABEL: Record<string, string> = { baseline: 'Baseline app', candidate: 'Current app', target: 'Target' };
const SEV_ORDER = ['high', 'medium', 'low', 'info', 'unknown'];
const PROFILE_TEXT: Record<string, string> = {
  quick: 'Quick: misconfigurations, exposed config files, technology detection',
  standard: 'Standard: + all exposures, exposed admin panels, known vulnerabilities and CVEs',
  full: 'Full: every HTTP template that passes the safety checks',
  custom: 'Custom: security.nuclei.templates from workbench.config.json',
};

const safeHref = (u: string) => (/^https?:\/\//i.test(u) ? u : null);
const dur = (ms: number | null | undefined) => (ms == null ? '—' : ms < 1000 ? `${ms}ms` : ms < 60_000 ? `${(ms / 1000).toFixed(1)}s` : `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`);
export const isTech = (o: { tags?: string[]; templateId: string; severity: string }) => o.severity === 'info' && ((o.tags ?? []).includes('tech') || /tech-detect|fingerprint/.test(o.templateId));

// ------------------------------------------------------------------ presentational pieces

export function ReadinessBox({ ov, checking, onRecheck, onUpdateTemplates }: { ov: any; checking?: boolean; onRecheck?: () => void; onUpdateTemplates?: () => void }) {
  const r = ov.readiness;
  const t = ov.templates;
  const up = ov.templateUpdate;
  const ok = (b: boolean) => <span className={`dot ${b ? 'on' : 'off'}`} />;
  return (
    <div className="box" aria-label="Nuclei readiness">
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <h3 style={{ margin: 0 }}>Nuclei</h3>
        <div className="row">
          {onUpdateTemplates && r.state === 'ready' && <button className="btn small" disabled={up?.running} onClick={onUpdateTemplates}>{up?.running ? 'Downloading templates…' : r.templates.state === 'ready' ? 'Update templates…' : 'Download templates…'}</button>}
          {onRecheck && <button className="btn small" disabled={checking} onClick={onRecheck}>{checking ? 'Checking…' : 'Re-check'}</button>}
        </div>
      </div>
      <dl className="kv small" style={{ marginTop: 8 }}>
        <dt>Executable</dt>
        <dd>{ok(r.state === 'ready')} {r.state === 'ready' ? <>v{r.version} <span className="mono faint">{r.binary}</span></> : <>{r.state.replace('_', ' ')}{r.reason ? `: ${r.reason}` : ''}</>}</dd>
        <dt>Templates</dt>
        <dd>{ok(r.templates.state === 'ready')} {r.templates.state === 'ready'
          ? <>{r.templates.version ? `v${r.templates.version} ` : ''}<span className="mono faint">{r.templates.dir}</span></>
          : <>{r.templates.state}{r.templates.reason ? `: ${r.templates.reason}` : ''}</>}</dd>
        {t && <><dt>Vetted set</dt><dd>{t.approved} approved · {t.rejected} excluded by the safety checks{t.missing.length ? ` · missing: ${t.missing.join(', ')}` : ''}</dd></>}
      </dl>
      {up && !up.running && up.ok !== null && (
        <details style={{ marginTop: 6 }} open={!up.ok}>
          <summary className="small" style={{ color: up.ok ? 'var(--ok)' : 'var(--bad)' }}>Template download {up.ok ? 'finished' : 'failed'} {timeAgo(up.finishedAt)}</summary>
          <pre className="log">{up.output}</pre>
        </details>
      )}
      {r.missingOptionalFlags?.length > 0 && <p className="small muted" style={{ marginTop: 6 }}>This nuclei build lacks optional flags: {r.missingOptionalFlags.map((f: string) => `-${f}`).join(', ')}.</p>}
      {ov.configFile && <p className="small" style={{ color: 'var(--warn)', marginTop: 6 }}>{ov.configFile}</p>}
      {!ov.usable && (
        <div style={{ marginTop: 8 }}>
          <p className="small"><b>Security scanning is unavailable.</b> {ov.reasons.join('; ')}</p>
          <ol className="explain small muted">{ov.setup.map((s: string, i: number) => <li key={i}>{s}</li>)}</ol>
        </div>
      )}
      {t && t.rejectedByReason.length > 0 && (
        <details style={{ marginTop: 6 }}><summary className="small muted">Why templates were excluded</summary>
          <ul className="explain small muted">{t.rejectedByReason.map((x: any) => <li key={x.reason}>{x.count} × {x.reason}</li>)}</ul>
        </details>
      )}
    </div>
  );
}

/** Live view of a running scan: nuclei's own statistics and what it is doing right now. */
export function LiveScan({ job }: { job: any }) {
  const p = job.progress;
  const feed: any[] = job.activity ?? [];
  return (
    <div className="box live" aria-label="Live scan">
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <b className="small">{job.side ? SIDE_LABEL[job.side] : 'Scan'} · {job.phase ?? 'scanning'}</b>
        <span className="small faint">{job.profile} profile · started {timeAgo(job.startedAt)}</span>
      </div>
      {p ? (
        <>
          <div className="progress" role="progressbar" aria-valuenow={p.percent} aria-valuemin={0} aria-valuemax={100}><span style={{ width: `${p.percent}%` }} /></div>
          <div className="row small">
            <span><b>{p.percent}%</b></span>
            <span className="muted">{p.requests.toLocaleString()} / {p.total.toLocaleString()} requests</span>
            <span className="muted">{p.rps} req/s</span>
            <span className="muted">{p.templates} templates × {p.hosts} URL{p.hosts === 1 ? '' : 's'}</span>
            <span style={{ color: p.matched ? 'var(--bad)' : undefined }}>{p.matched} matched</span>
            <span className="muted">{p.errors} errors</span>
            <span className="faint">{p.duration}</span>
          </div>
        </>
      ) : <p className="small muted">{job.findingsSoFar ? `${job.findingsSoFar} result(s) so far` : 'Waiting for nuclei statistics…'}</p>}
      <ActivityFeed events={feed.slice(-25)} />
    </div>
  );
}

export function ActivityFeed({ events }: { events: any[] }) {
  if (!events.length) return null;
  return (
    <ol className="feed" aria-label="Scan activity">
      {events.map((e, i) => (
        <li key={i} className={`feed-${e.kind}`}>
          <span className="faint mono">{new Date(e.at).toLocaleTimeString()}</span>
          {e.kind === 'match' ? <span className={`chip sev-${e.severity === 'critical' ? 'high' : e.severity}`}>{e.severity}</span> : <span className="feed-kind">{e.kind === 'command' ? '$' : e.kind}</span>}
          <span className={e.kind === 'command' ? 'mono small' : 'small'}>{e.text}</span>
        </li>
      ))}
    </ol>
  );
}

export function SeverityTotals({ counts }: { counts: Record<string, number> | null | undefined }) {
  if (!counts) return <p className="muted small">No severity totals: this scan did not produce a usable result.</p>;
  return (
    <div className="stats" aria-label="Severity totals">
      {SEV_ORDER.map((s) => (
        <div key={s} className="stat"><div className="n" style={{ color: s === 'high' && counts[s] ? 'var(--bad)' : undefined }}>{counts[s] ?? 0}</div><div className="muted small">{s === 'unknown' ? 'severity not supplied' : s}</div></div>
      ))}
    </div>
  );
}

const BUCKETS: { key: 'new' | 'recurring' | 'absent' | 'returned'; label: string; hint: string; cls: string }[] = [
  { key: 'new', label: 'New', hint: 'matched now, not in the comparison scan', cls: 'st-failed' },
  { key: 'returned', label: 'Returned (potential regression)', hint: 'previously no longer observed, matched again', cls: 'st-failed' },
  { key: 'recurring', label: 'Still present', hint: 'matched in both scans', cls: 'st-observed' },
  { key: 'absent', label: 'No longer observed', hint: 'the same templates ran on a comparable scan and did not match', cls: 'st-completed' },
];

export function SecurityComparison({ run, byId, onOpen }: { run: any; byId: Map<string, Finding>; onOpen?: (id: string) => void }) {
  const c = run.comparison;
  if (!c) return <p className="muted">No comparison: the scan was {run.status}.</p>;
  const against = run.mode === 'snapshots'
    ? 'the baseline snapshot, scanned in the same run'
    : c.against ? `the previous completed scan of this target (${timeAgo(c.against.startedAt)}, ${String(c.against.runId).slice(0, 14)})` : 'no earlier scan';
  return (
    <div aria-label="Security comparison">
      <p className="small muted">Compared with {against}. Findings are matched by template, matcher and endpoint (path and query parameter names).</p>
      {!c.comparable && (
        <div className="banner warn" style={{ borderRadius: 4, marginBottom: 8 }}>
          Not a valid comparison: {c.reasons.join('; ')}. Nothing is reported as fixed or no longer observed from this scan.
        </div>
      )}
      <div className="buckets">
        {BUCKETS.filter((b) => c.comparable || b.key === 'returned').map((b) => {
          const ids: string[] = c[b.key] ?? [];
          return (
            <section key={b.key} className="bucket">
              <h4><span className={`chip ${b.cls}`}>{ids.length}</span> {b.label}</h4>
              <p className="faint small">{b.hint}</p>
              <ul className="list">{ids.slice(0, 50).map((id) => {
                const f = byId.get(id);
                return <li key={id}><button onClick={() => onOpen?.(id)}><span className={`chip sev-${f?.severity ?? 'unknown'}`}>{f?.severity ?? '?'}</span><span className="lbl">{f?.title ?? id}</span></button></li>;
              })}</ul>
            </section>
          );
        })}
      </div>
    </div>
  );
}

export function FindingsTable({ rows, selected, onSelect, lifecycle }: { rows: any[]; selected?: string | null; onSelect?: (fid: string) => void; lifecycle: Map<string, Finding> }) {
  if (!rows.length) return <p className="muted">No vulnerability or misconfiguration template matched on this side.</p>;
  return (
    <table className="tbl" aria-label="Security findings">
      <thead><tr><th>Severity</th><th>Template</th><th>Matched at</th><th>Code</th><th>Status</th></tr></thead>
      <tbody>{rows.map((o) => {
        const f = lifecycle.get(o.findingId);
        const corr = f?.web?.correlation;
        return (
          <tr key={o._id} className="clickable" aria-selected={selected === o.findingId} onClick={() => onSelect?.(o.findingId)}>
            <td><span className={`chip sev-${o.severity}`}>{o.severity}</span>{o.originalSeverity && o.originalSeverity !== o.severity && <div className="faint small">published {o.originalSeverity}</div>}</td>
            <td><span className="mono small">{o.templateId}</span><div className="faint small">{o.name}</div></td>
            <td className="mono small" style={{ wordBreak: 'break-all' }}>{o.matchedAt}{o.occurrences > 1 && <span className="faint"> ×{o.occurrences}</span>}</td>
            <td className="small">{corr?.status === 'linked' ? <span className="chip st-observed">{corr.endpointId?.replace(/^ep:/, '')}</span> : <span className="muted">unlinked web finding</span>}</td>
            <td>{f ? <span className={`chip st-${f.status}`}>{(f.status ?? 'open').replace(/_/g, ' ')}</span> : <span className="muted">—</span>}{f?.potentialRegression && f.status === 'open' && <span className="chip st-failed" style={{ marginLeft: 4 }}>returned</span>}</td>
          </tr>
        );
      })}</tbody>
    </table>
  );
}

export function TechList({ rows }: { rows: any[] }) {
  if (!rows.length) return null;
  const items = rows.map((o) => ({ name: o.matcherName ?? o.extractedResults?.[0] ?? o.name ?? o.templateId, where: o.endpoint, tpl: o.templateId }));
  return (
    <div className="section">
      <h3>Detected technologies <span className="small muted">({items.length})</span></h3>
      <p className="small muted">Fingerprints (informational), not vulnerabilities. They tell you what the scanner believes the site runs on.</p>
      <div className="row">{items.map((t, i) => <span key={i} className="chip" title={`${t.tpl} at ${t.where}`}>{t.name}<span className="faint"> {t.where !== '/' ? t.where : ''}</span></span>)}</div>
    </div>
  );
}

export function WebFindingEvidence({ o, f, history, onOpenFinding, onOpenCode }: { o: any; f?: Finding; history?: any[]; onOpenFinding?: () => void; onOpenCode?: (loc: { file: string; line: number }) => void }) {
  const corr = f?.web?.correlation;
  return (
    <div className="box" style={{ marginTop: 10 }} aria-label="Finding details">
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <h3 style={{ margin: 0 }}>{o.name ?? o.templateId}</h3>
        {onOpenFinding && <button className="btn small" onClick={onOpenFinding}>Open in Findings</button>}
      </div>
      <p className="small muted" style={{ marginTop: 4 }}>Scanner result (nuclei). A matched template is evidence of the matched condition, not proof that it is exploitable.</p>
      <dl className="kv wide small">
        <dt>Template ID</dt><dd className="mono">{o.templateId}{o.templatePath && <span className="faint"> · {o.templatePath}</span>}</dd>
        <dt>Matched at</dt><dd className="mono">{o.method ? `${o.method} ` : ''}{o.matchedAt}</dd>
        {o.input && o.input !== '/' && <><dt>Scanned URL</dt><dd className="mono">{o.input} <span className="faint">(route from the code graph)</span></dd></>}
        <dt>Host</dt><dd className="mono">{o.host ?? '—'}{o.ip ? ` (${o.ip})` : ''}</dd>
        <dt>Severity</dt><dd>{o.severity}{o.originalSeverity ? ` (template: ${o.originalSeverity})` : ''}{o.classification?.cvssScore != null && ` · CVSS ${o.classification.cvssScore}`}</dd>
        {o.tags?.length > 0 && <><dt>Tags</dt><dd>{o.tags.map((t: string) => <span key={t} className="chip" style={{ marginRight: 4 }}>{t}</span>)}</dd></>}
        {(o.matcherName || o.extractorName) && <><dt>Matcher</dt><dd className="mono">{[o.matcherName, o.extractorName].filter(Boolean).join(' · ')}</dd></>}
        {o.extractedResults?.length > 0 && <><dt>Extracted</dt><dd className="mono">{o.extractedResults.join(', ')}</dd></>}
        {(o.classification?.cve?.length > 0 || o.classification?.cwe?.length > 0) && <><dt>Classification</dt><dd className="mono">{[...o.classification.cve, ...o.classification.cwe].join(', ')}</dd></>}
        <dt>Code</dt>
        <dd>{corr?.status === 'linked'
          ? <>{corr.reason} {corr.handlerLocations.map((l: any) => <button key={`${l.file}:${l.line}`} className="btn small" style={{ marginLeft: 4 }} onClick={() => onOpenCode?.(l)}>{l.file}:{l.line}</button>)}</>
          : <span className="muted">Unlinked web finding. {corr?.reason ?? ''}</span>}</dd>
      </dl>
      {o.description && <p className="small" style={{ marginTop: 8 }}>{o.description}</p>}
      {o.request && <details open><summary className="small muted">Request (redacted)</summary><pre className="log">{o.request}</pre></details>}
      {o.response && <details><summary className="small muted">Response (redacted{o.evidenceTruncated ? ', truncated' : ''})</summary><pre className="log">{o.response}</pre></details>}
      {o.curlCommand && <details><summary className="small muted">curl (redacted)</summary><pre className="log">{o.curlCommand}</pre></details>}
      {o.references?.length > 0 && <ul className="list small" style={{ marginTop: 6 }}>{o.references.map((u: string) => { const h = safeHref(u); return <li key={u}>{h ? <a href={h} target="_blank" rel="noreferrer noopener">{u}</a> : <span className="mono">{u}</span>}</li>; })}</ul>}
      {history && (
        <>
          <h3>Scan history</h3>
          {history.length ? <table className="tbl"><tbody>{history.map((r) => <tr key={r._id}><td className="muted" style={{ whiteSpace: 'nowrap' }}>{new Date(r.at).toLocaleString()}</td><td>{r.action.replace(/_/g, ' ')}</td><td className="mono small muted">{r.securityRunId}</td><td className="muted small">{r.result}</td></tr>)}</tbody></table> : <p className="muted small">No records yet.</p>}
        </>
      )}
    </div>
  );
}

export function SideStatus({ name, side, live }: { name: string; side: any; live?: { findingsSoFar: number; progress?: any } | null }) {
  const cls = RUN_CLASS[side.status] ?? '';
  return (
    <span className={`stage ${side.status === 'completed' ? 'done' : ['failed', 'timed_out'].includes(side.status) ? 'failed' : ['starting', 'scanning'].includes(side.status) ? 'active' : ''}`}>
      {SIDE_LABEL[name] ?? name}: <span className={cls ? '' : 'muted'}>{side.status.replace('_', ' ')}</span>
      {side.phase && <span className="faint"> · {side.phase}</span>}
      {live && side.status === 'scanning' && <span className="faint"> · {live.progress ? `${live.progress.percent}% · ` : ''}{live.findingsSoFar} result{live.findingsSoFar === 1 ? '' : 's'} so far</span>}
      {side.findings != null && side.status !== 'scanning' && <span className="faint"> · {side.findings} finding{side.findings === 1 ? '' : 's'}</span>}
    </span>
  );
}

export function WebRunDetail({ run, observations, findings, job, projectId, history, selected, onSelect, onOpenFinding, onOpenCode }: {
  run: any; observations: any[]; findings: Finding[]; job?: any; projectId: string; history?: any[];
  selected?: string | null; onSelect?: (fid: string | null) => void; onOpenFinding?: (fid: string) => void; onOpenCode?: (l: { file: string; line: number }) => void;
}) {
  const byId = new Map(findings.map((f) => [f._id, f]));
  const sideNames = Object.keys(run.sides ?? {});
  const currentSide = run.mode === 'snapshots' ? 'candidate' : 'target';
  const [side, setSide] = useState(currentSide);
  const sideObs = observations.filter((o) => o.side === side).sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  const rows = sideObs.filter((o) => !isTech(o));
  const tech = sideObs.filter((o) => isTech(o));
  const sel = sideObs.find((o) => o.findingId === selected);
  const live = job?.runId === run._id ? job : null;
  const s = run.sides?.[side] ?? {};
  return (
    <>
      <div className="section cmp-head">
        <div className="row">
          <span className={`chip ${RUN_CLASS[run.status] ?? ''}`}>{RUN_TEXT[run.status] ?? run.status}</span>
          {run.profile && <span className="chip">{run.profile} profile</span>}
          <span className="mono small faint">{run._id}</span>
          {run.toolVersion && <span className="small faint">nuclei {run.toolVersion}</span>}
          {run.templateSet?.version && <span className="small faint">templates {run.templateSet.version}</span>}
        </div>
        <p className="small">
          {run.mode === 'snapshots'
            ? <>Baseline snapshot <span className="mono">{run.target?.baselineSnapshotId?.slice(5, 17) ?? '…'}</span> and your files as of <span className="mono">{run.target?.candidateSnapshotId?.slice(5, 17) ?? '…'}</span>, each started on a private loopback port.</>
            : <>Target <span className="mono">{run.target?.url}</span>{run.target?.loopback ? ' (loopback)' : ' (authorized target)'}.</>}
          {' '}Started {timeAgo(run.startedAt)}{run.durationMs != null && ` · took ${dur(run.durationMs)}`} · {run.templateSet?.approvedCount ?? 0} vetted templates · {(run.target?.endpoints?.length ?? 0) + 1} URL{run.target?.endpoints?.length ? 's' : ''} · {run.settings?.rateLimit} req/s · {run.settings?.methods?.join('/')} only · redirects {run.settings?.redirects === 'none' ? 'not followed' : 'same host only'}.
        </p>
        <div className="pipeline">{sideNames.map((n) => <SideStatus key={n} name={n} side={run.sides[n]} live={live} />)}</div>
        {run.error && <div className="banner" style={{ borderRadius: 4 }}>{run.error}</div>}
        {run.setup && <ol className="explain small muted">{run.setup.map((x: string, i: number) => <li key={i}>{x}</li>)}</ol>}
        {sideNames.map((n) => run.sides[n].reason && <div key={n} className={`banner ${run.sides[n].status === 'failed' ? '' : 'warn'}`} style={{ borderRadius: 4 }}>{SIDE_LABEL[n]}: {run.sides[n].reason}</div>)}
        {run.staleAtFinish && <div className="banner warn" style={{ borderRadius: 4 }}>Your files changed during the scan; results describe the snapshot taken at the start.</div>}
        {run.notes?.map((n: string) => <p key={n} className="small muted">{n}</p>)}
      </div>

      {live && <div className="section"><LiveScan job={live} /></div>}

      {run.status !== 'running' && run.status !== 'unavailable' && (
        <>
          <div className="section"><h3>Security changes</h3><SecurityComparison run={run} byId={byId} onOpen={(id) => onSelect?.(id)} /></div>
          <div className="section"><h3>Severity totals <span className="small muted">({SIDE_LABEL[currentSide].toLowerCase()})</span></h3><SeverityTotals counts={run.sides?.[currentSide]?.bySeverity} /></div>
        </>
      )}

      {(observations.length > 0 || run.status !== 'running') && run.status !== 'unavailable' && (
        <div className="section">
          <div className="row" style={{ justifyContent: 'space-between' }}>
            <h3>Vulnerabilities and misconfigurations <span className="small muted">({rows.length})</span></h3>
            {sideNames.length > 1 && (
              <select className="input" style={{ width: 'auto' }} value={side} onChange={(e) => setSide(e.target.value)} aria-label="Side">
                {sideNames.map((n) => <option key={n} value={n}>{SIDE_LABEL[n]}</option>)}
              </select>
            )}
          </div>
          {s.findings == null && run.status !== 'running'
            ? <p className="muted">This side has no usable result ({s.status}). That is not the same as no findings.</p>
            : <FindingsTable rows={rows} selected={selected} onSelect={(fid) => onSelect?.(selected === fid ? null : fid)} lifecycle={byId} />}
          {sel && <WebFindingEvidence o={sel} f={byId.get(sel.findingId)} history={history} onOpenFinding={() => onOpenFinding?.(sel.findingId)} onOpenCode={onOpenCode} />}
        </div>
      )}
      <TechList rows={tech} />

      {run.status !== 'unavailable' && (
        <div className="section">
          <h3>How the website was scanned</h3>
          <dl className="kv wide small">
            <dt>URLs scanned</dt><dd className="mono">{(s.inputs?.length ? s.inputs : ['/', ...(run.target?.endpoints ?? [])]).join('  ')}</dd>
            {s.command && <><dt>Command</dt><dd className="mono">{s.command}</dd></>}
            {s.stats && <><dt>Requests</dt><dd>{s.stats.requests.toLocaleString()} sent · {s.stats.errors} errors · {s.stats.rps} req/s · {s.stats.duration}</dd></>}
            <dt>Templates</dt><dd>{s.templatesLoaded ?? 'unknown'} loaded by nuclei of {run.templateSet?.approvedCount ?? '?'} approved{run.templateSet?.rejectedCount ? ` (${run.templateSet.rejectedCount} excluded by the safety checks)` : ''}</dd>
          </dl>
          <table className="tbl" style={{ marginTop: 8 }}><thead><tr><th>Side</th><th>Exit</th><th>Time</th><th>Output</th><th>Notes</th></tr></thead>
            <tbody>{sideNames.map((n) => {
              const x = run.sides[n];
              return (
                <tr key={n}>
                  <td>{SIDE_LABEL[n]}{x.url && <div className="mono faint small">{x.url}</div>}</td>
                  <td className="mono small">{x.exitCode ?? '—'}</td>
                  <td className="small">{dur(x.durationMs)}</td>
                  <td className="small">{x.malformedLines ? `${x.malformedLines} malformed line(s) ` : ''}{x.outOfScope?.length ? `${x.outOfScope.length} out-of-scope ` : ''}{x.reportRef && <a href={artifactUrl(projectId, x.reportRef)} target="_blank" rel="noreferrer">redacted JSONL</a>}</td>
                  <td className="small">
                    {[...(x.toolErrors ?? []), ...(x.warnings ?? [])].slice(0, 6).map((w: string, i: number) => <div key={i} className="muted">{w}</div>)}
                    {x.stderrTail && <details><summary className="muted">nuclei log</summary><pre className="log">{x.stderrTail}</pre></details>}
                    {x.appLog && <details><summary className="muted">app log</summary><pre className="log">{x.appLog}</pre></details>}
                  </td>
                </tr>
              );
            })}</tbody>
          </table>
          {!live && run.activity?.length > 0 && <details style={{ marginTop: 8 }}><summary className="small muted">Scan activity ({run.activity.length} events)</summary><ActivityFeed events={run.activity} /></details>}
        </div>
      )}
      <div className="section">
        <h3>Limitations</h3>
        <ul className="explain limit">
          <li>Website changes (screenshots, DOM, assertions) and security changes (nuclei template matches) are separate results. A visual difference is not a vulnerability, and a security finding says nothing about how the page looks.</li>
          <li>Only vetted templates ran: plain HTTP, {run.settings?.methods?.join('/') ?? 'GET'} requests, no out-of-band, fuzzing, brute-force, code, headless or intrusive templates. Pages and issues those templates do not cover are not tested.</li>
          <li>A finding is "no longer observed" only after a completed scan of the same target ran the template that reported it against the same URL. Failed, cancelled or incomplete scans never clear anything.</li>
          <li>Graph links are route matches on the URL path; they do not trace the request through the code.</li>
        </ul>
      </div>
    </>
  );
}

// ------------------------------------------------------------------ stateful panel

export function WebSecurityPanel({ ctx }: { ctx: Ctx }) {
  const [ov, setOv] = useState<any>(null);
  const [checking, setChecking] = useState(false);
  const [runs, setRuns] = useState<any[] | null>(null);
  const [runId, setRunId] = useState<string | null>(null);
  const [mode, setMode] = useState<'snapshots' | 'url'>('url');
  const [url, setUrl] = useState('');
  const [profile, setProfile] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const job = ctx.status.security?.web?.job ?? null;
  const updating = ctx.status.security?.web?.templateUpdate?.running;
  const storeUp = ctx.status.store.available;

  const loadOverview = (refresh = false) => {
    setChecking(true);
    api.get<any>(`/api/projects/${ctx.projectId}/security/web${refresh ? '?refresh=1' : ''}`)
      .then((o) => { setOv(o); setUrl((u) => u || o.targets.defaultTarget); setProfile((p) => p ?? o.defaultProfile); })
      .catch((e) => setMsg(e.message)).finally(() => setChecking(false));
  };
  useEffect(() => { loadOverview(); }, [ctx.projectId]);
  useEffect(() => { if (updating === false) loadOverview(true); }, [updating]);
  useEffect(() => {
    if (!storeUp) { setRuns(null); return; }
    api.get<any[]>(`/api/projects/${ctx.projectId}/security/web/scans`).then(setRuns).catch(() => setRuns([]));
  }, [ctx.projectId, ctx.ticks.websec, storeUp]);
  useEffect(() => { if (job?.runId) setRunId(job.runId); }, [job?.runId]);

  const start = async () => {
    setBusy(true); setMsg(null);
    try {
      const r = await api.post<any>(`/api/projects/${ctx.projectId}/security/web/scans`, { mode, ...(mode === 'url' ? { url } : {}), ...(profile && profile !== 'custom' ? { profile } : {}), confirm: true });
      setRunId(r.runId);
      ctx.refreshStatus();
    } catch (e) {
      const ae = e as ApiError;
      if (ae.body?.runId) setRunId(ae.body.runId);
      setMsg(ae.body?.reasons ? `${ae.message}: ${ae.body.reasons.join('; ')}` : ae.message);
    } finally { setBusy(false); setConfirming(false); setAuthorized(false); }
  };
  const updateTemplates = async () => {
    if (!confirm('Download or update the public nuclei-templates now? This runs `nuclei -ut`, which downloads from GitHub into your templates directory.')) return;
    setMsg(null);
    try { await api.post(`/api/projects/${ctx.projectId}/security/web/templates/update`, { confirm: true }); ctx.refreshStatus(); loadOverview(); }
    catch (e) { setMsg((e as Error).message); }
  };

  const current = runs?.find((r) => r._id === runId) ?? runs?.[0];
  const snapOk = ov?.targets.snapshots.ok;
  const sel = ov && profile ? ov.profiles?.[profile] : null;
  const rate = ov ? (mode === 'url' && url && !/^https?:\/\/(localhost|127\.|\[::1\])/i.test(url) ? ov.settings.remoteRateLimit : ov.settings.rateLimit) : null;
  const eps: string[] = ov?.targets.graphEndpoints ?? [];
  const targetLabel = mode === 'snapshots' ? 'the baseline and current copies of your app, started by the workbench on private loopback ports' : url;
  return (
    <div className="col-body">
      <div className="col-controls">
        {ov ? <ReadinessBox ov={{ ...ov, templates: sel ?? ov.templates }} checking={checking} onRecheck={() => loadOverview(true)} onUpdateTemplates={() => void updateTemplates()} /> : <p className="muted small">Checking nuclei…</p>}
        <fieldset className="targets" disabled={!!job}>
          <legend className="small muted">What to scan</legend>
          <label className="row small"><input type="radio" name="wmode" checked={mode === 'url'} onChange={() => setMode('url')} /> Running website URL</label>
          {mode === 'url' && (
            <>
              <input className="input mono" value={url} onChange={(e) => { setUrl(e.target.value); setConfirming(false); }} aria-label="Target URL" placeholder="http://127.0.0.1:3000" />
              <p className="faint small">Loopback addresses are allowed. Any other origin must be listed in <span className="mono">security.nuclei.authorizedTargets</span>{ov?.targets.authorizedTargets.length ? ` (${ov.targets.authorizedTargets.join(', ')})` : ''}.</p>
            </>
          )}
          <label className="row small"><input type="radio" name="wmode" checked={mode === 'snapshots'} onChange={() => setMode('snapshots')} disabled={ov && !snapOk} /> Baseline vs. current files (workbench starts both)</label>
          {ov && !snapOk && <ul className="explain small faint">{ov.targets.snapshots.reasons.map((r: string) => <li key={r}>{r}</li>)}</ul>}
          {ov && Object.keys(ov.profiles ?? {}).length > 0 && (
            <label className="small" style={{ display: 'grid', gap: 4 }}>Templates
              <select className="input" value={profile ?? ''} onChange={(e) => { setProfile(e.target.value); setConfirming(false); }} aria-label="Scan profile">
                {Object.entries(ov.profiles).map(([p, t]: [string, any]) => <option key={p} value={p}>{PROFILE_TEXT[p] ?? p}{t ? ` (${t.approved} templates)` : ''}</option>)}
              </select>
            </label>
          )}
          {eps.length > 0 && <p className="faint small">Also scans {eps.length} GET route{eps.length === 1 ? '' : 's'} from your code: <span className="mono">{eps.slice(0, 6).join(' ')}{eps.length > 6 ? ' …' : ''}</span></p>}
        </fieldset>
        {job
          ? <div className="row"><span className="chip st-analyzing">scanning{job.progress ? ` · ${job.progress.percent}%` : ''}</span><button className="btn danger small" onClick={() => void api.post(`/api/projects/${ctx.projectId}/security/web/scans/cancel`).then(ctx.refreshStatus)}>Cancel scan</button></div>
          : !confirming
            ? <button className="btn primary" disabled={busy || updating || !ov?.usable || !sel?.approved || !storeUp || (mode === 'url' && !url) || (mode === 'snapshots' && !snapOk)} onClick={() => setConfirming(true)} title={!storeUp ? 'MongoDB is required to store scan results' : undefined}>Start security scan…</button>
            : (
              <div className="box confirm" role="alertdialog" aria-label="Confirm security scan">
                <p className="small"><b>Nuclei will send HTTP requests to {targetLabel}.</b></p>
                <p className="small muted">{sel?.approved} vetted templates against {eps.length + 1} URL{eps.length ? 's' : ''} · up to {rate} requests/s · {ov.settings.methods.join('/')} only · redirects {ov.settings.redirects === 'none' ? 'not followed' : 'same host only'}. No templates are downloaded and nothing is sent anywhere else.</p>
                <label className="row small"><input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} /> I am authorized to test this target.</label>
                <div className="row" style={{ marginTop: 8 }}>
                  <button className="btn primary small" disabled={!authorized || busy} onClick={() => void start()}>Send requests and scan</button>
                  <button className="btn small" onClick={() => { setConfirming(false); setAuthorized(false); }}>Cancel</button>
                </div>
              </div>
            )}
        {msg && <p className="small" role="status">{msg}</p>}
        {!storeUp && <p className="small muted">MongoDB is unavailable: scans cannot be recorded, so they cannot be started.</p>}
      </div>
      {runs && runs.length > 0 && (
        <label className="row small run-pick">Scan
          <select className="input" value={current?._id ?? ''} onChange={(e) => setRunId(e.target.value)} aria-label="Security scan">
            {runs.map((r) => (
              <option key={r._id} value={r._id}>
                {timeAgo(r.startedAt)} · {RUN_TEXT[r.status] ?? r.status} · {r.mode === 'snapshots' ? 'baseline vs current' : r.target?.origin}
                {r.counts ? ` · ${r.counts.total} finding${r.counts.total === 1 ? '' : 's'}` : ''}
              </option>
            ))}
          </select>
        </label>
      )}
      <div className="col-detail">{current ? <RunLoader ctx={ctx} runId={current._id} job={job} /> : <div className="empty">No security scan yet. Start one to see what nuclei finds on the running website.</div>}</div>
    </div>
  );
}

function RunLoader({ ctx, runId, job }: { ctx: Ctx; runId: string; job: any }) {
  const [d, setD] = useState<any>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [history, setHistory] = useState<any[] | undefined>(undefined);
  useEffect(() => { api.get<any>(`/api/projects/${ctx.projectId}/security/web/scans/${runId}`).then(setD).catch(() => setD(null)); }, [runId, ctx.ticks.websec, ctx.ticks.findings]);
  useEffect(() => {
    if (!selected) { setHistory(undefined); return; }
    api.get<any>(`/api/projects/${ctx.projectId}/findings/${selected}`).then((r) => setHistory(r.records)).catch(() => setHistory([]));
  }, [selected, ctx.ticks.findings]);
  if (!d?.run) return <div className="empty muted">Loading…</div>;
  return (
    <WebRunDetail run={d.run} observations={d.observations} findings={d.findings} job={job} projectId={ctx.projectId} history={history}
      selected={selected} onSelect={setSelected}
      onOpenFinding={(fid) => ctx.select({ nodeId: null, path: null, from: `finding:${fid}` }, 'issues')}
      onOpenCode={(l) => void api.post(`/api/projects/${ctx.projectId}/open-in-editor`, l)} />
  );
}
