import { useEffect, useMemo, useState } from 'react';
import type { Ctx } from '../App';
import { api, artifactUrl, timeAgo, TOOL_LABEL, SOURCE_NAME, type Finding } from '../api';
import { whereOf } from './ScansView';
import { Index } from '../graphUtil';
import { PathChain } from './GraphView';
import { WebFindingEvidence } from './WebSecurityPanel';

const CLASS_LABEL: Record<string, string> = {
  security_sensitive_path: 'Security-sensitive path',
  confirmed_test_failure: 'Confirmed test failure',
  observed: 'Observed',
  potentially_related: 'Potentially related',
  unverified: 'Unverified',
  inconclusive: 'Inconclusive',
  scanner_detected: 'Scanner detected',
};
const SOURCE_LABEL = (f: Finding) => (f.source === 'web' || !f.scanners?.length ? SOURCE_NAME[f.source] ?? f.source : `${SOURCE_NAME[f.source] ?? f.source} (${f.scanners.map((t) => TOOL_LABEL[t] ?? t).join(', ')})`);
const SCAN_SOURCES = new Set(['api', 'web', 'template', 'code', 'secrets', 'iac']);
/** Sources shown with the generic scanner-result panel; Nuclei (web) findings have their own evidence view. */
const GENERIC_SCAN_SOURCES = new Set(['api', 'template', 'code', 'secrets', 'iac']);
const STATUS_LABEL: Record<string, string> = { open: 'open', resolved: 'resolved', not_currently_observed: 'not currently observed' };
const safeHref = (u: string) => (/^https?:\/\//i.test(u) ? u : null);
const ACTION_LABEL: Record<string, string> = {
  observed: 'First observed', reopened: 'Observed again', verified_fixed: 'Verified fixed by browser run', resolved_by_analysis: 'Resolved: path no longer in graph',
  not_currently_observed: 'Not reported by the same scanner (version unchanged)', potential_regression: 'Reported again (potential regression)', version_removed: 'Resolved: vulnerable version no longer installed',
};
const WEB_ACTION_LABEL: Record<string, string> = {
  observed: 'First matched by nuclei', not_currently_observed: 'Not matched by a completed re-scan of the same target', potential_regression: 'Matched again (potential regression)',
};

export function IssuesView({ ctx }: { ctx: Ctx }) {
  const [status, setStatus] = useState<'open' | 'resolved' | 'not_currently_observed' | 'all'>('open');
  const [source, setSource] = useState<string>('all');
  const [items, setItems] = useState<Finding[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [current, setCurrent] = useState<string | null>(null);
  const [detail, setDetail] = useState<{ finding: Finding; records: any[] } | null>(null);
  const index = useMemo(() => (ctx.graph?.graph ? new Index(ctx.graph.graph) : null), [ctx.graph]);
  // Deep link from other views: selection.from = 'finding:<id>'
  useEffect(() => {
    const m = ctx.selection.from?.match(/^finding:(.+)$/);
    if (m) { setCurrent(m[1]); setStatus('all'); }
  }, [ctx.selection.from]);

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
            <option value="open">Open</option><option value="not_currently_observed">Not currently observed</option><option value="resolved">Resolved</option><option value="all">All</option>
          </select>
          <select className="input" style={{ width: 'auto' }} value={source} onChange={(e) => setSource(e.target.value as any)} aria-label="Source">
            <option value="all">All sources</option>{Object.entries(SOURCE_NAME).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          <span className="muted small">{shown.length}</span>
        </div>
        {!shown.length && <div className="empty">{status === 'open' ? 'No open findings for this filter.' : 'Nothing here yet.'}</div>}
        {shown.map((f) => (
          <button key={f._id} className="entry" aria-current={sel?._id === f._id} onClick={() => setCurrent(f._id)}>
            <div className="row">
              <span className={`chip sev-${f.severity}`}>{f.severity}</span>
              <span className={`chip st-${f.classification}`}>{CLASS_LABEL[f.classification] ?? f.classification}</span>
              {f.status && f.status !== 'open' && <span className={`chip st-${f.status}`}>{STATUS_LABEL[f.status] ?? f.status}</span>}
              {f.potentialRegression && f.status === 'open' && <span className="chip st-failed">potential regression</span>}
            </div>
            <div className="t">{f.title}</div>
            <div className="small faint">{SOURCE_LABEL(f)} · last seen {timeAgo(f.lastSeenAt)}</div>
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
        <div className="row"><span className={`chip sev-${f.severity}`}>{f.severity}</span><span className={`chip st-${f.classification}`}>{CLASS_LABEL[f.classification] ?? f.classification}</span><span className={`chip st-${f.status ?? 'open'}`}>{STATUS_LABEL[f.status ?? 'open'] ?? f.status}</span>{f.potentialRegression && <span className="chip st-failed">potential regression</span>}<span className="faint small mono">{f._id}</span></div>
        <h2 style={{ marginTop: 8 }}>{f.title}</h2>
        <p className="muted small">First seen {timeAgo(f.firstSeenAt)} · last seen {timeAgo(f.lastSeenAt)} · confidence {f.confidence}{f.confidenceNote ? ` (${f.confidenceNote})` : ''}</p>
      </div>
      {f.source === 'dependency' && f.pkg && <DependencyDetail f={f} ctx={ctx} />}
      {f.source === 'web' && <WebDetail f={f} ctx={ctx} />}
      {GENERIC_SCAN_SOURCES.has(f.source) && <ScanDetail f={f} ctx={ctx} />}
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
          <h3>{f.source === 'graph' ? 'Reachability paths' : f.source === 'dependency' ? 'Endpoints whose code calls into this package (existing code graph)' : SCAN_SOURCES.has(f.source) ? 'Code paths from the linked endpoint (existing code graph)' : 'Dependency paths from what the scenario exercised to the changed code'}</h3>
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
            <tr key={r._id}><td className="muted" style={{ whiteSpace: 'nowrap' }}>{new Date(r.at).toLocaleString()}</td><td>{(f.source === 'web' ? WEB_ACTION_LABEL[r.action] : undefined) ?? ACTION_LABEL[r.action] ?? r.action}</td><td className="mono small muted">{r.browserRunId ?? r.securityRunId ?? r.analysisRunId}</td><td className="muted">{r.result}</td></tr>
          ))}</tbody></table>
        ) : <p className="muted small">No records yet.</p>}
      </div>
    </>
  );
}

const USE_CHIP: Record<string, string> = {
  called_from_analysed_code: 'st-failed', imported_by_analysed_code: 'st-observed', transitive: 'st-observed', declared_not_imported: '', not_in_lockfile: '',
};

function DependencyDetail({ f, ctx }: { f: Finding; ctx: Ctx }) {
  const p = f.pkg!;
  const [obs, setObs] = useState<any[] | null>(null);
  useEffect(() => {
    api.get<any[]>(`/api/projects/${ctx.projectId}/findings/${f._id}/observations`).then(setObs).catch(() => setObs(null));
  }, [f._id, f.lastSeenAt]);
  return (
    <>
      <div className="section">
        <h3>Package</h3>
        <dl className="kv wide">
          <dt>Package</dt><dd className="mono">{p.name}@{p.version ?? 'unknown'} <span className="muted">({p.ecosystem}, {p.lockfile})</span></dd>
          <dt>Advisory</dt><dd className="mono">{f.canonicalId}{(f.ids ?? []).filter((i) => i !== f.canonicalId).length > 0 && <span className="muted"> · also {(f.ids ?? []).filter((i) => i !== f.canonicalId).join(', ')}</span>}</dd>
          <dt>Severity</dt><dd>{(f.evidence.severityByTool ?? []).map((s: any, i: number) => <span key={i} className="chip" style={{ marginRight: 4 }}>{TOOL_LABEL[s.tool] ?? s.tool}: {s.original ?? 'not supplied'}</span>)}{f.evidence.cvssScore != null && <span className="muted small"> CVSS {f.evidence.cvssScore}</span>}</dd>
          {(f.cwe ?? []).length > 0 && <><dt>CWE</dt><dd className="mono">{f.cwe!.join(', ')}</dd></>}
          <dt>Affected</dt><dd className="mono">{p.affectedRanges.length ? [...new Set(p.affectedRanges.map((r) => r.range))].join(' | ') : <span className="muted">not supplied</span>}</dd>
          <dt>Fixed in</dt><dd className="mono">{p.fixedVersions === null ? <span className="muted">not supplied by the scanner</span> : p.fixedVersions.length ? p.fixedVersions.join(', ') : <span className="muted">no fixed version listed</span>}</dd>
          <dt>Installed as</dt><dd>{p.direct ? `direct ${p.declaredAs ?? ''} dependency` : p.direct === false ? 'transitive dependency' : 'unknown'}{p.devOnly ? ' · development only' : ''}</dd>
          <dt>Scanners</dt><dd>{(f.scanners ?? []).map((t) => TOOL_LABEL[t] ?? t).join(', ')}</dd>
        </dl>
      </div>
      <div className="section">
        <h3>Use in this application</h3>
        {p.use ? (
          <>
            <p><span className={`chip ${USE_CHIP[p.use.evidence] ?? ''}`}>{p.use.label}</span>{(f.labels ?? []).includes('graph_linked') ? <span className="chip" style={{ marginLeft: 4 }}>graph linked</span> : <span className="chip" style={{ marginLeft: 4 }}>graph association unavailable</span>}</p>
            <p className="muted">{p.use.summary}</p>
            {p.use.introducedBy.length > 0 && <ul className="explain">{p.use.introducedBy.map((i, k) => <li key={k} className="mono small">{i.chain.join(' → ')} <span className="muted">({i.direct}: {i.directEvidence.replace(/_/g, ' ')})</span></li>)}</ul>}
          </>
        ) : <p className="muted">Unknown: no code graph was available when this was scanned.</p>}
      </div>
      {(f.references ?? []).length > 0 && <div className="section"><h3>References</h3><ul className="list">{f.references!.map((u) => { const h = safeHref(u); return <li key={u}>{h ? <a href={h} target="_blank" rel="noreferrer noopener">{u}</a> : <span className="mono">{u}</span>}</li>; })}</ul></div>}
      {obs && obs.length > 0 && (
        <div className="section">
          <h3>Scanner observations</h3>
          <table className="tbl"><thead><tr><th>When</th><th>Tool</th><th>Advisory</th><th>Published severity</th><th>Run</th></tr></thead><tbody>
            {obs.slice(0, 20).map((o) => <tr key={o._id}><td className="muted">{timeAgo(o.observedAt)}</td><td>{TOOL_LABEL[o.tool] ?? o.tool} <span className="faint small">{o.toolVersion}</span></td><td className="mono small">{o.advisoryId}</td><td>{o.originalSeverity ?? <span className="muted">not supplied</span>}</td><td className="mono small muted">{o.runId}</td></tr>)}
          </tbody></table>
        </div>
      )}
    </>
  );
}

/** Latest redacted nuclei observation for a web finding (the same evidence view as Website comparison → Security changes). */
function WebDetail({ f, ctx }: { f: Finding; ctx: Ctx }) {
  const [obs, setObs] = useState<any[] | null>(null);
  useEffect(() => {
    api.get<any[]>(`/api/projects/${ctx.projectId}/findings/${f._id}/observations`).then(setObs).catch(() => setObs(null));
  }, [f._id, f.lastSeenAt]);
  if (!obs?.length) return null;
  const latest = obs.find((o) => o.side !== 'baseline') ?? obs[0];
  return (
    <div className="section">
      <WebFindingEvidence o={latest} f={f} onOpenCode={(l) => void api.post(`/api/projects/${ctx.projectId}/open-in-editor`, l)} />
      <p className="small muted" style={{ marginTop: 6 }}>Observed in {new Set(obs.map((o) => o.runId)).size} scan(s); latest {timeAgo(latest.observedAt)} in <span className="mono">{latest.runId}</span>{latest.scopeKey === 'snapshots' ? ' (baseline vs current snapshots)' : ` (${latest.scopeKey.replace(/^url:/, '')})`}.</p>
    </div>
  );
}

function ScanDetail({ f, ctx }: { f: Finding; ctx: Ctx }) {
  const [obs, setObs] = useState<any[] | null>(null);
  useEffect(() => {
    api.get<any[]>(`/api/projects/${ctx.projectId}/findings/${f._id}/observations`).then(setObs).catch(() => setObs(null));
  }, [f._id, f.lastSeenAt]);
  const ev = f.evidence ?? {};
  return (
    <>
      <div className="section">
        <h3>Scanner result</h3>
        <dl className="kv wide">
          <dt>Where</dt><dd className="mono">{whereOf(f)}</dd>
          <dt>Rule</dt><dd className="mono">{(f.ruleIds ?? []).join(', ')}</dd>
          {(f.ids ?? []).length > 0 && <><dt>Identifiers</dt><dd className="mono small">{f.ids!.join(', ')}</dd></>}
          {(f.cwe ?? []).length > 0 && <><dt>CWE</dt><dd className="mono">{f.cwe!.join(', ')}</dd></>}
          <dt>Severity</dt><dd>{(ev.severityByTool ?? []).map((s: any, i: number) => <span key={i} className="chip" style={{ marginRight: 4 }}>{TOOL_LABEL[s.tool] ?? s.tool}: {s.original ?? 'not supplied'}{s.confidence ? ` · confidence ${s.confidence}` : ''}</span>)}</dd>
          <dt>Tools</dt><dd>{(f.scanners ?? []).map((t) => TOOL_LABEL[t] ?? t).join(', ')}</dd>
          <dt>Code link</dt><dd className="small">{ev.linkHow ?? <span className="muted">none: no matching endpoint or function in the code graph</span>}</dd>
        </dl>
      </div>
      {f.source === 'secrets' && (
        <div className="section">
          <h3>Secret match</h3>
          <dl className="kv wide">
            <dt>Match</dt><dd className="mono small">{ev.match ?? '—'} <span className="muted">(value redacted by Gitleaks; never stored)</span></dd>
            <dt>Lines</dt><dd className="mono small">{ev.lines ?? '—'}{ev.columns ? ` · columns ${ev.columns}` : ''}</dd>
            {ev.entropy != null && <><dt>Entropy</dt><dd className="mono small">{ev.entropy}</dd></>}
            {ev.fingerprint && <><dt>Fingerprint</dt><dd className="mono small">{ev.fingerprint} <span className="muted">(add to .gitleaksignore to accept)</span></dd></>}
            {ev.commit && <><dt>Commit</dt><dd className="mono small">{ev.commit}{ev.commitDate ? ` · ${new Date(ev.commitDate).toLocaleString()}` : ''}</dd></>}
          </dl>
        </div>
      )}
      {f.source === 'iac' && (
        <div className="section">
          <h3>Failed check</h3>
          <dl className="kv wide">
            <dt>Framework</dt><dd className="mono small">{ev.framework ?? '—'}</dd>
            <dt>Resource</dt><dd className="mono small">{ev.resource ?? '—'}</dd>
            {(ev.evaluatedKeys ?? []).length > 0 && <><dt>Evaluated</dt><dd className="mono small">{ev.evaluatedKeys.join(', ')}</dd></>}
            {(f.references ?? []).length > 0 && <><dt>Guideline</dt><dd className="small">{f.references![0]}</dd></>}
          </dl>
          {ev.code && <pre className="log">{ev.code}</pre>}
        </div>
      )}
      {(ev.request || ev.response) && (
        <div className="section">
          <h3>Recorded request and response</h3>
          {ev.request && <><p className="small muted">Request</p><pre className="log">{`${ev.request.method ?? ''} ${ev.request.path ?? ev.request.url ?? ''}\n${Object.entries(ev.request.headers ?? {}).map(([k, v]) => `${k}: ${v}`).join('\n')}${ev.request.body ? `\n\n${ev.request.body}` : ''}`}</pre></>}
          {ev.response && <><p className="small muted">Response</p><pre className="log">{`HTTP ${ev.response.status ?? ''}\n${Object.entries(ev.response.headers ?? {}).map(([k, v]) => `${k}: ${v}`).join('\n')}${ev.response.body ? `\n\n${ev.response.body}` : ''}`}</pre></>}
          {ev.occurrences > 1 && <p className="small muted">Seen {ev.occurrences} times in the run; the first occurrence is shown.</p>}
        </div>
      )}
      {(ev.snippet || ev.match) && <div className="section"><h3>Evidence</h3><pre className="log">{ev.snippet ?? ev.match}</pre></div>}
      {(f.references ?? []).length > 0 && <div className="section"><h3>References</h3><ul className="list">{f.references!.map((u) => { const h = safeHref(u); return <li key={u}>{h ? <a href={h} target="_blank" rel="noreferrer noopener">{u}</a> : <span className="mono">{u}</span>}</li>; })}</ul></div>}
      {obs && obs.length > 0 && (
        <div className="section">
          <h3>Observations</h3>
          <table className="tbl"><thead><tr><th>When</th><th>Tool</th><th>Rule</th><th>Reported severity</th><th>Run</th></tr></thead><tbody>
            {obs.slice(0, 20).map((o) => <tr key={o._id}><td className="muted">{timeAgo(o.observedAt)}</td><td>{TOOL_LABEL[o.tool] ?? o.tool} <span className="faint small">{o.toolVersion}</span></td><td className="mono small">{o.ruleId}</td><td>{o.originalSeverity ?? <span className="muted">not supplied</span>}</td><td className="mono small muted">{o.runId}</td></tr>)}
          </tbody></table>
        </div>
      )}
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
