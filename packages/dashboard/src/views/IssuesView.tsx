import { useEffect, useMemo, useState } from 'react';
import type { Ctx } from '../App';
import { api, artifactUrl, timeAgo, TOOL_LABEL, SOURCE_NAME, type Finding } from '../api';
import { whereOf } from './ScansView';
import { Index } from '../graphUtil';
import { PathChain } from './GraphView';
import { WebFindingEvidence } from './WebSecurityPanel';
import { SEVERITY_COLOR, SEVERITY_ORDER } from '../charts';
import { Icon } from '../icons';

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

const STATUS_TABS: [Status, string][] = [['open', 'Open'], ['not_currently_observed', 'Unobserved'], ['resolved', 'Resolved'], ['all', 'All']];
type Status = 'open' | 'resolved' | 'not_currently_observed' | 'all';

export function IssuesView({ ctx }: { ctx: Ctx }) {
  const [status, setStatus] = useState<Status>('open');
  const [source, setSource] = useState<string>('all');
  const [query, setQuery] = useState('');
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
  const needle = query.trim().toLowerCase();
  const shown = (items ?? []).filter((f) => (source === 'all' || f.source === source) && (!needle || `${f.title} ${f.locations.map((l) => l.file).join(' ')}`.toLowerCase().includes(needle)));
  const groups = SEVERITY_ORDER.map((sev) => [sev, shown.filter((f) => f.severity === sev)] as const).filter(([, list]) => list.length);
  const ordered = groups.flatMap(([, list]) => list);
  const sel = ordered.find((f) => f._id === current) ?? ordered[0];
  useEffect(() => {
    if (!sel) { setDetail(null); return; }
    api.get<{ finding: Finding; records: any[] }>(`/api/projects/${ctx.projectId}/findings/${sel._id}`).then(setDetail).catch(() => setDetail(null));
  }, [sel?._id, ctx.ticks.findings]);

  if (err) return <div className="empty"><h2>Findings unavailable</h2><p>{err}</p></div>;
  if (!items || !index) return <div className="empty muted">Loading…</div>;
  const sources = [...new Set(items.map((f) => f.source))];

  return (
    <div className="findings">
      <aside className="f-list" aria-label="Findings">
        <div className="f-list-head">
          <div className="f-filters">
            <label className="f-search"><Icon.search /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter by title or file" aria-label="Filter findings" /></label>
            <select className="input f-source" value={source} onChange={(e) => setSource(e.target.value)} aria-label="Source">
              <option value="all">All sources</option>{sources.map((k) => <option key={k} value={k}>{SOURCE_NAME[k] ?? k}</option>)}
            </select>
          </div>
          <div className="seg f-status" role="group" aria-label="Status">
            {STATUS_TABS.map(([id, label]) => <button key={id} aria-pressed={status === id} onClick={() => setStatus(id)}>{label}</button>)}
          </div>
        </div>
        <div className="f-list-body">
          {!ordered.length && <div className="f-empty">{needle ? 'No findings match this filter.' : status === 'open' ? 'No open findings. Nice.' : 'Nothing here yet.'}</div>}
          {groups.map(([sev, list]) => (
            <section key={sev} className="f-group">
              <h4 className="f-group-head"><i className="sev-dot" style={{ background: SEVERITY_COLOR[sev] }} />{sev}<span className="n">{list.length}</span></h4>
              {list.map((f) => (
                <button key={f._id} className="f-row" aria-current={sel?._id === f._id} onClick={() => setCurrent(f._id)}>
                  <span className="f-row-title">{f.title}</span>
                  <span className="f-row-meta">
                    {SOURCE_NAME[f.source] ?? f.source} · {timeAgo(f.lastSeenAt)}
                    {f.status && f.status !== 'open' && <span className="f-state">{STATUS_LABEL[f.status] ?? f.status}</span>}
                    {f.potentialRegression && f.status === 'open' && <span className="f-flag">regression</span>}
                  </span>
                </button>
              ))}
            </section>
          ))}
        </div>
      </aside>
      <div className="f-detail">
        {sel && <FindingDetail key={sel._id} f={detail?.finding ?? sel} records={detail?.records ?? []} index={index} ctx={ctx} />}
      </div>
    </div>
  );
}

type DetailTab = 'summary' | 'evidence' | 'paths' | 'history';

/** Merge duplicate file:line hits and group them per file. */
function groupLocations(locs: { file: string; line: number }[]) {
  const by = new Map<string, Set<number>>();
  for (const l of locs) by.set(l.file, (by.get(l.file) ?? new Set()).add(l.line));
  return [...by.entries()].map(([file, lines]) => ({ file, lines: [...lines].sort((a, b) => a - b) }));
}

function FindingDetail({ f, records, index, ctx }: { f: Finding; records: any[]; index: Index; ctx: Ctx }) {
  const [tab, setTab] = useState<DetailTab>('summary');
  const [allPaths, setAllPaths] = useState(false);
  const [copied, setCopied] = useState(false);
  const changed = new Set(f.correlation?.changedNodes ?? []);
  const paths = f.correlation?.paths?.length ? f.correlation.paths : f.paths;
  const locs = groupLocations(f.locations);
  const openLoc = (l: { file: string; line: number }) => void api.post(`/api/projects/${ctx.projectId}/open-in-editor`, l);
  const hasEvidence = (f.source === 'dependency' && !!f.pkg) || f.source === 'web' || GENERIC_SCAN_SOURCES.has(f.source) || (f.source === 'runtime' && f.evidence.failedAssertions?.length > 0);
  const tabs: [DetailTab, string, number?][] = [
    ['summary', 'Summary'],
    ...(hasEvidence ? [['evidence', 'Evidence'] as [DetailTab, string]] : []),
    ...(paths.length || locs.length ? [['paths', 'Code paths', paths.length || locs.length] as [DetailTab, string, number]] : []),
    ['history', 'History', records.length],
  ];
  const active = tabs.some(([id]) => id === tab) ? tab : 'summary';
  const pathsTitle = f.source === 'graph' ? 'Routes from an endpoint to the flagged code' : f.source === 'dependency' ? 'Endpoints whose code calls into this package' : SCAN_SOURCES.has(f.source) ? 'Code paths from the linked endpoint' : 'Paths from what the scenario exercised to the changed code';
  const copyId = () => navigator.clipboard?.writeText(f._id).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1400); }).catch(() => {});

  return (
    <article className="f-card">
      <header className="f-head">
        <div className="f-badges">
          <span className={`sev-badge sev-${f.severity}`}><i />{f.severity}</span>
          {f.status && f.status !== 'open' && <span className={`chip st-${f.status}`}>{STATUS_LABEL[f.status] ?? f.status}</span>}
          {f.potentialRegression && <span className="chip st-failed">potential regression</span>}
          <span className="f-kind">{CLASS_LABEL[f.classification] ?? f.classification}</span>
        </div>
        <h1 className="f-title">{f.title}</h1>
        <dl className="f-meta">
          <div><dt>Source</dt><dd title={SOURCE_LABEL(f)}>{SOURCE_LABEL(f)}</dd></div>
          <div><dt>First seen</dt><dd>{timeAgo(f.firstSeenAt)}</dd></div>
          <div><dt>Last seen</dt><dd>{timeAgo(f.lastSeenAt)}</dd></div>
          <div><dt>Confidence</dt><dd title={f.confidenceNote ?? undefined}>{f.confidence}</dd></div>
        </dl>
        <div className="f-actions">
          {paths.length > 0 && <button className="btn primary small" onClick={() => ctx.select({ nodeId: paths[0][paths[0].length - 1], path: paths[0], from: 'finding' }, 'graph')}>Show in graph</button>}
          {f.locations[0] && <button className="btn small" onClick={() => openLoc(f.locations[0])}>Open in editor</button>}
          <button className="btn small ghost" onClick={copyId} title={f._id}>{copied ? <><Icon.check /> Copied</> : <><Icon.copy /> Copy ID</>}</button>
        </div>
      </header>

      <div className="f-tabs seg" role="tablist" aria-label="Finding details">
        {tabs.map(([id, label, n]) => (
          <button key={id} role="tab" aria-selected={active === id} onClick={() => setTab(id)}>{label}{n ? <span className="n">{n}</span> : null}</button>
        ))}
      </div>

      <div className="f-body" role="tabpanel">
        {active === 'summary' && (
          <>
            <section className="f-sec">
              <h3>What was found</h3>
              <ul className="f-points">{f.explanation.map((e, i) => <li key={i}>{e}</li>)}</ul>
            </section>
            <section className="f-callout"><h3>Suggested next step</h3><p>{f.suggestedNextStep}</p></section>
            {f.correlation && (
              <section className="f-sec">
                <h3>Connection to code changes</h3>
                <p><span className={`chip ${f.correlation.status === 'potentially_related' ? 'st-observed' : ''}`}>{f.correlation.status === 'potentially_related' ? 'potentially related' : 'no supporting path'}</span></p>
                <p className="muted">{f.correlation.reason}</p>
              </section>
            )}
            {f.limitations.length > 0 && (
              <details className="f-disclose">
                <summary>Limitations of this result ({f.limitations.length})</summary>
                <ul className="f-points">{f.limitations.map((l, i) => <li key={i} className="muted">{l}</li>)}</ul>
              </details>
            )}
          </>
        )}

        {active === 'evidence' && (
          <>
            {f.source === 'dependency' && f.pkg && <DependencyDetail f={f} ctx={ctx} />}
            {f.source === 'web' && <WebDetail f={f} ctx={ctx} />}
            {GENERIC_SCAN_SOURCES.has(f.source) && <ScanDetail f={f} ctx={ctx} />}
            {f.source === 'runtime' && f.evidence.failedAssertions?.length > 0 && (
              <section className="f-sec"><h3>Browser evidence</h3>
                <div className="assert">{f.evidence.failedAssertions.map((a: any, i: number) => <span key={i} style={{ display: 'contents' }}><span className="mark-bad">✗</span><span><span className="mono">{a.step}</span><br /><span className="muted">{a.message}</span></span></span>)}</div>
                {f.lastSeenBrowserRunId && <RunShots ctx={ctx} runId={f.lastSeenBrowserRunId} scenario={f.scenario} />}
              </section>
            )}
          </>
        )}

        {active === 'paths' && (
          <>
            {paths.length > 0 && (
              <section className="f-sec">
                <h3>{pathsTitle} ({paths.length})</h3>
                <p className="f-hint">One row per route. Select a step to inspect it in the code graph.</p>
                <div className="f-paths">
                  {(allPaths ? paths : paths.slice(0, 3)).map((p, i) => <div className="f-path" key={i}><PathChain path={p} index={index} ctx={ctx} changed={changed} /></div>)}
                </div>
                {paths.length > 3 && <button className="btn small ghost" style={{ marginTop: 8 }} onClick={() => setAllPaths((v) => !v)}>{allPaths ? 'Show fewer' : `Show ${paths.length - 3} more`}</button>}
              </section>
            )}
            {locs.length > 0 && (
              <section className="f-sec">
                <h3>Source locations</h3>
                <ul className="f-locs">
                  {locs.map(({ file, lines }) => (
                    <li key={file}>
                      <span className="f-file">{file}</span>
                      <span className="f-lines">{lines.map((line) => <button key={line} className="f-line" onClick={() => openLoc({ file, line })} title={`Open ${file}:${line} in the editor`}>:{line}</button>)}</span>
                    </li>
                  ))}
                </ul>
              </section>
            )}
          </>
        )}

        {active === 'history' && (
          <section className="f-sec">
            <h3>Verification history</h3>
            {records.length ? (
              <table className="tbl"><tbody>{records.map((r) => (
                <tr key={r._id} title={r.browserRunId ?? r.securityRunId ?? r.analysisRunId}><td className="muted" style={{ whiteSpace: 'nowrap' }}>{new Date(r.at).toLocaleString()}</td><td>{(f.source === 'web' ? WEB_ACTION_LABEL[r.action] : undefined) ?? ACTION_LABEL[r.action] ?? r.action}</td><td className="muted">{r.result}</td></tr>
              ))}</tbody></table>
            ) : <p className="muted small">No records yet.</p>}
          </section>
        )}
      </div>
    </article>
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
