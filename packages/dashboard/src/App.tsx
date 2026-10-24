import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api, type GraphResponse, timeAgo } from './api';
import { GraphView } from './views/GraphView';
import { IssuesView } from './views/IssuesView';
import { ReachabilityView } from './views/ReachabilityView';
import { CompareView } from './views/CompareView';
import { HistoryView } from './views/HistoryView';
import { SecurityView } from './views/SecurityView';

export type Tab = 'graph' | 'issues' | 'reach' | 'compare' | 'security' | 'history';

export interface Selection { nodeId: string | null; path: string[] | null; from?: string }

export interface Ctx {
  projectId: string;
  status: any;
  graph: GraphResponse | null;
  ticks: Record<string, number>;
  selection: Selection;
  select: (s: Selection, goTo?: Tab) => void;
  refreshStatus: () => void;
}

const TABS: { id: Tab; label: string }[] = [
  { id: 'graph', label: 'Code graph' },
  { id: 'issues', label: 'Findings' },
  { id: 'reach', label: 'Reachability' },
  { id: 'compare', label: 'Website comparison' },
  { id: 'security', label: 'Dependency scan' },
  { id: 'history', label: 'History' },
];

export function App() {
  const [projects, setProjects] = useState<any[] | null>(null);
  const [projectId, setProjectId] = useState<string | null>(new URLSearchParams(location.search).get('project'));
  const [status, setStatus] = useState<any>(null);
  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [tab, setTab] = useState<Tab>((new URLSearchParams(location.search).get('tab') as Tab) || 'graph');
  const [selection, setSelection] = useState<Selection>({ nodeId: null, path: null });
  const [ticks, setTicks] = useState<Record<string, number>>({});
  const [connError, setConnError] = useState<string | null>(null);
  const [openFindings, setOpenFindings] = useState<number>(0);
  const bump = (k: string) => setTicks((t) => ({ ...t, [k]: (t[k] ?? 0) + 1 }));

  useEffect(() => {
    api.get<any[]>('/api/projects').then((ps) => {
      setProjects(ps);
      if (!projectId && ps[0]) setProjectId(ps[0].id);
    }).catch((e) => setConnError(String(e.message)));
  }, []);

  const refreshStatus = useCallback(() => {
    if (!projectId) return;
    api.get<any>(`/api/projects/${projectId}/status`).then((s) => { setStatus(s); setConnError(null); }).catch((e) => setConnError(String(e.message)));
  }, [projectId]);

  const refreshGraph = useCallback(() => {
    if (!projectId) return;
    api.get<GraphResponse>(`/api/projects/${projectId}/graph`).then(setGraph).catch(() => {});
  }, [projectId]);

  useEffect(() => {
    if (!projectId) return;
    refreshStatus();
    refreshGraph();
    const t = setInterval(refreshStatus, 5000);
    return () => clearInterval(t);
  }, [projectId, refreshStatus, refreshGraph]);

  useEffect(() => {
    if (!projectId) return;
    api.get<any[]>(`/api/projects/${projectId}/findings?status=open`).then((f) => setOpenFindings(f.length)).catch(() => setOpenFindings(0));
  }, [projectId, ticks.findings]);

  // Live updates from the service.
  const wsRef = useRef<WebSocket | null>(null);
  useEffect(() => {
    if (!projectId) return;
    let closed = false;
    const connect = () => {
      const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
      wsRef.current = ws;
      ws.onmessage = (ev) => {
        const m = JSON.parse(ev.data);
        if (m.projectId && m.projectId !== projectId) return;
        if (m.kind === 'graph') { refreshGraph(); bump('graph'); }
        if (m.kind === 'findings') bump('findings');
        if (m.kind === 'browser') bump('browser');
        if (m.kind === 'baseline') { refreshGraph(); bump('browser'); }
        if (m.kind === 'security') bump('security');
        bump('history');
        refreshStatus();
      };
      ws.onclose = () => { if (!closed) setTimeout(connect, 1500); };
    };
    connect();
    return () => { closed = true; wsRef.current?.close(); };
  }, [projectId, refreshGraph, refreshStatus]);

  const select = useCallback((s: Selection, goTo?: Tab) => { setSelection(s); if (goTo) setTab(goTo); }, []);

  const ctx = useMemo<Ctx | null>(() => projectId ? { projectId, status, graph, ticks, selection, select, refreshStatus } : null,
    [projectId, status, graph, ticks, selection, select, refreshStatus]);

  if (connError && !status) {
    return <div className="empty"><h2>Can’t reach the local analysis service</h2><p>{connError}</p><p className="muted">Start it with <code>npm start -- --project ./your-app</code> and reload this page.</p></div>;
  }
  if (projects && projects.length === 0) {
    return <div className="empty"><h2>No project is being monitored</h2><p>Open a folder from the editor extension, or start the service with <code>--project ./path</code>.</p></div>;
  }
  if (!ctx || !status) return <div className="empty muted">Loading…</div>;

  const job = status.browser?.job;
  return (
    <div className="shell">
      <StatusBar status={status} projects={projects ?? []} onProject={(id) => { setProjectId(id); setSelection({ nodeId: null, path: null }); }} />
      <div>
        {!status.store.available && <div className="banner">MongoDB is unavailable ({status.store.error ?? 'no connection'}). The live graph still updates; history, findings and verification are paused until it reconnects.</div>}
        {status.config.error && <div className="banner">{status.config.error}</div>}
        {status.analysis.status === 'failed' && <div className="banner">Last analysis failed: {status.analysis.error}. The graph shown is from the previous successful analysis.</div>}
        {status.unsavedBuffers.length > 0 && <div className="banner warn">Unsaved editor changes in {status.unsavedBuffers.join(', ')} are reflected in the graph (dashed outline) but not in any website run.</div>}
        <nav className="tabs" role="tablist">
          {TABS.map((t) => (
            <button key={t.id} role="tab" aria-selected={tab === t.id} onClick={() => setTab(t.id)}>
              {t.label}
              {t.id === 'issues' && openFindings > 0 && <span className="count bad">{openFindings}</span>}
              {t.id === 'compare' && job && <span className="count">{job.status.replace('_', ' ')}</span>}
              {t.id === 'security' && status.security?.dependencies?.job && <span className="count">scanning</span>}
            </button>
          ))}
        </nav>
      </div>
      <main className={`view ${tab}`}>
        {tab === 'graph' && <GraphView ctx={ctx} />}
        {tab === 'issues' && <IssuesView ctx={ctx} />}
        {tab === 'reach' && <ReachabilityView ctx={ctx} />}
        {tab === 'compare' && <CompareView ctx={ctx} />}
        {tab === 'security' && <SecurityView ctx={ctx} />}
        {tab === 'history' && <HistoryView ctx={ctx} />}
      </main>
    </div>
  );
}

function StatusBar({ status, projects, onProject }: { status: any; projects: any[]; onProject: (id: string) => void }) {
  const a = status.analysis.status;
  const live = status.live;
  return (
    <header className="status">
      {projects.length > 1 ? (
        <select className="input" style={{ width: 'auto' }} value={status.id} onChange={(e) => onProject(e.target.value)} aria-label="Project">
          {projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      ) : <span className="project" title={status.root}>{status.name}</span>}
      <span className="item"><span className={`dot ${status.monitoring ? 'on' : 'off'}`} />{status.monitoring ? 'Watching files' : 'Not watching'}</span>
      <span className="item"><span className={`dot ${a === 'idle' ? 'on' : a === 'failed' ? 'off' : 'busy'}`} />Analysis <b>{a}</b></span>
      {live && <span className="item" title={`Source hash ${live.sourceHash}`}>Source <b className="mono">{live.sourceHash.slice(0, 8)}</b> {timeAgo(live.analyzedAt)}</span>}
      {live?.lastChangedFiles?.length > 0 && <span className="item">Last change <b className="mono">{live.lastChangedFiles.slice(0, 2).join(', ')}</b></span>}
      <span className="item" title={status.baseline?.contentHash}>Baseline <b className="mono">{status.baseline ? status.baseline.snapshotId.replace('snap_', '').slice(0, 8) : 'not set'}</b></span>
      <span className="spacer" />
      <span className="item">{status.parser.provider}</span>
      <span className="item"><span className={`dot ${status.browser.available.ok ? 'on' : 'off'}`} />Browser</span>
      <span className="item"><span className={`dot ${status.store.available ? 'on' : 'off'}`} />MongoDB</span>
    </header>
  );
}
