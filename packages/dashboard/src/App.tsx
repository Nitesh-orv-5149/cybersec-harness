import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api, type GraphResponse, timeAgo } from './api';
import { GraphView } from './views/GraphView';
import { IssuesView } from './views/IssuesView';
import { ReachabilityView } from './views/ReachabilityView';
import { CompareView } from './views/CompareView';
import { HistoryView } from './views/HistoryView';
import { SecurityView } from './views/SecurityView';
import { AgentView } from './views/AgentView';
import { ScansView } from './views/ScansView';
import { OverviewView } from './views/OverviewView';
import { Icon, Logo } from './icons';
import { type Command, CommandPalette } from './CommandPalette';
import { TerminalLine } from './TerminalLine';

export type Tab = 'overview' | 'graph' | 'issues' | 'reach' | 'compare' | 'security' | 'scans' | 'agent' | 'history';

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

const TABS: { id: Tab; label: string; group: 'Analyze' | 'Secure' | 'Activity'; icon: () => JSX.Element }[] = [
  { id: 'overview', label: 'Overview', group: 'Analyze', icon: Icon.overview },
  { id: 'graph', label: 'Code graph', group: 'Analyze', icon: Icon.graph },
  { id: 'issues', label: 'Findings', group: 'Analyze', icon: Icon.findings },
  { id: 'reach', label: 'Reachability', group: 'Analyze', icon: Icon.reach },
  { id: 'compare', label: 'Website comparison', group: 'Analyze', icon: Icon.compare },
  { id: 'security', label: 'Dependency scan', group: 'Secure', icon: Icon.security },
  { id: 'scans', label: 'Security tools', group: 'Secure', icon: Icon.scans },
  { id: 'agent', label: 'AI agent', group: 'Activity', icon: Icon.agent },
  { id: 'history', label: 'History', group: 'Activity', icon: Icon.history },
];
const isMac = typeof navigator !== 'undefined' && /Mac|iP(hone|ad)/.test(navigator.platform);
const MOD = isMac ? '⌘' : 'Ctrl';

export function App() {
  const [projects, setProjects] = useState<any[] | null>(null);
  const [projectId, setProjectId] = useState<string | null>(new URLSearchParams(location.search).get('project'));
  const [status, setStatus] = useState<any>(null);
  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [tab, setTab] = useState<Tab>((new URLSearchParams(location.search).get('tab') as Tab) || 'overview');
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
        if (m.kind === 'websec') bump('websec');
        if (m.kind === 'agent') bump('agent');
        bump('history');
        refreshStatus();
      };
      ws.onclose = () => { if (!closed) setTimeout(connect, 1500); };
    };
    connect();
    return () => { closed = true; wsRef.current?.close(); };
  }, [projectId, refreshGraph, refreshStatus]);

  const select = useCallback((s: Selection, goTo?: Tab) => { setSelection(s); if (goTo) setTab(goTo); }, []);

  // Deep links: keep ?project= and ?tab= in the URL so a view can be shared or reloaded.
  useEffect(() => {
    const u = new URL(location.href);
    u.searchParams.set('tab', tab);
    if (projectId) u.searchParams.set('project', projectId);
    history.replaceState(null, '', u);
  }, [tab, projectId]);

  // Keyboard: ⌘K / Ctrl+K opens the palette; 1–9 jump to a view when not typing.
  const [paletteOpen, setPaletteOpen] = useState(false);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPaletteOpen((o) => !o); return; }
      const el = e.target as HTMLElement;
      if (e.metaKey || e.ctrlKey || e.altKey || el.closest('input, textarea, select, [contenteditable="true"]')) return;
      const n = Number(e.key);
      if (n >= 1 && n <= TABS.length) setTab(TABS[n - 1].id);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const commands = useMemo<Command[]>(() => [
    ...TABS.map((t, i) => ({ id: `go-${t.id}`, label: t.label, group: 'Go to', icon: <t.icon />, hint: String(i + 1), run: () => setTab(t.id) })),
    ...(projects ?? []).filter((p) => p.id !== projectId).map((p) => ({
      id: `proj-${p.id}`, label: `Switch to ${p.name}`, group: 'Projects', icon: <Icon.folder />,
      run: () => { setProjectId(p.id); setSelection({ nodeId: null, path: null }); },
    })),
    { id: 'reload', label: 'Refresh status', group: 'Actions', icon: <Icon.history />, run: () => refreshStatus() },
    { id: 'copy-link', label: 'Copy link to this view', group: 'Actions', icon: <Icon.copy />, run: () => { navigator.clipboard?.writeText(location.href).catch(() => {}); } },
  ], [projects, projectId, refreshStatus]);

  const ctx = useMemo<Ctx | null>(() => projectId ? { projectId, status, graph, ticks, selection, select, refreshStatus } : null,
    [projectId, status, graph, ticks, selection, select, refreshStatus]);

  if (connError && !status) {
    return <Splash title="Can’t reach the local analysis service" detail={connError} cmd="npm start -- --project ./your-app" note="Start the service, then reload this page." />;
  }
  if (projects && projects.length === 0) {
    return <Splash title="No project is being monitored" detail="Open a folder from the editor extension, or start the service with a project path." cmd="npm start -- --project ./path" />;
  }
  if (!ctx || !status) return <div className="splash"><div className="splash-card"><Logo size={40} /><div className="loader" aria-label="Loading" /></div></div>;

  const job = status.browser?.job;
  const scanning = (t: Tab): string | null => {
    if (t === 'compare') return job ? job.status.replace('_', ' ') : status.security?.web?.job ? 'scanning' : null;
    if (t === 'security') return status.security?.dependencies?.job ? 'scanning' : null;
    if (t === 'scans') return (status.security?.web?.job || Object.values(status.security?.scans ?? {}).some((k: any) => k?.job)) ? 'scanning' : null;
    return null;
  };
  const current = TABS.find((t) => t.id === tab) ?? TABS[0];

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <Logo />
          <div className="brand-text"><span className="brand-name">workbench</span><span className="brand-sub">code impact · security</span></div>
        </div>

        <button className="search-trigger" onClick={() => setPaletteOpen(true)}>
          <Icon.search /><span>Search…</span><kbd>{MOD} K</kbd>
        </button>

        <nav className="nav" aria-label="Views">
          {(['Analyze', 'Secure', 'Activity'] as const).map((g) => (
            <div className="nav-group" key={g}>
              <div className="nav-label">{g}</div>
              {TABS.filter((t) => t.group === g).map((t) => {
                const busy = scanning(t.id);
                return (
                  <button key={t.id} className="nav-item" aria-current={tab === t.id ? 'page' : undefined} onClick={() => setTab(t.id)} title={`${t.label} (${TABS.indexOf(t) + 1})`}>
                    <span className="nav-icon"><t.icon /></span>
                    <span className="nav-text">{t.label}</span>
                    {t.id === 'issues' && openFindings > 0 && <span className="count bad">{openFindings}</span>}
                    {busy && <span className="count live"><i className="pulse-dot" />{busy}</span>}
                    {!busy && !(t.id === 'issues' && openFindings > 0) && <kbd className="nav-kbd">{TABS.indexOf(t) + 1}</kbd>}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>

        <SystemHealth status={status} />
      </aside>

      <div className="main">
        <TopBar status={status} projects={projects ?? []} section={current.label}
          onProject={(id) => { setProjectId(id); setSelection({ nodeId: null, path: null }); }} />
        {!status.store.available && <div className="banner">MongoDB is unavailable ({status.store.error ?? 'no connection'}). The live graph still updates; history, findings and verification are paused until it reconnects.</div>}
        {status.config.error && <div className="banner">{status.config.error}</div>}
        {(status.config.warnings ?? []).map((w: string, i: number) => <div key={i} className="banner" style={{ opacity: 0.85 }}>{w}</div>)}
        {status.analysis.status === 'failed' && <div className="banner">Last analysis failed: {status.analysis.error}. The graph shown is from the previous successful analysis.</div>}
        {status.unsavedBuffers.length > 0 && <div className="banner warn">Unsaved editor changes in {status.unsavedBuffers.join(', ')} are reflected in the graph (dashed outline) but not in any website run.</div>}
      <main className={`view ${tab}`} key={tab}>
        {tab === 'overview' && <OverviewView ctx={ctx} goFindings={() => setTab('issues')} />}
        {tab === 'graph' && <GraphView ctx={ctx} />}
        {tab === 'issues' && <IssuesView ctx={ctx} />}
        {tab === 'reach' && <ReachabilityView ctx={ctx} />}
        {tab === 'compare' && <CompareView ctx={ctx} />}
        {tab === 'security' && <SecurityView ctx={ctx} />}
        {tab === 'scans' && <ScansView ctx={ctx} />}
        {tab === 'agent' && <AgentView ctx={ctx} />}
        {tab === 'history' && <HistoryView ctx={ctx} />}
      </main>
      </div>
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} commands={commands} />
    </div>
  );
}

function TopBar({ status, projects, section, onProject }: { status: any; projects: any[]; section: string; onProject: (id: string) => void }) {
  const a = status.analysis.status;
  const live = status.live;
  return (
    <header className="topbar">
      <div className="crumbs">
        <Icon.folder />
        {projects.length > 1 ? (
          <select className="crumb-select" value={status.id} onChange={(e) => onProject(e.target.value)} aria-label="Project">
            {projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        ) : <span className="crumb-project" title={status.root}>{status.name}</span>}
        <span className="crumb-sep">/</span>
        <span className="crumb-page">{section}</span>
      </div>
      <span className="spacer" />
      <div className="pills">
        <span className={`pill ${status.monitoring ? 'pill-live' : 'pill-off'}`} title={status.root}>
          <i className="pulse-dot" />{status.monitoring ? 'Live' : 'Paused'}
        </span>
        <span className={`pill ${a === 'idle' ? '' : a === 'failed' ? 'pill-bad' : 'pill-busy'}`}>analysis <b>{a}</b></span>
        {live && (
          <span className="pill mono" title={`Source hash ${live.sourceHash}${live.lastChangedFiles?.length ? `\nLast change: ${live.lastChangedFiles.join(', ')}` : ''}`}>
            <Icon.git /><b>{live.sourceHash.slice(0, 7)}</b><span className="faint">{timeAgo(live.analyzedAt)}</span>
          </span>
        )}
        <span className="pill mono" title={status.baseline?.contentHash ?? 'No baseline set'}>
          base <b>{status.baseline ? status.baseline.snapshotId.replace('snap_', '').slice(0, 7) : '—'}</b>
        </span>
      </div>
    </header>
  );
}

function SystemHealth({ status }: { status: any }) {
  const rows: [string, boolean, string?][] = [
    ['File watcher', !!status.monitoring],
    ['Browser', !!status.browser.available.ok, status.browser.available.reason],
    ['MongoDB', !!status.store.available, status.store.error],
  ];
  return (
    <div className="health">
      <div className="nav-label">System</div>
      {rows.map(([name, ok, why]) => (
        <div className="health-row" key={name} title={ok ? 'Operational' : why ?? 'Unavailable'}>
          <span className={`dot ${ok ? 'on' : 'off'}`} /><span>{name}</span><span className="health-state">{ok ? 'ok' : 'down'}</span>
        </div>
      ))}
      <div className="health-foot mono">{status.parser.provider}</div>
    </div>
  );
}

function Splash({ title, detail, cmd, note }: { title: string; detail: string; cmd: string; note?: string }) {
  return (
    <div className="splash">
      <div className="splash-card">
        <Logo size={40} />
        <h2>{title}</h2>
        <p className="muted">{detail}</p>
        <TerminalLine cmd={cmd} />
        {note && <p className="faint small">{note}</p>}
      </div>
    </div>
  );
}