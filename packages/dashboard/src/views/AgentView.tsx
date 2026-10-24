import { useEffect, useState } from 'react';
import type { Ctx } from '../App';
import { api, timeAgo } from '../api';

interface AgentEvent {
  _id: string;
  at: string;
  type: 'change' | 'decision' | 'tool_result' | 'scan' | 'info';
  endpoint?: string | null;
  tool?: string | null;
  severity?: 'high' | 'medium' | 'low' | 'info' | 'unknown' | null;
  title: string;
  detail?: string | null;
  data?: Record<string, any> | null;
}

const TYPE_LABEL: Record<AgentEvent['type'], string> = {
  change: 'change', decision: 'decision', tool_result: 'tool', scan: 'scan', info: 'info',
};

// Color the left rail by event type so the log scans quickly.
const TYPE_COLOR: Record<AgentEvent['type'], string> = {
  change: 'var(--endpoint)', decision: 'var(--warn)', tool_result: 'var(--muted)', scan: 'var(--endpoint)', info: 'var(--muted)',
};

export function AgentView({ ctx }: { ctx: Ctx }) {
  const [events, setEvents] = useState<AgentEvent[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [filter, setFilter] = useState<AgentEvent['type'] | 'all'>('all');
  const [open, setOpen] = useState<Record<string, boolean>>({});

  useEffect(() => {
    api.get<AgentEvent[]>(`/api/projects/${ctx.projectId}/agent/events?limit=400`)
      .then((d) => { setEvents(d); setErr(null); })
      .catch((e) => setErr(e.message));
  }, [ctx.projectId, ctx.ticks.agent]);

  if (err) return <div className="empty"><h2>Agent log unavailable</h2><p>{err}</p><p className="muted">The log is stored in MongoDB; it is paused while the store is unreachable.</p></div>;
  if (!events) return <div className="empty muted">Loading…</div>;

  const shown = filter === 'all' ? events : events.filter((e) => e.type === filter);
  const findings = events.filter((e) => e.type === 'tool_result' && e.data?.status === 'finding').length;
  const decisions = events.filter((e) => e.type === 'decision').length;
  const scans = events.filter((e) => e.type === 'scan').length;
  const counts: Record<string, number> = { all: events.length };
  for (const e of events) counts[e.type] = (counts[e.type] ?? 0) + 1;

  const clear = async () => {
    if (!confirm('Clear the agent activity log for this project?')) return;
    await api.post(`/api/projects/${ctx.projectId}/agent/events/clear`);
    setEvents([]);
  };

  const tabs: (AgentEvent['type'] | 'all')[] = ['all', 'change', 'decision', 'scan', 'tool_result', 'info'];

  return (
    <div className="scroll">
      <div className="toolbar">
        {tabs.map((t) => (
          <button key={t} className="btn small" aria-pressed={filter === t}
            style={filter === t ? { borderColor: 'var(--endpoint)' } : undefined}
            onClick={() => setFilter(t)}>
            {t === 'all' ? 'All' : TYPE_LABEL[t]}{counts[t] ? ` (${counts[t]})` : ''}
          </button>
        ))}
        <span className="spacer" style={{ flex: 1 }} />
        {events.length > 0 && <button className="btn small" onClick={clear}>Clear log</button>}
      </div>

      <div style={{ padding: '16px 20px' }}>
        <p className="small muted" style={{ marginTop: 0 }}>
          What the LLM orchestrator did, newest at the bottom. Each entry is one step: a code change it
          noticed, which tools it chose (and whether the model or the fallback chose them), and what each
          tool returned. Reported live by the orchestrator and stored in MongoDB.
        </p>

        <div className="stats section">
          <div className="stat"><div className="n">{decisions}</div><div className="muted small">tool-selection decisions</div></div>
          <div className="stat"><div className="n">{scans}</div><div className="muted small">dependency scans run</div></div>
          <div className="stat"><div className="n" style={{ color: findings ? 'var(--bad)' : undefined }}>{findings}</div><div className="muted small">findings reported</div></div>
        </div>

        {shown.length === 0 ? (
          <div className="empty muted" style={{ padding: 40 }}>
            No agent activity yet. Start the orchestrator (<code>packages/orchestrator/.venv/bin/python packages/orchestrator/main.py</code>)
            and edit a watched source file to trigger it.
          </div>
        ) : (
          <ul className="agent-log">
            {shown.map((e) => {
              const isOpen = open[e._id];
              const hasData = e.data && Object.keys(e.data).length > 0;
              return (
                <li key={e._id} className="agent-row" style={{ borderLeftColor: TYPE_COLOR[e.type] }}>
                  <div className="agent-head">
                    <span className="chip" style={{ borderColor: TYPE_COLOR[e.type], color: TYPE_COLOR[e.type] }}>{TYPE_LABEL[e.type]}</span>
                    {e.tool && <span className="chip mono">{e.tool}</span>}
                    {e.severity && e.severity !== 'info' && e.severity !== 'unknown' && <span className={`chip sev-${e.severity}`}>{e.severity}</span>}
                    <span className="agent-title">{e.title}</span>
                    <span className="spacer" style={{ flex: 1 }} />
                    {e.endpoint && <span className="mono small faint">{e.endpoint}</span>}
                    <span className="faint small" title={new Date(e.at).toLocaleString()}>{timeAgo(e.at)}</span>
                  </div>
                  {e.detail && <div className="small muted agent-detail">{e.detail}</div>}
                  {hasData && (
                    <div className="agent-detail">
                      <button className="btn small" onClick={() => setOpen((o) => ({ ...o, [e._id]: !isOpen }))}>
                        {isOpen ? 'Hide' : 'Show'} data
                      </button>
                      {isOpen && <pre className="agent-json">{JSON.stringify(e.data, null, 2)}</pre>}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}
