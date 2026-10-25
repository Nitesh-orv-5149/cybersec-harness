import { useEffect, useMemo, useState } from 'react';
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

// A "step" is one endpoint the agent investigated: its decision plus the tool calls that followed.
interface Step { endpoint: string | null; decision: AgentEvent | null; calls: AgentEvent[]; }
// A "turn" is everything triggered by one code change (like one turn of a coding agent).
interface Turn { id: string; change: AgentEvent | null; at: string; steps: Step[]; }

function groupTurns(events: AgentEvent[]): Turn[] {
  const turns: Turn[] = [];
  let turn: Turn | null = null;
  let step: Step | null = null;
  const newTurn = (change: AgentEvent | null, at: string): Turn => {
    const t: Turn = { id: change?._id ?? `t${turns.length}`, change, at, steps: [] };
    turns.push(t); step = null; return t;
  };
  for (const e of events) {
    if (e.type === 'change') { turn = newTurn(e, e.at); continue; }
    if (!turn) turn = newTurn(null, e.at);
    if (e.type === 'decision') { step = { endpoint: e.endpoint ?? null, decision: e, calls: [] }; turn.steps.push(step); continue; }
    // tool_result / scan / info: attach to the current step, or open a loose one
    if (!step) { step = { endpoint: e.endpoint ?? null, decision: null, calls: [] }; turn.steps.push(step); }
    step.calls.push(e);
  }
  return turns;
}

const statusOf = (e: AgentEvent): string => {
  const s = e.data?.status as string | undefined;
  if (e.type === 'scan') return s ?? 'run';
  return s ?? 'run';
};
const STATUS_TONE: Record<string, string> = {
  finding: 'bad', findings: 'bad', failed: 'bad', error: 'bad',
  clean: 'ok', skipped: 'faint', run: 'muted',
};
// Display label only — the underlying status value ('finding') is unchanged elsewhere (data model, filters).
const STATUS_LABEL: Record<string, string> = { finding: 'vulnerability', findings: 'vulnerabilities' };

function ToolCall({ e }: { e: AgentEvent }) {
  const [open, setOpen] = useState(false);
  const status = statusOf(e);
  const tone = STATUS_TONE[status] ?? 'muted';
  const hasData = e.data && Object.keys(e.data).length > 0;
  const name = e.tool ?? (e.type === 'scan' ? 'dependency-scan' : e.type);
  return (
    <div className={`call tone-${tone}`}>
      <button className="call-head" onClick={() => hasData && setOpen((o) => !o)} aria-expanded={open}>
        <span className="call-caret">{hasData ? (open ? '▾' : '▸') : '·'}</span>
        <span className="call-fn">{name}</span>
        <span className="call-msg">{e.title.replace(new RegExp(`^${name}:\\s*`), '')}</span>
        {e.severity && e.severity !== 'info' && e.severity !== 'unknown' && <span className={`chip sev-${e.severity}`}>{e.severity}</span>}
        <span className="spacer" style={{ flex: 1 }} />
        <span className={`call-status st-${tone}`}>{STATUS_LABEL[status] ?? status}</span>
      </button>
      {open && hasData && <pre className="call-out">{JSON.stringify(e.data, null, 2)}</pre>}
    </div>
  );
}

function StepBlock({ step }: { step: Step }) {
  const d = step.decision;
  const reason = (d?.data?.reason as string) ?? d?.detail ?? '';
  const isFallback = reason.startsWith('fallback');
  const chosen = (d?.data?.chosen as string[]) ?? [];
  return (
    <div className="step">
      {step.endpoint && <div className="step-ep mono">{step.endpoint}</div>}
      {d && (
        <div className="thought">
          <span className="thought-icon">✶</span>
          <span>
            Chose {chosen.length ? <b className="mono">{chosen.join(', ')}</b> : 'tools'}
            {reason && <span className={`decide-reason ${isFallback ? 'warn' : 'ok'}`}> · {isFallback ? reason : `decided by ${reason.replace(/^llm:\s*/, '')}`}</span>}
          </span>
        </div>
      )}
      <div className="calls">{step.calls.map((c) => <ToolCall key={c._id} e={c} />)}</div>
    </div>
  );
}

export function AgentView({ ctx }: { ctx: Ctx }) {
  const [events, setEvents] = useState<AgentEvent[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.get<AgentEvent[]>(`/api/projects/${ctx.projectId}/agent/events?limit=500`)
      .then((d) => { setEvents(d); setErr(null); })
      .catch((e) => setErr(e.message));
  }, [ctx.projectId, ctx.ticks.agent]);

  const turns = useMemo(() => (events ? groupTurns(events) : []), [events]);
  const findings = useMemo(() => (events ?? []).filter((e) => e.type === 'tool_result' && e.data?.status === 'finding').length, [events]);
  const lastAt = events && events.length ? events[events.length - 1].at : null;
  const running = !!ctx.status?.security?.dependencies?.job;

  if (err) return <div className="empty"><h2>Agent log unavailable</h2><p>{err}</p><p className="muted">The log is stored in MongoDB; it is paused while the store is unreachable.</p></div>;
  if (!events) return <div className="empty muted">Loading…</div>;

  const clear = async () => {
    if (!confirm('Clear the agent activity log for this project?')) return;
    await api.post(`/api/projects/${ctx.projectId}/agent/events/clear`);
    setEvents([]);
  };

  return (
    <div className="scroll agent2">
      <div className="agent-bar">
        <span className="item"><span className={`dot ${running ? 'busy' : 'on'}`} />{running ? 'Investigating…' : 'Watching for changes'}</span>
        <span className="item muted">{turns.length} turn{turns.length === 1 ? '' : 's'}</span>
        <span className="item muted">{events.length} steps</span>
        <span className="item" style={{ color: findings ? 'var(--bad)' : 'var(--muted)' }}>{findings} {findings === 1 ? 'vulnerability' : 'vulnerabilities'}</span>
        {lastAt && <span className="item muted">last {timeAgo(lastAt)}</span>}
        <span className="spacer" style={{ flex: 1 }} />
        {events.length > 0 && <button className="btn small" onClick={clear}>Clear</button>}
      </div>

      {turns.length === 0 ? (
        <div className="empty muted" style={{ padding: 40 }}>
          <p>The agent hasn’t done anything yet.</p>
          <p className="small">Start it with <code>packages/orchestrator/.venv/bin/python packages/orchestrator/main.py</code> and edit a watched source file — its work will stream here like a coding agent’s transcript.</p>
        </div>
      ) : (
        <div className="transcript">
          {turns.map((t) => (
            <section className="turn" key={t.id}>
              <div className="turn-rail"><span className="turn-dot" /></div>
              <div className="turn-body">
                <header className="turn-head">
                  <span className="turn-kind">change</span>
                  <span className="turn-title">{t.change?.title ?? 'Activity'}</span>
                  <span className="spacer" style={{ flex: 1 }} />
                  <span className="faint small" title={new Date(t.at).toLocaleString()}>{timeAgo(t.at)}</span>
                </header>
                {t.change?.detail && <div className="turn-sub mono small">{t.change.detail}</div>}
                {t.steps.map((s, i) => <StepBlock key={(s.decision?._id ?? 'loose') + i} step={s} />)}
              </div>
            </section>
          ))}
        </div>
      )}
    </div>
  );
}
