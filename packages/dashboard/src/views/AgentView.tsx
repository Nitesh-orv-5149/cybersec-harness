import { useEffect, useMemo, useState } from 'react';
import type { Ctx } from '../App';
import { api, timeAgo } from '../api';

interface AgentEvent {
  _id: string;
  at: string;
  type: 'change' | 'decision' | 'tool_result' | 'scan' | 'info' | 'memory';
  endpoint?: string | null;
  tool?: string | null;
  severity?: 'high' | 'medium' | 'low' | 'info' | 'unknown' | null;
  title: string;
  detail?: string | null;
  data?: Record<string, any> | null;
}

// A "step" is one endpoint the agent investigated: its decision plus the tool calls and memory accesses that followed.
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
    if (e.type === 'decision') {
      if (step && !step.decision && (!step.endpoint || step.endpoint === e.endpoint)) {
        step.decision = e;
        if (!step.endpoint) step.endpoint = e.endpoint ?? null;
      } else {
        step = { endpoint: e.endpoint ?? null, decision: e, calls: [] };
        turn.steps.push(step);
      }
      continue;
    }
    // tool_result / scan / info / memory: attach to current step or start one for this endpoint
    if (!step || (step.endpoint && e.endpoint && step.endpoint !== e.endpoint)) {
      step = { endpoint: e.endpoint ?? null, decision: null, calls: [] };
      turn.steps.push(step);
    }
    step.calls.push(e);
  }
  return turns;
}

const statusOf = (e: AgentEvent): string => {
  const s = e.data?.status as string | undefined;
  if (e.type === 'scan') return s ?? 'run';
  if (e.type === 'memory') return s ?? 'hit';
  return s ?? 'run';
};
const STATUS_TONE: Record<string, string> = {
  finding: 'bad', findings: 'bad', failed: 'bad', error: 'bad',
  clean: 'ok', skipped: 'faint', run: 'muted',
  hit: 'memory', cached: 'memory', cold: 'faint',
};

function MemoryCall({ e }: { e: AgentEvent }) {
  const [open, setOpen] = useState(false);
  const data = e.data || {};
  const status = statusOf(e);
  const tone = STATUS_TONE[status] ?? 'memory';
  const recalled: any[] = Array.isArray(data.recalled) ? data.recalled : [];
  const skippedClean: string[] = Array.isArray(data.skippedClean) ? data.skippedClean : [];
  const hasDetails = recalled.length > 0 || skippedClean.length > 0 || Boolean(data.candidates);

  return (
    <div className={`call call-memory tone-${tone}`}>
      <button className="call-head" onClick={() => hasDetails && setOpen((o) => !o)} aria-expanded={open}>
        <span className="call-caret">{hasDetails ? (open ? '▾' : '▸') : '·'}</span>
        <span className="call-icon">🧠</span>
        <span className="call-fn fn-memory">memory</span>
        <span className="call-msg">{e.title.replace(/^memory:\s*/, '')}</span>
        <span className="spacer" style={{ flex: 1 }} />
        {recalled.length > 0 && <span className="chip sev-medium">{recalled.length} recalled</span>}
        {skippedClean.length > 0 && <span className="chip sev-ok">{skippedClean.length} pruned</span>}
        <span className={`call-status st-${tone}`}>{status}</span>
      </button>

      {open && (
        <div className="call-memory-detail">
          {recalled.length > 0 && (
            <div className="memory-section">
              <div className="memory-subhead">Recalled Findings (injected into LLM context):</div>
              <ul className="memory-list">
                {recalled.map((m: any, idx: number) => {
                  const subjectKey = m.subject?.key || m.key || '';
                  const toolName = subjectKey.split('|')[0] || 'probe';
                  const content = (m.content || '').replace(/^\[finding\]\s*/, '');
                  return (
                    <li key={m._id || idx} className="memory-item">
                      <span className="memory-tool mono">{toolName}</span>
                      <span className="chip sev-medium">past finding</span>
                      <span className="memory-content">{content}</span>
                      {m.confidence && <span className="faint small">conf: {m.confidence}</span>}
                    </li>
                  );
                })}
              </ul>
            </div>
          )}

          {skippedClean.length > 0 && (
            <div className="memory-section">
              <div className="memory-subhead">Deterministic Clean Skips (bypassed LLM prompt):</div>
              <ul className="memory-list">
                {skippedClean.map((t: string) => (
                  <li key={t} className="memory-item">
                    <span className="memory-tool mono">{t}</span>
                    <span className="chip sev-ok">verified clean</span>
                    <span className="muted small">Cleared in earlier probe; deterministic skip.</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {recalled.length === 0 && skippedClean.length === 0 && (
            <div className="muted small" style={{ padding: '4px 0' }}>
              No previous observations recorded for this endpoint. Cold query.
            </div>
          )}

          <pre className="call-out">{JSON.stringify(e.data, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}

function ToolCall({ e }: { e: AgentEvent }) {
  const [open, setOpen] = useState(false);
  const status = statusOf(e);
  const tone = STATUS_TONE[status] ?? 'muted';
  const hasData = e.data && Object.keys(e.data).length > 0;
  const name = e.tool ?? (e.type === 'scan' ? 'dependency-scan' : e.type);
  const mem = e.data?.memory as { verdict?: string; ttl?: string } | undefined;

  return (
    <div className={`call tone-${tone}`}>
      <button className="call-head" onClick={() => hasData && setOpen((o) => !o)} aria-expanded={open}>
        <span className="call-caret">{hasData ? (open ? '▾' : '▸') : '·'}</span>
        <span className="call-fn">{name}</span>
        <span className="call-msg">{e.title.replace(new RegExp(`^${name}:\\s*`), '')}</span>
        {e.severity && e.severity !== 'info' && e.severity !== 'unknown' && <span className={`chip sev-${e.severity}`}>{e.severity}</span>}
        {mem?.verdict && (
          <span className="mem-badge" title={`Persisted to agent memory as [${mem.verdict}]${mem.ttl ? ` (ttl: ${mem.ttl})` : ''}`}>
            🧠 saved [{mem.verdict}]
          </span>
        )}
        <span className="spacer" style={{ flex: 1 }} />
        <span className={`call-status st-${tone}`}>{status}</span>
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
      <div className="calls">
        {step.calls.map((c) => (
          c.type === 'memory' || c.tool === 'memory'
            ? <MemoryCall key={c._id} e={c} />
            : <ToolCall key={c._id} e={c} />
        ))}
      </div>
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
        <span className="item" style={{ color: findings ? 'var(--bad)' : 'var(--muted)' }}>{findings} finding{findings === 1 ? '' : 's'}</span>
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
