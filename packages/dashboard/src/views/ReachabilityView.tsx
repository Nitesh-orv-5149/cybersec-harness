import { useEffect, useMemo, useState } from 'react';
import type { Ctx } from '../App';
import { api, type Finding } from '../api';
import { Index, nodeName } from '../graphUtil';
import { PathChain } from './GraphView';

export function ReachabilityView({ ctx }: { ctx: Ctx }) {
  const [items, setItems] = useState<Finding[] | null>(null);
  const [current, setCurrent] = useState<string | null>(null);
  const index = useMemo(() => (ctx.graph?.graph ? new Index(ctx.graph.graph) : null), [ctx.graph]);
  useEffect(() => {
    api.get<Finding[]>(`/api/projects/${ctx.projectId}/reachability`).then((r) => {
      r.sort((a, b) => ({ high: 3, medium: 2, low: 1, info: 0 }[b.severity] - { high: 3, medium: 2, low: 1, info: 0 }[a.severity]));
      setItems(r);
      if (!current && r[0]) setCurrent(r[0]._id);
    }).catch(() => setItems([]));
  }, [ctx.projectId, ctx.graph?.graphVersion]);

  if (!items || !index) return <div className="empty muted">Loading…</div>;
  if (!items.length) return <div className="empty"><h2>No sensitive sinks detected</h2><p className="muted">The parser looks for shell/code execution, dynamically built SQL, filesystem paths, server-side requests to dynamic URLs and DOM HTML injection with non-literal arguments. None were found in the analysed files. That does not mean the project is secure.</p></div>;
  const f = items.find((i) => i._id === current) ?? items[0];
  const sinkId = String(f.evidence.sink);
  const sink = index.nodes.get(sinkId);
  const changed = new Set(ctx.graph?.baselineDiff ? [...ctx.graph.baselineDiff.changedNodes, ...ctx.graph.baselineDiff.addedNodes] : []);
  const evidence = [...new Set(f.paths.flat())].map((id) => index.nodes.get(id)).filter((n) => n?.loc);

  return (
    <div className="split">
      <div className="master">
        <div className="toolbar"><span className="muted small">{items.length} sensitive sink{items.length > 1 ? 's' : ''}, computed live from the current graph</span></div>
        {items.map((i) => (
          <button key={i._id} className="entry" aria-current={i._id === f._id} onClick={() => setCurrent(i._id)}>
            <div className="row"><span className={`chip sev-${i.severity}`}>{i.severity}</span>{i.affectedByChange && <span className="chip" style={{ color: 'var(--changed)' }}>changed since baseline</span>}</div>
            <div className="t">{i.title}</div>
            <div className="mono small muted">{nodeName(index.nodes.get(String(i.evidence.sink)))}</div>
          </button>
        ))}
      </div>
      <div className="detail">
        <div className="section">
          <h2>{f.title}</h2>
          <p className="muted small">Sensitive target <span className="mono">{sink?.label}</span> at <span className="mono">{sink?.loc?.file}:{sink?.loc?.line}</span></p>
        </div>
        <div className="section">
          <h3>Paths from endpoints</h3>
          {f.paths.length ? f.paths.map((p, i) => <PathChain key={i} path={p} index={index} ctx={ctx} changed={changed} />) : <p className="muted">No endpoint reaches this sink through resolved calls.</p>}
          <button className="btn small" style={{ marginTop: 6 }} onClick={() => ctx.select({ nodeId: sinkId, path: f.paths[0] ?? null, from: 'reach' }, 'graph')}>Show in graph</button>
        </div>
        <div className="section">
          <h3>Why this was flagged</h3>
          <ul className="explain">{f.explanation.map((e, i) => <li key={i}>{e}</li>)}</ul>
        </div>
        <div className="section">
          <h3>Evidence</h3>
          <ul className="list">{evidence.map((n) => (
            <li key={n!.id}><button onClick={() => api.post(`/api/projects/${ctx.projectId}/open-in-editor`, { file: n!.loc!.file, line: n!.loc!.line })}>
              <span className="lbl">{n!.loc!.file}:{n!.loc!.line}</span><span className="faint small">{nodeName(n)}</span>
            </button></li>
          ))}</ul>
        </div>
        <div className="section">
          <h3>Classification</h3>
          <p>Potentially security-sensitive path · confidence {f.confidence}</p>
          <h3>Suggested next step</h3>
          <p>{f.suggestedNextStep}</p>
          <h3>Limitations</h3>
          <ul className="explain limit">{f.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul>
        </div>
      </div>
    </div>
  );
}
