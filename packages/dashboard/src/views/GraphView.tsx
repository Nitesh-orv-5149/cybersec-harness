import { useEffect, useMemo, useRef, useState } from 'react';
import cytoscape, { type Core } from 'cytoscape';
import dagre from 'cytoscape-dagre';
import type { Ctx } from '../App';
import { api, type Finding, type GraphEdge, type GraphNode, type NodeKind } from '../api';
import { EDGE_LABEL, Index, KIND_COLOR, KIND_LABEL, nodeName } from '../graphUtil';
import { SourceSnippet } from './SourceSnippet';

cytoscape.use(dagre);

type Focus = 'neighbours' | 'upstream' | 'downstream' | 'both';
type Highlight = 'none' | 'last' | 'baseline';

const ALL_KINDS: NodeKind[] = ['endpoint', 'function', 'database', 'sink', 'test', 'external', 'module'];
const reducedMotion = typeof matchMedia !== 'undefined' && matchMedia('(prefers-reduced-motion: reduce)').matches;

const STYLE: any[] = [
  { selector: 'node', style: {
    label: 'data(label)', 'font-family': 'IBM Plex Mono, monospace', 'font-size': 11, color: '#c5ccd6',
    'text-valign': 'bottom', 'text-halign': 'center', 'text-margin-y': 4, 'text-wrap': 'wrap', 'text-max-width': '150px',
    'text-background-color': '#151a21', 'text-background-opacity': 0.75, 'text-background-padding': '1px',
    width: 16, height: 16, 'background-color': 'data(color)', 'border-width': 0, 'border-color': '#ff9a3c',
  } as any },
  { selector: 'node[kind="endpoint"]', style: { shape: 'round-rectangle', width: 22, height: 14, color: '#a9c9f7', 'font-size': 11 } },
  { selector: 'node[kind="sink"]', style: { shape: 'diamond', width: 22, height: 22, color: '#f5a3aa', 'font-size': 10.5 } },
  { selector: 'node[kind="database"]', style: { shape: 'barrel', width: 18, height: 18 } },
  { selector: 'node[kind="test"]', style: { shape: 'tag', width: 16, height: 14, color: '#c9baf9' } },
  { selector: 'node[kind="external"]', style: { shape: 'hexagon' } },
  { selector: 'node[kind="module"]', style: { shape: 'rectangle', width: 12, height: 12, color: '#8a95a6' } },
  { selector: 'node[findingSeverity="high"]', style: { 'underlay-color': '#ef5f6b', 'underlay-opacity': 0.72, 'underlay-padding': 7 } },
  { selector: 'node[findingSeverity="medium"]', style: { 'underlay-color': '#e0b04a', 'underlay-opacity': 0.72, 'underlay-padding': 7 } },
  { selector: 'node[findingSeverity="low"], node[findingSeverity="info"], node[findingSeverity="unknown"]', style: { 'underlay-color': '#8a95a6', 'underlay-opacity': 0.7, 'underlay-padding': 6 } },
  { selector: 'node.unsaved', style: { 'border-width': 2, 'border-style': 'dashed', 'border-color': '#d8dee7' } },
  { selector: 'node.impacted', style: { 'border-width': 2, 'border-color': '#ff9a3c', 'border-opacity': 0.55 } },
  { selector: 'node.changed', style: { 'border-width': 3, 'border-color': '#ff9a3c', 'border-opacity': 1 } },
  { selector: 'node.sel', style: { 'border-width': 3, 'border-color': '#ffffff', 'font-weight': 'bold', color: '#ffffff' } as any },
  { selector: 'node.sel', style: { 'underlay-opacity': 0 } },
  { selector: 'edge', style: {
    width: 1.2, 'line-color': '#3d4756', 'target-arrow-color': '#3d4756', 'target-arrow-shape': 'triangle', 'arrow-scale': 0.7,
    'curve-style': 'bezier', opacity: 0.9,
  } },
  { selector: 'edge[certainty="inferred"]', style: { 'line-style': 'dashed' } },
  { selector: 'edge[kind="reaches_sensitive_sink"]', style: { 'line-color': '#7a3a42', 'target-arrow-color': '#7a3a42' } },
  { selector: 'edge[kind="imports"]', style: { 'line-color': '#2e3642', 'target-arrow-color': '#2e3642', width: 0.8 } },
  { selector: 'edge.impacted', style: { 'line-color': '#b8702f', 'target-arrow-color': '#b8702f', width: 1.8 } },
  { selector: 'edge.added', style: { 'line-color': '#ff9a3c', 'target-arrow-color': '#ff9a3c', width: 2 } },
  { selector: 'edge.hl', style: { 'line-color': '#d8dee7', 'target-arrow-color': '#d8dee7', width: 2.2, opacity: 1 } },
  { selector: 'edge.sel', style: { 'line-color': '#ffffff', 'target-arrow-color': '#ffffff', width: 3 } },
  { selector: '.dim', style: { opacity: 0.16 } },
  { selector: 'node.dim', style: { 'text-opacity': 0.25 } as any },
];

export function GraphView({ ctx }: { ctx: Ctx }) {
  const g = ctx.graph?.graph ?? null;
  const index = useMemo(() => (g ? new Index(g) : null), [g]);
  const [kinds, setKinds] = useState<Set<NodeKind>>(new Set(ALL_KINDS.filter((k) => k !== 'module')));
  const [search, setSearch] = useState('');
  const [focus, setFocus] = useState<Focus>('both');
  const [depth, setDepth] = useState(8);
  const [hideUnrelated, setHideUnrelated] = useState(false);
  const [highlight, setHighlight] = useState<Highlight>('last');
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingsError, setFindingsError] = useState<string | null>(null);
  const pickedDefault = useRef(false);
  useEffect(() => {
    if (pickedDefault.current || !ctx.graph?.graph) return;
    pickedDefault.current = true;
    const last = ctx.graph.lastDiff ? ctx.graph.lastDiff.changedNodes.length + ctx.graph.lastDiff.addedNodes.length : 0;
    const base = ctx.graph.baselineDiff ? ctx.graph.baselineDiff.changedNodes.length + ctx.graph.baselineDiff.addedNodes.length : 0;
    if (!last && base) setHighlight('baseline');
  }, [ctx.graph]);
  const [edgeSel, setEdgeSel] = useState<GraphEdge | null>(null);
  const cyRef = useRef<Core | null>(null);
  const boxRef = useRef<HTMLDivElement>(null);
  const layoutKey = useRef('');
  const lastPulsed = useRef(0);

  const selected = ctx.selection.nodeId && index ? index.nodes.get(ctx.selection.nodeId) ?? null : null;

  useEffect(() => {
    api.get<Finding[]>(`/api/projects/${ctx.projectId}/findings?status=open`)
      .then((items) => { setFindings(items); setFindingsError(null); })
      .catch((e) => setFindingsError((e as Error).message));
  }, [ctx.projectId, ctx.ticks.findings]);

  const findingsByNode = useMemo(() => {
    const severityRank: Record<Finding['severity'], number> = { high: 5, medium: 4, low: 3, info: 2, unknown: 1 };
    const result = new Map<string, { count: number; severity: Finding['severity'] }>();
    const graphNodes = g?.nodes ?? [];
    const graphNodeIds = new Set(graphNodes.map((node) => node.id));
    const add = (id: string, severity: Finding['severity']) => {
      const current = result.get(id);
      if (!current) result.set(id, { count: 1, severity });
      else result.set(id, {
        count: current.count + 1,
        severity: severityRank[severity] > severityRank[current.severity] ? severity : current.severity,
      });
    };
    for (const finding of findings) {
      const linkedNodes = new Set(finding.nodes.filter((id) => graphNodeIds.has(id)));
      for (const location of finding.locations) {
        const matches = graphNodes.filter((node) =>
          node.loc?.file === location.file && node.kind !== 'module' &&
          node.loc.line <= location.line && (node.loc.endLine ?? node.loc.line) >= location.line);
        if (matches.length) {
          const mostSpecific = Math.min(...matches.map((node) => (node.loc!.endLine ?? node.loc!.line) - node.loc!.line));
          for (const node of matches) {
            if ((node.loc!.endLine ?? node.loc!.line) - node.loc!.line === mostSpecific) linkedNodes.add(node.id);
          }
        } else {
          const module = graphNodes.find((node) => node.kind === 'module' && node.loc?.file === location.file);
          if (module) linkedNodes.add(module.id);
        }
      }
      for (const id of linkedNodes) add(id, finding.severity);
    }
    return result;
  }, [findings, g]);

  // Change sets for highlighting.
  const changeSet = useMemo(() => {
    const r = { changed: new Set<string>(), impacted: new Set<string>(), addedEdges: new Set<string>() };
    if (!ctx.graph || !index) return r;
    const src = highlight === 'last' ? ctx.graph.lastDiff : highlight === 'baseline' ? ctx.graph.baselineDiff : null;
    if (!src) return r;
    for (const id of [...src.changedNodes, ...src.addedNodes]) if (!id.startsWith('mod:') && index.nodes.has(id)) r.changed.add(id);
    for (const id of index.walk([...r.changed], 'up').keys()) if (!r.changed.has(id)) r.impacted.add(id);
    for (const e of src.addedEdges) r.addedEdges.add(e);
    return r;
  }, [ctx.graph, index, highlight]);

  // Init cytoscape once.
  const hasGraph = !!g;
  useEffect(() => {
    if (!boxRef.current || cyRef.current) return;
    const cy = cytoscape({ container: boxRef.current, style: STYLE, wheelSensitivity: 0.25, minZoom: 0.15, maxZoom: 3, boxSelectionEnabled: false });
    cyRef.current = cy;
    cy.on('tap', 'node', (ev) => { setEdgeSel(null); ctx.select({ nodeId: ev.target.id(), path: null }); });
    cy.on('tap', 'edge', (ev) => setEdgeSel(ev.target.data('raw')));
    cy.on('tap', (ev) => { if (ev.target === cy) { setEdgeSel(null); ctx.select({ nodeId: null, path: null }); } });
    return () => { cy.destroy(); cyRef.current = null; layoutKey.current = ''; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasGraph]);

  // Which nodes are visible.
  const visible = useMemo(() => {
    if (!g || !index) return null;
    let ids = new Set(g.nodes.filter((n) => kinds.has(n.kind)).map((n) => n.id));
    if (hideUnrelated && selected) {
      const keep = new Set<string>([selected.id]);
      if (focus !== 'downstream') for (const k of index.walk([selected.id], 'up', depth).keys()) keep.add(k);
      if (focus !== 'upstream') for (const k of index.walk([selected.id], 'down', depth).keys()) keep.add(k);
      if (focus === 'neighbours') { keep.clear(); keep.add(selected.id); for (const e of index.in.get(selected.id) ?? []) keep.add(e.source); for (const e of index.out.get(selected.id) ?? []) keep.add(e.target); }
      ids = new Set([...ids].filter((i) => keep.has(i)));
    }
    if (hideUnrelated && ctx.selection.path) ids = new Set([...ids].filter((i) => ctx.selection.path!.includes(i)));
    return ids;
  }, [g, index, kinds, hideUnrelated, selected, focus, depth, ctx.selection.path]);

  // Sync elements + layout when the visible set changes.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !g || !visible) return;
    const showImports = kinds.has('module');
    const els: cytoscape.ElementDefinition[] = [];
    for (const n of g.nodes) if (visible.has(n.id)) {
      const finding = findingsByNode.get(n.id);
      els.push({ group: 'nodes', data: {
        id: n.id, label: `${nodeName(n, n.label)}${finding ? ` [${finding.count}]` : ''}`, kind: n.kind, color: KIND_COLOR[n.kind],
        findingCount: finding?.count ?? 0, findingSeverity: finding?.severity ?? '',
      } });
    }
    for (const e of g.edges) {
      if (!visible.has(e.source) || !visible.has(e.target)) continue;
      if (e.kind === 'imports' && !showImports) continue;
      els.push({ group: 'edges', data: { id: e.id, source: e.source, target: e.target, kind: e.kind, certainty: e.certainty, raw: e } });
    }
    const key = els.map((e) => e.data.id).sort().join('|');
    if (key === layoutKey.current) {
      // same structure: just refresh data (labels, raw edge objects)
      for (const el of els) cy.getElementById(el.data.id!).data(el.data);
      return;
    }
    layoutKey.current = key;
    cy.batch(() => { cy.elements().remove(); cy.add(els); });
    cy.layout({ name: 'dagre', rankDir: 'LR', rankSep: 150, nodeSep: 34, edgeSep: 10, ranker: 'network-simplex', animate: false, fit: true, padding: 40 } as any).run();
  }, [g, visible, kinds, findingsByNode]);

  // Apply highlight classes.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !index) return;
    cy.batch(() => {
      cy.elements().removeClass('changed impacted added hl sel dim unsaved');
      for (const n of index.nodes.values()) if (n.fromUnsavedBuffer && n.kind !== 'module') cy.getElementById(n.id).addClass('unsaved');
      changeSet.changed.forEach((id) => cy.getElementById(id).addClass('changed'));
      changeSet.impacted.forEach((id) => cy.getElementById(id).addClass('impacted'));
      changeSet.addedEdges.forEach((id) => cy.getElementById(id).addClass('added'));
      if (changeSet.changed.size) cy.edges().forEach((e) => { if ((changeSet.changed.has(e.target().id()) || changeSet.impacted.has(e.target().id())) && (changeSet.impacted.has(e.source().id()))) e.addClass('impacted'); });

      let hlNodes: Set<string> | null = null;
      let hlEdges: string[] = [];
      if (ctx.selection.path) {
        hlNodes = new Set(ctx.selection.path);
        hlEdges = index.pathEdges(ctx.selection.path);
      } else if (selected) {
        hlNodes = new Set([selected.id]);
        if (focus === 'neighbours') {
          for (const e of index.in.get(selected.id) ?? []) { hlNodes.add(e.source); hlEdges.push(e.id); }
          for (const e of index.out.get(selected.id) ?? []) { hlNodes.add(e.target); hlEdges.push(e.id); }
        } else {
          if (focus !== 'downstream') for (const k of index.walk([selected.id], 'up', depth).keys()) hlNodes.add(k);
          if (focus !== 'upstream') for (const k of index.walk([selected.id], 'down', depth).keys()) hlNodes.add(k);
          // only edges on directed walks from/to the selection
          const up = focus !== 'downstream' ? index.walk([selected.id], 'up', depth) : new Map();
          const down = focus !== 'upstream' ? index.walk([selected.id], 'down', depth) : new Map();
          for (const [s, es] of index.out) for (const e of es) {
            if ((up.has(s) && up.has(e.target)) || (down.has(s) && down.has(e.target))) hlEdges.push(e.id);
          }
        }
      }
      if (hlNodes) {
        cy.elements().addClass('dim');
        hlNodes.forEach((id) => cy.getElementById(id).removeClass('dim'));
        hlEdges.forEach((id) => cy.getElementById(id).removeClass('dim').addClass('hl'));
      }
      if (selected) cy.getElementById(selected.id).addClass('sel');
      if (edgeSel) cy.getElementById(edgeSel.id).addClass('sel').removeClass('dim');
    });
  }, [index, changeSet, selected, focus, depth, ctx.selection.path, edgeSel, visible]);

  // One orchestrated moment: pulse changed nodes when a new graph version arrives with changes.
  useEffect(() => {
    const cy = cyRef.current;
    const v = ctx.graph?.graphVersion ?? 0;
    if (!cy || reducedMotion || v <= lastPulsed.current || !ctx.graph?.lastDiff?.changedNodes.length) { lastPulsed.current = v; return; }
    lastPulsed.current = v;
    const nodes = cy.nodes().filter((n) => ctx.graph!.lastDiff!.changedNodes.includes(n.id()));
    let i = 0;
    const pulse = () => {
      if (i++ >= 3) return;
      nodes.animate({ style: { 'border-width': 9 } as any }, { duration: 260 }).animate({ style: { 'border-width': 3 } as any }, { duration: 320, complete: pulse });
    };
    pulse();
  }, [ctx.graph?.graphVersion]);

  // Center on selection coming from another view.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    if (ctx.selection.path) { const els = cy.nodes().filter((n) => ctx.selection.path!.includes(n.id())); if (els.length) cy.animate({ fit: { eles: els, padding: 80 } } as any, { duration: reducedMotion ? 0 : 300 }); }
    else if (ctx.selection.nodeId && ctx.selection.from) {
      // fit to the selection and everything it highlights (impact + dependencies)
      setTimeout(() => { const els = cy.elements().not('.dim'); if (els.length) cy.animate({ fit: { eles: els, padding: 70 } } as any, { duration: reducedMotion ? 0 : 300 }); }, 0);
    }
  }, [ctx.selection]);

  const matches = useMemo(() => {
    if (!g || search.trim().length < 2) return [];
    const q = search.toLowerCase();
    return g.nodes.filter((n) => n.label.toLowerCase().includes(q) || n.id.toLowerCase().includes(q) || n.loc?.file.toLowerCase().includes(q)).slice(0, 12);
  }, [g, search]);

  if (!g) return <div className="empty">No graph yet. The first analysis is still running or found no supported files.</div>;

  const counts = ALL_KINDS.map((k) => [k, g.nodes.filter((n) => n.kind === k).length] as const);
  const toggleKind = (k: NodeKind) => setKinds((s) => { const n = new Set(s); n.has(k) ? n.delete(k) : n.add(k); return n; });
  const hasLast = !!ctx.graph?.lastDiff && (ctx.graph.lastDiff.changedNodes.length + ctx.graph.lastDiff.addedNodes.length) > 0;

  return (
    <div className="graph-layout">
      <aside className="rail" aria-label="Graph controls">
        <div>
          <input className="input" placeholder="Search symbol, file or route" value={search} onChange={(e) => setSearch(e.target.value)} aria-label="Search graph" />
          {matches.length > 0 && (
            <ul className="list" style={{ marginTop: 6 }}>
              {matches.map((n) => (
                <li key={n.id}><button onClick={() => { ctx.select({ nodeId: n.id, path: null, from: 'search' }); setSearch(''); }}>
                  <span className="legend-dot" style={{ background: KIND_COLOR[n.kind] }} /><span className="lbl">{nodeName(n)}</span>
                </button></li>
              ))}
            </ul>
          )}
        </div>
        <fieldset>
          <legend>Show</legend>
          {counts.map(([k, c]) => (
            <label key={k}>
              <input type="checkbox" checked={kinds.has(k)} onChange={() => toggleKind(k)} />
              <span className={`swatch ${k === 'sink' ? 'diamond' : ''}`} style={{ background: KIND_COLOR[k] }} />
              {KIND_LABEL[k]} <span className="faint">{c}</span>
            </label>
          ))}
        </fieldset>
        <fieldset>
          <legend>Highlight changes</legend>
          <label><input type="radio" name="hl" checked={highlight === 'last'} onChange={() => setHighlight('last')} /> Last saved change {hasLast ? '' : <span className="faint">(none)</span>}</label>
          <label><input type="radio" name="hl" checked={highlight === 'baseline'} onChange={() => setHighlight('baseline')} disabled={!ctx.graph?.baselineDiff} /> Since baseline</label>
          <label><input type="radio" name="hl" checked={highlight === 'none'} onChange={() => setHighlight('none')} /> Off</label>
          {(changeSet.changed.size > 0) && <p className="small muted" style={{ margin: '4px 0 0' }}><span style={{ color: 'var(--changed)' }}>{changeSet.changed.size} changed</span>, {changeSet.impacted.size} depend on them</p>}
        </fieldset>
        <fieldset>
          <legend>Findings</legend>
          <span className="small muted">Open findings show a count in the node label and a halo for the highest severity.</span>
          <p className="small" style={{ margin: '6px 0 0' }}>
            <span className="chip sev-high">high</span>{' '}
            <span className="chip sev-medium">medium</span>{' '}
            <span className="chip sev-low">low, info, unknown</span>
          </p>
          {findingsError && <p className="small st-failed" role="status">Could not load graph findings: {findingsError}</p>}
          {!findingsError && <p className="small muted" style={{ margin: '4px 0 0' }}>{findingsByNode.size} linked graph nodes</p>}
        </fieldset>
        <fieldset>
          <legend>When a node is selected</legend>
          {(['both', 'upstream', 'downstream', 'neighbours'] as Focus[]).map((f) => (
            <label key={f}><input type="radio" name="focus" checked={focus === f} onChange={() => setFocus(f)} />
              {f === 'both' ? 'Impact and dependencies' : f === 'upstream' ? 'What depends on it' : f === 'downstream' ? 'What it reaches' : 'Direct neighbours only'}</label>
          ))}
          <label>Depth <input type="range" min={1} max={12} value={depth} onChange={(e) => setDepth(Number(e.target.value))} style={{ flex: 1 }} /> {depth}</label>
          <label><input type="checkbox" checked={hideUnrelated} onChange={(e) => setHideUnrelated(e.target.checked)} /> Hide unrelated nodes</label>
        </fieldset>
        <fieldset>
          <legend>Edges</legend>
          <span className="small muted">Solid: resolved statically. Dashed: inferred (URL match, callback, route receiver name).</span>
        </fieldset>
        <p className="small faint">{g.stats.parsedFiles}/{g.stats.files} files parsed · {g.stats.unresolvedCalls} unresolved project calls{g.stats.parseErrors.length ? ` · ${g.stats.parseErrors.length} parse errors` : ''}</p>
      </aside>
      <div className="canvas-wrap">
        <div className="canvas-tools">
          <button className="btn small" onClick={() => cyRef.current?.fit(undefined, 40)}>Fit</button>
          <button className="btn small" onClick={() => { setEdgeSel(null); ctx.select({ nodeId: null, path: null }); setHideUnrelated(false); cyRef.current?.fit(undefined, 40); }}>Reset</button>
          {ctx.selection.path && <button className="btn small" onClick={() => ctx.select({ nodeId: ctx.selection.nodeId, path: null })}>Clear path</button>}
        </div>
        <div ref={boxRef} className="canvas" role="img" aria-label={`Dependency graph with ${g.nodes.length} nodes and ${g.edges.length} edges`} />
        <div className="canvas-note">Graph version {ctx.graph?.graphVersion} · built from the files on disk{ctx.status.unsavedBuffers.length ? ' plus unsaved editor buffers' : ''}</div>
      </div>
      <aside className="details" aria-label="Details">
        {edgeSel ? <EdgeDetails edge={edgeSel} index={index!} ctx={ctx} /> : selected ? <NodeDetails node={selected} index={index!} ctx={ctx} changeSet={changeSet} /> : <Overview ctx={ctx} index={index!} />}
      </aside>
    </div>
  );
}

function NodeLink({ id, index, ctx, note }: { id: string; index: Index; ctx: Ctx; note?: string }) {
  const n = index.nodes.get(id);
  return (
    <li><button onClick={() => ctx.select({ nodeId: id, path: null, from: 'details' })}>
      <span className="legend-dot" style={{ background: n ? KIND_COLOR[n.kind] : '#666' }} />
      <span className="lbl">{nodeName(n, id)}</span>{note && <span className="faint small">{note}</span>}
    </button></li>
  );
}

function Overview({ ctx, index }: { ctx: Ctx; index: Index }) {
  const d = ctx.graph?.lastDiff;
  const imp = ctx.graph?.lastImpact;
  return (
    <div>
      <h2>Latest change</h2>
      {!d ? <p className="muted">No change since monitoring started. Edit and save a file in the project; the graph updates within a second.</p> : (
        <>
          <p className="small muted">{ctx.graph?.lastChangedFiles.join(', ')}</p>
          <dl className="kv">
            <dt>Changed</dt><dd>{d.changedNodes.length} nodes</dd>
            <dt>Added</dt><dd>{d.addedNodes.length} nodes, {d.addedEdges.length} edges</dd>
            <dt>Removed</dt><dd>{d.removedNodes.length} nodes, {d.removedEdges.length} edges</dd>
          </dl>
          {[...d.changedNodes, ...d.addedNodes].filter((i) => !i.startsWith('mod:')).length > 0 && <><h3>Changed code</h3><ul className="list">{[...d.changedNodes, ...d.addedNodes].filter((i) => !i.startsWith('mod:')).map((id) => <NodeLink key={id} id={id} index={index} ctx={ctx} />)}</ul></>}
          {d.removedNodes.filter((i) => !i.startsWith('mod:')).length > 0 && <><h3>Removed</h3><ul className="list">{d.removedNodes.filter((i) => !i.startsWith('mod:')).map((id) => <li key={id} className="lbl mono small" style={{ padding: '2px 6px' }}>{id.replace(/^\w+:/, '')}</li>)}</ul></>}
          {imp && <>
            <h3>Potentially affected endpoints</h3>
            {imp.affectedEndpoints.length ? <ul className="list">{imp.affectedEndpoints.map((id) => <NodeLink key={id} id={id} index={index} ctx={ctx} />)}</ul> : <p className="muted small">None found through supported relationships.</p>}
            {imp.affectedClientCode.length > 0 && <><h3>Client code that calls them</h3><ul className="list">{imp.affectedClientCode.map((id) => <NodeLink key={id} id={id} index={index} ctx={ctx} />)}</ul></>}
            <h3>Tests that exercise the change</h3>
            {imp.affectedTests.length ? <ul className="list">{imp.affectedTests.map((id) => <NodeLink key={id} id={id} index={index} ctx={ctx} />)}</ul> : <p className="muted small">No test reaches the changed code. This change is untested.</p>}
            {imp.paths.length > 0 && <><h3>Dependency paths</h3>{imp.paths.slice(0, 6).map((p, i) => <PathChain key={i} path={p} index={index} ctx={ctx} changed={new Set(imp.changed)} />)}</>}
          </>}
        </>
      )}
      <h3>Reading the graph</h3>
      <p className="small muted">Arrows point from a dependent to what it depends on: endpoint → handler → service → sink. Orange marks changed code; a fainter orange ring marks everything that depends on it. Click any node to trace its impact.</p>
    </div>
  );
}

export function PathChain({ path, index, ctx, changed }: { path: string[]; index: Index; ctx: Ctx; changed?: Set<string> }) {
  return (
    <div className="path">
      {path.map((id, i) => {
        const n = index.nodes.get(id);
        return (
          <span key={id + i} style={{ display: 'contents' }}>
            {i > 0 && <span className="arrow" aria-hidden>›</span>}
            <button className={`hop k-${n?.kind ?? 'module'} ${changed?.has(id) ? 'changed' : ''}`} title={n?.loc ? `${n.loc.file}:${n.loc.line}` : id}
              onClick={() => ctx.select({ nodeId: id, path, from: 'path' }, 'graph')}>{nodeName(n, id.replace(/^\w+:/, ''))}</button>
          </span>
        );
      })}
    </div>
  );
}

function NodeDetails({ node, index, ctx, changeSet }: { node: GraphNode; index: Index; ctx: Ctx; changeSet: { changed: Set<string>; impacted: Set<string> } }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  useEffect(() => {
    api.get<Finding[]>(`/api/projects/${ctx.projectId}/findings?status=open`).then((items) => setFindings(items.filter((finding) =>
      finding.nodes.includes(node.id) || (!!node.loc && finding.locations.some((location) => {
        if (location.file !== node.loc!.file) return false;
        if (node.kind === 'module') return true;
        return location.line >= node.loc!.line && location.line <= (node.loc!.endLine ?? node.loc!.line);
      })),
    ))).catch(() => setFindings([]));
  }, [node.id, node.kind, node.loc?.file, node.loc?.line, node.loc?.endLine, ctx.projectId, ctx.ticks.findings]);
  const incoming = index.in.get(node.id) ?? [];
  const outgoing = index.out.get(node.id) ?? [];
  const up = index.walk([node.id], 'up');
  const down = index.walk([node.id], 'down');
  const pick = (m: Map<string, number>, k: NodeKind | 'client') => [...m.keys()].filter((id) => id !== node.id && (k === 'client' ? index.nodes.get(id)?.meta.isClient && index.nodes.get(id)?.kind === 'function' : index.nodes.get(id)?.kind === k));
  const m = node.meta;
  const openInEditor = () => node.loc && api.post(`/api/projects/${ctx.projectId}/open-in-editor`, { file: node.loc.file, line: node.loc.line });

  return (
    <div>
      <div className="kind"><span className="legend-dot" style={{ display: 'inline-block', background: KIND_COLOR[node.kind], marginRight: 6 }} />{KIND_LABEL[node.kind]}
        {changeSet.changed.has(node.id) && <span className="chip" style={{ marginLeft: 8, color: 'var(--changed)', borderColor: 'var(--changed)' }}>changed</span>}
        {changeSet.impacted.has(node.id) && <span className="chip" style={{ marginLeft: 8, color: 'var(--changed)' }}>depends on a change</span>}
        {node.fromUnsavedBuffer && <span className="chip" style={{ marginLeft: 8 }}>unsaved buffer</span>}
      </div>
      <div className="title">{nodeName(node)}</div>
      {node.loc && <div className="row small"><span className="mono muted">{node.loc.file}:{node.loc.line}</span><button className="btn small" onClick={openInEditor}>Open in editor</button></div>}

      {node.kind === 'endpoint' && <dl className="kv" style={{ marginTop: 10 }}>
        <dt>Method</dt><dd>{m.method}</dd><dt>Route</dt><dd className="mono">{m.path}</dd>
        <dt>Router</dt><dd>{m.framework} <span className="mono">{m.router}</span>{m.prefix ? <> mounted at <span className="mono">{m.prefix}</span></> : null}{m.mountResolved === false ? <span className="faint"> (mount not found)</span> : null}</dd>
        <dt>Auth</dt><dd style={{ color: m.authObserved ? undefined : 'var(--warn)' }}>{m.auth}</dd>
        {m.middleware?.length > 0 && <><dt>Middleware</dt><dd className="mono">{m.middleware.join(', ')}</dd></>}
      </dl>}
      {node.kind === 'sink' && <>
        <dl className="kv" style={{ marginTop: 10 }}>
          <dt>Call</dt><dd className="mono">{m.callee}()</dd>
          <dt>Argument</dt><dd className="mono">{m.argText}</dd>
          <dt>Input</dt><dd>{m.directRequestInput ? 'reads request data directly' : m.paramsUsed?.length ? `from parameter ${m.paramsUsed.join(', ')}` : 'origin not determined'}</dd>
          {m.sanitizationHint && <><dt>Sanitisation</dt><dd>possible (<span className="mono">{m.sanitizationHint}</span>), unverified</dd></>}
        </dl>
        <p className="small muted" style={{ marginTop: 8 }}>This is a sensitive operation, not a confirmed vulnerability. A path to it does not prove untrusted input reaches it.</p>
      </>}
      {(node.kind === 'function' || node.kind === 'database') && m.params?.length > 0 && <p className="small muted" style={{ marginTop: 8 }}>Parameters: <span className="mono">{m.params.join(', ')}</span></p>}

      {node.loc && <SourceSnippet projectId={ctx.projectId} file={node.loc.file} line={node.loc.line} tick={ctx.graph?.graphVersion ?? 0} />}

      {findings.length > 0 && <section className="section" aria-label="Finding explanations">
        <h3>Findings on this node</h3>
        {findings.map((finding) => (
          <article key={finding._id} style={{ padding: '8px 0', borderBottom: '1px solid var(--line)' }}>
            <div className="row">
              <span className={`chip sev-${finding.severity}`}>{finding.severity}</span>
              <b className="small">{finding.title}</b>
            </div>
            <p className="small" style={{ margin: '6px 0' }}>
              <b>How serious:</b> {severityExplanation(finding.severity)}
            </p>
            {finding.explanation.slice(0, 2).map((item, i) => <p key={i} className="small muted" style={{ margin: '4px 0' }}>{item}</p>)}
            <p className="small muted" style={{ margin: '4px 0' }}>
              Confidence: {finding.confidence}{finding.confidenceNote ? ` — ${finding.confidenceNote}` : ''}
            </p>
            {finding.suggestedNextStep && <p className="small" style={{ margin: '4px 0' }}><b>Next:</b> {finding.suggestedNextStep}</p>}
          </article>
        ))}
      </section>}

      <h3>Depends on it ({incoming.length})</h3>
      {incoming.length ? <ul className="list">{incoming.map((e) => <NodeLink key={e.id} id={e.source} index={index} ctx={ctx} note={`${EDGE_LABEL[e.kind] ?? e.kind}${e.certainty === 'inferred' ? ', inferred' : ''}`} />)}</ul> : <p className="small muted">Nothing in the analysed code calls this.</p>}
      <h3>It depends on ({outgoing.length})</h3>
      {outgoing.length ? <ul className="list">{outgoing.map((e) => <NodeLink key={e.id} id={e.target} index={index} ctx={ctx} note={`${EDGE_LABEL[e.kind] ?? e.kind}${e.certainty === 'inferred' ? ', inferred' : ''}`} />)}</ul> : <p className="small muted">No resolved dependencies.</p>}

      {node.kind !== 'endpoint' && <><h3>Endpoints that could be affected</h3>{pick(up, 'endpoint').length ? <ul className="list">{pick(up, 'endpoint').map((id) => <NodeLink key={id} id={id} index={index} ctx={ctx} />)}</ul> : <p className="small muted">None through supported relationships.</p>}</>}
      {pick(up, 'client').length > 0 && <><h3>Client code</h3><ul className="list">{pick(up, 'client').map((id) => <NodeLink key={id} id={id} index={index} ctx={ctx} />)}</ul></>}
      <h3>Tests</h3>{pick(up, 'test').length ? <ul className="list">{pick(up, 'test').map((id) => <NodeLink key={id} id={id} index={index} ctx={ctx} />)}</ul> : <p className="small muted">No test reaches this code.</p>}
      {pick(down, 'sink').length > 0 && <><h3>Sensitive sinks it reaches</h3><ul className="list">{pick(down, 'sink').map((id) => <NodeLink key={id} id={id} index={index} ctx={ctx} />)}</ul></>}
    </div>
  );
}

function severityExplanation(severity: Finding['severity']): string {
  switch (severity) {
    case 'high': return 'potentially serious; prioritize review. Severity is not proof that the issue is exploitable.';
    case 'medium': return 'worth investigating; practical impact may depend on configuration and exposure.';
    case 'low': return 'lower reported impact; review the evidence and context.';
    case 'info': return 'informational; this may be context rather than a confirmed vulnerability.';
    case 'unknown': return 'the scanner did not provide a severity, so impact is not ranked.';
  }
}

function EdgeDetails({ edge, index, ctx }: { edge: GraphEdge; index: Index; ctx: Ctx }) {
  return (
    <div>
      <div className="kind">Relationship</div>
      <div className="title">{EDGE_LABEL[edge.kind] ?? edge.kind}</div>
      <ul className="list"><NodeLink id={edge.source} index={index} ctx={ctx} note="from" /><NodeLink id={edge.target} index={index} ctx={ctx} note="to" /></ul>
      <dl className="kv" style={{ marginTop: 10 }}>
        <dt>Certainty</dt><dd>{edge.certainty === 'static' ? 'resolved statically' : 'inferred'} ({Math.round(edge.confidence * 100)}%)</dd>
        <dt>How</dt><dd>{edge.derivation}</dd>
        {edge.loc && <><dt>Where</dt><dd className="mono">{edge.loc.file}:{edge.loc.line}</dd></>}
      </dl>
      {edge.loc && <SourceSnippet projectId={ctx.projectId} file={edge.loc.file} line={edge.loc.line} tick={ctx.graph?.graphVersion ?? 0} />}
    </div>
  );
}
