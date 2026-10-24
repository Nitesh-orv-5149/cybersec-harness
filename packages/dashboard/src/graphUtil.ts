import type { Graph, GraphEdge, GraphNode, NodeKind } from './api';

export const KIND_COLOR: Record<NodeKind, string> = {
  endpoint: '#5b9bf0', function: '#5ec38b', sink: '#ef5f6b', database: '#e0b04a', test: '#a48bf6', external: '#46c2c7', module: '#6b7585',
};
export const KIND_LABEL: Record<NodeKind, string> = {
  endpoint: 'API endpoint', function: 'Function', sink: 'Sensitive sink', database: 'Database operation', test: 'Test', external: 'External service', module: 'Module',
};
export const EDGE_LABEL: Record<string, string> = {
  route_to_handler: 'route → handler', uses_middleware: 'uses middleware', calls: 'calls', imports: 'imports', renders: 'renders',
  sends_request_to: 'sends request to', reads_from: 'reads from', writes_to: 'writes to', reaches_sensitive_sink: 'reaches sensitive sink', tests: 'tests',
};

export class Index {
  nodes = new Map<string, GraphNode>();
  out = new Map<string, GraphEdge[]>();
  in = new Map<string, GraphEdge[]>();
  constructor(g: Graph) {
    for (const n of g.nodes) this.nodes.set(n.id, n);
    for (const e of g.edges) {
      if (e.kind === 'imports') continue;
      (this.out.get(e.source) ?? this.out.set(e.source, []).get(e.source)!).push(e);
      (this.in.get(e.target) ?? this.in.set(e.target, []).get(e.target)!).push(e);
    }
  }
  walk(start: string[], dir: 'up' | 'down', depth = 12): Map<string, number> {
    const dist = new Map<string, number>();
    let f = start.filter((s) => this.nodes.has(s));
    f.forEach((s) => dist.set(s, 0));
    for (let d = 1; d <= depth && f.length; d++) {
      const nf: string[] = [];
      for (const id of f) {
        const edges = dir === 'up' ? this.in.get(id) ?? [] : this.out.get(id) ?? [];
        for (const e of edges) { const n = dir === 'up' ? e.source : e.target; if (!dist.has(n)) { dist.set(n, d); nf.push(n); } }
      }
      f = nf;
    }
    return dist;
  }
  edgesWithin(ids: Set<string>): string[] {
    const out: string[] = [];
    for (const [s, es] of this.out) if (ids.has(s)) for (const e of es) if (ids.has(e.target)) out.push(e.id);
    return out;
  }
  pathEdges(path: string[]): string[] {
    const out: string[] = [];
    for (let i = 0; i + 1 < path.length; i++) {
      const e = (this.out.get(path[i]) ?? []).find((x) => x.target === path[i + 1]);
      if (e) out.push(e.id);
    }
    return out;
  }
}

export function nodeName(n: GraphNode | undefined, fallback = ''): string {
  if (!n) return fallback;
  if (n.meta.declKind === 'handler') return n.label;
  if (n.kind === 'function' || n.kind === 'database') return String(n.meta.qname ?? n.label);
  return n.label;
}
