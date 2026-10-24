// Graph queries: dependents (impact), dependencies (reachability), paths and version diffs.
import type { Graph, GraphEdge, GraphNode } from './types.js';

export class GraphIndex {
  readonly nodes = new Map<string, GraphNode>();
  readonly out = new Map<string, GraphEdge[]>();
  readonly in = new Map<string, GraphEdge[]>();

  constructor(readonly graph: Graph) {
    for (const n of graph.nodes) this.nodes.set(n.id, n);
    for (const e of graph.edges) {
      if (e.kind === 'imports') continue; // module imports are shown but not traversed for impact
      (this.out.get(e.source) ?? this.out.set(e.source, []).get(e.source)!).push(e);
      (this.in.get(e.target) ?? this.in.set(e.target, []).get(e.target)!).push(e);
    }
  }

  /** Everything that (transitively) depends on `ids`: callers, handlers, endpoints, client code, tests. */
  upstream(ids: string[], maxDepth = 12): Map<string, number> {
    return this.bfs(ids, maxDepth, (id) => (this.in.get(id) ?? []).map((e) => e.source));
  }

  /** Everything `ids` (transitively) depends on: callees, database ops, sinks. */
  downstream(ids: string[], maxDepth = 12): Map<string, number> {
    return this.bfs(ids, maxDepth, (id) => (this.out.get(id) ?? []).map((e) => e.target));
  }

  private bfs(start: string[], maxDepth: number, next: (id: string) => string[]): Map<string, number> {
    const dist = new Map<string, number>();
    let frontier = start.filter((s) => this.nodes.has(s));
    frontier.forEach((s) => dist.set(s, 0));
    for (let d = 1; d <= maxDepth && frontier.length; d++) {
      const nf: string[] = [];
      for (const id of frontier) for (const n of next(id)) if (!dist.has(n)) { dist.set(n, d); nf.push(n); }
      frontier = nf;
    }
    return dist;
  }

  /**
   * Enumerate dependency paths from any node matching `isStart` down to `target`
   * (walking edges backwards from the target). Paths are returned start -> target.
   */
  pathsTo(target: string, isStart: (n: GraphNode) => boolean, opts: { maxDepth?: number; maxPaths?: number } = {}): string[][] {
    const maxDepth = opts.maxDepth ?? 10;
    const maxPaths = opts.maxPaths ?? 25;
    const results: string[][] = [];
    const stack: string[] = [target];
    const walk = (id: string) => {
      if (results.length >= maxPaths) return;
      const node = this.nodes.get(id);
      if (node && isStart(node) && stack.length > 1) { results.push([...stack].reverse()); }
      if (stack.length > maxDepth) return;
      for (const e of this.in.get(id) ?? []) {
        if (stack.includes(e.source)) continue;
        stack.push(e.source);
        walk(e.source);
        stack.pop();
      }
    };
    walk(target);
    return results;
  }

  edgeBetween(a: string, b: string): GraphEdge | undefined {
    return (this.out.get(a) ?? []).find((e) => e.target === b);
  }
}

export interface GraphDiff {
  addedNodes: string[];
  removedNodes: string[];
  changedNodes: string[];
  addedEdges: string[];
  removedEdges: string[];
}

export function diffGraphs(before: Graph | null, after: Graph): GraphDiff {
  if (!before) return { addedNodes: after.nodes.map((n) => n.id), removedNodes: [], changedNodes: [], addedEdges: after.edges.map((e) => e.id), removedEdges: [] };
  const b = new Map(before.nodes.map((n) => [n.id, n]));
  const a = new Map(after.nodes.map((n) => [n.id, n]));
  const be = new Set(before.edges.map((e) => e.id));
  const ae = new Set(after.edges.map((e) => e.id));
  return {
    addedNodes: [...a.keys()].filter((k) => !b.has(k)),
    removedNodes: [...b.keys()].filter((k) => !a.has(k)),
    changedNodes: [...a.values()].filter((n) => b.has(n.id) && n.kind !== 'module' && b.get(n.id)!.hash !== n.hash).map((n) => n.id),
    addedEdges: [...ae].filter((k) => !be.has(k)),
    removedEdges: [...be].filter((k) => !ae.has(k)),
  };
}

export interface ImpactSummary {
  changed: string[];
  affectedEndpoints: string[];
  affectedClientCode: string[];
  affectedTests: string[];
  reachableSinks: string[];
  paths: string[][];
}

/** Given changed node ids, compute who could be affected and what sinks the change can reach. */
export function impactOf(index: GraphIndex, changed: string[]): ImpactSummary {
  const changedFns = changed.filter((id) => index.nodes.get(id)?.kind !== 'module');
  const up = index.upstream(changedFns);
  const down = index.downstream(changedFns);
  const self = new Set(changedFns);
  const pick = (m: Map<string, number>, f: (n: GraphNode) => boolean) =>
    [...m.keys()].filter((id) => { const n = index.nodes.get(id); return !!n && !self.has(id) && f(n); });
  const affectedEndpoints = pick(up, (n) => n.kind === 'endpoint');
  const affectedClientCode = pick(up, (n) => n.kind === 'function' && n.meta.isClient === true);
  const affectedTests = pick(up, (n) => n.kind === 'test');
  const reachableSinks = pick(down, (n) => n.kind === 'sink');
  const paths: string[][] = [];
  for (const c of changedFns) {
    for (const p of index.pathsTo(c, (n) => n.kind === 'endpoint' || (n.kind === 'function' && n.meta.isClient === true) || n.kind === 'test', { maxPaths: 8 })) {
      paths.push(p);
      if (paths.length >= 40) break;
    }
  }
  return { changed: changedFns, affectedEndpoints, affectedClientCode, affectedTests, reachableSinks, paths };
}
