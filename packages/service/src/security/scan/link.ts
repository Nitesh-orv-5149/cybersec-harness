// Link a scanner location to the code graph. Only structural facts are used: a file:line inside a function
// node, or a request (method + path) that matches an endpoint's route template. Nothing here claims that a
// finding is exploitable; it says which code the location belongs to and what that code reaches.
import type { Graph, GraphNode } from '../../analyzer/types.js';
import { GraphIndex } from '../../analyzer/query.js';
import { matchRoute } from '../../analyzer/linker.js';
import { endpointFor } from '../api/openapi.js';
import type { ObsLocation } from './types.js';

export interface GraphLink {
  endpointId: string | null;
  functionId: string | null;
  sinks: string[];              // sensitive sink nodes reachable from the endpoint / containing function
  paths: string[][];            // endpoint -> ... -> sink (or endpoint -> ... -> function)
  nodes: string[];
  locations: { file: string; line: number }[];
  how: string | null;           // how the link was established
}

const EMPTY: GraphLink = { endpointId: null, functionId: null, sinks: [], paths: [], nodes: [], locations: [], how: null };

function endpointForUrl(graph: Graph, method: string | undefined, url: string): string | null {
  let p: string;
  try { p = new URL(url).pathname; } catch { p = url; }
  const eps = graph.nodes.filter((n) => n.kind === 'endpoint' && (!method || String(n.meta.method).toUpperCase() === method.toUpperCase() || n.meta.method === 'all'));
  const hits = eps.filter((n) => matchRoute(String(n.meta.path), p));
  // prefer the most specific template (fewest params)
  hits.sort((a, b) => (String(a.meta.path).match(/:/g)?.length ?? 0) - (String(b.meta.path).match(/:/g)?.length ?? 0));
  return hits[0]?.id ?? null;
}

export function linkLocation(graph: Graph | null, loc: ObsLocation, ix?: GraphIndex): GraphLink {
  if (!graph) return EMPTY;
  const index = ix ?? new GraphIndex(graph);
  const nodeLoc = (id: string) => { const n = index.nodes.get(id); return n?.loc ? [{ file: n.loc.file, line: n.loc.line }] : []; };

  // 1. request-shaped locations
  let endpointId: string | null = null;
  let how: string | null = null;
  if (loc.operation) {
    const [m, ...rest] = loc.operation.split(' ');
    endpointId = endpointFor(graph, m!, rest.join(' '));
    if (endpointId) how = `operation ${loc.operation} matches route ${index.nodes.get(endpointId)?.label}`;
  }
  if (!endpointId && loc.url) {
    endpointId = endpointForUrl(graph, loc.method, loc.url);
    if (endpointId) how = `request URL path matches route ${index.nodes.get(endpointId)?.label}`;
  }
  if (endpointId) {
    const down = index.downstream([endpointId]);
    const sinks = [...down.keys()].filter((id) => index.nodes.get(id)?.kind === 'sink');
    const paths = sinks.flatMap((s) => index.pathsTo(s, (n) => n.id === endpointId, { maxPaths: 3 })).slice(0, 8);
    const handler = (index.out.get(endpointId) ?? []).find((e) => e.kind === 'route_to_handler')?.target ?? null;
    const nodes = [...new Set([endpointId, ...(handler ? [handler] : []), ...paths.flat()])];
    return { endpointId, functionId: handler, sinks, paths, nodes, locations: [...nodeLoc(endpointId), ...(handler ? nodeLoc(handler) : [])], how };
  }

  // 2. file:line locations
  if (loc.file && loc.line) {
    const containing = graph.nodes
      .filter((n): n is GraphNode & { loc: NonNullable<GraphNode['loc']> } => (n.kind === 'function' || n.kind === 'sink') && !!n.loc && n.loc.file === loc.file && n.loc.line <= loc.line! && (n.loc.endLine ?? n.loc.line) >= loc.line!)
      .sort((a, b) => ((a.loc.endLine ?? a.loc.line) - a.loc.line) - ((b.loc.endLine ?? b.loc.line) - b.loc.line));
    const sinkHere = containing.find((n) => n.kind === 'sink' && n.loc.line === loc.line) ?? null;
    const fn = containing.find((n) => n.kind === 'function') ?? null;
    if (!fn && !sinkHere) return { ...EMPTY, locations: [{ file: loc.file, line: loc.line }] };
    const target = sinkHere?.id ?? fn!.id;
    const paths = index.pathsTo(target, (n) => n.kind === 'endpoint', { maxPaths: 6 });
    const endpoints = [...new Set(paths.map((p) => p[0]!))];
    return {
      endpointId: endpoints[0] ?? null, functionId: fn?.id ?? null, sinks: sinkHere ? [sinkHere.id] : [], paths,
      nodes: [...new Set([target, ...(fn ? [fn.id] : []), ...paths.flat()])],
      locations: [{ file: loc.file, line: loc.line }],
      how: `${loc.file}:${loc.line} is inside ${sinkHere ? `sensitive call ${sinkHere.label}` : `function ${fn!.label}`}${endpoints.length ? `, reached from ${endpoints.length} endpoint(s)` : ''}`,
    };
  }
  return { ...EMPTY, locations: loc.file && loc.line ? [{ file: loc.file, line: loc.line }] : [] };
}
