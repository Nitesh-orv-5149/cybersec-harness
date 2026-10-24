// Link a URL that the scanner matched to an Express endpoint in the code graph. A link is made only when the
// graph actually contains a route whose template matches the concrete path (and the method, when the request
// dump told us the method). Ambiguous or unmatched URLs stay "unlinked web findings".
import type { Graph, GraphNode } from '../../analyzer/types.js';

export interface WebCorrelation {
  status: 'linked' | 'unlinked';
  endpointId: string | null;
  handlers: string[];
  handlerLocations: { file: string; line: number }[];
  reason: string;
}

/** Express path template -> RegExp over a concrete path. Null when the template cannot be matched safely. */
export function routeRegex(template: string): RegExp | null {
  if (/[()[\]?+]/.test(template.replace(/:[A-Za-z_]\w*/g, ''))) return null;
  const body = template
    .replace(/\/+$/, '')
    .split('/')
    .map((seg) => (seg.startsWith(':') ? '[^/]+' : seg === '*' ? '.*' : seg.replace(/[.*^${}|\\]/g, '\\$&')))
    .join('/');
  return new RegExp(`^${body || ''}/?$`);
}

export function correlate(graph: Graph | null, method: string | null, endpoint: string, basePath = '/'): WebCorrelation {
  const none = (reason: string): WebCorrelation => ({ status: 'unlinked', endpointId: null, handlers: [], handlerLocations: [], reason });
  if (!graph) return none('No code graph was available.');
  let p = endpoint.split('?')[0]!;
  const base = basePath.replace(/\/+$/, '');
  if (base && p.startsWith(base + '/')) p = p.slice(base.length);
  const eps = graph.nodes.filter((n): n is GraphNode => n.kind === 'endpoint' && n.meta.mountResolved !== false);
  const matches = eps.filter((n) => {
    const re = routeRegex(String(n.meta.path ?? ''));
    if (!re || !re.test(p)) return false;
    const m = String(n.meta.method ?? '').toUpperCase();
    return !method || m === method || m === 'ALL' || (method === 'HEAD' && m === 'GET');
  });
  if (!matches.length) return none(`No route in the code graph matches ${method ?? 'any method'} ${p}${p.includes('.') ? ' (likely a static file or a path the app does not route)' : ''}.`);
  // Prefer a literal route over a parameterised one, as Express would only if registered first; if several remain, refuse to guess.
  const literal = matches.filter((n) => !String(n.meta.path).includes(':') && !String(n.meta.path).includes('*'));
  const pick = literal.length === 1 ? literal : matches;
  if (pick.length !== 1) return none(`${pick.length} routes match ${p} (${pick.map((n) => n.label).join(', ')}); the URL is not linked to avoid guessing.`);
  const ep = pick[0]!;
  const handlerIds = graph.edges.filter((e) => e.source === ep.id && e.kind === 'route_to_handler').map((e) => e.target);
  const handlers = graph.nodes.filter((n) => handlerIds.includes(n.id));
  return {
    status: 'linked', endpointId: ep.id, handlers: handlers.map((h) => h.id),
    handlerLocations: handlers.filter((h) => h.loc).map((h) => ({ file: h.loc!.file, line: h.loc!.line })),
    reason: `${method ?? 'Request'} ${p} matches route ${ep.label}${method ? '' : ' (method unknown; path match only)'}.`,
  };
}
