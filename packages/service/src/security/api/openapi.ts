// OpenAPI documents for API testing: either derived from the code graph's endpoints (method, path template and
// the request inputs each handler reads directly) or loaded from a schema file in the project. Every operation is
// mapped back to a graph endpoint so failures link to handlers and sinks.
import fs from 'node:fs';
import path from 'node:path';
import type { Graph, GraphNode } from '../../analyzer/types.js';

export const SCHEMA_METHODS = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;
export type HttpMethod = (typeof SCHEMA_METHODS)[number];

/** Boundary values sent in Schemathesis' examples phase for every string input of a graph-derived schema.
 *  They probe input handling (empty values, quote characters, numeric edge cases), not specific exploits. */
export const BOUNDARY_EXAMPLES: Record<string, string> = { empty: '', singleQuote: "'", doubleQuote: '"', zero: '0', negative: '-1' };
const boundaryExamples = () => Object.fromEntries(Object.entries(BOUNDARY_EXAMPLES).map(([k, v]) => [k, { value: v }]));

export interface OperationInfo {
  key: string;                 // "GET /api/items/{id}" — the label Schemathesis reports
  method: HttpMethod;
  path: string;                // OpenAPI path template
  endpointId: string | null;   // graph node id when mapped
  inputs: { location: string; name: string | null }[];
}

export interface PreparedSchema {
  source: 'graph' | 'file';
  document: Record<string, unknown>;
  schemaFile: string | null;   // project-relative path for file schemas
  operations: OperationInfo[]; // operations that will be tested (after method filter)
  excluded: { key: string; reason: string }[];
  notes: string[];
}

/** Express template (/a/:id, /files/*) -> OpenAPI template (/a/{id}); null when it cannot be expressed. */
export function expressToOpenApi(p: string): { path: string; params: string[] } | null {
  if (/[*()?+]/.test(p.replace(/:[A-Za-z_]\w*/g, ''))) return null;
  const params: string[] = [];
  const out = p.replace(/:([A-Za-z_]\w*)/g, (_, n: string) => { params.push(n); return `{${n}}`; });
  return { path: out || '/', params };
}

const norm = (p: string) => (p.replace(/\{[^}]+\}/g, '{}').replace(/:[A-Za-z_]\w*/g, '{}').replace(/\/+$/, '') || '/');

/** Map a method + OpenAPI path to a graph endpoint (exact template match, then suffix match for server base paths). */
export function endpointFor(graph: Graph | null, method: string, oaPath: string): string | null {
  if (!graph) return null;
  const eps = graph.nodes.filter((n) => n.kind === 'endpoint' && String(n.meta.method).toUpperCase() === method.toUpperCase());
  const want = norm(oaPath);
  const exact = eps.find((n) => norm(String(n.meta.path)) === want);
  if (exact) return exact.id;
  const suffix = eps.filter((n) => norm(String(n.meta.path)).endsWith(want) || want.endsWith(norm(String(n.meta.path))));
  return suffix.length === 1 ? suffix[0]!.id : null;
}

export function schemaFromGraph(graph: Graph, methods: string[]): PreparedSchema {
  const paths: Record<string, Record<string, unknown>> = {};
  const operations: OperationInfo[] = [];
  const excluded: PreparedSchema['excluded'] = [];
  const endpoints = graph.nodes.filter((n): n is GraphNode => n.kind === 'endpoint').sort((a, b) => a.id.localeCompare(b.id));
  for (const ep of endpoints) {
    const method = String(ep.meta.method).toUpperCase();
    const key = `${method} ${ep.meta.path}`;
    if (!(SCHEMA_METHODS as readonly string[]).includes(method)) { excluded.push({ key, reason: `method ${method} cannot be described as one OpenAPI operation` }); continue; }
    if (!methods.includes(method)) { excluded.push({ key, reason: `${method} is not in security.api.methods` }); continue; }
    if (ep.meta.mountResolved === false) { excluded.push({ key, reason: 'router mount prefix could not be resolved, so the real URL is unknown' }); continue; }
    const conv = expressToOpenApi(String(ep.meta.path));
    if (!conv) { excluded.push({ key, reason: 'path uses wildcards or regex syntax that OpenAPI cannot express' }); continue; }
    const inputs = ((ep.meta.inputs as { location: string; name: string | null }[] | undefined) ?? []);
    const params: Record<string, unknown>[] = conv.params.map((n) => ({ name: n, in: 'path', required: true, schema: { type: 'string', minLength: 1 }, examples: Object.fromEntries(Object.entries(boundaryExamples()).filter(([k]) => k !== 'empty')) }));
    for (const q of inputs.filter((i) => i.location === 'query' && i.name)) {
      if (!params.some((p) => p.name === q.name && p.in === 'query')) params.push({ name: q.name, in: 'query', required: false, schema: { type: 'string' }, examples: boundaryExamples() });
    }
    const op: Record<string, unknown> = {
      operationId: `${method.toLowerCase()}_${conv.path.replace(/[^A-Za-z0-9]+/g, '_').replace(/^_|_$/g, '') || 'root'}`,
      summary: `${ep.label} (from code graph)`,
      'x-workbench-endpoint': ep.id,
      'x-workbench-source': ep.loc ? `${ep.loc.file}:${ep.loc.line}` : null,
      parameters: params,
      responses: { default: { description: 'Not described: derived from code, no response contract is known.' } },
    };
    const body = inputs.filter((i) => i.location === 'body');
    if (['POST', 'PUT', 'PATCH'].includes(method) && body.length) {
      const named = body.filter((b) => b.name).map((b) => b.name!);
      op.requestBody = {
        required: false,
        content: { 'application/json': { schema: named.length ? { type: 'object', properties: Object.fromEntries(named.map((n) => [n, {}])) } : { type: 'object' } } },
      };
    }
    (paths[conv.path] ??= {})[method.toLowerCase()] = op;
    operations.push({ key: `${method} ${conv.path}`, method: method as HttpMethod, path: conv.path, endpointId: ep.id, inputs });
  }
  return {
    source: 'graph', schemaFile: null, operations, excluded,
    document: { openapi: '3.0.3', info: { title: 'Derived from the workbench code graph', version: '1' }, paths },
    notes: [
      'Schema derived from Express routes in the code graph. Parameter and body types are unknown (any value is allowed), and only inputs read directly in the handler are listed.',
      'No response contracts are known, so only checks that need no schema (such as not_a_server_error) are meaningful.',
      `String inputs carry boundary examples (${Object.values(BOUNDARY_EXAMPLES).map((v) => JSON.stringify(v)).join(', ')}) that the examples phase sends in addition to generated values.`,
    ],
  };
}

/** Load a project OpenAPI document (JSON or YAML-free JSON only) and list its operations. */
export function schemaFromFile(root: string, rel: string, graph: Graph | null, methods: string[]): PreparedSchema {
  const abs = path.resolve(root, rel);
  if (!abs.startsWith(path.resolve(root) + path.sep)) throw new Error(`schema path ${rel} is outside the project`);
  const text = fs.readFileSync(abs, 'utf8');
  let doc: Record<string, unknown>;
  try { doc = JSON.parse(text); }
  catch { throw new Error(`${rel} is not JSON. Only JSON OpenAPI documents are supported in this version; convert YAML with any converter first.`); }
  const pathsObj = (doc.paths ?? {}) as Record<string, Record<string, unknown>>;
  const operations: OperationInfo[] = [];
  const excluded: PreparedSchema['excluded'] = [];
  for (const [p, item] of Object.entries(pathsObj)) {
    for (const m of Object.keys(item)) {
      const method = m.toUpperCase();
      if (!(SCHEMA_METHODS as readonly string[]).includes(method)) continue;
      const key = `${method} ${p}`;
      if (!methods.includes(method)) { excluded.push({ key, reason: `${method} is not in security.api.methods` }); continue; }
      operations.push({ key, method: method as HttpMethod, path: p, endpointId: endpointFor(graph, method, p), inputs: [] });
    }
  }
  const unmapped = operations.filter((o) => !o.endpointId).length;
  return {
    source: 'file', schemaFile: rel, document: doc, operations, excluded,
    notes: unmapped ? [`${unmapped} operation(s) could not be matched to an endpoint in the code graph; their failures are not linked to code.`] : [],
  };
}
