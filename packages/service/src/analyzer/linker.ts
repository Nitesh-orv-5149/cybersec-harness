// Language-agnostic linker: turns per-file facts into a typed dependency graph.
// It never invents relationships: an edge exists only when a reference resolves to a known declaration.
import path from 'node:path';
import type { EdgeKind, FileFacts, Graph, GraphEdge, GraphNode, SinkKind } from './types.js';
import { AUTH_HINT } from './js-adapter.js';

export const SINK_LABELS: Record<SinkKind, string> = {
  command_exec: 'shell command execution',
  code_exec: 'dynamic code execution',
  sql_dynamic: 'dynamically built SQL query',
  path_access: 'filesystem path access',
  ssrf: 'server-side request to dynamic URL',
  dom_xss: 'HTML injection into DOM',
};

const DB_OBJECT = /^(db|database|pool|client|knex|prisma|repo|repository|store)$/i;
const DB_WRITE = /^(insert|create|update|upsert|delete|remove|save|write|set|put|destroy)/i;
const EXTS = ['', '.js', '.ts', '.tsx', '.jsx', '.mjs', '.cjs', '/index.js', '/index.ts', '/index.tsx'];

export function matchRoute(template: string, url: string): boolean {
  const clean = url.split('?')[0].split('#')[0].replace(/\/+$/, '') || '/';
  const t = template.replace(/\/+$/, '') || '/';
  const ts_ = t.split('/');
  const us = clean.split('/');
  for (let i = 0; i < ts_.length; i++) {
    if (ts_[i] === '*') return true;
    if (i >= us.length) return false;
    if (ts_[i].startsWith(':')) { if (!us[i]) return false; continue; }
    if (us[i].startsWith(':')) continue; // URL built from template literal: '/api/orders/' + id
    if (ts_[i] !== us[i]) return false;
  }
  return ts_.length === us.length;
}

function joinRoute(prefix: string, p: string): string {
  const j = `/${prefix}/${p}`.replace(/\/+/g, '/');
  return j.length > 1 ? j.replace(/\/$/, '') : j;
}

export function link(all: FileFacts[], provider: string, unsavedFiles: Set<string> = new Set()): Graph {
  const byFile = new Map(all.map((f) => [f.file, f]));
  const nodes = new Map<string, GraphNode>();
  const edges = new Map<string, GraphEdge>();
  let unresolvedCalls = 0;

  const addNode = (n: GraphNode) => { if (!nodes.has(n.id)) nodes.set(n.id, n); return n.id; };
  const addEdge = (e: Omit<GraphEdge, 'id'>) => {
    if (e.source === e.target) return;
    const id = `${e.kind}:${e.source}->${e.target}`;
    if (!edges.has(id)) edges.set(id, { id, ...e });
  };

  const resolveSpec = (from: string, spec: string): string | null => {
    if (!spec.startsWith('.')) return null;
    const base = path.posix.normalize(path.posix.join(path.posix.dirname(from), spec));
    const stems = [base, base.replace(/\.(m|c)?js$/, '')];
    for (const s of stems) for (const ext of EXTS) if (byFile.has(s + ext)) return s + ext;
    return null;
  };

  const declId = (file: string, qname: string) => {
    const f = byFile.get(file)!;
    const d = f.decls.find((x) => x.qname === qname);
    return d?.kind === 'test' ? `test:${file}#${qname}` : `fn:${file}#${qname}`;
  };
  const hasDecl = (file: string, qname: string) => !!byFile.get(file)?.decls.some((d) => d.qname === qname);

  /** Resolve a local identifier in `file` to (file, localName) following imports/re-exports. */
  const resolveBinding = (file: string, name: string, depth = 0): { file: string; local: string } | null => {
    const f = byFile.get(file);
    if (!f || depth > 5) return null;
    const imp = f.imports.find((i) => i.local === name);
    if (imp) {
      const target = resolveSpec(file, imp.spec);
      if (!target) return null;
      if (imp.imported === '*') return { file: target, local: '*' };
      const local = byFile.get(target)!.exports[imp.imported];
      return local ? resolveBinding(target, local, depth + 1) : null;
    }
    if (hasDecl(file, name) || f.objectVars.includes(name) || name in f.routerVars) return { file, local: name };
    return null;
  };

  const resolveIdent = (file: string, name: string): string | null => {
    const b = resolveBinding(file, name);
    if (!b || b.local === '*') return null;
    return hasDecl(b.file, b.local) ? declId(b.file, b.local) : null;
  };

  const resolveMember = (file: string, obj: string, prop: string): string | null => {
    const b = resolveBinding(file, obj);
    if (!b) return null;
    if (b.local === '*') {
      const tf = byFile.get(b.file)!;
      const local = tf.exports[prop];
      return local && hasDecl(b.file, local) ? declId(b.file, local) : null;
    }
    const q = `${b.local}.${prop}`;
    return hasDecl(b.file, q) ? declId(b.file, q) : null;
  };

  const isKnownLocal = (file: string, name: string) => {
    const f = byFile.get(file)!;
    return hasDecl(file, name) || f.objectVars.includes(name) || f.imports.some((i) => i.local === name && i.spec.startsWith('.'));
  };

  // ---- modules, imports, declarations ----
  for (const f of all) {
    addNode({
      id: `mod:${f.file}`, kind: 'module', label: f.file, loc: { file: f.file, line: 1 }, hash: f.hash,
      fromUnsavedBuffer: unsavedFiles.has(f.file) || undefined,
      meta: { language: f.language, isTest: f.isTest, isClient: f.isClient, parseError: f.parseError },
    });
  }
  for (const f of all) {
    for (const imp of f.imports) {
      const t = resolveSpec(f.file, imp.spec);
      if (t) addEdge({ source: `mod:${f.file}`, target: `mod:${t}`, kind: 'imports', loc: { file: f.file, line: imp.line }, certainty: 'static', confidence: 1, derivation: `import of '${imp.spec}' resolved to ${t}` });
    }
    for (const d of f.decls) {
      const obj = d.qname.includes('.') ? d.qname.split('.')[0] : '';
      const isDb = d.kind !== 'test' && DB_OBJECT.test(obj) && f.objectVars.includes(obj);
      const id = declId(f.file, d.qname);
      addNode({
        id,
        kind: d.kind === 'test' ? 'test' : isDb ? 'database' : 'function',
        label: d.kind === 'test' ? d.qname : d.kind === 'handler' ? d.qname.replace(/^route /, 'handler ') : `${d.qname}()`,
        loc: { file: f.file, line: d.line, endLine: d.endLine },
        hash: d.hash,
        fromUnsavedBuffer: unsavedFiles.has(f.file) || undefined,
        meta: { qname: d.qname, declKind: d.kind, params: d.params, sanitizationHint: d.sanitizationHint, isClient: f.isClient },
      });
    }
  }

  // ---- route prefixes from mounts ----
  type RouterRef = { file: string; local: string };
  const mountsOf: { target: RouterRef; prefix: string; receiver: RouterRef; line: number; file: string }[] = [];
  for (const f of all) {
    for (const m of f.mounts) {
      const target = resolveBinding(f.file, m.target);
      if (!target) continue;
      mountsOf.push({ target, prefix: m.prefix, receiver: { file: f.file, local: m.receiver }, line: m.line, file: f.file });
    }
  }
  const prefixesFor = (r: RouterRef, depth = 0): { prefix: string; resolved: boolean }[] => {
    if (depth > 6) return [{ prefix: '', resolved: false }];
    const kind = byFile.get(r.file)?.routerVars[r.local];
    const parents = mountsOf.filter((m) => m.target.file === r.file && m.target.local === r.local);
    if (!parents.length) return [{ prefix: '', resolved: kind === 'app' }];
    return parents.flatMap((m) => prefixesFor(m.receiver, depth + 1).map((p) => ({ prefix: joinRoute(p.prefix, m.prefix), resolved: p.resolved })));
  };

  const endpoints: GraphNode[] = [];
  for (const f of all) {
    for (const r of f.routes) {
      const receiverKnown = r.receiver in f.routerVars;
      for (const { prefix, resolved } of prefixesFor({ file: f.file, local: r.receiver })) {
        const full = joinRoute(prefix, r.path);
        const authMw = r.middleware.filter((m) => AUTH_HINT.test(m));
        const id = addNode({
          id: `ep:${r.method} ${full}`, kind: 'endpoint', label: `${r.method} ${full}`,
          loc: { file: f.file, line: r.line }, hash: r.hash,
          fromUnsavedBuffer: unsavedFiles.has(f.file) || undefined,
          meta: {
            method: r.method, path: full, routeTemplate: r.path, prefix, router: r.receiver, framework: 'express',
            middleware: r.middleware,
            auth: authMw.length ? `auth-like middleware observed: ${authMw.join(', ')}` : 'no auth-like middleware observed',
            authObserved: authMw.length > 0,
            mountResolved: resolved,
            receiverCertainty: receiverKnown ? 'static' : 'inferred',
          },
        });
        endpoints.push(nodes.get(id)!);
        const certainty = receiverKnown ? 'static' as const : 'inferred' as const;
        let handlerId: string | null = null;
        if (r.handler?.kind === 'inline') handlerId = declId(f.file, r.handler.qname);
        else if (r.handler?.kind === 'ident') handlerId = resolveIdent(f.file, r.handler.name);
        else if (r.handler?.kind === 'member') handlerId = resolveMember(f.file, r.handler.object, r.handler.prop);
        if (handlerId) {
          // request inputs the handler reads directly (used to describe the endpoint, e.g. for API schema generation)
          const hm = /^fn:(.+)#(.+)$/.exec(handlerId);
          const ins = hm ? (byFile.get(hm[1])?.inputs ?? []).filter((x) => x.from === hm[2]) : [];
          if (ins.length) nodes.get(id)!.meta.inputs = ins.map((x) => ({ location: x.location, name: x.name, line: x.line, file: hm![1] }));
        }
        if (handlerId) addEdge({ source: id, target: handlerId, kind: 'route_to_handler', loc: { file: f.file, line: r.line }, certainty, confidence: receiverKnown ? 1 : 0.7, derivation: receiverKnown ? `route registered on Express ${f.routerVars[r.receiver]} '${r.receiver}'` : `route-like call on '${r.receiver}' (receiver type inferred from name)` });
        for (const mw of r.middleware) {
          const mid = /^[A-Za-z_$][\w$]*$/.test(mw) ? resolveIdent(f.file, mw) : null;
          if (mid) addEdge({ source: id, target: mid, kind: 'uses_middleware', loc: { file: f.file, line: r.line }, certainty, confidence: 1, derivation: 'middleware argument in route registration' });
        }
      }
    }
  }

  // ---- calls ----
  for (const f of all) {
    for (const c of f.calls) {
      const from = c.from ? declId(f.file, c.from) : `mod:${f.file}`;
      let target: string | null = null;
      let base: string | null = null;
      if (c.callee.kind === 'ident') { target = resolveIdent(f.file, c.callee.name); base = c.callee.name; }
      else if (c.callee.kind === 'member') { target = resolveMember(f.file, c.callee.object, c.callee.prop); base = c.callee.object; }
      if (!target) {
        if (!c.asReference && base && isKnownLocal(f.file, base) && !(base in f.routerVars)) unresolvedCalls++;
        continue;
      }
      const tnode = nodes.get(target)!;
      const fromNode = nodes.get(from);
      let kind: EdgeKind = 'calls';
      if (fromNode?.kind === 'test') kind = 'tests';
      else if (tnode.kind === 'database') {
        const prop = c.callee.kind === 'member' ? c.callee.prop : String(tnode.meta.qname).split('.').pop()!;
        kind = DB_WRITE.test(prop) ? 'writes_to' : 'reads_from';
      }
      addEdge({
        source: from, target, kind, loc: { file: f.file, line: c.line },
        certainty: c.asReference ? 'inferred' : 'static', confidence: c.asReference ? 0.7 : 1,
        derivation: c.asReference ? 'function passed as a callback argument' : c.callee.kind === 'member' ? `member call ${c.callee.object}.${c.callee.prop}() resolved through ${c.callee.object}` : 'direct call resolved through scope/imports',
      });
    }
    for (const r of f.renders) {
      const target = resolveIdent(f.file, r.tag);
      if (target) addEdge({ source: r.from ? declId(f.file, r.from) : `mod:${f.file}`, target, kind: 'renders', loc: { file: f.file, line: r.line }, certainty: 'static', confidence: 1, derivation: `JSX element <${r.tag}>` });
    }
  }

  // ---- client/server requests ----
  for (const f of all) {
    for (const r of f.requests) {
      const from = r.from ? declId(f.file, r.from) : `mod:${f.file}`;
      if (/^https?:\/\//.test(r.url)) {
        let host = r.url;
        try { host = new URL(r.url).host; } catch { /* keep raw */ }
        const ext = addNode({ id: `ext:${host}`, kind: 'external', label: host, meta: { url: r.url } });
        addEdge({ source: from, target: ext, kind: 'sends_request_to', loc: { file: f.file, line: r.line }, certainty: 'static', confidence: 1, derivation: 'HTTP request to literal absolute URL' });
        continue;
      }
      for (const ep of endpoints) {
        if (ep.meta.method !== r.method && ep.meta.method !== 'ALL') continue;
        if (!matchRoute(String(ep.meta.path), r.url)) continue;
        addEdge({ source: from, target: ep.id, kind: 'sends_request_to', loc: { file: f.file, line: r.line }, certainty: 'inferred', confidence: 0.8, derivation: `string literal '${r.method} ${r.url}' matched route template ${ep.label}` });
      }
    }
  }

  // ---- sensitive sinks ----
  for (const f of all) {
    const seen = new Map<string, number>();
    for (const s of f.sinks) {
      const from = s.from ? declId(f.file, s.from) : `mod:${f.file}`;
      const key = `${from}:${s.sinkKind}:${s.callee}`;
      const n = (seen.get(key) ?? 0) + 1;
      seen.set(key, n);
      const id = `sink:${key}${n > 1 ? `#${n}` : ''}`;
      addNode({
        id, kind: 'sink', label: `${s.callee}() · ${SINK_LABELS[s.sinkKind]}`,
        loc: { file: f.file, line: s.line },
        fromUnsavedBuffer: unsavedFiles.has(f.file) || undefined,
        meta: {
          sinkKind: s.sinkKind, callee: s.callee, argText: s.argText, directRequestInput: s.directRequestInput,
          paramsUsed: s.paramsUsed, classification: 'sensitive_sink', within: from,
          sanitizationHint: byFile.get(f.file)!.decls.find((d) => d.qname === s.from)?.sanitizationHint,
        },
      });
      addEdge({ source: from, target: id, kind: 'reaches_sensitive_sink', loc: { file: f.file, line: s.line }, certainty: 'static', confidence: 1, derivation: `${s.callee}() called with non-literal argument ${s.argText}` });
    }
  }

  return {
    nodes: [...nodes.values()],
    edges: [...edges.values()],
    provider,
    stats: {
      files: all.length,
      parsedFiles: all.filter((f) => !f.parseError).length,
      parseErrors: all.filter((f) => f.parseError).map((f) => ({ file: f.file, message: f.parseError! })),
      unresolvedCalls,
      unsupportedFiles: 0,
    },
  };
}
