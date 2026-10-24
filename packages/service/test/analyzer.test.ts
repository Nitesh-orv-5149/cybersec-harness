import { describe, expect, it } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { Analyzer, analyzeDirectory } from '../src/analyzer/index.js';
import { GraphIndex, diffGraphs, impactOf } from '../src/analyzer/query.js';
import { matchRoute } from '../src/analyzer/linker.js';

const SAMPLE = path.resolve(__dirname, '../../../sample-app');
const opts = (root = SAMPLE) => ({ root, include: ['src', 'public/js', 'tests'], exclude: [], clientDirs: ['public'] });

function tmpProject(files: Record<string, string>) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wb-an-'));
  for (const [f, t] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true }); fs.writeFileSync(path.join(dir, f), t); }
  return dir;
}

describe('JS/TS adapter + linker on the sample app', () => {
  const g = analyzeDirectory(opts());
  const ids = new Set(g.nodes.map((n) => n.id));
  const edge = (kind: string, s: string, t: string) => g.edges.find((e) => e.kind === kind && e.source === s && e.target === t);

  it('resolves router mount prefixes into full endpoint paths', () => {
    expect(ids).toContain('ep:GET /api/orders');
    expect(ids).toContain('ep:GET /api/orders/:id/receipt');
    expect(ids).toContain('ep:GET /api/tools/files/:name');
    expect(ids).toContain('ep:GET /health');
  });

  it('links endpoint -> handler -> service -> shared util', () => {
    expect(edge('route_to_handler', 'ep:GET /api/orders', 'fn:src/routes/orders.js#listOrders')).toBeTruthy();
    expect(edge('calls', 'fn:src/routes/orders.js#listOrders', 'fn:src/services/orderService.js#orderService.list')).toBeTruthy();
    expect(edge('calls', 'fn:src/services/orderService.js#toView', 'fn:src/lib/format.js#formatCurrency')?.certainty).toBe('static');
  });

  it('records auth middleware observations', () => {
    const post = g.nodes.find((n) => n.id === 'ep:POST /api/orders')!;
    const get = g.nodes.find((n) => n.id === 'ep:GET /api/orders')!;
    expect(post.meta.authObserved).toBe(true);
    expect(get.meta.authObserved).toBe(false);
  });

  it('detects dynamic sinks and ignores literal ones', () => {
    const sinks = g.nodes.filter((n) => n.kind === 'sink').map((n) => n.meta.sinkKind).sort();
    expect(sinks).toEqual(['command_exec', 'path_access', 'sql_dynamic', 'sql_dynamic', 'ssrf']);
    const exec = g.nodes.find((n) => n.meta.sinkKind === 'command_exec')!;
    expect(exec.meta.directRequestInput).toBe(true);
  });

  it('marks client URL matches as inferred and maps tests', () => {
    const e = edge('sends_request_to', 'fn:public/js/orders.js#loadOrders', 'ep:GET /api/orders')!;
    expect(e.certainty).toBe('inferred');
    expect(g.edges.some((x) => x.kind === 'tests' && x.target === 'fn:src/lib/format.js#formatCurrency')).toBe(true);
  });

  it('computes impact of a shared utility', () => {
    const imp = impactOf(new GraphIndex(g), ['fn:src/lib/format.js#formatCurrency']);
    expect(imp.affectedEndpoints.sort()).toEqual(['ep:GET /api/orders', 'ep:GET /api/orders/:id', 'ep:GET /api/orders/:id/cancel', 'ep:GET /api/orders/:id/export', 'ep:GET /api/orders/:id/receipt', 'ep:POST /api/orders']);
    expect(imp.affectedClientCode).toContain('fn:public/js/orders.js#loadOrders');
    expect(imp.affectedTests.length).toBe(2);
    expect(imp.changed).toEqual(['fn:src/lib/format.js#formatCurrency']);
  });
});

describe('no fabricated relationships', () => {
  it('does not create edges for dynamic dispatch or unknown modules', () => {
    const dir = tmpProject({
      'src/a.js': "import lib from 'some-lib';\nconst handlers = {};\nexport function run(name) { handlers[name](); lib.go(); missing(); }\n",
    });
    const g = analyzeDirectory({ ...opts(dir), include: ['src'] });
    expect(g.edges.filter((e) => e.kind !== 'imports')).toEqual([]);
  });
});

describe('incremental analysis', () => {
  it('reparses only when content changes and flags unsaved buffers', () => {
    const dir = tmpProject({ 'src/x.js': 'export function a() { return b(); }\nfunction b() { return 1; }\n' });
    const an = new Analyzer({ ...opts(dir), include: ['src'] });
    an.fullScan();
    const g1 = an.build();
    expect(an.parseFile('src/x.js')).toBe(false);
    an.setOverlay('src/x.js', 'export function a() { return 2; }\nfunction b() { return 1; }\n');
    const g2 = an.build();
    const d = diffGraphs(g1, g2);
    expect(d.changedNodes).toContain('fn:src/x.js#a');
    expect(d.removedEdges).toContain('calls:fn:src/x.js#a->fn:src/x.js#b');
    expect(g2.nodes.find((n) => n.id === 'fn:src/x.js#a')!.fromUnsavedBuffer).toBe(true);
    an.setOverlay('src/x.js', null);
    expect(an.build().nodes.find((n) => n.id === 'fn:src/x.js#a')!.fromUnsavedBuffer).toBeUndefined();
  });

  it('keeps stable ids for unchanged symbols when lines shift', () => {
    const dir = tmpProject({ 'src/x.js': 'export function a() { return 1; }\n' });
    const an = new Analyzer({ ...opts(dir), include: ['src'] });
    an.fullScan();
    const g1 = an.build();
    fs.writeFileSync(path.join(dir, 'src/x.js'), '\n\n// comment\nexport function a() { return 1; }\n');
    an.parseFile('src/x.js');
    const d = diffGraphs(g1, an.build());
    expect(d.addedNodes).toEqual([]);
    expect(d.changedNodes).toEqual([]);
  });
});

describe('route matching', () => {
  it('matches params and template-literal URLs', () => {
    expect(matchRoute('/api/orders/:id', '/api/orders/42')).toBe(true);
    expect(matchRoute('/api/orders/:id', '/api/orders/:param')).toBe(true);
    expect(matchRoute('/api/orders', '/api/orders/42')).toBe(false);
    expect(matchRoute('/api/orders', '/api/orders?x=1')).toBe(true);
  });
});

describe('SQL sink detection', () => {
  it('flags interpolated, concatenated and variable-built SQL but not parameterised queries', () => {
    const dir = tmpProject({
      'src/db.js': 'export const db = { query(s, p) { return []; } };\n',
      'src/app.js': [
        "import express from 'express';",
        "import { db } from './db.js';",
        'const app = express();',
        "app.get('/a', a); app.get('/b', b); app.get('/c', c); app.get('/d', d);",
        'function a(req) { return db.query(`SELECT * FROM t WHERE id = ${req.query.id}`); }',
        "function b(req) { return db.query('SELECT * FROM t WHERE n = ' + req.query.n); }",
        "function c(req) { return db.query('SELECT * FROM t WHERE id = ?', [req.query.id]); }",
        'function d(req) { const sql = `SELECT * FROM t WHERE id = ${req.query.id}`; return db.query(sql); }',
      ].join('\n'),
    });
    const g = analyzeDirectory({ ...opts(dir), include: ['src'] });
    const flagged = g.nodes.filter((n) => n.kind === 'sink').map((n) => String(n.meta.within).split('#')[1]).sort();
    expect(flagged).toEqual(['a', 'b', 'd']);
    expect(g.nodes.find((n) => n.kind === 'sink' && String(n.meta.within).endsWith('#d'))!.meta.directRequestInput).toBe(true);
  });
});

describe('handler factories (Juice Shop style)', () => {
  it('resolves app.get(path, wrap(factory())) to the function the factory returns, with its inputs and sinks', () => {
    const dir = tmpProject({
      'src/server.ts': [
        "import express from 'express';",
        "import { searchProducts } from './routes/search';",
        "import * as utils from './lib/utils';",
        "import * as orders from './routes/orders';",
        'const app = express();',
        "app.get('/rest/products/search', utils.asyncHandler(searchProducts()));",
        "app.get('/rest/orders/:id', orders.getOrder({ verbose: true }));",
        "app.get('/rest/plain', plain);",
        'function plain(req, res) { res.send(req.query.x); }',
      ].join('\n'),
      'src/lib/utils.ts': 'export function asyncHandler(fn) { return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next); }\n',
      'src/routes/search.ts': [
        'export function searchProducts () {',
        '  return (req, res, next) => {',
        "    const criteria = req.query.q ?? '';",
        '    db.query(`SELECT * FROM Products WHERE name LIKE \'%${criteria}%\'`).then((r) => res.json(r));',
        '  };',
        '}',
      ].join('\n'),
      'src/routes/orders.ts': 'export const getOrder = (opts) => async (req, res) => { const { id } = req.params; res.json({ id, opts }); };\n',
    });
    const g = analyzeDirectory({ ...opts(dir), include: ['src'] });
    const ix = new GraphIndex(g);
    const handlerOf = (ep: string) => g.edges.find((e) => e.kind === 'route_to_handler' && e.source === ep)?.target;

    expect(handlerOf('ep:GET /rest/products/search')).toBe('fn:src/routes/search.ts#searchProducts.<returned>');
    expect(ix.nodes.get('fn:src/routes/search.ts#searchProducts.<returned>')!.label).toBe('handler returned by searchProducts()');
    expect(g.nodes.find((n) => n.id === 'ep:GET /rest/products/search')!.meta.inputs).toEqual([expect.objectContaining({ location: 'query', name: 'q' })]);
    const sinks = [...ix.downstream(['ep:GET /rest/products/search']).keys()].filter((id) => ix.nodes.get(id)?.kind === 'sink');
    expect(sinks.map((s) => ix.nodes.get(s)!.meta.sinkKind)).toContain('sql_dynamic');

    expect(handlerOf('ep:GET /rest/orders/:id')).toBe('fn:src/routes/orders.ts#getOrder.<returned>');
    expect(g.nodes.find((n) => n.id === 'ep:GET /rest/orders/:id')!.meta.inputs).toEqual([expect.objectContaining({ location: 'path', name: 'id' })]);
    expect(handlerOf('ep:GET /rest/plain')).toBe('fn:src/server.ts#plain');
  });
});
