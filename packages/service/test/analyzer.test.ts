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
    expect(imp.affectedEndpoints.sort()).toEqual(['ep:GET /api/orders', 'ep:GET /api/orders/:id', 'ep:GET /api/orders/:id/receipt', 'ep:POST /api/orders']);
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
