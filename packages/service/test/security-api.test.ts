// API testing (Schemathesis): schema generation from the code graph, report reading against real
// Schemathesis 4.32.4 output (fixtures/api), argument building and authorisation rules.
import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { ProjectConfigSchema } from '../src/config.js';
import { analyzeDirectory } from '../src/analyzer/index.js';
import { expressToOpenApi, schemaFromFile, schemaFromGraph, BOUNDARY_EXAMPLES } from '../src/security/api/openapi.js';
import { displayArgs, readEvents, readRunSummary, schemathesisArgs } from '../src/security/api/schemathesis.js';
import { apiKind } from '../src/security/api/kind.js';
import { linkLocation } from '../src/security/scan/link.js';

const FX = path.resolve(__dirname, 'fixtures/api');
const APP = path.join(FX, 'items-app');
const read = (f: string) => fs.readFileSync(path.join(FX, f), 'utf8');
const graph = analyzeDirectory({ root: APP, include: ['src'], exclude: ['node_modules'], clientDirs: [] });
const apiCfg = (api: object = {}) => ProjectConfigSchema.parse({ security: { api } }).security.api;

describe('request inputs and graph-derived OpenAPI', () => {
  it('records the inputs each handler reads', () => {
    const search = graph.nodes.find((n) => n.id === 'ep:GET /api/items/search')!;
    expect(search.meta.inputs).toEqual([expect.objectContaining({ location: 'query', name: 'q' })]);
    const byId = graph.nodes.find((n) => n.id === 'ep:GET /api/items/:id')!;
    expect(byId.meta.inputs).toEqual([expect.objectContaining({ location: 'path', name: 'id' })]);
  });

  it('converts Express templates and refuses ones OpenAPI cannot express', () => {
    expect(expressToOpenApi('/a/:id/b/:name')).toEqual({ path: '/a/{id}/b/{name}', params: ['id', 'name'] });
    expect(expressToOpenApi('/files/*')).toBeNull();
  });

  it('builds one operation per endpoint with boundary examples, mapped back to graph endpoints', () => {
    const s = schemaFromGraph(graph, ['GET']);
    expect(s.operations.map((o) => o.key).sort()).toEqual(['GET /api/items/search', 'GET /api/items/{id}', 'GET /health']);
    expect(s.operations.every((o) => o.endpointId?.startsWith('ep:'))).toBe(true);
    const q = (s.document as any).paths['/api/items/search'].get.parameters[0];
    expect(q).toMatchObject({ name: 'q', in: 'query', required: false });
    expect(Object.values(q.examples).map((e: any) => e.value)).toEqual(Object.values(BOUNDARY_EXAMPLES));
    expect((s.document as any).paths['/api/items/search'].get['x-workbench-endpoint']).toBe('ep:GET /api/items/search');
  });

  it('honours the method allow-list and says why operations were left out', () => {
    const s = schemaFromGraph(graph, ['POST']);
    expect(s.operations).toEqual([]);
    expect(s.excluded.every((e) => /not in security.api.methods/.test(e.reason))).toBe(true);
  });

  it('loads a project schema file, refuses paths outside the project and maps operations to endpoints', () => {
    const tmp = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'wb-oa-'));
    fs.writeFileSync(path.join(tmp, 'openapi.json'), read('graph-derived.openapi.json'));
    const s = schemaFromFile(tmp, 'openapi.json', graph, ['GET']);
    expect(s.operations.find((o) => o.key === 'GET /api/items/{id}')?.endpointId).toBe('ep:GET /api/items/:id');
    expect(() => schemaFromFile(tmp, '../etc/passwd', graph, ['GET'])).toThrow(/outside the project/);
  });
});

describe('Schemathesis reports (real 4.32.4 output)', () => {
  it('reads the run summary', () => {
    const s = readRunSummary(read('schemathesis-4.32.4.run.json'));
    expect('error' in s).toBe(false);
    if ('error' in s) return;
    expect(s).toMatchObject({ version: '4.32.4', complete: true, stopReason: 'completed', operations: { selected: 3, tested: 3, errored: 0 } });
  });

  it('rejects summaries it cannot interpret instead of assuming success', () => {
    expect(readRunSummary('{broken')).toHaveProperty('error');
    expect(readRunSummary('{"foo":1}')).toHaveProperty('error');
  });

  it('extracts one observation per failing check with request/response evidence', () => {
    const r = readEvents(read('schemathesis-4.32.4.events.ndjson'), { toolVersion: '4.32.4', headerNames: [] });
    expect(r.testedOperations).toEqual(['GET /api/items/search', 'GET /api/items/{id}', 'GET /health']);
    expect(r.malformedLines).toBe(0);
    expect(r.observations).toHaveLength(1);
    const o = r.observations[0]!;
    expect(o).toMatchObject({ tool: 'schemathesis', ruleId: 'ST101', ruleName: 'Server error', severity: 'high', originalSeverity: 'critical', location: { operation: 'GET /api/items/search', method: 'GET' } });
    expect((o.evidence as any).request.path).toBe("/api/items/search?q=%27");
    expect((o.evidence as any).response.status).toBe(500);
    expect((o.evidence as any).response.body).toContain('SQL syntax error');
    expect(o.ids).toEqual(['not_a_server_error', 'ST101']);
  });

  it('redacts credentials in recorded requests', () => {
    const line = JSON.stringify({ ScenarioFinished: { status: 'failure', phase: 'fuzzing', recorder: {
      label: 'GET /x', cases: {}, checks: { c1: [{ name: 'not_a_server_error', status: 'failure', failure_info: { failure: { code: 'ST101', title: 'Server error', severity: 'critical', operation: 'GET /x' } } }] },
      interactions: { c1: { request: { method: 'GET', uri: 'http://127.0.0.1:1/x?token=abc', headers: { Authorization: ['Bearer s3cr3t'], 'X-Api-Key': ['k'] } }, response: { status_code: 500, headers: {}, content: 'boom' } } },
    } } });
    const r = readEvents(line, { toolVersion: null, headerNames: ['X-Api-Key'] });
    const req = (r.observations[0]!.evidence as any).request;
    expect(req.headers).toEqual({ Authorization: '[redacted]', 'X-Api-Key': '[redacted]' });
    expect(req.path).toBe('/x?token=***');
  });

  it('ignores malformed lines but counts them', () => {
    const r = readEvents('not json\n{"Other":{}}\n', { toolVersion: null, headerNames: [] });
    expect(r).toMatchObject({ observations: [], malformedLines: 1, scenarios: 0 });
  });
});

describe('Schemathesis command line and authorisation', () => {
  it('builds an argument array with local report paths, method filters and no database', () => {
    const args = schemathesisArgs({ schema: '/s.json', baseUrl: 'http://127.0.0.1:5', cfg: apiCfg({ seed: 3, headers: { Authorization: 'Bearer t' } }), runJson: '/r.json', ndjson: '/e.ndjson' });
    expect(args.slice(0, 4)).toEqual(['run', '/s.json', '--url', 'http://127.0.0.1:5']);
    expect(args).toContain('--generation-database');
    expect(args.join(' ')).toContain('--include-method GET --include-method HEAD --include-method OPTIONS');
    expect(args.join(' ')).toContain('--report json,ndjson');
    expect(displayArgs(args).join(' ')).toContain('-H Authorization: [redacted]');
    expect(displayArgs(args).join(' ')).not.toContain('Bearer t');
  });

  it('is disabled for active testing by default and needs a per-run confirmation', () => {
    const cfg = ProjectConfigSchema.parse({});
    expect(cfg.security.api.allowActiveTesting).toBe(false);
    expect(cfg.security.api.methods).toEqual(['GET', 'HEAD', 'OPTIONS']);
    expect(apiKind.preconditions(cfg, { confirmActive: true })[0]).toMatch(/allowActiveTesting/);
    const on = ProjectConfigSchema.parse({ security: { api: { allowActiveTesting: true } } });
    expect(apiKind.preconditions(on, {})).toEqual([expect.stringMatching(/confirm/)]);
    expect(apiKind.preconditions(on, { confirmActive: true })).toEqual([]);
  });
});

describe('graph linking', () => {
  it('links an operation to its endpoint, handler and the sinks it reaches', () => {
    const l = linkLocation(graph, { operation: 'GET /api/items/search' });
    expect(l.endpointId).toBe('ep:GET /api/items/search');
    expect(l.functionId).toBe('fn:src/routes/items.js#searchItems');
    expect(l.sinks.some((s) => s.includes('sql_dynamic'))).toBe(true);
  });

  it('links a request URL with a concrete id to the parameterised route', () => {
    expect(linkLocation(graph, { method: 'GET', url: 'http://127.0.0.1:9/api/items/42' }).endpointId).toBe('ep:GET /api/items/:id');
  });

  it('links a file:line inside a handler and finds the endpoints above it', () => {
    const l = linkLocation(graph, { file: 'src/routes/items.js', line: 11 });
    expect(l.functionId).toBe('fn:src/routes/items.js#searchItems');
    expect(l.endpointId).toBe('ep:GET /api/items/search');
  });

  it('returns no link for unknown locations', () => {
    expect(linkLocation(graph, { operation: 'GET /nope' }).how).toBeNull();
    expect(linkLocation(null, { file: 'x.js', line: 1 }).how).toBeNull();
  });
});
