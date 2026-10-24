// REAL nuclei execution (no mocked process). Opt-in: WORKBENCH_REAL_NUCLEI=1 and a nuclei binary on PATH (or
// WORKBENCH_NUCLEI_BIN). The target is a disposable HTTP server on a random loopback port started by this test, and
// the only templates are the two hand-written test templates in fixtures/web/templates. Nothing is downloaded:
// nuclei runs with -duc and DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD=true. Persistence uses the in-memory store.
//
//   cd packages/service && WORKBENCH_REAL_NUCLEI=1 npx vitest run test/web-nuclei.real.test.ts
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { ProjectConfigSchema } from '../src/config.js';
import { which } from '../src/security/exec.js';
import { WebScanService } from '../src/security/web/service.js';
import { checkNuclei } from '../src/security/web/nuclei.js';
import { execTool } from '../src/security/exec.js';
import { sleep } from '../src/util.js';
import { MemoryStore } from './helpers/memoryStore.js';

const TEMPLATES = path.resolve(__dirname, 'fixtures/web/templates');
const BIN = process.env.WORKBENCH_NUCLEI_BIN;
const enabled = process.env.WORKBENCH_REAL_NUCLEI === '1' && !!which('nuclei', BIN);
const cfg = () => ProjectConfigSchema.parse({ security: { nuclei: { binary: BIN, templatesDir: TEMPLATES, templates: ['http'], rateLimit: 20, timeoutMs: 120_000 } } }).security.nuclei;

describe.skipIf(!enabled)('real nuclei against a disposable local app', () => {
  let server: http.Server;
  let url: string;
  const mode = { vulnerable: true, requests: [] as string[] };

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      mode.requests.push(`${req.method} ${req.url}`);
      if (req.url === '/canary') {
        res.writeHead(200, { 'X-Workbench-Canary': 'exposed', 'Set-Cookie': 'sid=REALSECRET123; HttpOnly', 'Content-Type': 'text/plain' });
        return res.end('canary-version=4.5.6');
      }
      if (req.url === '/debug' && mode.vulnerable) { res.writeHead(200); return res.end('WORKBENCH-DEBUG-ENABLED'); }
      res.writeHead(404); res.end('not found');
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  });
  afterAll(() => new Promise((r) => server.close(r)));

  it('detects the installed version and verifies every flag the workbench uses', async () => {
    const r = await checkNuclei(cfg(), execTool, which, os.tmpdir());
    expect(r.state, r.reason ?? '').toBe('ready');
    expect(r.version).toMatch(/^\d+\.\d+\.\d+/);
    expect(r.templates.state).toBe('ready');
    console.log(`nuclei ${r.version} at ${r.binary}; optional flags missing: ${r.missingOptionalFlags.join(', ') || 'none'}`);
  });

  it('scans, persists findings, then sees the debug page disappear and come back', async () => {
    const store = new MemoryStore();
    const svc = new WebScanService({
      projectId: 'prj_real', projectDir: fs.mkdtempSync(path.join(os.tmpdir(), 'wb-real-nuclei-')), store: store as never, cfg, graph: () => null,
      graphVersion: () => null, sourceHash: () => null, snapshotReadiness: () => ({ ok: false, reasons: ['n/a'] }), prepareSnapshots: async () => { throw new Error('n/a'); },
      emit: () => {},
    });
    const scan = async () => {
      const { runId, status } = await svc.start({ mode: 'url', url });
      expect(status).toBe('running');
      const end = Date.now() + 120_000;
      while (svc.job && Date.now() < end) await sleep(100);
      return store.col('security_scan_runs').findOne({ _id: runId });
    };

    const first = await scan();
    console.log(JSON.stringify({ status: first.status, side: { ...first.sides.target, stderrTail: undefined }, counts: first.counts }, null, 2));
    expect(first.status, first.sides.target.reason ?? '').toBe('completed');
    expect(first.sides.target.templatesLoaded).toBe(2);
    expect(first.counts).toMatchObject({ total: 2, new: 2 });
    expect(mode.requests.every((r) => r.startsWith('GET '))).toBe(true);
    const obs = await store.col('security_observations').find({ runId: first._id }).toArray();
    const canary = obs.find((o: any) => o.templateId === 'workbench-canary-header');
    expect(canary).toMatchObject({ severity: 'medium', method: 'GET', endpoint: '/canary' });
    expect(canary.matchedAt).toBe(`${url}/canary`);
    expect(canary.extractedResults).toEqual(['4.5.6']);
    expect(canary.response).toContain('X-Workbench-Canary: exposed');
    expect(JSON.stringify(obs)).not.toContain('REALSECRET123');
    fs.writeFileSync(path.join(__dirname, 'fixtures/web/nuclei-output.real.jsonl'), obs.map((o: any) => JSON.stringify({ templateId: o.templateId, matchedAt: o.matchedAt.replace(url, 'http://127.0.0.1:PORT'), severity: o.originalSeverity, extracted: o.extractedResults })).join('\n') + '\n');

    mode.vulnerable = false;
    const second = await scan();
    expect(second.status).toBe('completed');
    expect(second.comparison).toMatchObject({ comparable: true });
    expect(second.comparison.absent).toHaveLength(1);

    mode.vulnerable = true;
    const third = await scan();
    expect(third.comparison.returned).toHaveLength(1);
  }, 400_000);
  it('incremental: re-runs only what changed, and still notices a fix', async () => {
    const store = new MemoryStore();
    const graph = { provider: 't', stats: { files: 0, parsedFiles: 0, parseErrors: [], unresolvedCalls: 0, unsupportedFiles: 0 }, edges: [],
      nodes: ['/api/a', '/api/b'].map((p) => ({ id: `ep:GET ${p}`, kind: 'endpoint' as const, label: p, hash: p, meta: { method: 'GET', path: p } })) };
    const svc = new WebScanService({
      projectId: 'prj_real_inc', projectDir: fs.mkdtempSync(path.join(os.tmpdir(), 'wb-real-inc-')), store: store as never, cfg, graph: () => graph,
      graphVersion: () => 1, sourceHash: () => null, snapshotReadiness: () => ({ ok: false, reasons: ['n/a'] }), prepareSnapshots: async () => { throw new Error('n/a'); },
      emit: () => {},
    });
    const scan = async () => {
      mode.requests.length = 0;
      const { runId } = await svc.start({ mode: 'url', url });
      const end = Date.now() + 120_000;
      while (svc.job && Date.now() < end) await sleep(100);
      const doc = await store.col('security_scan_runs').findOne({ _id: runId });
      // requests nuclei sent (the fixture templates probe <input>/canary and <input>/debug); the rest is fingerprinting
      return { doc, inc: doc.sides.target.incremental, nucleiRequests: mode.requests.filter((r) => /\/(canary|debug)$/.test(r)).sort() };
    };
    mode.vulnerable = true;
    const first = await scan();
    expect(first.doc.status, first.doc.sides.target.reason ?? '').toBe('completed');
    expect(first.inc).toMatchObject({ mode: 'full', pairs: { applicable: 6, toRun: 6 }, cache: { cachedNegatives: 4, recordedMatches: 2 } });
    expect(first.nucleiRequests).toEqual(['GET /api/a/canary', 'GET /api/a/debug', 'GET /api/b/canary', 'GET /api/b/debug', 'GET /canary', 'GET /debug']);

    const second = await scan(); // nothing changed: only the two matching checks at the root are re-verified
    expect(second.doc.status).toBe('completed');
    expect(second.inc).toMatchObject({ mode: 'delta', pairs: { toRun: 2, cached: 4 } });
    expect(second.nucleiRequests).toEqual(['GET /canary', 'GET /debug']);
    expect(second.doc.counts).toMatchObject({ recurring: 2, new: 0 });

    mode.vulnerable = false; // the fix is noticed although /debug's own fingerprint is not an input
    const third = await scan();
    expect(third.nucleiRequests).toEqual(['GET /canary', 'GET /debug']);
    expect(third.doc.counts).toMatchObject({ notCurrentlyObserved: 1 });

    mode.vulnerable = true; // and its return, although no fingerprint changed
    const fourth = await scan();
    expect(fourth.nucleiRequests).toEqual(['GET /canary', 'GET /debug']);
    expect(fourth.doc.counts).toMatchObject({ regressions: 1 });
    console.log(JSON.stringify({ first: first.inc.pairs, second: second.inc.pairs, groups: second.inc.groups }, null, 1));
  }, 400_000);
});
