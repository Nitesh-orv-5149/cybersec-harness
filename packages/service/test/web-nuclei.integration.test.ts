// Nuclei web scanning end-to-end through the HTTP API and ProjectSession.
//  - "HTTP API" tests need no database: they check that the routes refuse unconfirmed and unauthorized scans.
//  - "with MongoDB" tests run against a REAL MongoDB (WORKBENCH_TEST_MONGO, default mongodb://127.0.0.1:27017) and are
//    skipped when it is unreachable. The nuclei PROCESS is still mocked there (fake exec); see web-nuclei.real.test.ts
//    for the real binary.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { MongoClient } from 'mongodb';
import { Store } from '../src/store/mongo.js';
import { ProjectSession } from '../src/project.js';
import { Service } from '../src/server.js';
import { serviceConfig } from '../src/config.js';
import { freePort } from '../src/runner.js';
import { sleep } from '../src/util.js';
import type { Exec, ExecResult, Which } from '../src/security/types.js';
import { OPTIONAL_FLAGS, REQUIRED_FLAGS } from '../src/security/web/nuclei.js';

const URI = process.env.WORKBENCH_TEST_MONGO || 'mongodb://127.0.0.1:27017';
const DB = `workbench_test_web_${Date.now()}`;
const TEMPLATES = path.resolve(__dirname, 'fixtures/web/templates');

const res = (p: Partial<ExecResult>): ExecResult => ({ exitCode: 0, signal: null, stdout: '', stdoutBytes: 0, stdoutTruncated: false, stderrTail: '', timedOut: false, cancelled: false, spawnError: null, durationMs: 3, ...p });
const HELP = [...REQUIRED_FLAGS, ...OPTIONAL_FLAGS].map((f) => ` -${f}, -x-${f}  d`).join('\n');
const fake = { stdout: '', exit: 0, calls: 0 };
const which: Which = (n) => `/fake/bin/${n}`;
const exec: Exec = async (_b, args) => {
  if (args[0] === '-version') return res({ stderrTail: '[INF] Nuclei Engine Version: v3.11.1' });
  if (args[0] === '-h') return res({ stdout: HELP });
  if (args[0] === '-tv') return res({ stderrTail: `[INF] Public nuclei-templates version: v10.3.1 (${TEMPLATES})` });
  fake.calls++;
  return res({ stdout: fake.stdout, exitCode: fake.exit, stderrTail: '[INF] Templates loaded for current scan: 2\n' });
};
const okFetch = (async () => new Response('ok')) as unknown as typeof fetch;
const line = (id: string, p: string, sev = 'medium') => JSON.stringify({ 'template-id': id, info: { name: id, severity: sev }, type: 'http', host: 'http://127.0.0.1:4555', url: 'http://127.0.0.1:4555', 'matched-at': `http://127.0.0.1:4555${p}`, request: `GET ${p} HTTP/1.1\r\nHost: x\r\nCookie: sid=SECRET\r\n\r\n` });

function makeProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wb-web-proj-'));
  fs.mkdirSync(path.join(root, 'src'));
  fs.writeFileSync(path.join(root, 'src/app.js'), "const express = require('express');\nconst app = express();\napp.get('/canary', (req, res) => res.send('x'));\napp.listen(3000);\n");
  fs.writeFileSync(path.join(root, 'workbench.config.json'), JSON.stringify({ analysis: { include: ['src'] }, security: { nuclei: { templatesDir: TEMPLATES, templates: ['http'] } } }));
  return root;
}

describe('HTTP API (no database needed)', () => {
  let svc: Service;
  let server: http.Server;
  let base: string;
  let projectId: string;
  beforeAll(async () => {
    const port = await freePort();
    svc = new Service(serviceConfig({ port, mongoUri: 'mongodb://127.0.0.1:1', dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'wb-web-api-')) }));
    const s = await svc.addProject(makeProject(), false);
    projectId = s.id;
    server = http.createServer(svc.app());
    await new Promise<void>((r) => server.listen(port, '127.0.0.1', () => r()));
    base = `http://127.0.0.1:${port}/api/projects/${projectId}/security/web/scans`;
  });
  afterAll(async () => { await new Promise((r) => server.close(r)); for (const s of svc.sessions.values()) await s.dispose(); });
  const post = (body: unknown) => fetch(base, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

  it('refuses a scan that was not explicitly confirmed', async () => {
    const r = await post({ mode: 'url', url: 'http://127.0.0.1:3000' });
    expect(r.status).toBe(400);
    expect(JSON.stringify(await r.json())).toContain('confirm must be true');
    expect((await post({ mode: 'url', url: 'http://127.0.0.1:3000', confirm: 'yes' })).status).toBe(400);
  });

  it('refuses unauthorized targets and URLs with credentials before anything runs', async () => {
    const r = await post({ mode: 'url', url: 'https://example.com', confirm: true });
    expect(r.status).toBe(400);
    expect((await r.json()).error).toContain('not authorized');
    expect((await post({ mode: 'url', url: 'http://u:p@127.0.0.1:3000', confirm: true })).status).toBe(400);
    expect((await post({ mode: 'url', confirm: true })).status).toBe(400);
  });

  it('refuses snapshot mode until a baseline and approved run commands exist', async () => {
    const r = await post({ mode: 'snapshots', confirm: true });
    expect(r.status).toBe(409);
    expect((await r.json()).error).toContain('cannot be started');
  });

  it('returns 503 for a confirmed, authorized scan when MongoDB is down (results must be persisted)', async () => {
    expect((await post({ mode: 'url', url: 'http://127.0.0.1:3000', confirm: true })).status).toBe(503);
  });
});

const probe = new MongoClient(URI, { serverSelectionTimeoutMS: 1500 });
const reachable = await probe.connect().then(() => true).catch(() => false);
await probe.close().catch(() => {});
let store: Store;
let session: ProjectSession;

describe.skipIf(!reachable)('with MongoDB (real server, mocked nuclei process)', () => {
  beforeAll(async () => {
    store = new Store(URI, DB);
    await store.connect();
    session = new ProjectSession(makeProject(), store, fs.mkdtempSync(path.join(os.tmpdir(), 'wb-web-data-')), { exec, which, fetch: okFetch });
    await session.init();
  }, 30_000);
  afterAll(async () => {
    await session.dispose();
    const c = new MongoClient(URI);
    await c.connect();
    await c.db(DB).dropDatabase();
    await c.close();
    await store.close();
  });

  async function scan(stdout: string, exit = 0) {
    fake.stdout = stdout;
    fake.exit = exit;
    const { runId } = await session.web.start({ mode: 'url', url: 'http://127.0.0.1:4555' });
    const end = Date.now() + 10_000;
    while (session.web.job && Date.now() < end) await sleep(25);
    return (await store.col('security_scan_runs').findOne({ _id: runId as never }))!;
  }
  const webFindings = () => store.col('graph_findings').find({ projectId: session.id, source: 'web' }).toArray();

  it('persists runs, redacted observations and findings linked to the code graph', async () => {
    const run = await scan([line('workbench-canary-header', '/canary'), line('workbench-debug-page', '/debug', 'low')].join('\n'));
    expect(run).toMatchObject({ category: 'web_dast', status: 'completed', counts: { total: 2, new: 2 } });
    const f = await webFindings();
    expect(f).toHaveLength(2);
    const canary = f.find((x) => x.web.templateId === 'workbench-canary-header')!;
    expect(canary.web.correlation).toMatchObject({ status: 'linked', endpointId: 'ep:GET /canary' });
    expect(f.find((x) => x.web.templateId === 'workbench-debug-page')!.web.correlation.status).toBe('unlinked');
    const obs = await store.col('security_observations').find({ runId: run._id }).toArray();
    expect(obs).toHaveLength(2);
    expect(JSON.stringify(obs)).not.toContain('SECRET');
  });

  it('keeps history: absent after a completed re-test, unchanged after a failed one, regression when it returns', async () => {
    const r2 = await scan(line('workbench-canary-header', '/canary'));
    expect(r2.comparison).toMatchObject({ comparable: true });
    expect(r2.comparison.absent).toHaveLength(1);
    const failed = await scan('', 1);
    expect(failed.status).toBe('failed');
    const debugId = r2.comparison.absent[0];
    expect((await store.col('graph_findings').findOne({ _id: debugId }))!.status).toBe('not_currently_observed');
    const r4 = await scan([line('workbench-canary-header', '/canary'), line('workbench-debug-page', '/debug', 'low')].join('\n'));
    expect(r4.comparison.returned).toEqual([debugId]);
    // the failed run is not the comparison base
    expect(r4.comparison.against.runId).toBe(r2._id);
    const records = await store.col('verification_records').find({ findingId: debugId }).sort({ at: 1 }).toArray();
    expect(records.map((r) => r.action)).toEqual(['observed', 'not_currently_observed', 'potential_regression']);
    const runs = await store.col('security_scan_runs').find({ projectId: session.id, category: 'web_dast' }).sort({ startedAt: 1 }).toArray();
    expect(runs.map((r) => r.status)).toEqual(['completed', 'completed', 'failed', 'completed']);
  });

  it('keeps incremental state in MongoDB behind lookup and TTL indexes, and serves an unchanged re-scan from it', async () => {
    const idx = await store.col('web_scan_cache').indexes();
    expect(idx.find((i) => i.key.expiresAt === 1)).toMatchObject({ expireAfterSeconds: 0 });
    expect(idx.some((i) => i.key.projectId === 1 && i.key.scope === 1)).toBe(true);
    expect((await store.col('web_endpoints').indexes()).some((i) => i.key.projectId === 1 && i.key.scope === 1 && i.key.kind === 1)).toBe(true);
    // both fixture templates have findings at '/', so they are always re-verified there; '/canary' comes from the cache
    const r = await scan([line('workbench-canary-header', '/canary'), line('workbench-debug-page', '/debug', 'low')].join('\n'));
    expect(r.status).toBe('completed');
    expect(r.sides.target.incremental).toMatchObject({ mode: 'delta', pairs: { applicable: 4, toRun: 2, cached: 2 } });
    const buckets = await store.col('web_scan_cache').find({ projectId: session.id }).toArray();
    expect(buckets.map((b) => b.input).sort()).toEqual(['/', '/canary']);
    expect(buckets[0]!.expiresAt).toBeInstanceOf(Date);
    const site = await store.col('web_endpoints').findOne({ projectId: session.id, kind: 'site' });
    expect(site?.fingerprint.infraHash).toMatch(/^[0-9a-f]{16}$/);
  });
});
