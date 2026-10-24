// API testing end-to-end: ProjectSession + MongoDB + the managed local target (the fixture app really starts).
// Part 1 replays the real Schemathesis 4.32.4 reports through a fake process so lifecycle rules are deterministic.
// Part 2 runs the real `schemathesis` when it is on PATH (skipped otherwise).
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { MongoClient } from 'mongodb';
import { Store } from '../src/store/mongo.js';
import { ProjectSession } from '../src/project.js';
import { sleep } from '../src/util.js';
import { which as realWhich } from '../src/security/exec.js';
import type { Exec, ExecResult, Which } from '../src/security/types.js';

const URI = process.env.WORKBENCH_TEST_MONGO || 'mongodb://127.0.0.1:27017';
const FX = path.resolve(__dirname, 'fixtures/api');
const NODE_MODULES = path.resolve(__dirname, '../../../node_modules');
const RUN_JSON = fs.readFileSync(path.join(FX, 'schemathesis-4.32.4.run.json'), 'utf8');
const EVENTS = fs.readFileSync(path.join(FX, 'schemathesis-4.32.4.events.ndjson'), 'utf8');
// Same stream with every failing check turned into a pass: "the server error is gone".
const EVENTS_CLEAN = EVENTS.split('\n').map((l) => l.replace(/"status":\s*"failure"/g, '"status":"success"')).join('\n');

let reachable = false;
const made: { store: Store; session: ProjectSession; db: string }[] = [];

async function makeSession(opts: { exec?: Exec; which?: Which; config?: (c: any) => void; approve?: boolean } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wb-api-proj-'));
  fs.cpSync(path.join(FX, 'items-app'), root, { recursive: true });
  fs.symlinkSync(NODE_MODULES, path.join(root, 'node_modules'));
  if (opts.config) {
    const c = JSON.parse(fs.readFileSync(path.join(root, 'workbench.config.json'), 'utf8'));
    opts.config(c);
    fs.writeFileSync(path.join(root, 'workbench.config.json'), JSON.stringify(c));
  }
  const db = `workbench_test_api_${Date.now()}_${made.length}`;
  const store = new Store(URI, db);
  await store.connect();
  const session = new ProjectSession(root, store, fs.mkdtempSync(path.join(os.tmpdir(), 'wb-api-data-')), { exec: opts.exec, which: opts.which });
  await session.init();
  if (opts.approve !== false) await session.approveRunConfig(session.loaded.runHash!);
  made.push({ store, session, db });
  return { store, session };
}

async function runScan(session: ProjectSession, store: Store, opts = { confirmActive: true }) {
  const sc = session.scans.get('api')!;
  const { runId } = await sc.start(opts, 'test');
  const end = Date.now() + 120_000;
  while (sc.job && Date.now() < end) await sleep(100);
  return (await store.col('security_scan_runs').findOne({ _id: runId as never }))!;
}

// Fake Schemathesis: copies the real reports to the requested paths.
const fake = { events: EVENTS, runJson: RUN_JSON, writeReports: true, exit: 1, calls: 0 };
const fakeWhich: Which = (name) => (name === 'schemathesis' ? '/fake/bin/schemathesis' : null);
const fakeExec: Exec = async (_bin, args): Promise<ExecResult> => {
  const base = { signal: null, stdoutTruncated: false, stderrTail: '', timedOut: false, cancelled: false, spawnError: null, durationMs: 5 };
  if (args[0] === '--version') return { ...base, exitCode: 0, stdout: 'schemathesis, version 4.32.4\n', stdoutBytes: 30 };
  fake.calls++;
  const at = (flag: string) => args[args.indexOf(flag) + 1]!;
  if (fake.writeReports) {
    fs.writeFileSync(at('--report-json-path'), fake.runJson);
    fs.writeFileSync(at('--report-ndjson-path'), fake.events);
  }
  return { ...base, exitCode: fake.exit, stdout: '', stdoutBytes: 0 };
};

beforeAll(async () => {
  const probe = new MongoClient(URI, { serverSelectionTimeoutMS: 1500 });
  reachable = await probe.connect().then(() => true).catch(() => false);
  await probe.close().catch(() => {});
}, 10_000);

afterAll(async () => {
  for (const m of made) {
    await m.session.dispose();
    const c = new MongoClient(URI);
    await c.connect();
    await c.db(m.db).dropDatabase();
    await c.close();
    await m.store.close();
  }
});

describe('API testing with MongoDB (recorded Schemathesis reports)', () => {
  it('refuses to start without config authorisation, dashboard confirmation and approved run commands', async () => {
    if (!reachable) return;
    const { session } = await makeSession({ exec: fakeExec, which: fakeWhich, approve: false, config: (c) => { c.security.api.allowActiveTesting = false; } });
    const sc = session.scans.get('api')!;
    const reasons = sc.blockers({});
    expect(reasons.join(' | ')).toMatch(/allowActiveTesting/);
    expect(reasons.join(' | ')).toMatch(/confirm in the dashboard/);
    expect(reasons.join(' | ')).toMatch(/run commands have not been approved/);
    await expect(sc.start({ confirmActive: true })).rejects.toThrow(/allowActiveTesting/);
    expect(fake.calls).toBe(0);
  });

  it('records a failure with evidence, graph links, observations and history; then applies the lifecycle', async () => {
    if (!reachable) return;
    const { session, store } = await makeSession({ exec: fakeExec, which: fakeWhich });
    fake.events = EVENTS;
    const run1 = await runScan(session, store);
    expect(run1).toMatchObject({ status: 'completed', category: 'api_testing', active: true, authorization: { confirmedInDashboard: true } });
    expect(run1.coverage.status).toBe('covered');
    expect(run1.counts).toMatchObject({ total: 1, new: 1, graphLinked: 1 });
    expect(run1.target.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    expect(run1.tools[0]).toMatchObject({ tool: 'schemathesis', status: 'completed', observationCount: 1, version: '4.32.4' });
    expect(run1.tools[0].reportRef).toMatch(/schemathesis-run\.json$/);

    const [f] = await store.col('graph_findings').find({ projectId: session.id, source: 'api' }).toArray();
    expect(f).toMatchObject({ status: 'open', severity: 'high', category: 'api_testing', ruleIds: ['schemathesis:ST101'] });
    expect(f!.labels).toEqual(expect.arrayContaining(['observed_at_runtime', 'graph_linked', 'reaches_sensitive_sink']));
    expect(f!.nodes).toContain('fn:src/routes/items.js#searchItems');
    expect(f!.evidence.response.status).toBe(500);
    const obs = await store.col('security_observations').find({ findingId: f!._id }).toArray();
    expect(obs).toHaveLength(1);
    expect(obs[0]).toMatchObject({ category: 'api_testing', tool: 'schemathesis', ruleId: 'ST101', originalSeverity: 'critical' });

    // Same failure again: recurring, not new.
    const run2 = await runScan(session, store);
    expect(run2.counts).toMatchObject({ total: 1, new: 0, recurring: 1 });

    // The operation was tested and passed: not currently observed (never "resolved").
    fake.events = EVENTS_CLEAN;
    const run3 = await runScan(session, store);
    expect(run3.counts).toMatchObject({ total: 0, notCurrentlyObserved: 1 });
    expect((await store.col('graph_findings').findOne({ _id: f!._id }))!.status).toBe('not_currently_observed');

    // Reported again: potential regression.
    fake.events = EVENTS;
    const run4 = await runScan(session, store);
    expect(run4.counts).toMatchObject({ regressions: 1 });
    expect((await store.col('graph_findings').findOne({ _id: f!._id }))!).toMatchObject({ status: 'open', potentialRegression: true });
  }, 120_000);

  it('never records a missing or unreadable report as a clean result', async () => {
    if (!reachable) return;
    const { session, store } = await makeSession({ exec: fakeExec, which: fakeWhich });
    fake.events = EVENTS;
    fake.writeReports = false;
    const run = await runScan(session, store);
    fake.writeReports = true;
    expect(run.status).toBe('failed');
    expect(run.counts).toBeNull();
    expect(run.tools[0].status).toBe('failed');
    expect(run.coverage.reason).toMatch(/no run report/);
  }, 60_000);

  it('reports the scanner as unavailable (not clean) when it is not installed', async () => {
    if (!reachable) return;
    const { session, store } = await makeSession({ exec: fakeExec, which: () => null });
    const run = await runScan(session, store);
    expect(run.status).toBe('unavailable');
    expect(run.counts).toBeNull();
    expect(run.tools[0]).toMatchObject({ status: 'unavailable', readiness: 'not_installed', observationCount: null });
  }, 30_000);

  it('fails clearly when the local copy of the app cannot start', async () => {
    if (!reachable) return;
    const { session, store } = await makeSession({ exec: fakeExec, which: fakeWhich, config: (c) => { c.run.start = 'node does-not-exist.js'; } });
    const run = await runScan(session, store);
    expect(run.status).toBe('failed');
    expect(run.counts).toBeNull();
    expect(run.coverage.reason).toMatch(/local copy of the app did not start/);
  }, 60_000);
});

const REAL = !!realWhich('schemathesis');
describe.runIf(REAL)('API testing with the real Schemathesis', () => {
  it('finds the unhandled quote in /api/items/search and links it to the dynamic SQL call', async () => {
    if (!reachable) return;
    const { session, store } = await makeSession();
    const run = await runScan(session, store);
    expect(run.status).toBe('completed');
    expect(run.coverage.detail.tested).toEqual(['GET /api/items/search', 'GET /api/items/{id}', 'GET /health']);
    const fs_ = await store.col('graph_findings').find({ projectId: session.id, source: 'api' }).toArray();
    const f = fs_.find((x) => x.location.operation === 'GET /api/items/search')!;
    expect(f).toBeTruthy();
    expect(f.evidence.response.status).toBe(500);
    expect(f.labels).toContain('reaches_sensitive_sink');
  }, 180_000);
});
