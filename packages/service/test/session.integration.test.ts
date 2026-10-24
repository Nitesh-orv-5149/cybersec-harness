// Integration test against a real MongoDB (skipped when unreachable).
//   WORKBENCH_TEST_MONGO=mongodb://127.0.0.1:27017 npx vitest run
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { MongoClient } from 'mongodb';
import { Store } from '../src/store/mongo.js';
import { ProjectSession } from '../src/project.js';
import { sleep } from '../src/util.js';

const URI = process.env.WORKBENCH_TEST_MONGO || 'mongodb://127.0.0.1:27017';
const DB = `workbench_test_${Date.now()}`;
const SAMPLE = path.resolve(__dirname, '../../../sample-app');

let reachable = false;
let store: Store;
let session: ProjectSession;
let root: string;

beforeAll(async () => {
  const probe = new MongoClient(URI, { serverSelectionTimeoutMS: 1500 });
  reachable = await probe.connect().then(() => true).catch(() => false);
  await probe.close().catch(() => {});
  if (!reachable) return;
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'wb-proj-'));
  fs.cpSync(SAMPLE, root, { recursive: true, filter: (s) => !s.includes('node_modules') && !s.includes(`${path.sep}dist`) });
  store = new Store(URI, DB);
  await store.connect();
  session = new ProjectSession(root, store, fs.mkdtempSync(path.join(os.tmpdir(), 'wb-data-')));
  await session.init();
  await session.startMonitoring();
}, 30_000);

afterAll(async () => {
  if (!reachable) return;
  await session.dispose();
  const c = new MongoClient(URI);
  await c.connect();
  await c.db(DB).dropDatabase();
  await c.close();
  await store.close();
});

const waitFor = async (fn: () => boolean | Promise<boolean>, ms = 8000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await fn()) return true; await sleep(100); }
  return false;
};

describe.runIf(process.env.CI !== 'skip-mongo')('project session with MongoDB', () => {
  it('builds the initial graph and persists a project + run', async () => {
    if (!reachable) return;
    expect(session.live!.graph.nodes.length).toBeGreaterThan(30);
    expect(await store.col('projects').countDocuments({ _id: session.id as never })).toBe(1);
    expect(await store.col('analysis_runs').countDocuments({ projectId: session.id, status: 'completed' })).toBe(1);
    expect(await store.col('graph_findings').countDocuments({ projectId: session.id, source: 'graph' })).toBe(5);
  });

  it('reacts to a saved change without git, records one event, and computes impact', async () => {
    if (!reachable) return;
    const v = session.live!.graphVersion;
    const f = path.join(root, 'src/lib/format.js');
    fs.writeFileSync(f, fs.readFileSync(f, 'utf8').replace('export function formatCurrency(cents) {', "export function formatCurrency(cents) {\n  if (cents == null) return '';"));
    expect(await waitFor(() => session.live!.graphVersion > v)).toBe(true);
    expect(session.live!.lastDiff!.changedNodes).toEqual(['fn:src/lib/format.js#formatCurrency']);
    expect(session.live!.lastImpact!.affectedEndpoints.length).toBe(4);
    const events = await store.col('file_events').find({ projectId: session.id, path: 'src/lib/format.js' }).toArray();
    expect(events.length).toBe(1);
    expect(events[0].status).toBe('analyzed');
  });

  it('coalesces rapid edits into few analysis runs', async () => {
    if (!reachable) return;
    const before = await store.col('analysis_runs').countDocuments({ projectId: session.id });
    const f = path.join(root, 'src/lib/validate.js');
    const text = fs.readFileSync(f, 'utf8');
    for (let i = 0; i < 8; i++) { fs.writeFileSync(f, `${text}\n// edit ${i}\n`); await sleep(30); }
    await sleep(2500);
    const after = await store.col('analysis_runs').countDocuments({ projectId: session.id });
    expect(after - before).toBeGreaterThanOrEqual(1);
    expect(after - before).toBeLessThanOrEqual(3);
  });

  it('marks a baseline and refuses verification until run commands are approved', async () => {
    if (!reachable) return;
    const b = await session.markBaseline();
    expect(b.snapshotId).toMatch(/^snap_/);
    const ready = session.verificationReady();
    expect(ready.ok).toBe(false);
    expect(ready.reasons.join(' ')).toMatch(/not been approved/);
    const r = await session.verify('test');
    expect(r.error).toBeTruthy();
  });

  it('records a deleted file and removes its nodes', async () => {
    if (!reachable) return;
    const v = session.live!.graphVersion;
    fs.rmSync(path.join(root, 'src/routes/tools.js'));
    expect(await waitFor(() => session.live!.graphVersion > v)).toBe(true);
    expect(session.live!.graph.nodes.some((n) => n.loc?.file === 'src/routes/tools.js')).toBe(false);
    expect(await waitFor(async () => (await store.col('graph_findings').countDocuments({ projectId: session.id, status: 'resolved' })) >= 3)).toBe(true);
    expect(await store.col('verification_records').countDocuments({ projectId: session.id, action: 'resolved_by_analysis' })).toBeGreaterThanOrEqual(3);
  });

  it('serves the dashboard aggregations', async () => {
    if (!reachable) return;
    const s = await store.dashboardSummary(session.id);
    expect(s.findings.byStatus.length).toBeGreaterThan(0);
    expect(s.activity.length).toBeGreaterThan(0);
  });
});
