// Secrets detection and infrastructure checks end-to-end: ProjectSession + ScanService + MongoDB.
// Part 1 replays recorded Gitleaks/Checkov reports through a fake process so lifecycle rules are deterministic.
// Part 2 uses the real binaries when GITLEAKS_BIN / CHECKOV_BIN (or PATH) provide them; skipped otherwise.
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
import { FAKE, writeLeakyProject } from './helpers/secrets.js';

const URI = process.env.WORKBENCH_TEST_MONGO || 'mongodb://127.0.0.1:27017';
const FX = path.resolve(__dirname, 'fixtures');
const GL_REPORT = JSON.parse(fs.readFileSync(path.join(FX, 'secrets/gitleaks-8.24.3.report.json'), 'utf8')) as any[];
const CK_REPORT = fs.readFileSync(path.join(FX, 'iac/checkov-3.3.30.results.json'), 'utf8');

let reachable = false;
const made: { store: Store; session: ProjectSession; db: string }[] = [];

async function makeSession(root: string, hooks: { exec?: Exec; which?: Which } = {}) {
  if (!fs.existsSync(path.join(root, 'workbench.config.json'))) fs.writeFileSync(path.join(root, 'workbench.config.json'), '{}');
  const db = `workbench_test_static_${Date.now()}_${made.length}`;
  const store = new Store(URI, db);
  await store.connect();
  const session = new ProjectSession(root, store, fs.mkdtempSync(path.join(os.tmpdir(), 'wb-static-data-')), hooks);
  await session.init();
  made.push({ store, session, db });
  return { store, session };
}

async function runKind(session: ProjectSession, store: Store, kind: 'secrets' | 'iac', mode?: string) {
  const sc = session.scans.get(kind)!;
  const { runId } = await sc.start({ mode }, 'test');
  const end = Date.now() + 180_000;
  while (sc.job && Date.now() < end) await sleep(50);
  return (await store.col('security_scan_runs').findOne({ _id: runId as never }))!;
}

// Fake tools: write whatever report the test sets.
const fake = { gitleaks: [] as any[], gitleaksExit: 42 as number | null, checkov: CK_REPORT, root: '' };
const fakeWhich: Which = (name) => (name === 'gitleaks' || name === 'checkov' ? `/fake/bin/${name}` : null);
const fakeExec: Exec = async (bin, args): Promise<ExecResult> => {
  const base = { signal: null, stdoutTruncated: false, stderrTail: '', timedOut: false, cancelled: false, spawnError: null, durationMs: 4, stdout: '', stdoutBytes: 0 };
  if (bin.endsWith('gitleaks')) {
    if (args[0] === 'version') return { ...base, exitCode: 0, stdout: '8.24.3\n' };
    if (fake.gitleaksExit !== 1) fs.writeFileSync(args[args.indexOf('--report-path') + 1]!, JSON.stringify(fake.gitleaks));
    return { ...base, exitCode: fake.gitleaksExit, stderrTail: fake.gitleaksExit === 1 ? 'FTL boom' : 'INF scanned ~100 bytes (100 bytes) in 1ms' };
  }
  if (args[0] === '--version') return { ...base, exitCode: 0, stdout: '3.3.30\n' };
  fs.writeFileSync(path.join(args[args.indexOf('--output-file-path') + 1]!, 'results_json.json'), fake.checkov.replaceAll('/fixture/project', fake.root));
  return { ...base, exitCode: 0 };
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
  }
});

describe('secrets detection with MongoDB', () => {
  it('records findings, marks a re-scanned absent one not_currently_observed, flags its return as a regression', async (t) => {
    if (!reachable) return t.skip();
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wb-sec-proj-'));
    const { session, store } = await makeSession(root, { exec: fakeExec, which: fakeWhich });
    const src = GL_REPORT.filter((f) => f.File.startsWith('src/'));
    const findings = () => store.col('graph_findings').find({ source: 'secrets' }).sort({ _id: 1 }).toArray();

    fake.gitleaks = src; fake.gitleaksExit = 42;
    const r1 = await runKind(session, store, 'secrets');
    expect(r1.status).toBe('completed');
    expect(r1.category).toBe('secrets');
    expect(r1.active).toBe(false);
    expect(r1.counts).toMatchObject({ total: 3, new: 3 });
    const f1 = await findings();
    expect(f1.map((f) => f.status)).toEqual(['open', 'open', 'open']);
    expect(f1.every((f) => f.classification === 'scanner_detected' && f.category === 'secrets')).toBe(true);
    expect(f1.find((f) => f.ruleIds[0] === 'gitleaks:private-key')!.location).toMatchObject({ file: 'src/key.pem', line: 1 });

    // a history run covers commits only: working-tree findings are not touched
    fs.mkdirSync(path.join(root, '.git'));
    fake.gitleaks = []; fake.gitleaksExit = 0;
    const h = await runKind(session, store, 'secrets', 'history');
    expect(h.status).toBe('completed');
    expect(h.counts).toMatchObject({ total: 0, notRechecked: 3, notCurrentlyObserved: 0 });

    // a failed run changes nothing and has no counts
    fake.gitleaksExit = 1;
    const bad = await runKind(session, store, 'secrets');
    expect(bad.status).toBe('failed');
    expect(bad.counts).toBeNull();
    expect((await findings()).every((f) => f.status === 'open')).toBe(true);

    // the private key is gone from a completed workspace run
    fake.gitleaks = src.filter((f) => f.RuleID !== 'private-key'); fake.gitleaksExit = 42;
    const r2 = await runKind(session, store, 'secrets');
    expect(r2.counts).toMatchObject({ total: 2, recurring: 2, notCurrentlyObserved: 1 });
    expect((await findings()).find((f) => f.ruleIds[0] === 'gitleaks:private-key')!.status).toBe('not_currently_observed');

    fake.gitleaks = src;
    const r3 = await runKind(session, store, 'secrets');
    expect(r3.counts).toMatchObject({ regressions: 1 });
    const pk = (await findings()).find((f) => f.ruleIds[0] === 'gitleaks:private-key')!;
    expect(pk).toMatchObject({ status: 'open', potentialRegression: true });
    const obs = await store.col('security_observations').countDocuments({ category: 'secrets' });
    expect(obs).toBe(3 + 2 + 3);
  }, 60_000);
});

describe('infrastructure checks with MongoDB', () => {
  it('stores "not applicable" (no counts) for a project without IaC files', async (t) => {
    if (!reachable) return t.skip();
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wb-noiac-proj-'));
    fs.writeFileSync(path.join(root, 'index.js'), 'module.exports = 1;\n');
    const { session, store } = await makeSession(root, { exec: fakeExec, which: fakeWhich });
    const r = await runKind(session, store, 'iac');
    expect(r.status).toBe('not_applicable');
    expect(r.counts).toBeNull();
    expect(r.coverage.reason).toMatch(/no infrastructure-as-code files found/);
    expect(await store.col('graph_findings').countDocuments({ source: 'iac' })).toBe(0);
  }, 30_000);

  it('records Checkov failures as findings with their check ids and file locations', async (t) => {
    if (!reachable) return t.skip();
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wb-iac-proj-'));
    fs.cpSync(path.join(FX, 'iac/project'), root, { recursive: true });
    fake.root = root;
    const { session, store } = await makeSession(root, { exec: fakeExec, which: fakeWhich });
    const r = await runKind(session, store, 'iac');
    expect(r.status).toBe('completed');
    expect(r.counts).toMatchObject({ total: 38, new: 38 });
    expect(r.counts.bySeverity).toEqual({ unknown: 38 });
    const ssh = await store.col('graph_findings').findOne({ source: 'iac', ruleIds: 'checkov:CKV_AWS_24' });
    expect(ssh).toMatchObject({ location: { file: 'infra/main.tf', resource: 'aws_security_group.web' }, severity: 'unknown' });
    expect(r.tools[0].reportRef).toMatch(/checkov-results\.json$/);
  }, 30_000);
});

const gitleaksBin = process.env.GITLEAKS_BIN || realWhich('gitleaks');
const checkovBin = process.env.CHECKOV_BIN || realWhich('checkov');

describe('real tools through the service', () => {
  it.runIf(!!gitleaksBin)('Gitleaks: real run, nothing unredacted reaches MongoDB or the run directory', async (t) => {
    if (!reachable) return t.skip();
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wb-gl-svc-'));
    writeLeakyProject(root);
    const { session, store } = await makeSession(root, { which: (n, e) => (n === 'gitleaks' && !e ? gitleaksBin! : realWhich(n, e)) });
    const r = await runKind(session, store, 'secrets');
    expect(r.status).toBe('completed');
    expect(r.counts).toMatchObject({ total: 2 });
    const dump = JSON.stringify([r, await store.col('graph_findings').find({}).toArray(), await store.col('security_observations').find({}).toArray()]);
    expect(dump).not.toContain(FAKE.stripe);
    expect(dump).not.toContain(FAKE.github);
    const dataDir = path.dirname(path.dirname(path.join((session as any).projectDir)));
    const files = fs.readdirSync(dataDir, { recursive: true }).map(String).filter((f) => fs.statSync(path.join(dataDir, f)).isFile());
    for (const f of files) expect(fs.readFileSync(path.join(dataDir, f), 'utf8')).not.toContain(FAKE.github);
  }, 60_000);

  it.runIf(!!checkovBin)('Checkov: real offline run on the fixture project', async (t) => {
    if (!reachable) return t.skip();
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wb-ck-svc-'));
    fs.cpSync(path.join(FX, 'iac/project'), root, { recursive: true });
    const { session, store } = await makeSession(root, { which: (n, e) => (n === 'checkov' && !e ? checkovBin! : realWhich(n, e)) });
    const r = await runKind(session, store, 'iac');
    expect(r.status).toBe('completed');
    expect(r.counts.total).toBeGreaterThanOrEqual(30);
    expect(r.coverage.detail.frameworkResults.map((x: any) => x.framework).sort()).toEqual(['dockerfile', 'github_actions', 'kubernetes', 'terraform']);
  }, 180_000);
});
