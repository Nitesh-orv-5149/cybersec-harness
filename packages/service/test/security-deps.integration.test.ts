// Dependency scanning end-to-end through ProjectSession + real MongoDB (skipped when unreachable).
// The scanner process is mocked with the *real* npm audit report from fixtures; see README there.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { MongoClient } from 'mongodb';
import { Store } from '../src/store/mongo.js';
import { ProjectSession } from '../src/project.js';
import { sleep } from '../src/util.js';
import type { Exec, ExecResult, Which } from '../src/security/types.js';
import { mergeObservations } from '../src/security/deps/merge.js';

const URI = process.env.WORKBENCH_TEST_MONGO || 'mongodb://127.0.0.1:27017';
const DB = `workbench_test_deps_${Date.now()}`;
const FX = path.resolve(__dirname, 'fixtures/deps');
const REAL = JSON.parse(fs.readFileSync(path.join(FX, 'npm-audit.vulnerable.real.json'), 'utf8'));

let reachable = false;
let store: Store;
let session: ProjectSession;
let root: string;

// Mutable fake environment: which tools exist and what `npm audit` prints.
const env = { installed: new Set(['npm']), npmStdout: JSON.stringify(REAL), npmExit: 1, calls: 0 };
const which: Which = (name) => (env.installed.has(name) ? `/fake/bin/${name}` : null);
const exec: Exec = async (_bin, args): Promise<ExecResult> => {
  const base = { signal: null, stdoutTruncated: false, stderrTail: '', timedOut: false, cancelled: false, spawnError: null, durationMs: 3 };
  if (args[0] === '--version') return { ...base, exitCode: 0, stdout: '10.9.9\n', stdoutBytes: 7 };
  env.calls++;
  return { ...base, exitCode: env.npmExit, stdout: env.npmStdout, stdoutBytes: env.npmStdout.length };
};
const without = (pkg: string) => { const r = structuredClone(REAL); delete r.vulnerabilities[pkg]; return JSON.stringify(r); };

beforeAll(async () => {
  const probe = new MongoClient(URI, { serverSelectionTimeoutMS: 1500 });
  reachable = await probe.connect().then(() => true).catch(() => false);
  await probe.close().catch(() => {});
  if (!reachable) return;
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'wb-deps-proj-'));
  fs.cpSync(path.join(FX, 'npm-vulnerable'), root, { recursive: true });
  fs.writeFileSync(path.join(root, 'workbench.config.json'), JSON.stringify({ analysis: { include: ['src'] }, security: { allowNetwork: true } }));
  store = new Store(URI, DB);
  await store.connect();
  session = new ProjectSession(root, store, fs.mkdtempSync(path.join(os.tmpdir(), 'wb-deps-data-')), { exec, which });
  await session.init();
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

async function scan() {
  const { runId } = await session.deps.start('test');
  const end = Date.now() + 10_000;
  while (session.deps.job && Date.now() < end) await sleep(50);
  return (await store.col('security_scan_runs').findOne({ _id: runId as never }))!;
}
const findings = () => store.col('graph_findings').find({ projectId: session.id, source: 'dependency' }).toArray();

describe.runIf(process.env.CI !== 'skip-mongo')('dependency scanning with MongoDB', () => {
  it('reports real readiness: npm present, OSV-Scanner and Trivy missing', async () => {
    if (!reachable) return;
    const s = await session.deps.scanners(true);
    expect(Object.fromEntries(s.map((x) => [x.tool, x.state]))).toEqual({ 'osv-api': 'needs_network', 'npm-audit': 'ready', 'osv-scanner': 'not_installed', trivy: 'not_installed' });
  });

  it('persists a run, canonical findings, observations and graph links', async () => {
    if (!reachable) return;
    const run = await scan();
    expect(run.status).toBe('completed');
    expect(run.coverage).toEqual([expect.objectContaining({ lockfile: 'package-lock.json', status: 'covered', by: ['npm-audit'] })]);
    expect(run.tools.find((t: any) => t.tool === 'osv-scanner')).toMatchObject({ status: 'unavailable', selected: false, observationCount: null });
    expect(run.counts).toMatchObject({ total: 21, new: 21, recurring: 0 });
    expect(fs.existsSync(path.join(session.artifactPath(run.tools.find((t: any) => t.tool === 'npm-audit').reportRef)!))).toBe(true);
    const fs1 = await findings();
    expect(fs1.length).toBe(21);
    const lodash = fs1.find((f) => f.canonicalId === 'GHSA-35jh-r3h4-6jhm')!;
    expect(lodash).toMatchObject({ classification: 'scanner_detected', severity: 'high', status: 'open', scanners: ['npm-audit'] });
    expect(lodash.labels).toEqual(['scanner_detected', 'graph_linked', 'reachable_path']);
    expect(lodash.pkg.use.evidence).toBe('called_from_analysed_code');
    expect(lodash.nodes).toContain('ep:GET /merge');
    const qs = fs1.find((f) => f.pkg.name === 'qs')!;
    expect(qs.labels).toEqual(['scanner_detected']);
    expect(qs.pkg.use.introducedBy[0].direct).toBe('express');
    expect(await store.col('security_observations').countDocuments({ runId: run._id })).toBe(21);
  });

  it('does not duplicate findings on a repeat scan, keeps per-run observations, and ingestion is idempotent', async () => {
    if (!reachable) return;
    const run = await scan();
    expect(run.counts).toMatchObject({ total: 21, new: 0, recurring: 21 });
    expect((await findings()).length).toBe(21);
    expect(await store.col('security_observations').countDocuments({ projectId: session.id })).toBe(42);
    // Re-ingest the same run's observations: unique ids make it a no-op.
    const { parseNpmAudit } = await import('../src/security/deps/npmAudit.js');
    const parsed = parseNpmAudit(JSON.stringify(REAL), { lockVersions: new Map([['node_modules/lodash', '4.17.20']]), toolVersion: '10.9.9', sourceFile: 'package-lock.json' }) as any;
    const lodashOnly = mergeObservations(parsed.observations.filter((o: any) => o.packageName === 'lodash'));
    await (session.deps as any).syncFindings(run._id, lodashOnly, [], [], [], null, null);
    expect(await store.col('security_observations').countDocuments({ projectId: session.id })).toBe(42);
  });

  it('a failed scan changes no finding and reports no counts', async () => {
    if (!reachable) return;
    env.npmStdout = fs.readFileSync(path.join(FX, 'npm-audit.enolock.real.json'), 'utf8');
    const run = await scan();
    expect(run.status).toBe('failed');
    expect(run.counts).toBeNull();
    expect(run.tools.find((t: any) => t.tool === 'npm-audit').reason).toContain('ENOLOCK');
    expect((await findings()).every((f) => f.status === 'open')).toBe(true);
  });

  it('an unavailable scanner is reported as unavailable, never as zero vulnerabilities', async () => {
    if (!reachable) return;
    env.installed = new Set();
    const before = env.calls;
    const run = await scan();
    expect(run.status).toBe('unavailable');
    expect(run.counts).toBeNull();
    expect(run.coverage[0]).toMatchObject({ status: 'unavailable', by: [] });
    expect(env.calls).toBe(before);
    expect((await findings()).every((f) => f.status === 'open')).toBe(true);
    env.installed = new Set(['npm']);
  });

  it('marks an advisory not currently observed only when the same tool re-checked an unchanged version', async () => {
    if (!reachable) return;
    env.npmStdout = without('lodash');
    const run = await scan();
    expect(run.counts.notCurrentlyObserved).toBe(5);
    const lodash = (await findings()).filter((f) => f.pkg.name === 'lodash');
    expect(lodash.every((f) => f.status === 'not_currently_observed')).toBe(true);
    expect(await store.col('verification_records').countDocuments({ projectId: session.id, action: 'not_currently_observed' })).toBe(5);
  });

  it('flags a potential regression when it is reported again', async () => {
    if (!reachable) return;
    env.npmStdout = JSON.stringify(REAL);
    const run = await scan();
    expect(run.counts.regressions).toBe(5);
    const lodash = (await findings()).filter((f) => f.pkg.name === 'lodash');
    expect(lodash.every((f) => f.status === 'open' && f.potentialRegression === true)).toBe(true);
  });

  it('resolves a finding only when the vulnerable version is gone from the lockfile', async () => {
    if (!reachable) return;
    const lockPath = path.join(root, 'package-lock.json');
    const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
    lock.packages['node_modules/minimist'].version = '1.2.8';
    fs.writeFileSync(lockPath, JSON.stringify(lock, null, 2));
    env.npmStdout = without('minimist');
    const run = await scan();
    expect(run.counts.resolvedVersionRemoved).toBe(1);
    const mini = (await findings()).find((f) => f.pkg.name === 'minimist')!;
    expect(mini).toMatchObject({ status: 'resolved', resolution: 'version_removed' });
    const summary = await store.dependencySummary(session.id);
    expect(summary.findings.byStatus.find((x: any) => x._id === 'resolved').count).toBe(1);
  });
});
