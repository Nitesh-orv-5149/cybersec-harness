// Dependency-scanner adapters, orchestration and correlation. Process execution is mocked except for the
// exec tests, which spawn a local `node` child to prove timeout and output limits. Fixture provenance is in
// test/fixtures/deps/README.md (*.real.json = real tool output, *.synthetic.json = hand-written).
import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ProjectConfigSchema } from '../src/config.js';
import type { DependencyTarget, Exec, ExecResult, Readiness, Which } from '../src/security/types.js';
import { parseNpmAudit, npmAuditAdapter } from '../src/security/deps/npmAudit.js';
import { parseOsvScanner, osvScannerAdapter } from '../src/security/deps/osvScanner.js';
import { osvApiAdapter } from '../src/security/deps/osvApi.js';
import { parseTrivy, trivyAdapter } from '../src/security/deps/trivy.js';
import { mapCvssScore, mapLabel } from '../src/security/deps/severity.js';
import { mergeObservations } from '../src/security/deps/merge.js';
import { checkReadiness, runDependencyScan } from '../src/security/deps/orchestrator.js';
import { chainsTo, detectTargets, lockVersions, parseLockfile } from '../src/security/deps/lockfile.js';
import { buildUsageIndex, packageNameFromSpec, packageUse } from '../src/security/deps/packageUse.js';
import { execTool } from '../src/security/exec.js';
import { Analyzer } from '../src/analyzer/index.js';
import { GraphIndex } from '../src/analyzer/query.js';

const FX = path.resolve(__dirname, 'fixtures/deps');
const PROJ = path.join(FX, 'npm-vulnerable');
const read = (f: string) => fs.readFileSync(path.join(FX, f), 'utf8');
const model = parseLockfile(fs.readFileSync(path.join(PROJ, 'package-lock.json'), 'utf8'), fs.readFileSync(path.join(PROJ, 'package.json'), 'utf8'));
const versions = lockVersions(model);
const ctx = { lockVersions: versions, toolVersion: 'x', sourceFile: 'package-lock.json' };
// Process-tool tests pin the classic order; the web-API adapter is tested separately below.
const cfgWith = (security: any = {}) => ProjectConfigSchema.parse({ security: { ...security, dependencies: { order: ['osv-scanner', 'npm-audit', 'trivy'], ...(security.dependencies ?? {}) } } }).security;
const target: DependencyTarget = { ecosystem: 'npm', root: PROJ, lockfile: 'package-lock.json', manifest: 'package.json', lockfileHash: 'h', manifestHash: 'm' };
const execResult = (p: Partial<ExecResult>): ExecResult => ({ exitCode: 0, signal: null, stdout: '', stdoutBytes: 0, stdoutTruncated: false, stderrTail: '', timedOut: false, cancelled: false, spawnError: null, durationMs: 5, ...p });

describe('npm audit adapter (real reports)', () => {
  const out = parseNpmAudit(read('npm-audit.vulnerable.real.json'), ctx);
  const obs = out.status === 'completed' ? out.observations : [];

  it('parses every advisory with ids, severity, ranges and installed versions from the lockfile', () => {
    expect(out.status).toBe('completed');
    expect(obs.length).toBe(21);
    const cmd = obs.find((o) => o.advisoryId === 'GHSA-35jh-r3h4-6jhm')!;
    expect(cmd).toMatchObject({ tool: 'npm-audit', packageName: 'lodash', installedVersion: '4.17.20', severity: 'high', originalSeverity: 'high', affectedRange: '<4.17.21', fixedVersions: null, toolRef: '1106913' });
    expect(cmd.cwe).toEqual(['CWE-77', 'CWE-94']);
    expect(cmd.lockfileNodes).toEqual(['node_modules/lodash']);
    expect(cmd.remediation).toContain('lodash');
  });

  it('keeps the published label: critical maps to high but stays visible, moderate maps to medium', () => {
    const mini = obs.find((o) => o.packageName === 'minimist')!;
    expect(mini.severity).toBe('high');
    expect(mini.originalSeverity).toBe('critical');
    expect(obs.find((o) => o.originalSeverity === 'moderate')!.severity).toBe('medium');
  });

  it('never invents CVE identifiers (npm audit does not report them)', () => {
    expect(obs.flatMap((o) => [o.advisoryId, ...o.aliases]).some((id) => id.startsWith('CVE-'))).toBe(false);
  });

  it('treats a clean report as a completed scan with zero observations', () => {
    expect(parseNpmAudit(read('npm-audit.clean.real.json'), ctx)).toEqual({ status: 'completed', observations: [], notes: [] });
  });

  it('reports npm errors (no lockfile) as failed, not as zero findings', () => {
    const r = parseNpmAudit(read('npm-audit.enolock.real.json'), ctx);
    expect(r.status).toBe('failed');
    expect(r.status === 'failed' && r.reason).toContain('ENOLOCK');
  });

  it('rejects malformed, empty and unsupported output', () => {
    const real = read('npm-audit.vulnerable.real.json');
    expect(parseNpmAudit(real.slice(0, real.length / 2), ctx).status).toBe('failed');
    expect(parseNpmAudit('', ctx).status).toBe('failed');
    const v1 = parseNpmAudit(JSON.stringify({ auditReportVersion: 1, advisories: {} }), ctx);
    expect(v1.status === 'failed' && v1.reason).toMatch(/unsupported npm audit report format/);
  });

  it('does not trust the exit code: npm exits 1 when it finds advisories', () => {
    const r = npmAuditAdapter.interpret(execResult({ exitCode: 1, stdout: read('npm-audit.vulnerable.real.json') }), target, '10.9.9', { lockVersions: versions });
    expect(r.status).toBe('completed');
  });

  it('turns timeouts, truncated output and spawn errors into failures', () => {
    const real = read('npm-audit.vulnerable.real.json');
    for (const p of [{ timedOut: true, stdout: real }, { stdoutTruncated: true, stdout: real }, { spawnError: 'ENOENT' }, { cancelled: true }]) {
      expect(npmAuditAdapter.interpret(execResult(p), target, null, { lockVersions: versions }).status).toBe('failed');
    }
  });

  it('builds a safe argument array', () => {
    expect(npmAuditAdapter.buildArgs(target, cfgWith())).toEqual(['audit', '--json', '--package-lock-only']);
    expect(npmAuditAdapter.buildArgs(target, cfgWith({ dependencies: { includeDev: false } }))).toEqual(['audit', '--json', '--package-lock-only', '--omit=dev']);
  });
});

describe('OSV-Scanner adapter (synthetic fixture)', () => {
  const out = parseOsvScanner(read('osv-scanner.synthetic.json'), ctx);
  const obs = out.status === 'completed' ? out.observations : [];
  it('parses ids, aliases, affected ranges and fixed versions', () => {
    const l = obs.find((o) => o.packageName === 'lodash')!;
    expect(l).toMatchObject({ advisoryId: 'GHSA-35jh-r3h4-6jhm', installedVersion: '4.17.20', severity: 'high', originalSeverity: 'HIGH', affectedRange: '>=0 <4.17.21', fixedVersions: ['4.17.21'], cvssScore: 7.2 });
    expect(l.aliases).toEqual(expect.arrayContaining(['GHSA-35jh-r3h4-6jhm', 'CVE-2021-23337']));
    expect(l.cwe).toEqual(['CWE-77', 'CWE-94']);
  });
  it('falls back to the group CVSS score, then to unknown', () => {
    const m = obs.find((o) => o.packageName === 'minimist')!;
    expect(m).toMatchObject({ severity: 'high', originalSeverity: 'CVSS 9.8', fixedVersions: ['1.2.6', '0.2.4'] });
    expect(m.affectedRange).toBe('>=1.0.0 <1.2.6 || >=0 <0.2.4');
    expect(obs.find((o) => o.packageName === 'send')).toMatchObject({ severity: 'unknown', originalSeverity: null, fixedVersions: [] });
  });
  it('maps documented exit codes', () => {
    const fx = read('osv-scanner.synthetic.json');
    const run = (exitCode: number, stdout = fx) => osvScannerAdapter.interpret(execResult({ exitCode, stdout }), target, '2.0.0', { lockVersions: versions }).status;
    expect(run(1)).toBe('completed');
    expect(run(0, '{"results":[]}')).toBe('completed');
    expect(run(128, '')).toBe('inconclusive');
    expect(run(127, '')).toBe('failed');
    expect(run(2)).toBe('failed');
    expect(run(1, '{"results": "nope"}')).toBe('failed');
  });
  it('passes the lockfile and respects offline mode', () => {
    expect(osvScannerAdapter.buildArgs(target, cfgWith())).toEqual(['scan', '--format', 'json', '-L', 'package-lock.json']);
    expect(osvScannerAdapter.buildArgs(target, cfgWith({ dependencies: { osvOffline: true } }))).toContain('--offline-vulnerabilities');
    expect(osvScannerAdapter.networkHosts(cfgWith({ dependencies: { osvOffline: true } }))).toEqual([]);
  });
});

describe('Trivy adapter (synthetic fixture)', () => {
  const out = parseTrivy(read('trivy.synthetic.json'), ctx);
  const obs = out.status === 'completed' ? out.observations : [];
  it('parses package, installed version, advisory id, severity and fixed versions', () => {
    expect(obs.length).toBe(3);
    expect(obs[0]).toMatchObject({ tool: 'trivy', advisoryId: 'CVE-2021-23337', packageName: 'lodash', installedVersion: '4.17.20', fixedVersions: ['4.17.21'], severity: 'high', cvssScore: 7.2 });
    expect(obs[1]).toMatchObject({ severity: 'high', originalSeverity: 'CRITICAL', fixedVersions: ['1.2.6', '0.2.4'] });
    expect(obs[2]).toMatchObject({ severity: 'unknown', originalSeverity: 'UNKNOWN', fixedVersions: null });
  });
  it('only ingests the scanned lockfile and says so', () => {
    expect(out.notes.join(' ')).toContain('nested/package-lock.json');
  });
  it('is inconclusive when the lockfile has no result entry, failed on schema mismatch or non-zero exit', () => {
    expect(parseTrivy(JSON.stringify({ SchemaVersion: 2, Results: [] }), ctx).status).toBe('inconclusive');
    expect(parseTrivy(JSON.stringify({ SchemaVersion: 1, Results: [] }), ctx).status).toBe('failed');
    expect(trivyAdapter.interpret(execResult({ exitCode: 1, stdout: read('trivy.synthetic.json') }), target, '0.60.0', { lockVersions: versions }).status).toBe('failed');
  });
  it('uses --exit-code 0 so a non-zero exit means failure, and supports offline mode', () => {
    const args = trivyAdapter.buildArgs(target, cfgWith());
    expect(args.slice(0, 9)).toEqual(['fs', '--scanners', 'vuln', '--format', 'json', '--quiet', '--exit-code', '0', '--timeout']);
    expect(trivyAdapter.buildArgs(target, cfgWith({ dependencies: { trivyOffline: true } }))).toEqual(expect.arrayContaining(['--skip-db-update', '--offline-scan']));
  });
});

describe('severity mapping', () => {
  it('is explicit and keeps unknown as unknown', () => {
    expect(['critical', 'high', 'moderate', 'medium', 'low', 'info', 'UNKNOWN', '', null].map((s) => mapLabel(s as string))).toEqual(['high', 'high', 'medium', 'medium', 'low', 'info', 'unknown', 'unknown', 'unknown']);
    expect([0, 3.9, 4, 6.9, 7, 9.8, null].map((s) => mapCvssScore(s))).toEqual(['info', 'low', 'medium', 'medium', 'high', 'high', 'unknown']);
  });
});

describe('cross-tool deduplication', () => {
  const all = [
    ...(parseNpmAudit(read('npm-audit.vulnerable.real.json'), ctx) as { observations: any[] }).observations,
    ...(parseOsvScanner(read('osv-scanner.synthetic.json'), ctx) as { observations: any[] }).observations,
    ...(parseTrivy(read('trivy.synthetic.json'), ctx) as { observations: any[] }).observations,
  ];
  const merged = mergeObservations(all);
  it('merges observations that share a tool-supplied id and keeps every tool\'s provenance', () => {
    const m = merged.find((x) => x.packageName === 'lodash' && x.ids.includes('GHSA-35jh-r3h4-6jhm'))!;
    expect(m.tools).toEqual(['npm-audit', 'osv-scanner', 'trivy']);
    expect(m.canonicalId).toBe('GHSA-35jh-r3h4-6jhm');
    expect(m.ids).toContain('CVE-2021-23337');
    expect(m.observations.length).toBe(3);
    expect(m.severityByTool.map((s) => s.original)).toEqual(['high', 'HIGH', 'HIGH']);
    expect(m.fixedVersions).toEqual(['4.17.21']);
  });
  it('does not merge advisories without a shared identifier', () => {
    const mini = merged.filter((x) => x.packageName === 'minimist');
    expect(mini.map((x) => x.canonicalId).sort()).toEqual(['GHSA-xvch-5gv4-984h', 'SYNTHETIC-TRIVY-0001']);
    expect(mini.find((x) => x.canonicalId === 'GHSA-xvch-5gv4-984h')!.tools).toEqual(['npm-audit', 'osv-scanner']);
  });
  it('is stable for repeated input (idempotent)', () => {
    expect(mergeObservations([...all, ...all]).length).toBe(merged.length);
  });
});

// ---- readiness and selection with mocked processes ----

function fakeTools(spec: Record<string, { found?: boolean; version?: string; versionExit?: number; run?: Partial<ExecResult> }>) {
  const calls: { binary: string; args: string[] }[] = [];
  const which: Which = (name) => (spec[name]?.found === false || !spec[name] ? null : `/fake/bin/${name}`);
  const exec: Exec = async (binary, args) => {
    calls.push({ binary, args });
    const s = spec[path.basename(binary)];
    if (args[0] === '--version') return execResult({ exitCode: s?.versionExit ?? 0, stdout: s?.version ?? '' });
    return execResult(s?.run ?? {});
  };
  return { which, exec, calls };
}

const OSV_OK = { version: 'osv-scanner version: 2.0.1', run: { exitCode: 1, stdout: read('osv-scanner.synthetic.json') } };
const NPM_OK = { version: '10.9.9', run: { exitCode: 1, stdout: read('npm-audit.vulnerable.real.json') } };
const TRIVY_OK = { version: 'Version: 0.60.0', run: { exitCode: 0, stdout: read('trivy.synthetic.json') } };

describe('readiness detection', () => {
  it('reports missing, broken, network-gated and ready tools without downloading anything', async () => {
    const f = fakeTools({ npm: { version: '10.9.9' }, trivy: { version: 'garbage', versionExit: 2 } });
    const rd = await checkReadiness(cfgWith(), f.exec, f.which, PROJ);
    const by = Object.fromEntries(rd.map((r) => [r.tool, r]));
    expect(by['osv-scanner'].state).toBe('not_installed');
    expect(by['npm-audit']).toMatchObject({ state: 'needs_network', version: '10.9.9' });
    expect(by.trivy).toMatchObject({ state: 'not_functional', reason: 'version check exited with 2' });
    expect(f.calls.every((c) => c.args[0] === '--version')).toBe(true);
  });
  it('allows offline modes without network permission and honours disabled tools', async () => {
    const f = fakeTools({ 'osv-scanner': { version: 'osv-scanner version: 2.0.1' }, npm: { version: '10.9.9' } });
    const rd = await checkReadiness(cfgWith({ dependencies: { osvOffline: true, order: ['osv-scanner'] } }), f.exec, f.which, PROJ);
    expect(rd.find((r) => r.tool === 'osv-scanner')!.state).toBe('ready');
    expect(rd.find((r) => r.tool === 'npm-audit')!.state).toBe('disabled');
  });
  it('rejects a configured binary path that is not executable', async () => {
    const rd = await checkReadiness(cfgWith({ dependencies: { binaries: { trivy: '/nonexistent/trivy' } } }), fakeTools({}).exec, (n, e) => (e ? null : null), PROJ);
    expect(rd.find((r) => r.tool === 'trivy')!.reason).toContain('/nonexistent/trivy');
  });
});

describe('scanner selection and fallback', () => {
  const run = async (security: unknown, spec: Parameters<typeof fakeTools>[0]) => {
    const cfg = cfgWith({ allowNetwork: true, ...(security as object) });
    const f = fakeTools(spec);
    const rd = await checkReadiness(cfg, f.exec, f.which, PROJ);
    const res = await runDependencyScan(cfg, [target], [], rd, { exec: f.exec, lockVersions: () => versions });
    return { res, calls: f.calls.filter((c) => c.args[0] !== '--version'), by: Object.fromEntries(res.tools.map((t) => [t.tool, t])) };
  };

  it('first-available runs one tool and records why the others did not run', async () => {
    const { res, calls, by } = await run({}, { 'osv-scanner': OSV_OK, npm: NPM_OK, trivy: TRIVY_OK });
    expect(calls.map((c) => path.basename(c.binary))).toEqual(['osv-scanner']);
    expect(by['npm-audit']).toMatchObject({ status: 'skipped', selected: false });
    expect(by['npm-audit'].reason).toContain('already covered');
    expect(res.coverage[0]).toMatchObject({ status: 'covered', by: ['osv-scanner'] });
  });

  it('falls back to the next ready tool when the first one fails, and labels it', async () => {
    const { res, by } = await run({}, { 'osv-scanner': { ...OSV_OK, run: { exitCode: 127, stdout: '' } }, npm: NPM_OK });
    expect(by['osv-scanner'].status).toBe('failed');
    expect(by['npm-audit']).toMatchObject({ status: 'completed', observationCount: 21 });
    expect(by['npm-audit'].notes[0]).toContain('fallback after osv-scanner failed');
    expect(res.coverage[0]).toMatchObject({ status: 'covered', by: ['npm-audit'] });
  });

  it('does not fall back when fallbackOnFailure is false', async () => {
    const { res, by } = await run({ dependencies: { fallbackOnFailure: false } }, { 'osv-scanner': { ...OSV_OK, run: { timedOut: true, durationMs: 1000 } }, npm: NPM_OK });
    expect(by['osv-scanner'].status).toBe('timed_out');
    expect(by['npm-audit'].status).toBe('skipped');
    expect(res.coverage[0].status).toBe('failed');
    expect(res.observations).toEqual([]);
  });

  it('all-available runs every ready tool for cross-checking', async () => {
    const { calls, res } = await run({ dependencies: { mode: 'all-available' } }, { 'osv-scanner': OSV_OK, npm: NPM_OK, trivy: TRIVY_OK });
    expect(calls.length).toBe(3);
    expect(res.coverage[0]).toMatchObject({ status: 'covered', by: ['osv-scanner', 'npm-audit', 'trivy'] });
  });

  it('marks coverage unavailable (never zero) when no tool can run, and keeps going when one tool fails', async () => {
    const none = await run({}, {});
    expect(none.res.coverage[0]).toMatchObject({ status: 'unavailable', by: [] });
    expect(none.res.coverage[0].reason).toContain('osv-scanner not_installed');
    expect(none.res.tools.every((t) => t.observationCount === null)).toBe(true);

    const partial = await run({ dependencies: { mode: 'all-available' } }, { 'osv-scanner': { ...OSV_OK, run: { exitCode: 1, stdout: '{broken' } }, npm: NPM_OK });
    expect(partial.res.coverage[0]).toMatchObject({ status: 'partial', by: ['npm-audit'] });
  });

  it('respects the network setting at selection time', async () => {
    const cfg = cfgWith({ allowNetwork: false });
    const f = fakeTools({ npm: NPM_OK });
    const rd = await checkReadiness(cfg, f.exec, f.which, PROJ);
    const res = await runDependencyScan(cfg, [target], [], rd, { exec: f.exec, lockVersions: () => versions });
    expect(res.tools.find((t) => t.tool === 'npm-audit')).toMatchObject({ status: 'unavailable', selected: false });
    expect(f.calls.filter((c) => c.args[0] !== '--version')).toEqual([]);
  });

  it('skips tools that do not support the lockfile', async () => {
    const shrink = { ...target, lockfile: 'npm-shrinkwrap.json' };
    const cfg = cfgWith({ allowNetwork: true });
    const f = fakeTools({ 'osv-scanner': OSV_OK, npm: NPM_OK });
    const rd = await checkReadiness(cfg, f.exec, f.which, PROJ);
    const res = await runDependencyScan(cfg, [shrink], [], rd, { exec: f.exec, lockVersions: () => versions });
    expect(res.tools.find((t) => t.tool === 'osv-scanner')).toMatchObject({ status: 'skipped' });
    expect(res.coverage[0].by).toEqual(['npm-audit']);
  });
});

describe('safe process execution', () => {
  const node = process.execPath;
  it('kills the process group on timeout', async () => {
    const r = await execTool(node, ['-e', 'setTimeout(() => {}, 10000)'], { cwd: os.tmpdir(), timeoutMs: 300, maxOutputBytes: 1024 });
    expect(r.timedOut).toBe(true);
    expect(r.durationMs).toBeLessThan(5000);
  });
  it('bounds stdout and flags truncation', async () => {
    const r = await execTool(node, ['-e', 'process.stdout.write("x".repeat(500000))'], { cwd: os.tmpdir(), timeoutMs: 10000, maxOutputBytes: 64 * 1024 });
    expect(r.stdoutTruncated).toBe(true);
    expect(r.stdout.length).toBeLessThanOrEqual(64 * 1024);
  });
  it('passes arguments literally (no shell interpretation)', async () => {
    const r = await execTool(node, ['-e', 'console.log(process.argv[1])', '$(id); `id` && echo pwned'], { cwd: os.tmpdir(), timeoutMs: 10000, maxOutputBytes: 1024 });
    expect(r.stdout.trim()).toBe('$(id); `id` && echo pwned');
  });
  it('reports a missing executable as a spawn error', async () => {
    const r = await execTool('/nonexistent/bin/tool', [], { cwd: os.tmpdir(), timeoutMs: 1000, maxOutputBytes: 1024 });
    expect(r.spawnError).toContain('ENOENT');
  });
});

describe('lockfile model and package use', () => {
  it('detects the npm target and reports manifests it cannot scan', () => {
    expect(detectTargets(PROJ).targets.map((t) => t.lockfile)).toEqual(['package-lock.json']);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wb-deps-'));
    fs.writeFileSync(path.join(dir, 'package.json'), '{}');
    fs.writeFileSync(path.join(dir, 'yarn.lock'), '');
    const d = detectTargets(dir);
    expect(d.targets).toEqual([]);
    expect(d.unsupported.map((u) => u.file)).toEqual(['package.json', 'yarn.lock']);
  });

  it('resolves dev flags and dependency chains', () => {
    expect(model.packages.get('node_modules/minimist')!.dev).toBe(true);
    expect(chainsTo(model, 'node_modules/qs')[0]).toEqual({ introducedBy: 'express', chain: ['express', 'qs'] });
    expect(packageNameFromSpec('@scope/pkg/sub')).toBe('@scope/pkg');
    expect(packageNameFromSpec('lodash/merge')).toBe('lodash');
    expect(packageNameFromSpec('./local')).toBeNull();
    expect(packageNameFromSpec('node:fs')).toBeNull();
  });

  it('distinguishes called, transitive and declared-but-unused packages using the code graph', () => {
    const an = new Analyzer({ root: PROJ, include: ['src'], exclude: [], clientDirs: [] });
    an.fullScan();
    const g = an.build();
    const usage = buildUsageIndex(an.factsList(), g);
    const ix = new GraphIndex(g);
    const lodash = packageUse('lodash', ['node_modules/lodash'], model, usage, ix);
    expect(lodash).toMatchObject({ evidence: 'called_from_analysed_code', direct: true, devOnly: false, callers: ['fn:src/app.js#mergeSettings'], endpoints: ['ep:GET /merge'] });
    expect(lodash.paths[0][0]).toBe('ep:GET /merge');
    const qs = packageUse('qs', ['node_modules/qs'], model, usage, ix);
    expect(qs.evidence).toBe('transitive');
    expect(qs.introducedBy[0]).toMatchObject({ direct: 'express', directEvidence: 'called_from_analysed_code' });
    expect(qs.endpoints).toEqual([]);
    const mini = packageUse('minimist', ['node_modules/minimist'], model, usage, ix);
    expect(mini).toMatchObject({ evidence: 'declared_not_imported', devOnly: true, declaredAs: 'dev' });
    expect(packageUse('ghost', ['node_modules/ghost'], model, usage, ix).evidence).toBe('not_in_lockfile');
  });
});

// Opt-in: runs every scanner that is really installed against the fixture lockfile (network required).
//   WORKBENCH_REAL_SCANNERS=1 npx vitest run test/security-deps.test.ts -t "real scanners"
describe.runIf(process.env.WORKBENCH_REAL_SCANNERS === '1')('real scanners', () => {
  const real = cfgWith({ allowNetwork: true, dependencies: { mode: 'all-available' } });
  it('every installed scanner completes and reports advisories for the vulnerable fixture', async () => {
    const { which } = await import('../src/security/exec.js');
    const rd = await checkReadiness(real, execTool, which, PROJ);
    const ready = rd.filter((r) => r.state === 'ready');
    console.log(rd.map((r) => `${r.tool}: ${r.state} ${r.version ?? ''} ${r.reason ?? ''}`).join('\n'));
    expect(ready.length).toBeGreaterThan(0);
    const t = { ...target, ...detectTargets(PROJ).targets[0] };
    const res = await runDependencyScan(real, [t], [], rd, { exec: execTool, lockVersions: () => versions });
    for (const r of ready) {
      const rec = res.tools.find((x) => x.tool === r.tool)!;
      console.log(`${rec.tool} ${rec.status} ${rec.observationCount} ${rec.reason ?? ''}`);
      expect(rec.status).toBe('completed');
      expect(rec.observationCount).toBeGreaterThan(0);
    }
  }, 300_000);
});

// ---- OSV.dev web API adapter (fake fetch; shapes follow the documented querybatch / vulns/{id} responses) ----
const OSV_RECORD = {
  id: 'GHSA-35jh-r3h4-6jhm', aliases: ['CVE-2021-23337'], summary: 'Command Injection in lodash',
  database_specific: { severity: 'HIGH', cwe_ids: ['CWE-77'] },
  severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' }],
  affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }],
  references: [{ type: 'ADVISORY', url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm' }],
};
function fakeOsvFetch(opts: { fail?: 'query' | 'vuln' | 'down'; withdrawn?: boolean } = {}) {
  const calls: string[] = [];
  const f = (async (url: string, init?: RequestInit) => {
    calls.push(`${init?.method ?? 'GET'} ${url}`);
    if (opts.fail === 'down') throw new Error('getaddrinfo ENOTFOUND api.osv.dev');
    const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status });
    if (url.endsWith('/v1/query')) return json({});
    if (url.endsWith('/v1/querybatch')) {
      if (opts.fail === 'query') return json({ error: 'boom' }, 500);
      const body = JSON.parse(String(init?.body));
      return json({ results: body.queries.map((q: any) => (q.package.name === 'lodash' && q.version === '4.17.20' ? { vulns: [{ id: OSV_RECORD.id, modified: 'x' }] } : {})) });
    }
    if (url.includes('/v1/vulns/')) return opts.fail === 'vuln' ? json({ error: 'nope' }, 503) : json(opts.withdrawn ? { ...OSV_RECORD, withdrawn: '2024-01-01T00:00:00Z' } : OSV_RECORD);
    return json({}, 404);
  }) as unknown as typeof fetch;
  return { f, calls };
}
const apiCtx = (f: typeof fetch, extra: object = {}) => ({
  fetch: f, packages: [...model.packages.values()].map((p) => ({ name: p.name, version: p.version, dev: p.dev })), lockVersions: versions, timeoutMs: 10_000, ...extra,
});

describe('OSV.dev web API adapter', () => {
  it('needs no binary: readiness is ready only when network is allowed and the API answers', async () => {
    const none = fakeOsvFetch();
    const off = await checkReadiness(cfgWith({ dependencies: { order: ['osv-api'] } }), (async () => execResult({})) as Exec, (() => null) as Which, PROJ, ['osv-api'], none.f);
    expect(off[0]).toMatchObject({ state: 'needs_network', binary: null });
    expect(none.calls).toEqual([]);                       // nothing sent while network is not allowed
    const on = await checkReadiness(cfgWith({ allowNetwork: true, dependencies: { order: ['osv-api'] } }), (async () => execResult({})) as Exec, (() => null) as Which, PROJ, ['osv-api'], none.f);
    expect(on[0]).toMatchObject({ state: 'ready', binary: null });
    const down = await checkReadiness(cfgWith({ allowNetwork: true, dependencies: { order: ['osv-api'] } }), (async () => execResult({})) as Exec, (() => null) as Which, PROJ, ['osv-api'], fakeOsvFetch({ fail: 'down' }).f);
    expect(down[0].state).toBe('unreachable');
    expect(down[0].reason).toContain('ENOTFOUND');
  });

  it('turns matched OSV records into observations with the same parser as osv-scanner', async () => {
    const { f, calls } = fakeOsvFetch();
    const r = await osvApiAdapter.runApi!(target, apiCtx(f));
    expect(r.outcome.status).toBe('completed');
    const obs = r.outcome.status === 'completed' ? r.outcome.observations : [];
    expect(obs).toHaveLength(1);
    expect(obs[0]).toMatchObject({ tool: 'osv-api', packageName: 'lodash', installedVersion: '4.17.20', advisoryId: 'GHSA-35jh-r3h4-6jhm', severity: 'high', fixedVersions: ['4.17.21'] });
    expect(obs[0]!.aliases).toContain('CVE-2021-23337');
    expect(calls.filter((c) => c.includes('querybatch'))).toHaveLength(1);
    expect(calls.filter((c) => c.includes('/v1/vulns/'))).toHaveLength(1);
  });

  it('skips withdrawn advisories and sends no source code, only names and versions', async () => {
    const { f } = fakeOsvFetch({ withdrawn: true });
    const r = await osvApiAdapter.runApi!(target, apiCtx(f));
    expect(r.outcome.status === 'completed' && r.outcome.observations).toEqual([]);
    const sent: string[] = [];
    const spy = (async (u: string, i?: RequestInit) => { if (i?.body) sent.push(String(i.body)); return (f as any)(u, i); }) as unknown as typeof fetch;
    await osvApiAdapter.runApi!(target, apiCtx(spy));
    expect(sent.join('')).not.toMatch(/src\/|password|secret/i);
  });

  it('fails the whole run on any API error instead of reporting partial or zero results', async () => {
    for (const fail of ['query', 'vuln', 'down'] as const) {
      const r = await osvApiAdapter.runApi!(target, apiCtx(fakeOsvFetch({ fail }).f));
      expect(r.outcome.status, fail).toBe('failed');
    }
  });

  it('orchestrator: falls back from an unreachable API to npm audit and never claims the API covered the lockfile', async () => {
    const f = fakeTools({ npm: NPM_OK });
    const cfg = cfgWith({ allowNetwork: true, dependencies: { order: ['osv-api', 'npm-audit'] } });
    const rd = await checkReadiness(cfg, f.exec, f.which, PROJ, ['osv-api', 'npm-audit'], fakeOsvFetch({ fail: 'down' }).f);
    const res = await runDependencyScan(cfg, [target], [], rd, { exec: f.exec, lockVersions: () => versions });
    const by = Object.fromEntries(res.tools.map((t) => [t.tool, t]));
    expect(by['osv-api']).toMatchObject({ status: 'unavailable', observationCount: null });
    expect(by['npm-audit'].status).toBe('completed');
    expect(res.coverage[0]).toMatchObject({ status: 'covered', by: ['npm-audit'] });
  });

  it('orchestrator: runs the API through the same pipeline when reachable', async () => {
    const f = fakeTools({});
    const net = fakeOsvFetch();
    const cfg = cfgWith({ allowNetwork: true, dependencies: { order: ['osv-api', 'npm-audit'] } });
    const rd = await checkReadiness(cfg, f.exec, f.which, PROJ, ['osv-api', 'npm-audit'], net.f);
    const res = await runDependencyScan(cfg, [target], [], rd, {
      exec: f.exec, lockVersions: () => versions, fetch: net.f,
      lockPackages: () => [...model.packages.values()].map((p) => ({ name: p.name, version: p.version, dev: p.dev })),
    });
    expect(res.tools.find((t) => t.tool === 'osv-api')).toMatchObject({ status: 'completed', selected: true, observationCount: 1, version: 'osv.dev API v1' });
    expect(res.coverage[0]).toMatchObject({ status: 'covered', by: ['osv-api'] });
    expect(res.reports[0]!.tool).toBe('osv-api');
  });
});
