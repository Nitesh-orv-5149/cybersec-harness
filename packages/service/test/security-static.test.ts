// Secrets detection (Gitleaks) and infrastructure checks (Checkov): report readers against real tool output
// (fixtures/secrets, fixtures/iac), IaC detection, argument building and every non-clean outcome of a run.
// The last block runs the real binaries when GITLEAKS_BIN / CHECKOV_BIN (or PATH) provide them; skipped otherwise.
import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ProjectConfigSchema } from '../src/config.js';
import { execTool, which as realWhich } from '../src/security/exec.js';
import type { Exec, ExecResult, Readiness } from '../src/security/types.js';
import type { KindContext } from '../src/security/scan/types.js';
import {
  gitleaksArgs, gitleaksConfig, parseGitleaksVersion, readGitleaksReport, sanitizeGitleaksReport, scannedBytes, supportsDirCommand,
} from '../src/security/secrets/gitleaks.js';
import { secretsKind } from '../src/security/secrets/kind.js';
import { detectIac } from '../src/security/iac/detect.js';
import { checkovArgs, parseCheckovVersion, readCheckovReport } from '../src/security/iac/checkov.js';
import { iacKind } from '../src/security/iac/kind.js';
import { FAKE, writeLeakyProject } from './helpers/secrets.js';

const FX = path.resolve(__dirname, 'fixtures');
const IAC_PROJECT = path.join(FX, 'iac/project');
const GL_REPORT = fs.readFileSync(path.join(FX, 'secrets/gitleaks-8.24.3.report.json'), 'utf8');
const CK_REPORT = fs.readFileSync(path.join(FX, 'iac/checkov-3.3.30.results.json'), 'utf8');
const tmp = (p: string) => fs.mkdtempSync(path.join(os.tmpdir(), p));

const R = (over: Partial<ExecResult>): ExecResult => ({ exitCode: 0, signal: null, stdout: '', stdoutBytes: 0, stdoutTruncated: false, stderrTail: '', timedOut: false, cancelled: false, spawnError: null, durationMs: 3, ...over });
const ready = (tool: 'gitleaks' | 'checkov', version: string): Readiness => ({ tool, state: 'ready', version, binary: `/fake/${tool}`, reason: null, checkedAt: '' });

function ctx(root: string, exec: Exec, readiness: Readiness[], over: { mode?: string; cfg?: object } = {}): KindContext {
  const runDir = tmp('wb-run-');
  return {
    root, runDir, cfg: ProjectConfigSchema.parse({ security: over.cfg ?? {} }), graph: null, exec, which: () => null, signal: new AbortController().signal,
    readiness, startTarget: async () => { throw new Error('static kinds never start a target'); }, onTool: () => {}, options: { mode: over.mode },
  };
}

// ------------------------------------------------------------------------------------------------ Gitleaks
describe('Gitleaks adapter', () => {
  it('parses versions and requires the dir/git commands (8.19+)', () => {
    expect(parseGitleaksVersion('8.24.3\n')).toBe('8.24.3');
    expect(parseGitleaksVersion('v8.18.0')).toBe('8.18.0');
    expect(parseGitleaksVersion('gitleaks')).toBeNull();
    expect(supportsDirCommand('8.24.3')).toBe(true);
    expect(supportsDirCommand('8.18.4')).toBe(false);
    expect(supportsDirCommand('9.0.0')).toBe(true);
  });

  it('builds a redacting, report-to-file command with a distinct leaks exit code', () => {
    const a = gitleaksArgs({ mode: 'workspace', configPath: '/r/c.toml', reportPath: '/r/out.json', maxTargetMegabytes: 10 });
    expect(a.slice(0, 2)).toEqual(['dir', '.']);
    expect(a).toContain('--redact');
    expect(a[a.indexOf('--exit-code') + 1]).toBe('42');
    expect(a[a.indexOf('--report-format') + 1]).toBe('json');
    expect(gitleaksArgs({ mode: 'history', configPath: 'c', reportPath: 'r', maxTargetMegabytes: 1 })[0]).toBe('git');
  });

  it('extends the default rules, or the project\'s own .gitleaks.toml, and adds excluded directories', () => {
    const root = tmp('wb-gl-cfg-');
    const d = gitleaksConfig(root, ['dist', '.next']);
    expect(d.base).toBe('Gitleaks default rules');
    expect(d.toml).toContain('useDefault = true');
    expect(d.toml).toContain(`'''(^|/)dist(/|$)'''`);
    expect(d.toml).toContain(`'''(^|/)\\.next(/|$)'''`);
    fs.writeFileSync(path.join(root, '.gitleaks.toml'), 'title = "own"\n');
    const own = gitleaksConfig(root, []);
    expect(own.base).toMatch(/project/);
    expect(own.toml).toContain(`path = '''${path.join(root, '.gitleaks.toml')}'''`);
    expect(own.toml).not.toContain('[allowlist]');
  });

  it('reads the real 8.24.3 report: rule ids, locations and redacted evidence', () => {
    const r = readGitleaksReport(GL_REPORT, { toolVersion: '8.24.3', mode: 'workspace' });
    if ('error' in r) throw new Error(r.error);
    expect(r.unredacted).toBe(0);
    expect(r.observations.map((o) => `${o.ruleId}@${o.location.file}:${o.location.line}`).sort()).toEqual([
      'github-pat@dist/bundle.js:1', 'github-pat@src/config.js:3', 'private-key@src/key.pem:1', 'stripe-access-token@src/config.js:2',
    ]);
    const pk = r.observations.find((o) => o.ruleId === 'private-key')!;
    expect(pk.location).toEqual({ file: 'src/key.pem', line: 1, endLine: 4 });
    expect(pk.originalSeverity).toBeNull();
    expect(pk.severity).toBe('high');
    expect(pk.cwe).toEqual(['CWE-798']);
    expect(pk.evidence).toMatchObject({ rule: 'private-key', fingerprint: 'src/key.pem:private-key:1', match: 'REDACTED' });
    expect(new Set(r.observations.map((o) => o.dedupeKey)).size).toBe(4);
  });

  it('never keeps a value the tool failed to redact', () => {
    const leaked = JSON.stringify([{ RuleID: 'generic-api-key', File: 'a.js', StartLine: 1, EndLine: 1, StartColumn: 1, EndColumn: 9, Match: `key = "${FAKE.stripe}"`, Secret: FAKE.stripe, Email: 'dev@example.com' }]);
    const r = readGitleaksReport(leaked, { toolVersion: null, mode: 'workspace' });
    if ('error' in r) throw new Error(r.error);
    expect(r.unredacted).toBe(1);
    expect(JSON.stringify(r.observations)).not.toContain(FAKE.stripe);
    const kept = sanitizeGitleaksReport(leaked);
    expect(kept).not.toContain(FAKE.stripe);
    expect(kept).not.toContain('dev@example.com');
  });

  it('keeps commit identity for history findings', () => {
    const h = JSON.stringify([{ RuleID: 'github-pat', File: 'src/a.js', StartLine: 3, EndLine: 3, StartColumn: 1, EndColumn: 5, Match: 'REDACTED', Secret: 'REDACTED', Commit: 'abc123def4567890', Date: '2026-10-01T00:00:00Z' }]);
    const r = readGitleaksReport(h, { toolVersion: null, mode: 'history' });
    if ('error' in r) throw new Error(r.error);
    expect(r.observations[0]!.location.commit).toBe('abc123def4567890');
    expect(r.observations[0]!.dedupeKey).toContain('abc123def4567890');
  });

  it('rejects malformed reports and reads the scanned size from the log', () => {
    expect(readGitleaksReport('{', { toolVersion: null, mode: 'workspace' })).toHaveProperty('error');
    expect(readGitleaksReport('{}', { toolVersion: null, mode: 'workspace' })).toHaveProperty('error');
    expect(readGitleaksReport('[{"File":"x"}]', { toolVersion: null, mode: 'workspace' })).toHaveProperty('error');
    expect(scannedBytes('6:53PM INF scanned ~26283 bytes (26.28 KB) in 666ms\n6:53PM INF no leaks found')).toBe(26283);
    expect(scannedBytes('nothing')).toBeNull();
  });
});

describe('secrets kind outcomes', () => {
  const root = tmp('wb-sec-kind-');
  const writeReport = (args: string[], content: string) => fs.writeFileSync(args[args.indexOf('--report-path') + 1]!, content);

  it('is unavailable (not clean) when Gitleaks is missing', async () => {
    const r = await secretsKind.run(ctx(root, async () => R({}), [{ tool: 'gitleaks', state: 'not_installed', version: null, binary: null, reason: "none of 'gitleaks' found on PATH", checkedAt: '' }]));
    expect(r.coverage.status).toBe('unavailable');
    expect(r.observations).toEqual([]);
    expect(r.tools[0]!.observationCount).toBeNull();
  });

  it('turns leaks into observations and keeps only the sanitised report', async () => {
    const c = ctx(root, async (_b, args) => { writeReport(args, GL_REPORT); return R({ exitCode: 42, stderrTail: 'INF scanned ~398 bytes (398 bytes) in 10ms\nWRN leaks found: 4' }); }, [ready('gitleaks', '8.24.3')]);
    const r = await secretsKind.run(c);
    expect(r.coverage).toMatchObject({ status: 'covered', detail: { mode: 'workspace', bytesScanned: 398, config: 'Gitleaks default rules' } });
    expect(r.observations).toHaveLength(4);
    expect(r.tools[0]).toMatchObject({ status: 'completed', observationCount: 4, exitCode: 42 });
    expect(fs.existsSync(path.join(c.runDir, '.gitleaks-raw.json'))).toBe(false);
    expect(r.reports.map((x) => x.name)).toEqual(['report.json', 'config.toml']);
    expect(r.inScope({ location: { file: 'src/a.js' } })).toBe(true);
    expect(r.inScope({ location: { file: 'src/a.js', commit: 'abc' } })).toBe(false);
  });

  it('reports a clean result only with exit 0 and an empty report', async () => {
    const r = await secretsKind.run(ctx(root, async (_b, args) => { writeReport(args, '[]'); return R({ exitCode: 0 }); }, [ready('gitleaks', '8.24.3')]));
    expect(r.coverage.status).toBe('covered');
    expect(r.tools[0]!.observationCount).toBe(0);
  });

  it('fails on a Gitleaks error, a missing report, or an exit code that contradicts the report', async () => {
    const err = await secretsKind.run(ctx(root, async () => R({ exitCode: 1, stderrTail: 'FTL failed to load config' }), [ready('gitleaks', '8.24.3')]));
    expect(err.coverage).toMatchObject({ status: 'failed', reason: expect.stringContaining('exited with 1') });
    const none = await secretsKind.run(ctx(root, async () => R({ exitCode: 0 }), [ready('gitleaks', '8.24.3')]));
    expect(none.coverage).toMatchObject({ status: 'failed', reason: expect.stringContaining('wrote no report') });
    const mismatch = await secretsKind.run(ctx(root, async (_b, args) => { writeReport(args, '[]'); return R({ exitCode: 42 }); }, [ready('gitleaks', '8.24.3')]));
    expect(mismatch.coverage.status).toBe('failed');
    expect(mismatch.tools[0]!.status).toBe('inconclusive');
    const timeout = await secretsKind.run(ctx(root, async () => R({ exitCode: null, timedOut: true }), [ready('gitleaks', '8.24.3')]));
    expect(timeout.tools[0]!.status).toBe('timed_out');
  });

  it('does not run history mode outside a git repository root', async () => {
    let calls = 0;
    const r = await secretsKind.run(ctx(root, async () => { calls++; return R({}); }, [ready('gitleaks', '8.24.3')], { mode: 'history' }));
    expect(r.coverage.status).toBe('not_run');
    expect(calls).toBe(0);
  });
});

// ------------------------------------------------------------------------------------------------ Checkov
describe('IaC detection', () => {
  it('finds each framework in the fixture project', () => {
    const d = detectIac(IAC_PROJECT, ['node_modules']);
    expect(d.frameworks).toEqual({
      terraform: ['infra/main.tf'], dockerfile: ['Dockerfile'], kubernetes: ['k8s/deployment.yaml'], github_actions: ['.github/workflows/ci.yml'],
    });
  });

  it('finds nothing in a plain JS project (so the run is "not applicable")', () => {
    const root = tmp('wb-noiac-');
    fs.writeFileSync(path.join(root, 'package.json'), '{"name":"x","version":"1.0.0"}');
    fs.writeFileSync(path.join(root, 'tsconfig.json'), '{}');
    fs.writeFileSync(path.join(root, 'config.yaml'), 'port: 3000\nkind: web\n');
    expect(detectIac(root, []).frameworks).toEqual({});
  });

  it('recognises CloudFormation, Helm (without its templates as plain manifests), and honours excludes', () => {
    const root = tmp('wb-iac-');
    fs.writeFileSync(path.join(root, 'stack.yaml'), 'AWSTemplateFormatVersion: "2010-09-09"\nResources:\n  B:\n    Type: AWS::S3::Bucket\n');
    fs.mkdirSync(path.join(root, 'chart/templates'), { recursive: true });
    fs.writeFileSync(path.join(root, 'chart/Chart.yaml'), 'apiVersion: v2\nname: c\nversion: 0.1.0\n');
    fs.writeFileSync(path.join(root, 'chart/templates/dep.yaml'), 'apiVersion: apps/v1\nkind: Deployment\n');
    fs.mkdirSync(path.join(root, 'vendor'));
    fs.writeFileSync(path.join(root, 'vendor/main.tf'), 'resource "x" "y" {}\n');
    const d = detectIac(root, ['vendor']);
    expect(d.frameworks).toEqual({ cloudformation: ['stack.yaml'], helm: ['chart/Chart.yaml'] });
  });
});

describe('Checkov adapter', () => {
  it('builds an offline, soft-fail command for the detected frameworks only', () => {
    const a = checkovArgs({ outDir: '/r/out', frameworks: ['terraform', 'dockerfile'], exclude: ['node_modules', '.terraform'], skipChecks: ['CKV_DOCKER_2'] });
    expect(a).toEqual(expect.arrayContaining(['--soft-fail', '--skip-download', '--framework', 'terraform,dockerfile', '--skip-check', 'CKV_DOCKER_2']));
    expect(a[a.indexOf('--output') + 1]).toBe('json');
    expect(a.filter((x) => x === '--skip-path')).toHaveLength(2);
    expect(a).toContain('(^|/)\\.terraform(/|$)');
    expect(parseCheckovVersion('3.3.30\n')).toBe('3.3.30');
  });

  it('reads the real 3.3.30 report: per-framework results and failed checks with locations', () => {
    const r = readCheckovReport(CK_REPORT, { root: '/fixture/project' });
    if ('error' in r) throw new Error(r.error);
    expect(r.version).toBe('3.3.30');
    expect(Object.fromEntries(r.frameworks.map((f) => [f.framework, f.failed]))).toEqual({ kubernetes: 20, dockerfile: 3, github_actions: 1, terraform: 14 });
    expect(r.observations).toHaveLength(38);
    const ssh = r.observations.find((o) => o.ruleId === 'CKV_AWS_24')!;
    expect(ssh.location).toMatchObject({ file: 'infra/main.tf', resource: 'aws_security_group.web' });
    expect(ssh.ruleName).toMatch(/port 22/);
    expect(ssh.severity).toBe('unknown');
    expect(ssh.originalSeverity).toBeNull();
    expect(String(ssh.evidence.code)).toContain('0.0.0.0/0');
    const latest = r.observations.find((o) => o.ruleId === 'CKV_DOCKER_7')!;
    expect(latest.location).toMatchObject({ file: 'Dockerfile', line: 2 });
    // GitHub Actions graph checks report line 0; it is clamped to a real line
    expect(r.observations.find((o) => o.ruleId === 'CKV2_GHA_1')!.location.line).toBe(1);
    expect(new Set(r.observations.map((o) => o.dedupeKey)).size).toBe(38);
  });

  it('keeps severities when Checkov supplies them, and handles the single-report and summary-only shapes', () => {
    const one = JSON.parse(CK_REPORT)[1];
    one.results.failed_checks[0].severity = 'CRITICAL';
    const r = readCheckovReport(JSON.stringify(one), { root: '/x' });
    if ('error' in r) throw new Error(r.error);
    expect(r.frameworks).toHaveLength(1);
    expect(r.observations[0]).toMatchObject({ severity: 'high', originalSeverity: 'CRITICAL' });
    const empty = readCheckovReport('{"passed":0,"failed":0,"skipped":0,"parsing_errors":0,"resource_count":0,"checkov_version":"3.3.30"}', { root: '/x' });
    expect(empty).toMatchObject({ version: '3.3.30', frameworks: [], observations: [] });
    expect(readCheckovReport('nope', { root: '/x' })).toHaveProperty('error');
    expect(readCheckovReport('[{"foo":1}]', { root: '/x' })).toHaveProperty('error');
  });
});

describe('IaC kind outcomes', () => {
  const outFile = (args: string[]) => path.join(args[args.indexOf('--output-file-path') + 1]!, 'results_json.json');

  it('is "not applicable" with no IaC files, and never calls Checkov', async () => {
    const root = tmp('wb-noiac-run-');
    fs.writeFileSync(path.join(root, 'index.js'), 'console.log(1)\n');
    let calls = 0;
    const r = await iacKind.run(ctx(root, async () => { calls++; return R({}); }, [{ tool: 'checkov', state: 'not_installed', version: null, binary: null, reason: 'missing', checkedAt: '' }]));
    expect(r.coverage.status).toBe('not_applicable');
    expect(r.coverage.reason).toMatch(/no infrastructure-as-code files found/);
    expect(calls).toBe(0);
  });

  it('is unavailable (not clean) when IaC exists but Checkov is missing', async () => {
    const r = await iacKind.run(ctx(IAC_PROJECT, async () => R({}), [{ tool: 'checkov', state: 'not_installed', version: null, binary: null, reason: "none of 'checkov' found on PATH", checkedAt: '' }]));
    expect(r.coverage.status).toBe('unavailable');
    expect(r.coverage.detail.files).toHaveProperty('terraform');
  });

  it('records findings and full coverage from the real report, running offline', async () => {
    let seen: { args: string[]; env?: Record<string, string>; localOnly?: boolean } | null = null;
    const r = await iacKind.run(ctx(IAC_PROJECT, async (_b, args, o) => {
      seen = { args, env: o.extraEnv, localOnly: o.localOnly };
      fs.writeFileSync(outFile(args), CK_REPORT.replaceAll('/fixture/project', IAC_PROJECT));
      return R({ exitCode: 0 });
    }, [ready('checkov', '3.3.30')]));
    expect(seen!.env).toMatchObject({ BC_SKIP_MAPPING: 'TRUE', CKV_SKIP_PACKAGE_UPDATE_CHECK: 'TRUE' });
    expect(seen!.localOnly).toBe(true);
    expect(seen!.args[seen!.args.indexOf('--framework') + 1]!.split(',').sort()).toEqual(['dockerfile', 'github_actions', 'kubernetes', 'terraform']);
    expect(r.coverage.status).toBe('covered');
    expect(r.observations).toHaveLength(38);
    expect(r.inScope({ location: { file: 'infra/main.tf' } })).toBe(true);
    expect(r.inScope({ location: { file: 'gone/old.tf' } })).toBe(true);   // file deleted -> re-checked by definition
  });

  it('is partial when a detected framework produced no result, failed on a Checkov error', async () => {
    const onlyTf = JSON.stringify(JSON.parse(CK_REPORT).filter((x: any) => x.check_type === 'terraform'));
    const part = await iacKind.run(ctx(IAC_PROJECT, async (_b, args) => { fs.writeFileSync(outFile(args), onlyTf); return R({ exitCode: 0 }); }, [ready('checkov', '3.3.30')]));
    expect(part.coverage.status).toBe('partial');
    expect(part.coverage.reason).toMatch(/no result for .*Dockerfiles/);
    expect(part.inScope({ location: { file: 'Dockerfile' } })).toBe(false);
    expect(part.inScope({ location: { file: 'infra/main.tf' } })).toBe(true);
    const err = await iacKind.run(ctx(IAC_PROJECT, async () => R({ exitCode: 2, stderrTail: 'Traceback ...' }), [ready('checkov', '3.3.30')]));
    expect(err.coverage).toMatchObject({ status: 'failed', reason: expect.stringContaining('exited with 2') });
    const noReport = await iacKind.run(ctx(IAC_PROJECT, async () => R({ exitCode: 0 }), [ready('checkov', '3.3.30')]));
    expect(noReport.coverage).toMatchObject({ status: 'failed', reason: 'Checkov wrote no JSON report' });
  });
});

// ------------------------------------------------------------------------------------------------ real binaries
const gitleaksBin = process.env.GITLEAKS_BIN || realWhich('gitleaks');
const checkovBin = process.env.CHECKOV_BIN || realWhich('checkov');

describe.runIf(!!gitleaksBin)('real Gitleaks', () => {
  it('finds the fake credentials, skips excluded dist/, and stores nothing unredacted', async () => {
    const root = tmp('wb-gl-real-');
    writeLeakyProject(root);
    const version = parseGitleaksVersion((await execTool(gitleaksBin!, ['version'], { cwd: root, timeoutMs: 10_000, maxOutputBytes: 4096 })).stdout)!;
    const r = await secretsKind.run(ctx(root, execTool, [{ ...ready('gitleaks', version), binary: gitleaksBin! }]));
    expect(r.coverage.status).toBe('covered');
    expect(r.observations.map((o) => `${o.ruleId}@${o.location.file}:${o.location.line}`).sort()).toEqual(['github-pat@src/config.js:3', 'stripe-access-token@src/config.js:2']);
    const stored = JSON.stringify({ obs: r.observations, reports: r.reports, tools: r.tools });
    expect(stored).not.toContain(FAKE.stripe);
    expect(stored).not.toContain(FAKE.github);
  }, 60_000);
});

describe.runIf(!!checkovBin)('real Checkov', () => {
  it('checks the fixture project offline and reports the same failed checks as the recorded report', async () => {
    const version = parseCheckovVersion((await execTool(checkovBin!, ['--version'], { cwd: IAC_PROJECT, timeoutMs: 60_000, maxOutputBytes: 4096 })).stdout)!;
    const r = await iacKind.run(ctx(IAC_PROJECT, execTool, [{ ...ready('checkov', version), binary: checkovBin! }]));
    expect(r.coverage.status).toBe('covered');
    const ids = new Set(r.observations.map((o) => o.ruleId));
    for (const id of ['CKV_AWS_24', 'CKV_DOCKER_7', 'CKV_K8S_16', 'CKV2_GHA_1']) expect(ids.has(id)).toBe(true);
  }, 180_000);
});

describe('readiness: broken script interpreter (spawn ENOENT on a file that exists)', () => {
  it('names the missing #! interpreter instead of a bare ENOENT', async () => {
    const { probeBinary } = await import('../src/security/readiness.js');
    const dir = tmp('wb-broken-venv-');
    const bin = path.join(dir, 'checkov');
    fs.writeFileSync(bin, `#!${path.join(dir, 'pipx/venvs/checkov/bin/python')}\nimport sys\n`, { mode: 0o755 });
    const r = await probeBinary({ tool: 'checkov', names: ['checkov'], explicit: bin, versionArgs: ['--version'], parseVersion: parseCheckovVersion, exec: execTool, which: realWhich, cwd: dir });
    expect(r.state).toBe('not_functional');
    expect(r.reason).toContain('pipx/venvs/checkov/bin/python');
    expect(r.reason).toContain("from the script's #! line) does not exist");
    expect(r.reason).toContain('pipx reinstall checkov');
  });
});
