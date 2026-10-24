// Infrastructure checks kind: Checkov on the IaC files the workbench finds in the project.
// No IaC files -> "not applicable" (never a clean result). Checkov runs offline with only the detected frameworks.
import fs from 'node:fs';
import path from 'node:path';
import type { Readiness, ToolRunRecord } from '../types.js';
import { probeBinary } from '../readiness.js';
import type { KindRunResult, ScanKind } from '../scan/types.js';
import { detectIac, FRAMEWORK_LABEL, type IacFramework } from './detect.js';
import { CHECKOV_OFFLINE_ENV, checkovArgs, parseCheckovVersion, readCheckovReport } from './checkov.js';

const TOOL = 'checkov';
const LIMITATIONS = [
  'Policy checks on configuration files. Whether a failed check matters depends on how and where the infrastructure is deployed.',
  'Without a Prisma Cloud API key Checkov reports no severities; they are shown as "unknown" rather than guessed. No key is ever passed by the workbench.',
  'Helm charts and Kustomize need the helm / kustomize binaries; if they are missing Checkov skips those frameworks and the run is marked partial.',
  'Terraform modules from registries are not downloaded, so resources inside external modules are not checked.',
];

function record(rd: Readiness | undefined, patch: Partial<ToolRunRecord>): ToolRunRecord {
  return {
    tool: TOOL, displayName: 'Checkov', version: rd?.version ?? null, readiness: rd?.state ?? 'not_installed', selected: false, status: 'skipped',
    reason: null, exitCode: null, durationMs: null, observationCount: null, stderrTail: null, reportRef: null, reportSha256: null, notes: [],
    limitations: LIMITATIONS, networkHosts: [], ...patch,
  };
}

export const iacKind: ScanKind = {
  id: 'iac', category: 'iac', label: 'Infrastructure checks', findingSource: 'iac',
  description: 'Checkov checks Terraform, CloudFormation, Kubernetes, Helm, Dockerfiles and CI pipeline files found in the project.',
  dynamic: false, modes: ['files'], activeModes: [],
  tools: [{
    id: TOOL, displayName: 'Checkov', networkHosts: [], limitations: LIMITATIONS,
    readiness: async ({ cfg, exec, which, root }) => {
      const r = await probeBinary({ tool: TOOL, names: ['checkov'], explicit: cfg.security.iac.binary, versionArgs: ['--version'], parseVersion: parseCheckovVersion, exec, which, cwd: root, timeoutMs: 60_000 });
      if (r.state === 'ready' && Number(r.version!.split('.')[0]) < 3) return { ...r, state: 'not_functional', reason: `Checkov ${r.version} found; this integration reads the report format of version 3.x` };
      return r;
    },
  }],
  enabled: (cfg) => cfg.security.iac.enabled,
  preconditions: () => [],

  async run(ctx): Promise<KindRunResult> {
    const cfg = ctx.cfg.security.iac;
    const rd = ctx.readiness.find((x) => x.tool === TOOL);
    const notes: string[] = [];

    // 1. what is there to check (independent of whether Checkov is installed)
    const det = detectIac(ctx.root, cfg.exclude);
    const fws = Object.keys(det.frameworks) as IacFramework[];
    const filesByFw = Object.fromEntries(fws.map((f) => [f, det.frameworks[f]]));
    const allFiles = new Set(fws.flatMap((f) => det.frameworks[f]!));
    if (det.truncated) notes.push(`stopped looking for IaC files after ${det.filesWalked} files; add large directories to security.iac.exclude`);
    const fail = (status: KindRunResult['coverage']['status'], reason: string, tools: ToolRunRecord[], detail: Record<string, unknown> = {}): KindRunResult =>
      ({ tools, observations: [], coverage: { status, reason, detail: { files: filesByFw, ...detail } }, reports: [], notes, inScope: () => false });

    if (!fws.length) {
      return {
        tools: [record(rd, { status: 'skipped', reason: 'no supported IaC files in the project' })], observations: [], reports: [], notes,
        coverage: { status: 'not_applicable', reason: `no infrastructure-as-code files found (looked for ${det.lookedFor.join(', ')}; ${det.filesWalked} files checked, excluding ${cfg.exclude.join(', ')})`, detail: { filesWalked: det.filesWalked, lookedFor: det.lookedFor } },
        inScope: () => false,
      };
    }
    if (!rd || rd.state !== 'ready') return fail('unavailable', `Checkov is not usable: ${rd?.reason ?? 'readiness not checked'}`, [record(rd, { status: 'unavailable', reason: rd?.reason ?? null })]);

    // 2. run
    const outDir = path.join(ctx.runDir, 'checkov-out');
    fs.mkdirSync(outDir, { recursive: true });
    const args = checkovArgs({ outDir, frameworks: fws, exclude: cfg.exclude, skipChecks: cfg.skipChecks });
    ctx.onTool(TOOL, 'running');
    let r;
    try { r = await ctx.exec(rd.binary!, args, { cwd: ctx.root, timeoutMs: cfg.timeoutMs, maxOutputBytes: 1024 * 1024, signal: ctx.signal, localOnly: true, discardStdout: true, env: CHECKOV_OFFLINE_ENV }); }
    finally { ctx.onTool(TOOL, 'done'); }
    const base = { selected: true, exitCode: r.exitCode, durationMs: r.durationMs, stderrTail: r.stderrTail ? r.stderrTail.slice(-2000) : null, notes: [`command: checkov ${args.map((a) => (a === outDir ? '<run>/checkov-out' : a)).join(' ')}`] };

    if (r.spawnError || r.timedOut || r.cancelled) {
      const status = r.cancelled ? 'cancelled' : r.timedOut ? 'timed_out' : 'failed';
      const reason = r.spawnError ? `could not start Checkov: ${r.spawnError}` : r.timedOut ? `timed out after ${Math.round(cfg.timeoutMs / 1000)}s` : 'cancelled';
      return fail('failed', reason, [record(rd, { ...base, status, reason })]);
    }
    const reportFile = path.join(outDir, 'results_json.json');
    const text = fs.existsSync(reportFile) ? fs.readFileSync(reportFile, 'utf8') : null;
    // --soft-fail: failed checks still exit 0, so a non-zero exit is an error in Checkov itself
    if (r.exitCode !== 0 || text === null) {
      const reason = r.exitCode !== 0 ? `Checkov exited with ${r.exitCode}${r.stderrTail ? `: ${r.stderrTail.trim().split('\n').slice(-2).join(' ')}` : ''}` : 'Checkov wrote no JSON report';
      return { ...fail('failed', reason, [record(rd, { ...base, status: 'failed', reason })]), reports: text ? [{ tool: TOOL, name: 'results.json', content: text }] : [] };
    }
    const reports: KindRunResult['reports'] = [{ tool: TOOL, name: 'results.json', content: text }];
    const parsed = readCheckovReport(text, { root: ctx.root });
    if ('error' in parsed) return { ...fail('failed', parsed.error, [record(rd, { ...base, status: 'failed', reason: parsed.error })]), reports };

    // 3. coverage: every detected framework must have produced a report
    const reported = new Set(parsed.frameworks.map((f) => f.framework));
    const missing = fws.filter((f) => !reported.has(f));
    const checked = parsed.frameworks.filter((f) => f.passed + f.failed + f.skipped > 0);
    const problems: string[] = [];
    if (missing.length) problems.push(`no result for ${missing.map((m) => FRAMEWORK_LABEL[m]).join(', ')} (Checkov skipped ${missing.length > 1 ? 'them' : 'it'}; ${missing.some((m) => m === 'helm' || m === 'kustomize') ? 'helm/kustomize binaries may be missing' : 'see stderr'})`);
    if (parsed.parsingErrors.length) problems.push(`${parsed.parsingErrors.length} file(s) could not be parsed: ${parsed.parsingErrors.slice(0, 5).join(', ')}`);
    if (det.truncated) problems.push('IaC file search was truncated');
    const status = !checked.length ? 'failed' : problems.length ? 'partial' : 'covered';
    const parseErr = new Set(parsed.parsingErrors);
    const missingFiles = new Set(missing.flatMap((m) => det.frameworks[m]!));
    const toolNotes = [...base.notes];
    if (parsed.skipped.length) toolNotes.push(`${parsed.skipped.length} check(s) suppressed (inline checkov:skip or security.iac.skipChecks)`);
    return {
      tools: [record(rd, { ...base, status: checked.length ? 'completed' : 'inconclusive', version: parsed.version ?? rd.version, reason: checked.length ? null : 'Checkov evaluated no checks', observationCount: checked.length ? parsed.observations.length : null, notes: toolNotes })],
      observations: checked.length ? parsed.observations : [],
      coverage: {
        status, reason: status === 'covered' ? null : status === 'failed' ? 'Checkov evaluated no checks on the detected files' : problems.join('; '),
        detail: { files: filesByFw, results: parsed.frameworks.map((f) => `${f.framework}: ${f.failed} failed, ${f.passed} passed, ${f.skipped} suppressed, ${f.parsingErrors} parse error(s), ${f.resources} resource(s)`), frameworkResults: parsed.frameworks, parsingErrors: parsed.parsingErrors, suppressed: parsed.skipped.slice(0, 50), skipChecks: cfg.skipChecks, excluded: cfg.exclude },
      },
      reports, notes,
      // A previously reported file was re-checked when it was part of a framework that produced results and parsed
      // cleanly, or when it no longer exists / is no longer an IaC file.
      inScope: (f) => {
        const file = f.location?.file;
        if (!file || parseErr.has(file) || missingFiles.has(file)) return false;
        return allFiles.has(file) || !fs.existsSync(path.join(ctx.root, file));
      },
    };
  },
};
