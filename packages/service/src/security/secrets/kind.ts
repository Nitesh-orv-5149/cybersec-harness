// Secrets detection kind: Gitleaks over the project files (workspace mode) or the project's git history
// (history mode). Read-only: nothing is sent anywhere and no application is started. Gitleaks runs with
// --redact; the raw report is deleted after reading and only a sanitised copy is kept.
import fs from 'node:fs';
import path from 'node:path';
import type { Readiness, ToolRunRecord } from '../types.js';
import { probeBinary } from '../readiness.js';
import type { KindRunResult, ScanKind } from '../scan/types.js';
import {
  LEAKS_EXIT_CODE, gitleaksArgs, gitleaksConfig, parseGitleaksVersion, readGitleaksReport, sanitizeGitleaksReport, scannedBytes, supportsDirCommand,
} from './gitleaks.js';

const TOOL = 'gitleaks';
const LIMITATIONS = [
  'Pattern and entropy rules: a match can be a test fixture, an example value or an already revoked key. Gitleaks cannot tell, and it assigns no severity (the workbench shows every match as high).',
  'Secrets that match no rule (custom formats, split strings, values built at runtime) are not found.',
  'Workspace mode reads the files as they are now. A secret removed from the files but still in an old commit is only found in history mode.',
  'Gitleaks\' default allowlist skips node_modules, lockfiles and binary assets; security.secrets.exclude adds more directories.',
];

function record(rd: Readiness | undefined, patch: Partial<ToolRunRecord>): ToolRunRecord {
  return {
    tool: TOOL, displayName: 'Gitleaks', version: rd?.version ?? null, readiness: rd?.state ?? 'not_installed', selected: false, status: 'skipped',
    reason: null, exitCode: null, durationMs: null, observationCount: null, stderrTail: null, reportRef: null, reportSha256: null, notes: [],
    limitations: LIMITATIONS, networkHosts: [], ...patch,
  };
}

export const secretsKind: ScanKind = {
  id: 'secrets', category: 'secrets', label: 'Secrets detection', findingSource: 'secrets',
  description: 'Gitleaks looks for credentials, tokens and private keys in the project files (workspace) or in every commit (history).',
  dynamic: false, modes: ['workspace', 'history'], activeModes: [],
  tools: [{
    id: TOOL, displayName: 'Gitleaks', networkHosts: [], limitations: LIMITATIONS,
    readiness: async ({ cfg, exec, which, root }) => {
      const r = await probeBinary({ tool: TOOL, names: ['gitleaks'], explicit: cfg.security.secrets.binary, versionArgs: ['version'], parseVersion: parseGitleaksVersion, exec, which, cwd: root });
      if (r.state === 'ready' && !supportsDirCommand(r.version!)) return { ...r, state: 'not_functional', reason: `Gitleaks ${r.version} found; this integration needs 8.19 or newer (the 'dir' and 'git' commands)` };
      return r;
    },
  }],
  enabled: (cfg) => cfg.security.secrets.enabled,
  preconditions: () => [],

  async run(ctx): Promise<KindRunResult> {
    const cfg = ctx.cfg.security.secrets;
    const mode = ctx.options.mode === 'history' ? 'history' : 'workspace';
    const rd = ctx.readiness.find((x) => x.tool === TOOL);
    const notes: string[] = [];
    const fail = (status: KindRunResult['coverage']['status'], reason: string, tools: ToolRunRecord[], detail: Record<string, unknown> = {}): KindRunResult =>
      ({ tools, observations: [], coverage: { status, reason, detail: { mode, ...detail } }, reports: [], notes, inScope: () => false });

    if (!rd || rd.state !== 'ready') return fail('unavailable', `Gitleaks is not usable: ${rd?.reason ?? 'readiness not checked'}`, [record(rd, { status: 'unavailable', reason: rd?.reason ?? null })]);
    if (mode === 'history' && !fs.existsSync(path.join(ctx.root, '.git'))) {
      return fail('not_run', 'history mode needs the project folder to be the top of a git repository (no .git here)', [record(rd, { status: 'skipped', reason: 'not a git repository root' })]);
    }

    const conf = gitleaksConfig(ctx.root, mode === 'workspace' ? cfg.exclude : []);
    const configPath = path.join(ctx.runDir, 'gitleaks.toml');
    fs.writeFileSync(configPath, conf.toml);
    const rawReport = path.join(ctx.runDir, '.gitleaks-raw.json');
    const args = gitleaksArgs({ mode, configPath, reportPath: rawReport, maxTargetMegabytes: cfg.maxTargetMegabytes });
    ctx.onTool(TOOL, 'running');
    let r;
    try { r = await ctx.exec(rd.binary!, args, { cwd: ctx.root, timeoutMs: cfg.timeoutMs, maxOutputBytes: 1024 * 1024, signal: ctx.signal, discardStdout: true }); }
    finally { ctx.onTool(TOOL, 'done'); }

    const rawText = fs.existsSync(rawReport) ? fs.readFileSync(rawReport, 'utf8') : null;
    if (rawText !== null) fs.rmSync(rawReport, { force: true });
    const stderr = r.stderrTail ?? '';
    const base = { selected: true, exitCode: r.exitCode, durationMs: r.durationMs, stderrTail: stderr ? stderr.slice(-2000) : null, notes: [`command: gitleaks ${args.map((a) => (a === configPath ? '<run>/gitleaks.toml' : a === rawReport ? '<run>/report.json' : a)).join(' ')}`] };
    const detail = { config: conf.base, excluded: mode === 'workspace' ? cfg.exclude : [], maxTargetMegabytes: cfg.maxTargetMegabytes };
    const reports: KindRunResult['reports'] = [{ tool: TOOL, name: 'config.toml', content: conf.toml }];

    if (r.spawnError || r.timedOut || r.cancelled) {
      const status = r.cancelled ? 'cancelled' : r.timedOut ? 'timed_out' : 'failed';
      const reason = r.spawnError ? `could not start Gitleaks: ${r.spawnError}` : r.timedOut ? `timed out after ${Math.round(cfg.timeoutMs / 1000)}s` : 'cancelled';
      return { ...fail('failed', reason, [record(rd, { ...base, status, reason })], detail), reports };
    }
    if (r.exitCode !== 0 && r.exitCode !== LEAKS_EXIT_CODE) {
      const reason = `Gitleaks exited with ${r.exitCode}${stderr ? `: ${stderr.trim().split('\n').slice(-2).join(' ')}` : ''}`;
      return { ...fail('failed', reason, [record(rd, { ...base, status: 'failed', reason })], detail), reports };
    }
    if (rawText === null) {
      return { ...fail('failed', `Gitleaks exited with ${r.exitCode} but wrote no report`, [record(rd, { ...base, status: 'failed', reason: 'missing report' })], detail), reports };
    }
    const parsed = readGitleaksReport(rawText, { toolVersion: rd.version, mode });
    reports.unshift({ tool: TOOL, name: 'report.json', content: sanitizeGitleaksReport(rawText) });
    if ('error' in parsed) return { ...fail('failed', parsed.error, [record(rd, { ...base, status: 'failed', reason: parsed.error })], detail), reports };
    // Exit code and report must agree; if they do not, the result is not trusted.
    if ((r.exitCode === LEAKS_EXIT_CODE) !== (parsed.observations.length > 0)) {
      const reason = `exit code ${r.exitCode} does not match the report (${parsed.observations.length} finding(s))`;
      return { ...fail('failed', reason, [record(rd, { ...base, status: 'inconclusive', reason })], detail), reports };
    }
    const toolNotes = [...base.notes];
    if (parsed.unredacted) toolNotes.push(`${parsed.unredacted} finding(s) came back without redaction; their values were withheld and not stored`);
    const bytes = scannedBytes(stderr);
    return {
      tools: [record(rd, { ...base, status: 'completed', observationCount: parsed.observations.length, notes: toolNotes })],
      observations: parsed.observations,
      coverage: { status: 'covered', reason: null, detail: { mode, ...detail, bytesScanned: bytes } },
      reports, notes,
      // workspace runs re-check working-tree findings only; history runs re-check commit findings only
      inScope: (f) => (mode === 'history' ? !!f.location?.commit : !f.location?.commit),
    };
  },
};
