// Dependency-scan orchestration: detect which tools are really usable, pick tools per target according to
// the configured policy, run them independently, and report coverage truthfully.
import type {
  AdvisoryObservation, ApiRunResult, CoverageRecord, ExecResult, ToolOutcome, DependencyScannerAdapter, DependencyTarget, Exec, Readiness, SecurityConfig, ToolId, ToolRunRecord, Which,
} from '../types.js';
import { npmAuditAdapter } from './npmAudit.js';
import { osvScannerAdapter } from './osvScanner.js';
import { osvApiAdapter, probeOsvApi } from './osvApi.js';
import { trivyAdapter } from './trivy.js';

export const DEPENDENCY_ADAPTERS: Record<ToolId, DependencyScannerAdapter> = {
  'osv-api': osvApiAdapter,
  'osv-scanner': osvScannerAdapter,
  'npm-audit': npmAuditAdapter,
  trivy: trivyAdapter,
};
export const ALL_TOOLS: ToolId[] = ['osv-api', 'npm-audit', 'osv-scanner', 'trivy'];
const BINARY_KEY: Record<ToolId, 'osv-scanner' | 'npm' | 'trivy' | null> = { 'osv-api': null, 'osv-scanner': 'osv-scanner', 'npm-audit': 'npm', trivy: 'trivy' };

export async function checkReadiness(cfg: SecurityConfig, exec: Exec, which: Which, cwd: string, tools: ToolId[] = ALL_TOOLS, fetchFn: typeof fetch = globalThis.fetch): Promise<Readiness[]> {
  return Promise.all(tools.map(async (tool): Promise<Readiness> => {
    const a = DEPENDENCY_ADAPTERS[tool];
    const base = { tool, version: null, binary: null, checkedAt: new Date().toISOString() };
    if (!cfg.dependencies.enabled) return { ...base, state: 'disabled', reason: 'security.dependencies.enabled is false' };
    if (!cfg.dependencies.order.includes(tool)) return { ...base, state: 'disabled', reason: 'not listed in security.dependencies.order' };
    if (a.kind === 'api') {
      if (!cfg.allowNetwork) return { ...base, state: 'needs_network', reason: `contacts ${a.networkHosts(cfg).join(', ')}; security.allowNetwork is false` };
      const p = await probeOsvApi(fetchFn);
      return p.ok ? { ...base, version: a.parseVersion(''), state: 'ready', reason: null } : { ...base, state: 'unreachable', reason: p.reason };
    }
    const keyName = BINARY_KEY[tool];
    const explicit = keyName ? cfg.dependencies.binaries[keyName] : undefined;
    const binary = which(a.executable, explicit);
    if (!binary) {
      return { ...base, state: 'not_installed', reason: explicit ? `configured path ${explicit} is not an executable file` : `'${a.executable}' was not found on PATH` };
    }
    const r = await exec(binary, a.versionArgs, { cwd, timeoutMs: 15_000, maxOutputBytes: 64 * 1024 });
    const version = r.exitCode === 0 ? a.parseVersion(r.stdout) : null;
    if (r.spawnError || r.timedOut || r.exitCode !== 0 || !version) {
      const why = r.spawnError ?? (r.timedOut ? 'version check timed out' : r.exitCode !== 0 ? `version check exited with ${r.exitCode}` : 'unrecognised version output');
      return { ...base, binary, state: 'not_functional', reason: why };
    }
    const hosts = a.networkHosts(cfg);
    if (hosts.length && !cfg.allowNetwork) {
      return { ...base, binary, version, state: 'needs_network', reason: `contacts ${hosts.join(', ')}; security.allowNetwork is false` };
    }
    return { ...base, binary, version, state: 'ready', reason: null };
  }));
}

export interface OrchestratorDeps {
  exec: Exec;
  /** lockfile path -> version map for the target, used by adapters to resolve installed versions */
  lockVersions: (t: DependencyTarget) => Map<string, string>;
  /** packages from the parsed lockfile (null when it could not be parsed locally); needed by API adapters */
  lockPackages?: (t: DependencyTarget) => { name: string; version: string | null; dev: boolean }[] | null;
  fetch?: typeof fetch;
  signal?: AbortSignal;
  onTool?: (tool: ToolId, phase: 'running' | 'done') => void;
}

export interface DependencyScanResult {
  tools: ToolRunRecord[];
  coverage: CoverageRecord[];
  observations: AdvisoryObservation[];
  reports: { tool: ToolId; target: string; stdout: string }[];
}

function record(a: DependencyScannerAdapter, rd: Readiness | undefined, cfg: SecurityConfig, patch: Partial<ToolRunRecord>): ToolRunRecord {
  return {
    tool: a.id, displayName: a.displayName, version: rd?.version ?? null, readiness: rd?.state ?? 'not_installed', selected: false,
    status: 'skipped', reason: null, exitCode: null, durationMs: null, observationCount: null, stderrTail: null, reportRef: null, reportSha256: null,
    notes: [], limitations: a.limitations, networkHosts: a.networkHosts(cfg), ...patch,
  };
}

export async function runDependencyScan(
  cfg: SecurityConfig, targets: DependencyTarget[], unsupported: { file: string; ecosystem: string; reason: string }[],
  readiness: Readiness[], deps: OrchestratorDeps,
): Promise<DependencyScanResult> {
  const tools: ToolRunRecord[] = [];
  const coverage: CoverageRecord[] = [];
  const observations: AdvisoryObservation[] = [];
  const reports: DependencyScanResult['reports'] = [];
  const rdOf = (t: ToolId) => readiness.find((r) => r.tool === t);

  for (const target of targets) {
    const candidates = cfg.dependencies.order.map((id) => DEPENDENCY_ADAPTERS[id]);
    const ran: { tool: ToolId; status: ToolRunRecord['status'] }[] = [];
    let haveCompleted = false;
    for (const a of candidates) {
      const rd = rdOf(a.id);
      const sup = a.supports(target);
      if (!sup.ok) { tools.push(record(a, rd, cfg, { status: 'skipped', reason: sup.reason })); continue; }
      if (!rd || rd.state !== 'ready') { tools.push(record(a, rd, cfg, { status: 'unavailable', reason: rd?.reason ?? 'readiness not checked' })); continue; }
      if (cfg.dependencies.mode === 'first-available' && haveCompleted) {
        tools.push(record(a, rd, cfg, { status: 'skipped', reason: `not needed: ${ran.find((r) => r.status === 'completed')?.tool} already covered ${target.lockfile} (mode first-available)` }));
        continue;
      }
      if (cfg.dependencies.mode === 'first-available' && ran.length && !cfg.dependencies.fallbackOnFailure) {
        tools.push(record(a, rd, cfg, { status: 'skipped', reason: 'previous tool failed and fallbackOnFailure is false' }));
        continue;
      }
      if (deps.signal?.aborted) { tools.push(record(a, rd, cfg, { status: 'cancelled', reason: 'scan cancelled' })); continue; }
      deps.onTool?.(a.id, 'running');
      let exec: ExecResult;
      let outcome: ToolOutcome;
      if (a.kind === 'api') {
        const pk = deps.lockPackages?.(target) ?? null;
        const r: ApiRunResult = pk
          ? await a.runApi!(target, { fetch: deps.fetch ?? globalThis.fetch, packages: cfg.dependencies.includeDev ? pk : pk.filter((p) => !p.dev), lockVersions: deps.lockVersions(target), signal: deps.signal, timeoutMs: cfg.dependencies.timeoutMs })
          : { outcome: { status: 'failed', reason: `${target.lockfile} could not be parsed locally, so there are no package versions to send`, notes: [] } as ToolOutcome, raw: '', durationMs: 0, timedOut: false, cancelled: false };
        outcome = r.outcome;
        exec = { exitCode: null, signal: null, stdout: r.raw, stdoutBytes: r.raw.length, stdoutTruncated: false, stderrTail: '', timedOut: r.timedOut, cancelled: r.cancelled, spawnError: null, durationMs: r.durationMs };
      } else {
        exec = await deps.exec(rd.binary!, a.buildArgs(target, cfg), {
          cwd: target.root, timeoutMs: cfg.dependencies.timeoutMs, maxOutputBytes: cfg.dependencies.maxOutputBytes, signal: deps.signal,
        });
        outcome = a.interpret(exec, target, rd.version, { lockVersions: deps.lockVersions(target) });
      }
      deps.onTool?.(a.id, 'done');
      const status: ToolRunRecord['status'] = exec.cancelled ? 'cancelled' : exec.timedOut ? 'timed_out' : outcome.status;
      const fallbackNote = ran.length ? [`fallback after ${ran.map((r) => `${r.tool} ${r.status}`).join(', ')}`] : [];
      tools.push(record(a, rd, cfg, {
        selected: true, status, exitCode: exec.exitCode, durationMs: exec.durationMs,
        reason: outcome.status === 'completed' ? null : outcome.reason,
        observationCount: outcome.status === 'completed' ? outcome.observations.length : null,
        stderrTail: exec.stderrTail ? exec.stderrTail.slice(-2000) : null,
        notes: [...fallbackNote, ...outcome.notes],
      }));
      if (exec.stdout && !exec.stdoutTruncated) reports.push({ tool: a.id, target: target.lockfile, stdout: exec.stdout });
      ran.push({ tool: a.id, status });
      if (outcome.status === 'completed') { haveCompleted = true; observations.push(...outcome.observations); }
    }
    const completed = ran.filter((r) => r.status === 'completed').map((r) => r.tool);
    const failedSelected = ran.filter((r) => r.status !== 'completed');
    coverage.push({
      category: 'dependency_vulns', ecosystem: target.ecosystem, lockfile: target.lockfile,
      status: completed.length ? (failedSelected.length && cfg.dependencies.mode === 'all-available' ? 'partial' : 'covered') : ran.length ? 'failed' : 'unavailable',
      by: completed,
      reason: completed.length
        ? (failedSelected.length ? `${failedSelected.map((r) => `${r.tool} ${r.status}`).join(', ')}` : null)
        : ran.length
          ? `every selected tool failed: ${failedSelected.map((r) => `${r.tool} ${r.status}`).join(', ')}`
          : `no usable scanner: ${candidates.map((a) => `${a.id} ${rdOf(a.id)?.state ?? 'unknown'}`).join(', ')}`,
    });
  }
  for (const u of unsupported) {
    coverage.push({ category: 'dependency_vulns', ecosystem: u.ecosystem, lockfile: u.file, status: 'unavailable', by: [], reason: u.reason });
  }
  if (!targets.length && !unsupported.length) {
    coverage.push({ category: 'dependency_vulns', ecosystem: 'none', lockfile: '-', status: 'not_run', by: [], reason: 'no supported dependency manifest found at the project root' });
  }
  return { tools, coverage, observations, reports };
}
