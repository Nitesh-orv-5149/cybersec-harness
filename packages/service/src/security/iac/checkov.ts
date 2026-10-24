// Checkov adapter: arguments, offline environment and the JSON report reader.
// Checkov prints one report object per framework (a list when there are several, a bare object when there
// is one, and a summary-only object when it found nothing to check). All three shapes are handled.
import { redact } from '../../util.js';
import type { AppSeverity } from '../types.js';
import type { ScanObservation } from '../scan/types.js';
import type { IacFramework } from './detect.js';

export function parseCheckovVersion(s: string): string | null {
  return s.trim().match(/^(\d+\.\d+\.\d+)/m)?.[1] ?? null;
}

/** Switches that keep Checkov offline: no mapping/guideline download from Prisma Cloud, no PyPI update check. */
export const CHECKOV_OFFLINE_ENV: Record<string, string> = { BC_SKIP_MAPPING: 'TRUE', CKV_SKIP_PACKAGE_UPDATE_CHECK: 'TRUE' };

export function checkovArgs(o: { outDir: string; frameworks: IacFramework[]; exclude: string[]; skipChecks: string[] }): string[] {
  const args = ['--directory', '.', '--output', 'json', '--output-file-path', o.outDir, '--soft-fail', '--skip-download', '--framework', o.frameworks.join(',')];
  for (const d of o.exclude) args.push('--skip-path', `(^|/)${d.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(/|$)`);
  if (o.skipChecks.length) args.push('--skip-check', o.skipChecks.join(','));
  return args;
}

const SEV: Record<string, AppSeverity> = { CRITICAL: 'high', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', INFO: 'info' };

interface CheckovCheck {
  check_id: string; bc_check_id?: string | null; check_name?: string; check_result?: { result?: string; evaluated_keys?: string[] };
  code_block?: [number, string][] | null; file_path?: string; repo_file_path?: string; file_line_range?: [number, number];
  resource?: string; resource_address?: string | null; severity?: string | null; guideline?: string | null; check_class?: string;
  benchmarks?: Record<string, unknown> | null; details?: string[];
}
interface CheckovReport {
  check_type: string;
  results: { passed_checks?: CheckovCheck[]; failed_checks?: CheckovCheck[]; skipped_checks?: CheckovCheck[]; parsing_errors?: string[] };
  summary: { passed: number; failed: number; skipped: number; parsing_errors: number; resource_count: number; checkov_version: string };
}

export interface FrameworkSummary { framework: string; passed: number; failed: number; skipped: number; parsingErrors: number; resources: number }

export interface CheckovResult {
  version: string | null;
  frameworks: FrameworkSummary[];
  parsingErrors: string[];        // project-relative files Checkov could not parse
  skipped: { checkId: string; file: string; reason: string | null }[];
  observations: ScanObservation[];
}

const relFile = (p: string | undefined) => (p ?? '').replace(/\\/g, '/').replace(/^\/+/, '');

export function readCheckovReport(text: string, opts: { root: string }): CheckovResult | { error: string } {
  let data: unknown;
  try { data = JSON.parse(text); } catch (e) { return { error: `Checkov report is not valid JSON: ${(e as Error).message}` }; }
  const list: unknown[] = Array.isArray(data) ? data : [data];
  const result: CheckovResult = { version: null, frameworks: [], parsingErrors: [], skipped: [], observations: [] };
  const rootPrefix = opts.root.replace(/\\/g, '/').replace(/\/+$/, '') + '/';
  const toRel = (p: string) => { const s = p.replace(/\\/g, '/'); return s.startsWith(rootPrefix) ? s.slice(rootPrefix.length) : relFile(s); };

  for (const item of list) {
    if (!item || typeof item !== 'object') return { error: 'Checkov report has an entry that is not an object' };
    const o = item as Partial<CheckovReport> & Record<string, unknown>;
    if (!('check_type' in o)) {
      // summary-only shape: Checkov found nothing to check
      if (typeof o.checkov_version === 'string') { result.version ??= o.checkov_version; continue; }
      return { error: 'Checkov report entry has neither check_type nor a summary' };
    }
    const rep = o as CheckovReport;
    if (!rep.results || !rep.summary) return { error: `Checkov report for ${rep.check_type} has no results/summary` };
    result.version ??= rep.summary.checkov_version ?? null;
    result.frameworks.push({ framework: rep.check_type, passed: rep.summary.passed, failed: rep.summary.failed, skipped: rep.summary.skipped, parsingErrors: rep.summary.parsing_errors, resources: rep.summary.resource_count });
    for (const pe of rep.results.parsing_errors ?? []) result.parsingErrors.push(toRel(pe));
    for (const s of rep.results.skipped_checks ?? []) result.skipped.push({ checkId: s.check_id, file: relFile(s.repo_file_path ?? s.file_path), reason: (s.check_result as { suppress_comment?: string } | undefined)?.suppress_comment ?? null });
    for (const c of rep.results.failed_checks ?? []) {
      const file = relFile(c.repo_file_path ?? c.file_path);
      const [start, end] = c.file_line_range ?? [1, 1];
      const line = Math.max(1, start || 1);
      const resource = c.resource_address ?? c.resource ?? null;
      const original = c.severity ?? null;
      const code = Array.isArray(c.code_block) ? c.code_block.slice(0, 15).map(([n, t]) => `${n}: ${redact(String(t)).replace(/\n$/, '')}`).join('\n') : null;
      result.observations.push({
        tool: 'checkov', toolVersion: rep.summary.checkov_version ?? null,
        ruleId: c.check_id, ruleName: c.check_name ?? null,
        title: `${c.check_name ?? c.check_id}${resource ? ` (${resource})` : ''}`,
        message: c.check_name ? `${c.check_id}: ${c.check_name}` : null,
        // Without a Prisma Cloud key Checkov reports no severity; it stays "unknown" rather than being guessed.
        severity: original ? (SEV[original.toUpperCase()] ?? 'unknown') : 'unknown', originalSeverity: original,
        confidence: null, cwe: [], references: c.guideline ? [c.guideline] : [],
        location: { file, line, endLine: Math.max(line, end || line), ...(resource ? { resource } : {}) },
        evidence: {
          framework: rep.check_type, checkId: c.check_id, bcCheckId: c.bc_check_id ?? null, resource,
          evaluatedKeys: c.check_result?.evaluated_keys ?? [], lines: `${line}-${Math.max(line, end || line)}`, code,
          checkClass: c.check_class ?? null, details: c.details ?? [],
        },
        dedupeKey: `iac|${file}|${resource ?? line}|${c.check_id}`,
        ids: [`checkov:${c.check_id}`, ...(c.bc_check_id ? [`bc:${c.bc_check_id}`] : [])],
      });
    }
  }
  return result;
}
