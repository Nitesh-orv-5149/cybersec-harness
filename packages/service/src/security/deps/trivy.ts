// Trivy adapter (filesystem mode, vulnerability scanner only). Trivy downloads its vulnerability DB from
// mirror.gcr.io / ghcr.io unless run with a cached DB (--skip-db-update --offline-scan).
// Output: `trivy fs --scanners vuln --format json` -> { SchemaVersion: 2, Results: [{ Target, Vulnerabilities }] }.
import { z } from 'zod';
import type { AdvisoryObservation, DependencyScannerAdapter, ToolOutcome } from '../types.js';
import { mapLabel } from './severity.js';
import { genericFailure, idKey, parseJson } from './common.js';
import { nameFromPath } from './lockfile.js';

const TrivyVuln = z.object({
  VulnerabilityID: z.string(),
  PkgName: z.string(),
  InstalledVersion: z.string().optional(),
  FixedVersion: z.string().optional(),
  Status: z.string().optional(),
  Severity: z.string().optional(),
  Title: z.string().optional(),
  PrimaryURL: z.string().optional(),
  CweIDs: z.array(z.string()).nullable().optional(),
  CVSS: z.record(z.object({ V3Score: z.number().optional(), V3Vector: z.string().optional() }).passthrough()).nullable().optional(),
}).passthrough();

export const TrivyReport = z.object({
  SchemaVersion: z.literal(2),
  Results: z.array(z.object({
    Target: z.string(),
    Class: z.string().optional(),
    Type: z.string().optional(),
    Vulnerabilities: z.array(TrivyVuln).nullable().optional(),
  }).passthrough()).nullable().optional(),
}).passthrough();

export function parseTrivy(stdout: string, ctx: { lockVersions: Map<string, string>; toolVersion: string | null; sourceFile: string }): ToolOutcome {
  const json = parseJson(stdout);
  if (!json.ok) return { status: 'failed', reason: json.reason, notes: [] };
  const rep = TrivyReport.safeParse(json.value);
  if (!rep.success) return { status: 'failed', reason: `unsupported Trivy report format: ${rep.error.issues.slice(0, 3).map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`, notes: [] };
  const results = rep.data.Results ?? [];
  // Trivy reports targets relative to the scanned directory ('.'), so only an exact match is this lockfile.
  const mine = results.filter((r) => r.Target === ctx.sourceFile || r.Target === `./${ctx.sourceFile}`);
  const notes: string[] = [];
  const others = results.filter((r) => !mine.includes(r)).map((r) => r.Target);
  if (others.length) notes.push(`Trivy also reported targets outside this run's scope (not ingested): ${others.slice(0, 5).join(', ')}`);
  if (!mine.length) {
    return { status: 'inconclusive', reason: `Trivy's report has no result entry for ${ctx.sourceFile}, so there is no evidence the lockfile was analysed; not treated as zero vulnerabilities.`, notes };
  }
  const obs: AdvisoryObservation[] = [];
  for (const r of mine) {
    for (const v of r.Vulnerabilities ?? []) {
      const fixed = v.FixedVersion ? v.FixedVersion.split(',').map((s) => s.trim()).filter(Boolean) : [];
      const cvss = v.CVSS ? (v.CVSS.ghsa ?? v.CVSS.nvd ?? Object.values(v.CVSS)[0]) : undefined;
      const nodes = [...ctx.lockVersions.entries()].filter(([pp, ver]) => nameFromPath(pp) === v.PkgName && (!v.InstalledVersion || ver === v.InstalledVersion)).map(([pp]) => pp);
      obs.push({
        tool: 'trivy', toolVersion: ctx.toolVersion, ecosystem: 'npm', packageName: v.PkgName, installedVersion: v.InstalledVersion ?? null,
        advisoryId: idKey(v.VulnerabilityID), aliases: [idKey(v.VulnerabilityID)], toolRef: null,
        title: v.Title ?? null, url: v.PrimaryURL ?? null,
        severity: mapLabel(v.Severity), originalSeverity: v.Severity ?? null,
        cvssScore: cvss?.V3Score ?? null, cvssVector: cvss?.V3Vector ?? null,
        cwe: v.CweIDs ?? [], affectedRange: null, fixedVersions: v.FixedVersion !== undefined ? fixed : null,
        remediation: fixed.length ? `Upgrade ${v.PkgName} to ${fixed.join(' or ')} (Trivy FixedVersion).` : v.Status ? `Trivy status: ${v.Status}; no fixed version listed.` : null,
        lockfileNodes: nodes, sourceFile: r.Target,
      });
    }
  }
  return { status: 'completed', observations: obs, notes };
}

export const trivyAdapter: DependencyScannerAdapter = {
  id: 'trivy',
  displayName: 'Trivy',
  category: 'dependency_vulns',
  outputFormat: 'trivy JSON (SchemaVersion 2)',
  executable: 'trivy',
  networkHosts: (cfg) => (cfg.dependencies.trivyOffline ? [] : ['mirror.gcr.io', 'ghcr.io (vulnerability DB download)']),
  supports: (t) => (t.ecosystem === 'npm' && t.lockfile === 'package-lock.json' ? { ok: true } : { ok: false, reason: `this adapter ingests only package-lock.json results from Trivy (found ${t.lockfile})` }),
  versionArgs: ['--version'],
  parseVersion: (s) => s.match(/Version:\s*v?(\d+\.\d+\.\d+[\w.-]*)/i)?.[1] ?? s.match(/(\d+\.\d+\.\d+[\w.-]*)/)?.[1] ?? null,
  buildArgs: (_t, cfg) => [
    'fs', '--scanners', 'vuln', '--format', 'json', '--quiet', '--exit-code', '0',
    '--timeout', `${Math.max(30, Math.floor(cfg.dependencies.timeoutMs / 1000) - 5)}s`,
    '--skip-dirs', 'node_modules',
    ...(cfg.dependencies.trivyOffline ? ['--skip-db-update', '--offline-scan'] : []),
    '.',
  ],
  interpret(exec, target, toolVersion, ctx) {
    const fail = genericFailure(exec);
    if (fail) return fail;
    // --exit-code 0 is passed, so any non-zero exit is an execution failure rather than "vulnerabilities found".
    if (exec.exitCode !== 0) return { status: 'failed', reason: `trivy exited with ${exec.exitCode}: ${exec.stderrTail.trim().split('\n').slice(-1)[0] ?? ''}`.trim(), notes: [] };
    return parseTrivy(exec.stdout, { lockVersions: ctx.lockVersions, toolVersion, sourceFile: target.lockfile });
  },
  limitations: [
    'Matches lockfile package versions against the Trivy vulnerability DB; it does not check whether vulnerable code is called.',
    'Online mode downloads the vulnerability DB; offline mode relies on a previously cached DB whose age is not verified here.',
    'This adapter ingests only the root package-lock.json result.',
  ],
};
