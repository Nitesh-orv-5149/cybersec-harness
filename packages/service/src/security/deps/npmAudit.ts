// npm audit adapter. npm sends the dependency tree from package-lock.json to the registry's bulk advisory
// endpoint and reports matches (GitHub Advisory Database). Parsed from `npm audit --json` (auditReportVersion 2).
import { z } from 'zod';
import type { AdvisoryObservation, DependencyScannerAdapter, ExecResult, ToolOutcome } from '../types.js';
import { mapLabel } from './severity.js';
import { genericFailure, normaliseGhsa, parseJson } from './common.js';

const Via = z.object({
  source: z.union([z.number(), z.string()]).optional(),
  name: z.string(),
  dependency: z.string().optional(),
  title: z.string().optional(),
  url: z.string().optional(),
  severity: z.string().optional(),
  cwe: z.array(z.string()).optional(),
  cvss: z.object({ score: z.number().nullable().optional(), vectorString: z.string().nullable().optional() }).partial().optional(),
  range: z.string().optional(),
}).passthrough();

const Vuln = z.object({
  name: z.string(),
  severity: z.string().optional(),
  isDirect: z.boolean().optional(),
  via: z.array(z.union([z.string(), Via])),
  effects: z.array(z.string()).optional(),
  range: z.string().optional(),
  nodes: z.array(z.string()).default([]),
  fixAvailable: z.union([z.boolean(), z.object({ name: z.string(), version: z.string(), isSemVerMajor: z.boolean().optional() }).passthrough()]).optional(),
}).passthrough();

export const NpmAuditReport = z.object({
  auditReportVersion: z.literal(2),
  vulnerabilities: z.record(Vuln),
  metadata: z.object({ vulnerabilities: z.record(z.number()).optional(), dependencies: z.unknown().optional() }).passthrough().optional(),
}).passthrough();

const NpmError = z.object({ error: z.object({ code: z.string().nullable().optional(), summary: z.string().optional(), detail: z.string().optional() }).passthrough() });

function remediationText(fix: z.infer<typeof Vuln>['fixAvailable']): string | null {
  if (fix === undefined) return null;
  if (fix === true) return 'npm audit reports a fix is available within the declared ranges (npm audit fix).';
  if (fix === false) return 'npm audit reports no fix available.';
  return `npm audit suggests upgrading ${fix.name} to ${fix.version}${fix.isSemVerMajor ? ' (semver-major change)' : ''}.`;
}

export function parseNpmAudit(stdout: string, ctx: { lockVersions: Map<string, string>; toolVersion: string | null; sourceFile: string }): ToolOutcome {
  const json = parseJson(stdout);
  if (!json.ok) return { status: 'failed', reason: json.reason, notes: [] };
  const err = NpmError.safeParse(json.value);
  if (err.success) return { status: 'failed', reason: `npm audit error ${err.data.error.code ?? ''}: ${err.data.error.summary ?? 'unknown error'}`.trim(), notes: [] };
  const rep = NpmAuditReport.safeParse(json.value);
  if (!rep.success) return { status: 'failed', reason: `unsupported npm audit report format: ${rep.error.issues.slice(0, 3).map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`, notes: [] };

  const obs: AdvisoryObservation[] = [];
  const seen = new Set<string>();
  for (const v of Object.values(rep.data.vulnerabilities)) {
    for (const via of v.via) {
      if (typeof via === 'string') continue; // transitive "via <package>" entries describe propagation, not a separate advisory
      const ghsa = normaliseGhsa(via.url?.match(/GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/i)?.[0]);
      const advisoryId = ghsa ?? (via.source !== undefined ? `npm-advisory-${via.source}` : `npm:${via.name}:${via.title ?? 'untitled'}`);
      const nodes = v.nodes.length ? v.nodes : [null];
      for (const node of nodes) {
        const installed = node ? ctx.lockVersions.get(node) ?? null : null;
        const key = `${via.name}|${installed}|${advisoryId}`;
        if (seen.has(key)) continue;
        seen.add(key);
        obs.push({
          tool: 'npm-audit', toolVersion: ctx.toolVersion, ecosystem: 'npm', packageName: via.name, installedVersion: installed,
          advisoryId, aliases: ghsa ? [ghsa] : [advisoryId], toolRef: via.source !== undefined ? String(via.source) : null,
          title: via.title ?? null, url: via.url ?? null,
          severity: mapLabel(via.severity), originalSeverity: via.severity ?? null,
          cvssScore: via.cvss?.score ?? null, cvssVector: via.cvss?.vectorString ?? null,
          cwe: via.cwe ?? [], affectedRange: via.range ?? null, fixedVersions: null,
          remediation: remediationText(v.fixAvailable), lockfileNodes: node ? [node] : [], sourceFile: ctx.sourceFile,
        });
      }
    }
  }
  const notes: string[] = [];
  if (obs.some((o) => o.installedVersion === null)) notes.push('Some installed versions could not be resolved from the lockfile.');
  return { status: 'completed', observations: obs, notes };
}

export const npmAuditAdapter: DependencyScannerAdapter = {
  id: 'npm-audit',
  displayName: 'npm audit',
  category: 'dependency_vulns',
  outputFormat: 'npm-audit-json (auditReportVersion 2)',
  executable: 'npm',
  networkHosts: () => ['configured npm registry (default registry.npmjs.org) bulk advisory endpoint'],
  supports: (t) => (t.ecosystem === 'npm' ? { ok: true } : { ok: false, reason: 'npm audit only supports npm lockfiles' }),
  versionArgs: ['--version'],
  parseVersion: (s) => s.trim().split('\n')[0]?.match(/^\d+\.\d+\.\d+\S*$/)?.[0] ?? null,
  buildArgs: (_t, cfg) => ['audit', '--json', '--package-lock-only', ...(cfg.dependencies.includeDev ? [] : ['--omit=dev'])],
  interpret(exec: ExecResult, target, toolVersion, ctx) {
    const fail = genericFailure(exec);
    if (fail) return fail;
    // npm audit exits non-zero when it finds advisories, so the exit code alone means nothing here: the report decides.
    return parseNpmAudit(exec.stdout, { lockVersions: ctx.lockVersions, toolVersion, sourceFile: target.lockfile });
  },
  limitations: [
    'npm ecosystem only; reads package-lock.json / npm-shrinkwrap.json at the project root.',
    'Advisories come from the configured registry (GitHub Advisory Database for registry.npmjs.org). CVE identifiers are not included in its report.',
    'Reports affected ranges per advisory, not exact fixed versions; the fix suggestion is for the top-level package npm would change.',
    'Sends the dependency tree (package names and versions) to the registry.',
  ],
};
