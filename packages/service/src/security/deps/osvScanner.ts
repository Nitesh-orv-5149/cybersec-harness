// OSV-Scanner adapter. Matches lockfile packages against the OSV database (api.osv.dev, or a local cache with
// --offline-vulnerabilities). Output: `osv-scanner scan --format json -L <lockfile>` -> { results: [...] }.
// Exit codes (osv-scanner docs): 0 no vulns, 1 vulns found, 127 general error, 128 no packages found.
import path from 'node:path';
import { z } from 'zod';
import type { AdvisoryObservation, DependencyScannerAdapter, ToolOutcome } from '../types.js';
import { mapCvssScore, mapLabel } from './severity.js';
import { genericFailure, idKey, parseJson } from './common.js';
import { nameFromPath } from './lockfile.js';

const Event = z.object({ introduced: z.string().optional(), fixed: z.string().optional(), last_affected: z.string().optional(), limit: z.string().optional() }).passthrough();
const OsvRecord = z.object({
  id: z.string(),
  aliases: z.array(z.string()).nullable().optional(),
  summary: z.string().optional(),
  details: z.string().optional(),
  severity: z.array(z.object({ type: z.string(), score: z.string() }).passthrough()).nullable().optional(),
  affected: z.array(z.object({
    package: z.object({ ecosystem: z.string().optional(), name: z.string().optional(), purl: z.string().optional() }).passthrough().optional(),
    ranges: z.array(z.object({ type: z.string(), events: z.array(Event) }).passthrough()).nullable().optional(),
    versions: z.array(z.string()).nullable().optional(),
  }).passthrough()).nullable().optional(),
  references: z.array(z.object({ type: z.string().optional(), url: z.string() }).passthrough()).nullable().optional(),
  database_specific: z.record(z.unknown()).nullable().optional(),
}).passthrough();

export const OsvScannerReport = z.object({
  results: z.array(z.object({
    source: z.object({ path: z.string(), type: z.string().optional() }).passthrough(),
    packages: z.array(z.object({
      package: z.object({ name: z.string(), version: z.string().optional(), ecosystem: z.string().optional() }).passthrough(),
      vulnerabilities: z.array(OsvRecord).nullable().optional(),
      groups: z.array(z.object({ ids: z.array(z.string()), aliases: z.array(z.string()).nullable().optional(), max_severity: z.string().optional() }).passthrough()).nullable().optional(),
    }).passthrough()).nullable().optional(),
  }).passthrough()).nullable(),
}).passthrough();

function rangeText(events: z.infer<typeof Event>[]): string {
  const parts: string[] = [];
  let open: string | null = null;
  for (const e of events) {
    if (e.introduced !== undefined) open = e.introduced === '0' ? '>=0' : `>=${e.introduced}`;
    if (e.fixed !== undefined) { parts.push(`${open ?? '>=0'} <${e.fixed}`); open = null; }
    if (e.last_affected !== undefined) { parts.push(`${open ?? '>=0'} <=${e.last_affected}`); open = null; }
  }
  if (open) parts.push(open);
  return parts.join(' || ');
}

export function parseOsvScanner(stdout: string, ctx: { lockVersions: Map<string, string>; toolVersion: string | null; sourceFile: string }): ToolOutcome {
  const json = parseJson(stdout);
  if (!json.ok) return { status: 'failed', reason: json.reason, notes: [] };
  const rep = OsvScannerReport.safeParse(json.value);
  if (!rep.success) return { status: 'failed', reason: `unsupported osv-scanner report format: ${rep.error.issues.slice(0, 3).map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`, notes: [] };
  const obs: AdvisoryObservation[] = [];
  let packagesSeen = 0;
  for (const r of rep.data.results ?? []) {
    for (const p of r.packages ?? []) {
      packagesSeen++;
      const name = p.package.name;
      const version = p.package.version ?? null;
      const eco = (p.package.ecosystem ?? 'npm').toLowerCase() === 'npm' ? 'npm' : (p.package.ecosystem ?? 'unknown');
      for (const v of p.vulnerabilities ?? []) {
        const group = (p.groups ?? []).find((g) => g.ids.includes(v.id));
        const ds = (v.database_specific ?? {}) as Record<string, unknown>;
        const dsSeverity = typeof ds.severity === 'string' ? ds.severity : null;
        const groupScore = group?.max_severity ? Number(group.max_severity) : null;
        const severity = dsSeverity ? mapLabel(dsSeverity) : mapCvssScore(groupScore);
        const original = dsSeverity ?? (groupScore !== null && !Number.isNaN(groupScore) ? `CVSS ${groupScore}` : null);
        const aff = (v.affected ?? []).find((a) => a.package?.name === name) ?? null;
        const events = (aff?.ranges ?? []).flatMap((rg) => rg.events);
        const fixed = [...new Set(events.map((e) => e.fixed).filter((x): x is string => !!x))];
        const cvss = (v.severity ?? []).find((s) => /^CVSS_V3/.test(s.type)) ?? null;
        const aliases = [...new Set([v.id, ...(v.aliases ?? []), ...(group?.aliases ?? [])].map(idKey))];
        const nodes = [...ctx.lockVersions.entries()].filter(([pp, ver]) => nameFromPath(pp) === name && (version === null || ver === version)).map(([pp]) => pp);
        obs.push({
          tool: 'osv-scanner', toolVersion: ctx.toolVersion, ecosystem: eco, packageName: name, installedVersion: version,
          advisoryId: idKey(v.id), aliases, toolRef: null,
          title: v.summary ?? null,
          url: (v.references ?? []).find((x) => x.type === 'ADVISORY')?.url ?? `https://osv.dev/vulnerability/${encodeURIComponent(v.id)}`,
          severity, originalSeverity: original,
          cvssScore: groupScore !== null && !Number.isNaN(groupScore) ? groupScore : null, cvssVector: cvss?.score ?? null,
          cwe: Array.isArray(ds.cwe_ids) ? (ds.cwe_ids as unknown[]).map(String) : [],
          affectedRange: events.length ? rangeText(events) : null,
          fixedVersions: aff ? fixed : null,
          remediation: fixed.length ? `Upgrade ${name} to ${fixed.join(' or ')} or later (OSV affected ranges).` : aff ? 'The OSV record lists no fixed version.' : null,
          lockfileNodes: nodes, sourceFile: path.basename(r.source.path) || ctx.sourceFile,
        });
      }
    }
  }
  return { status: 'completed', observations: obs, notes: packagesSeen ? [] : ['osv-scanner returned no package entries.'] };
}

export const osvScannerAdapter: DependencyScannerAdapter = {
  id: 'osv-scanner',
  displayName: 'OSV-Scanner',
  category: 'dependency_vulns',
  outputFormat: 'osv-scanner JSON (results[].packages[].vulnerabilities[] = OSV records)',
  executable: 'osv-scanner',
  networkHosts: (cfg) => (cfg.dependencies.osvOffline ? [] : ['api.osv.dev']),
  supports: (t) => (t.ecosystem === 'npm' && t.lockfile === 'package-lock.json' ? { ok: true } : { ok: false, reason: `this adapter passes only package-lock.json to osv-scanner (found ${t.lockfile})` }),
  versionArgs: ['--version'],
  parseVersion: (s) => s.match(/(\d+\.\d+\.\d+[\w.-]*)/)?.[1] ?? null,
  buildArgs: (t, cfg) => ['scan', '--format', 'json', ...(cfg.dependencies.osvOffline ? ['--offline-vulnerabilities'] : []), '-L', t.lockfile],
  interpret(exec, target, toolVersion, ctx) {
    const fail = genericFailure(exec);
    if (fail) return fail;
    if (exec.exitCode === 128) return { status: 'inconclusive', reason: 'osv-scanner reported that it found no packages in the lockfile (exit 128)', notes: [] };
    if (exec.exitCode !== 0 && exec.exitCode !== 1) {
      return { status: 'failed', reason: `osv-scanner exited with ${exec.exitCode}${exec.exitCode === 127 ? ' (general error)' : ''}: ${exec.stderrTail.trim().split('\n').slice(-1)[0] ?? ''}`.trim(), notes: [] };
    }
    return parseOsvScanner(exec.stdout, { lockVersions: ctx.lockVersions, toolVersion, sourceFile: target.lockfile });
  },
  limitations: [
    'Matches package versions from the lockfile against OSV records; it does not check whether vulnerable code is called.',
    'Online mode sends package names and versions to api.osv.dev; offline mode needs a previously downloaded local database.',
    'This adapter currently passes only the root package-lock.json.',
  ],
};
