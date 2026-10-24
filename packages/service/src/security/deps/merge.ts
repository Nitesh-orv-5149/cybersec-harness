// Cross-tool deduplication. Observations describe the same finding only when they concern the same
// ecosystem + package + installed version AND share at least one advisory identifier the tools themselves
// supplied (primary id or alias). Nothing is merged on title similarity or inferred CVE<->GHSA mappings.
import type { AdvisoryObservation, AppSeverity, ToolId } from '../types.js';
import { maxSeverity } from './severity.js';

export interface MergedAdvisory {
  ecosystem: string;
  packageName: string;
  installedVersion: string | null;
  canonicalId: string;
  ids: string[];
  tools: ToolId[];
  observations: AdvisoryObservation[];
  severity: AppSeverity;                         // highest severity any tool reported
  severityByTool: { tool: ToolId; severity: AppSeverity; original: string | null }[];
  title: string | null;
  url: string | null;
  cwe: string[];
  affectedRanges: { tool: ToolId; range: string }[];
  fixedVersions: string[] | null;                // null = no tool supplied fixed versions
  remediation: { tool: ToolId; text: string }[];
  lockfileNodes: string[];
  cvssScore: number | null;
}

const rank = (id: string) => (id.startsWith('GHSA-') ? 0 : id.startsWith('CVE-') ? 1 : 2);
export function canonicalOf(ids: string[]): string {
  return [...ids].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b))[0];
}

export function mergeObservations(all: AdvisoryObservation[]): MergedAdvisory[] {
  const byPkg = new Map<string, AdvisoryObservation[]>();
  for (const o of all) {
    const k = `${o.ecosystem}|${o.packageName}|${o.installedVersion ?? '?'}`;
    (byPkg.get(k) ?? byPkg.set(k, []).get(k)!).push(o);
  }
  const out: MergedAdvisory[] = [];
  for (const group of byPkg.values()) {
    // union-find over shared identifiers
    const parent = group.map((_, i) => i);
    const find = (i: number): number => (parent[i] === i ? i : (parent[i] = find(parent[i])));
    const owner = new Map<string, number>();
    group.forEach((o, i) => {
      for (const id of new Set([o.advisoryId, ...o.aliases])) {
        const j = owner.get(id);
        if (j === undefined) owner.set(id, i);
        else parent[find(i)] = find(j);
      }
    });
    const clusters = new Map<number, AdvisoryObservation[]>();
    group.forEach((o, i) => { const r = find(i); (clusters.get(r) ?? clusters.set(r, []).get(r)!).push(o); });
    for (const obs of clusters.values()) {
      const ids = [...new Set(obs.flatMap((o) => [o.advisoryId, ...o.aliases]))].sort();
      const first = obs.find((o) => o.advisoryId.startsWith('GHSA-')) ?? obs[0];
      const fixedLists = obs.map((o) => o.fixedVersions).filter((f): f is string[] => f !== null);
      out.push({
        ecosystem: first.ecosystem, packageName: first.packageName, installedVersion: first.installedVersion,
        canonicalId: canonicalOf(ids), ids,
        tools: [...new Set(obs.map((o) => o.tool))].sort(),
        observations: obs,
        severity: obs.map((o) => o.severity).reduce(maxSeverity),
        severityByTool: obs.map((o) => ({ tool: o.tool, severity: o.severity, original: o.originalSeverity })),
        title: first.title ?? obs.find((o) => o.title)?.title ?? null,
        url: first.url ?? obs.find((o) => o.url)?.url ?? null,
        cwe: [...new Set(obs.flatMap((o) => o.cwe))].sort(),
        affectedRanges: obs.filter((o) => o.affectedRange).map((o) => ({ tool: o.tool, range: o.affectedRange! })),
        fixedVersions: fixedLists.length ? [...new Set(fixedLists.flat())] : null,
        remediation: obs.filter((o) => o.remediation).map((o) => ({ tool: o.tool, text: o.remediation! })),
        lockfileNodes: [...new Set(obs.flatMap((o) => o.lockfileNodes))].sort(),
        cvssScore: obs.map((o) => o.cvssScore).filter((s): s is number => s !== null).sort((a, b) => b - a)[0] ?? null,
      });
    }
  }
  return out.sort((a, b) => a.packageName.localeCompare(b.packageName) || a.canonicalId.localeCompare(b.canonicalId));
}
