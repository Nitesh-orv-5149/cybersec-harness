// Evidence that an installed package is actually used by the analysed application, derived from the
// existing analyzer facts (imports/requires and resolved call sites) and the existing code graph.
// It never claims the vulnerable function inside a package is called: npm advisories do not identify
// affected symbols in a machine-readable way, so the strongest statement made is "code calls into the package".
import type { FileFacts, Graph } from '../../analyzer/types.js';
import { GraphIndex } from '../../analyzer/query.js';
import { chainsTo, type LockModel } from './lockfile.js';

export type UseEvidence =
  | 'called_from_analysed_code'   // direct dependency, imported, and a call through the imported binding was resolved
  | 'imported_by_analysed_code'   // direct dependency imported, but no call through the binding was resolved
  | 'declared_not_imported'       // listed in package.json but no import found in analysed files
  | 'transitive'                  // only installed because another package depends on it
  | 'not_in_lockfile';            // the reported package/version is not in the lockfile

export interface PackageUse {
  evidence: UseEvidence;
  direct: boolean;
  declaredAs: 'prod' | 'dev' | 'optional' | 'peer' | null;
  devOnly: boolean;
  importers: string[];        // mod:<file> node ids
  callers: string[];          // fn:/mod: node ids whose code calls through the imported binding
  endpoints: string[];        // endpoints whose handlers reach a caller in the existing graph
  paths: string[][];          // endpoint -> ... -> caller paths (existing graph)
  introducedBy: { direct: string; chain: string[]; directEvidence: UseEvidence }[];
  summary: string;
}

export function packageNameFromSpec(spec: string): string | null {
  if (!spec || spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('node:') || spec.includes(':')) return null;
  const parts = spec.split('/');
  return spec.startsWith('@') ? (parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null) : parts[0];
}

export interface UsageIndex {
  importers: Map<string, Set<string>>;
  importSites: Map<string, { file: string; line: number }[]>;
  callers: Map<string, Set<string>>;
  analysedFiles: number;
}

export function buildUsageIndex(facts: FileFacts[], graph: Graph): UsageIndex {
  const nodeIds = new Set(graph.nodes.map((n) => n.id));
  const importers = new Map<string, Set<string>>();
  const importSites = new Map<string, { file: string; line: number }[]>();
  const callers = new Map<string, Set<string>>();
  for (const f of facts) {
    const locals = new Map<string, string>(); // local binding -> package
    for (const imp of f.imports) {
      const pkg = packageNameFromSpec(imp.spec);
      if (!pkg) continue;
      (importers.get(pkg) ?? importers.set(pkg, new Set()).get(pkg)!).add(`mod:${f.file}`);
      (importSites.get(pkg) ?? importSites.set(pkg, []).get(pkg)!).push({ file: f.file, line: imp.line });
      locals.set(imp.local, pkg);
    }
    for (const c of f.calls) {
      const local = c.callee.kind === 'ident' ? c.callee.name : c.callee.kind === 'member' ? c.callee.object : null;
      const pkg = local ? locals.get(local) : undefined;
      if (!pkg || c.asReference) continue;
      const decl = c.from ? f.decls.find((d) => d.qname === c.from) : undefined;
      const id = decl ? `${decl.kind === 'test' ? 'test' : 'fn'}:${f.file}#${decl.qname}` : `mod:${f.file}`;
      if (nodeIds.has(id)) (callers.get(pkg) ?? callers.set(pkg, new Set()).get(pkg)!).add(id);
    }
  }
  return { importers, importSites, callers, analysedFiles: facts.length };
}

function directEvidence(name: string, usage: UsageIndex): UseEvidence {
  if (usage.callers.get(name)?.size) return 'called_from_analysed_code';
  if (usage.importers.get(name)?.size) return 'imported_by_analysed_code';
  return 'declared_not_imported';
}

const LABEL: Record<UseEvidence, string> = {
  called_from_analysed_code: 'called from analysed code',
  imported_by_analysed_code: 'imported by analysed code (no resolved call)',
  declared_not_imported: 'declared in package.json but not imported by analysed files',
  transitive: 'transitive dependency',
  not_in_lockfile: 'not found in the lockfile',
};
export const USE_LABEL = LABEL;

export function packageUse(name: string, lockfileNodes: string[], model: LockModel | null, usage: UsageIndex, ix: GraphIndex): PackageUse {
  const rootDep = model?.root.deps.find((d) => d.name === name) ?? null;
  const nodes = lockfileNodes.filter((n) => model?.packages.has(n));
  const devOnly = nodes.length ? nodes.every((n) => model!.packages.get(n)!.dev) : rootDep?.type === 'dev';
  const topLevel = nodes.includes(`node_modules/${name}`);
  const direct = !!rootDep && (topLevel || !nodes.length);
  const importers = [...(usage.importers.get(name) ?? [])].sort();
  const callers = [...(usage.callers.get(name) ?? [])].sort();
  const paths: string[][] = [];
  const endpoints = new Set<string>();
  for (const c of callers) {
    for (const p of ix.pathsTo(c, (n) => n.kind === 'endpoint', { maxPaths: 4 })) { paths.push(p); endpoints.add(p[0]); }
  }
  let evidence: UseEvidence;
  if (model && !nodes.length) evidence = 'not_in_lockfile';
  else if (direct) evidence = directEvidence(name, usage);
  else evidence = 'transitive';

  const introducedBy = model && !direct
    ? nodes.flatMap((n) => chainsTo(model, n, 3)).slice(0, 5).map((c) => ({ direct: c.introducedBy, chain: c.chain, directEvidence: directEvidence(c.introducedBy, usage) }))
    : [];

  let summary: string;
  if (evidence === 'transitive') {
    summary = introducedBy.length
      ? `Transitive dependency, pulled in by ${[...new Set(introducedBy.map((i) => `${i.direct} (${LABEL[i.directEvidence]})`))].join(', ')}. Whether the vulnerable code in ${name} runs depends on how those packages use it, which is not analysed.`
      : 'Transitive dependency; the chain from a direct dependency could not be resolved from the lockfile.';
  } else if (evidence === 'called_from_analysed_code') {
    summary = `Imported in ${importers.length} file(s) and called from ${callers.length} function(s)${endpoints.size ? `, reachable from ${endpoints.size} endpoint(s)` : ''}. This shows the package is used, not that the vulnerable function is.`;
  } else {
    summary = LABEL[evidence][0].toUpperCase() + LABEL[evidence].slice(1) + '.';
  }
  if (devOnly) summary += ' Installed as a development dependency only.';
  return { evidence, direct, declaredAs: rootDep?.type ?? null, devOnly, importers, callers, endpoints: [...endpoints].sort(), paths: paths.slice(0, 10), introducedBy, summary };
}
