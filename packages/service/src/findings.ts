// Deterministic finding rules. Inputs and outputs are structured; nothing here guesses causality.
//
// Severity scale (documented, consistent):
//   high   - command/code execution or dynamic SQL reachable from an endpoint without observed sanitization,
//            or a browser assertion that passed on baseline and fails on candidate.
//   medium - path/SSRF/DOM sinks reachable from an endpoint; high-class sinks with auth or sanitization observed;
//            new console errors / failed requests; large visual differences.
//   low    - sinks with no endpoint path; small visual differences; pre-existing failures.
//   info   - context only.
// "critical" is intentionally never assigned: it would require verified exploitability, which static
// reachability and UI checks cannot establish.
import path from 'node:path';
import type { Graph, GraphNode, SinkKind } from './analyzer/types.js';
import { GraphIndex, impactOf } from './analyzer/query.js';
import { matchRoute, SINK_LABELS } from './analyzer/linker.js';
import type { ComparisonItem } from './compare.js';
import type { ScenarioResult } from './browser.js';
import type { ManifestEntry } from './snapshots.js';
import { shortHash } from './util.js';

export type Severity = 'high' | 'medium' | 'low' | 'info';
export const SEVERITY_RANK: Record<Severity, number> = { high: 3, medium: 2, low: 1, info: 0 };
const DOWN: Record<Severity, Severity> = { high: 'medium', medium: 'low', low: 'low', info: 'info' };

export type Classification =
  | 'security_sensitive_path' | 'confirmed_test_failure' | 'observed' | 'potentially_related' | 'unverified' | 'inconclusive';

export interface FindingDraft {
  _id: string;
  source: 'graph' | 'runtime';
  category: string;
  classification: Classification;
  severity: Severity;
  severityRank: number;
  title: string;
  explanation: string[];
  nodes: string[];
  edges: string[];
  paths: string[][];
  locations: { file: string; line: number }[];
  evidence: Record<string, unknown>;
  suggestedNextStep: string;
  confidence: 'high' | 'medium' | 'low';
  limitations: string[];
  affectedByChange?: boolean;
  scenario?: { id: string; name: string; viewport: string };
  correlation?: { status: 'potentially_related' | 'no_supporting_path'; changedNodes: string[]; exercised: string[]; paths: string[][]; changedAssets: string[]; reason: string };
}

const BASE_SEVERITY: Record<SinkKind, Severity> = {
  command_exec: 'high', code_exec: 'high', sql_dynamic: 'high', path_access: 'medium', ssrf: 'medium', dom_xss: 'medium',
};

const NEXT_STEP: Record<SinkKind, string> = {
  command_exec: 'Avoid building shell strings from request data; use execFile with an argument array and an allowlist, then add a test with hostile input.',
  code_exec: 'Remove dynamic evaluation or restrict it to a fixed allowlist; add a test proving untrusted input is rejected.',
  sql_dynamic: 'Use parameterised queries/placeholders instead of string interpolation; add a test with quote and comment characters.',
  path_access: 'Resolve the path and verify it stays inside the intended directory (path.resolve + prefix check); add a ../ traversal test.',
  ssrf: 'Validate the destination against an allowlist of hosts/schemes before requesting it; add a test using an internal address.',
  dom_xss: 'Use textContent or a sanitiser instead of HTML injection; add a test rendering a <script> payload.',
};

function locOf(n: GraphNode | undefined) {
  return n?.loc ? { file: n.loc.file, line: n.loc.line } : null;
}

export function graphFindings(graph: Graph, changedSinceBaseline: Set<string>): FindingDraft[] {
  const ix = new GraphIndex(graph);
  const out: FindingDraft[] = [];
  for (const sink of graph.nodes.filter((n) => n.kind === 'sink')) {
    const kind = sink.meta.sinkKind as SinkKind;
    const paths = ix.pathsTo(sink.id, (n) => n.kind === 'endpoint', { maxPaths: 12 });
    const endpoints = [...new Set(paths.map((p) => p[0]))];
    const eps = endpoints.map((id) => ix.nodes.get(id)!);
    const explanation: string[] = [];
    let severity: Severity = BASE_SEVERITY[kind];
    explanation.push(`${sink.meta.callee}() is called with a non-literal argument: ${sink.meta.argText}`);
    if (sink.meta.directRequestInput) explanation.push('The argument references request data (req.query/params/body/headers) directly.');
    else if ((sink.meta.paramsUsed as string[])?.length) explanation.push(`The argument is built from function parameter(s) ${(sink.meta.paramsUsed as string[]).join(', ')}; their origin is traced only through the call graph, not through data flow.`);
    if (!paths.length) {
      severity = 'low';
      explanation.push('No static call path from a registered endpoint to this function was found.');
    } else {
      explanation.push(`Reachable from ${endpoints.length} endpoint(s): ${eps.map((e) => e.label).join(', ')}.`);
      const unauth = eps.filter((e) => !e.meta.authObserved);
      if (unauth.length) explanation.push(`No auth-like middleware observed on: ${unauth.map((e) => e.label).join(', ')}.`);
      else { severity = DOWN[severity]; explanation.push('Every reaching endpoint has auth-like middleware; severity lowered one level (auth does not prove safety).'); }
    }
    if (sink.meta.sanitizationHint) {
      severity = DOWN[severity];
      explanation.push(`Possible sanitisation/validation observed in the enclosing function (${sink.meta.sanitizationHint}); not verified, severity lowered one level.`);
    }
    const onPath = new Set(paths.flat());
    const affectedByChange = [...onPath].some((id) => changedSinceBaseline.has(id)) || changedSinceBaseline.has(sink.id);
    if (affectedByChange) explanation.push('Code on this path changed since the baseline snapshot.');
    const edges: string[] = [];
    for (const p of paths) for (let i = 0; i + 1 < p.length; i++) { const e = ix.edgeBetween(p[i], p[i + 1]); if (e) edges.push(e.id); }
    out.push({
      _id: `gf_${shortHash(sink.id, 16)}`,
      source: 'graph',
      category: kind,
      classification: 'security_sensitive_path',
      severity, severityRank: SEVERITY_RANK[severity],
      title: paths.length ? `${SINK_LABELS[kind]} reachable from ${endpoints.length} endpoint${endpoints.length > 1 ? 's' : ''}` : `${SINK_LABELS[kind]} with no endpoint path found`,
      explanation,
      nodes: [...onPath, sink.id], edges: [...new Set(edges)], paths,
      locations: [...onPath, sink.id].map((id) => locOf(ix.nodes.get(id))).filter(Boolean) as { file: string; line: number }[],
      evidence: { sink: sink.id, callee: sink.meta.callee, argText: sink.meta.argText, endpoints },
      suggestedNextStep: NEXT_STEP[kind],
      confidence: sink.meta.directRequestInput ? 'medium' : 'low',
      limitations: [
        'A reachable call path does not prove that attacker-controlled input reaches the sink or that exploitation succeeds.',
        'Dynamic dispatch, re-exports through barrels and framework magic may hide additional paths.',
        ...(graph.stats.unresolvedCalls ? [`${graph.stats.unresolvedCalls} call(s) to project code could not be resolved statically.`] : []),
      ],
      affectedByChange,
    });
  }
  return out;
}

export function staticAssetToFile(urlPath: string, staticMap: Record<string, string>): string | null {
  for (const [prefix, dir] of Object.entries(staticMap).sort((a, b) => b[0].length - a[0].length)) {
    if (!urlPath.startsWith(prefix)) continue;
    let rest = urlPath.slice(prefix.length).replace(/^\/+/, '');
    if (rest === '' || rest.endsWith('/')) rest += 'index.html';
    return path.posix.normalize(path.posix.join(dir, rest));
  }
  return null;
}

export interface CorrelationInput {
  candidateGraph: Graph;
  changedNodes: string[];              // changed/added nodes between baseline and candidate graphs
  changedFiles: string[];              // files changed between baseline and candidate manifests
  staticMap: Record<string, string>;
}

export function runtimeFindings(items: ComparisonItem[], candidateResults: ScenarioResult[], input: CorrelationInput): FindingDraft[] {
  const ix = new GraphIndex(input.candidateGraph);
  const endpoints = input.candidateGraph.nodes.filter((n) => n.kind === 'endpoint');
  const out: FindingDraft[] = [];
  for (const item of items) {
    if (item.classification !== 'confirmed_test_failure' && item.classification !== 'observed') continue;
    const res = candidateResults.find((r) => r.scenarioId === item.scenarioId && r.viewport === item.viewport);

    // What this scenario actually exercised at runtime (observed requests and loaded assets).
    const exercised = new Set<string>();
    for (const req of res?.apiRequests ?? []) {
      for (const ep of endpoints) if (ep.meta.method === req.method && matchRoute(String(ep.meta.path), req.path)) exercised.add(ep.id);
    }
    const loadedFiles = (res?.scriptsLoaded ?? []).map((u) => staticAssetToFile(u, input.staticMap)).filter(Boolean) as string[];
    for (const f of loadedFiles) if (ix.nodes.has(`mod:${f}`)) exercised.add(`mod:${f}`);

    // Changed graph nodes that the exercised entry points depend on.
    const related: string[] = [];
    const paths: string[][] = [];
    for (const ch of input.changedNodes) {
      const ps = ix.pathsTo(ch, (n) => exercised.has(n.id), { maxPaths: 3 });
      const direct = exercised.has(ch);
      if (ps.length || direct) { related.push(ch); paths.push(...(ps.length ? ps : [[ch]])); }
    }
    const changedAssets = loadedFiles.filter((f) => input.changedFiles.includes(f));

    const explanation: string[] = [];
    if (item.classification === 'confirmed_test_failure') {
      explanation.push(`Scenario "${item.scenarioName}" (${item.viewport}) passed on the baseline and fails on the candidate.`);
      for (const a of item.failedAssertions) explanation.push(`Failed: ${a.step} — ${a.message}`);
    } else {
      explanation.push(...item.notes);
    }
    explanation.push(`At runtime this scenario requested ${res?.apiRequests.length ?? 0} API call(s) and loaded ${loadedFiles.length} project asset(s).`);

    let correlation: FindingDraft['correlation'];
    if (related.length || changedAssets.length) {
      const parts: string[] = [];
      if (related.length) parts.push(`${related.length} changed code node(s) are on dependency paths from what the scenario exercised`);
      if (changedAssets.length) parts.push(`the page loaded changed file(s): ${changedAssets.join(', ')}`);
      correlation = { status: 'potentially_related', changedNodes: related, exercised: [...exercised], paths: paths.slice(0, 10), changedAssets, reason: `${parts.join('; ')}. This is supporting evidence, not proof of cause.` };
      explanation.push(correlation.reason);
    } else {
      correlation = { status: 'no_supporting_path', changedNodes: [], exercised: [...exercised], paths: [], changedAssets: [], reason: input.changedNodes.length || input.changedFiles.length ? 'No dependency path or loaded asset connects the code changes to this scenario; the cause is unverified (it may be data, environment or an unanalysed file).' : 'No source differences between baseline and candidate; the difference may be nondeterministic.' };
      explanation.push(correlation.reason);
    }

    const kind = item.classification === 'confirmed_test_failure' ? 'ui_regression' : item.newConsoleErrors.length || item.newFailedRequests.length ? 'runtime_errors' : 'visual_difference';
    const sev = item.severity === 'info' ? 'low' : item.severity;
    const nodes = [...new Set([...correlation.paths.flat(), ...correlation.exercised])];
    out.push({
      _id: `rf_${shortHash(`${item.scenarioId}|${item.viewport}|${kind}`, 16)}`,
      source: 'runtime',
      category: kind,
      classification: item.classification === 'confirmed_test_failure' ? 'confirmed_test_failure' : 'observed',
      severity: sev, severityRank: SEVERITY_RANK[sev],
      title: kind === 'ui_regression' ? `"${item.scenarioName}" regressed on ${item.viewport}` : kind === 'runtime_errors' ? `New runtime errors in "${item.scenarioName}" (${item.viewport})` : `Visual change in "${item.scenarioName}" (${item.viewport})`,
      explanation,
      nodes, edges: [], paths: correlation.paths,
      locations: correlation.changedNodes.map((id) => locOf(ix.nodes.get(id))).filter(Boolean) as { file: string; line: number }[],
      evidence: { failedAssertions: item.failedAssertions, newConsoleErrors: item.newConsoleErrors, newFailedRequests: item.newFailedRequests, visualDiffRatio: item.visual?.ratio ?? null, regions: item.visual?.regions ?? [] },
      suggestedNextStep: correlation.status === 'potentially_related'
        ? `Inspect ${correlation.changedNodes.map((id) => ix.nodes.get(id)?.label).filter(Boolean).slice(0, 3).join(', ') || correlation.changedAssets.join(', ')} and re-run verification after a fix.`
        : 'Reproduce manually and check environment/data differences; re-run verification to rule out flakiness.',
      confidence: item.classification === 'confirmed_test_failure' && correlation.status === 'potentially_related' ? 'high' : item.classification === 'confirmed_test_failure' ? 'medium' : 'low',
      limitations: [
        'Correlation uses observed requests/assets and static dependency paths; it does not prove the change caused the failure.',
        ...(input.changedFiles.some((f) => !ix.nodes.has(`mod:${f}`) && !/\.(css|html?)$/.test(f)) ? ['Some changed files are not analysed by the current parser and cannot be linked.'] : []),
      ],
      scenario: { id: item.scenarioId, name: item.scenarioName, viewport: item.viewport },
      correlation,
    });
  }
  return out;
}

export function impactForChanged(graph: Graph, changed: string[]) {
  return impactOf(new GraphIndex(graph), changed);
}

export type { ManifestEntry };
