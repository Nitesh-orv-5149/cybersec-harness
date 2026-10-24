export type NodeKind = 'endpoint' | 'function' | 'module' | 'external' | 'database' | 'sink' | 'test';

export interface GraphNode {
  id: string; kind: NodeKind; label: string;
  loc?: { file: string; line: number; endLine?: number };
  hash?: string; fromUnsavedBuffer?: boolean; meta: Record<string, any>;
}
export interface GraphEdge {
  id: string; source: string; target: string; kind: string;
  loc?: { file: string; line: number }; certainty: 'static' | 'inferred'; confidence: number; derivation: string;
}
export interface Graph { nodes: GraphNode[]; edges: GraphEdge[]; stats: any; provider: string }
export interface GraphDiff { addedNodes: string[]; removedNodes: string[]; changedNodes: string[]; addedEdges: string[]; removedEdges: string[] }
export interface Impact { changed: string[]; affectedEndpoints: string[]; affectedClientCode: string[]; affectedTests: string[]; reachableSinks: string[]; paths: string[][] }

export interface GraphResponse {
  graph: Graph | null; graphVersion: number; graphHash: string; sourceHash: string;
  lastDiff: GraphDiff | null; lastImpact: Impact | null; lastChangedFiles: string[];
  baselineDiff: (GraphDiff & { impact: Impact | null }) | null;
}

export interface PackageInfo {
  ecosystem: string; name: string; version: string | null; lockfile: string; lockfileNodes: string[];
  affectedRanges: { tool: string; range: string }[]; fixedVersions: string[] | null;
  direct: boolean | null; devOnly: boolean | null; declaredAs: string | null;
  use: { evidence: string; label: string; summary: string; importers: string[]; callers: string[]; endpoints: string[]; introducedBy: { direct: string; chain: string[]; directEvidence: string }[] } | null;
}

export interface Finding {
  _id: string; source: 'graph' | 'runtime' | 'dependency' | 'api' | 'web' | 'template' | 'code' | 'secrets' | 'iac'; category: string; classification: string; severity: 'high' | 'medium' | 'low' | 'info' | 'unknown';
  labels?: string[]; ids?: string[]; canonicalId?: string; cwe?: string[]; scanners?: string[]; pkg?: PackageInfo; references?: string[];
  potentialRegression?: boolean; confidenceNote?: string; resolution?: string;
  ruleIds?: string[]; location?: { file?: string; line?: number; endLine?: number; url?: string; method?: string; operation?: string; param?: string; commit?: string; resource?: string };
  title: string; explanation: string[]; nodes: string[]; edges: string[]; paths: string[][];
  locations: { file: string; line: number }[]; evidence: Record<string, any>; suggestedNextStep: string;
  confidence: string; limitations: string[]; affectedByChange?: boolean; status?: 'open' | 'resolved' | 'not_currently_observed';
  scenario?: { id: string; name: string; viewport: string };
  correlation?: { status: string; changedNodes: string[]; exercised: string[]; paths: string[][]; changedAssets: string[]; reason: string };
  firstSeenAt?: string; lastSeenAt?: string; resolvedAt?: string | null; lastSeenBrowserRunId?: string;
}

export class ApiError extends Error {
  constructor(public status: number, message: string, public body: any) { super(message); }
}

async function req<T>(method: string, url: string, body?: unknown): Promise<T> {
  const res = await fetch(url, { method, headers: body ? { 'content-type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, data?.error ?? `HTTP ${res.status}`, data);
  return data as T;
}

export const api = {
  get: <T,>(url: string) => req<T>('GET', url),
  post: <T,>(url: string, body: unknown = {}) => req<T>('POST', url, body),
};

export const artifactUrl = (projectId: string, rel: string | null | undefined) =>
  rel ? `/api/projects/${projectId}/artifacts/${rel.split('/').map(encodeURIComponent).join('/')}` : '';

export const TOOL_LABEL: Record<string, string> = {
  'osv-api': 'OSV.dev (web API)', 'osv-scanner': 'OSV-Scanner', 'npm-audit': 'npm audit', trivy: 'Trivy', grype: 'Grype', syft: 'Syft',
  schemathesis: 'Schemathesis', zap: 'OWASP ZAP', nuclei: 'Nuclei', semgrep: 'Semgrep', gitleaks: 'Gitleaks', checkov: 'Checkov',
};
export const SOURCE_NAME: Record<string, string> = {
  graph: 'Code analysis', runtime: 'Website run', dependency: 'Dependency scan', api: 'API testing', web: 'Dynamic web scan',
  template: 'Template scan', code: 'Source-code scan', secrets: 'Secrets scan', iac: 'Infrastructure check',
};

export function shortId(id: string, n = 10) { return id.length > n ? id.slice(0, n) : id; }

export function timeAgo(iso?: string | Date | null) {
  if (!iso) return '—';
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 5) return 'just now';
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return new Date(iso).toLocaleDateString();
}
