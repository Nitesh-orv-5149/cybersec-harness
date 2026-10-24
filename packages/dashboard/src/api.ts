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

export interface Finding {
  _id: string; source: 'graph' | 'runtime'; category: string; classification: string; severity: 'high' | 'medium' | 'low' | 'info';
  title: string; explanation: string[]; nodes: string[]; edges: string[]; paths: string[][];
  locations: { file: string; line: number }[]; evidence: Record<string, any>; suggestedNextStep: string;
  confidence: string; limitations: string[]; affectedByChange?: boolean; status?: 'open' | 'resolved';
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
