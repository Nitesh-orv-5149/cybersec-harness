// Graph model shared by the analyzer, service, persistence and dashboard.
// Edge direction convention: source DEPENDS ON target
// (endpoint -> handler, caller -> callee, function -> sink, client code -> endpoint, test -> function).
// "Impact" of a change therefore walks edges in reverse; "reachability" walks them forward.

export type NodeKind = 'endpoint' | 'function' | 'module' | 'external' | 'database' | 'sink' | 'test';

export type EdgeKind =
  | 'route_to_handler'
  | 'uses_middleware'
  | 'calls'
  | 'imports'
  | 'renders'
  | 'sends_request_to'
  | 'reads_from'
  | 'writes_to'
  | 'reaches_sensitive_sink'
  | 'tests';

export type Certainty = 'static' | 'inferred';

export interface SourceLoc {
  file: string;
  line: number;
  endLine?: number;
}

export interface GraphNode {
  id: string;
  kind: NodeKind;
  label: string;
  loc?: SourceLoc;
  /** Content hash of the node's source text; used to detect changes between graph versions. */
  hash?: string;
  /** True when the node was derived from an unsaved editor buffer rather than the file on disk. */
  fromUnsavedBuffer?: boolean;
  meta: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  kind: EdgeKind;
  loc?: SourceLoc;
  certainty: Certainty;
  confidence: number;
  derivation: string;
}

export interface GraphStats {
  files: number;
  parsedFiles: number;
  parseErrors: { file: string; message: string }[];
  unresolvedCalls: number;
  unsupportedFiles: number;
}

export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: GraphStats;
  provider: string;
}

export type SinkKind = 'command_exec' | 'code_exec' | 'sql_dynamic' | 'path_access' | 'ssrf' | 'dom_xss';

// ---- Per-file facts produced by a language adapter (language-specific), consumed by the linker (generic) ----

export interface ImportBinding {
  local: string;
  spec: string;
  imported: string; // 'default' | '*' | exported name
  line: number;
}

export interface DeclFact {
  qname: string; // stable within the file, e.g. "listOrders", "orderService.fetch", "route GET /orders/:id"
  kind: 'function' | 'test' | 'handler';
  line: number;
  endLine: number;
  hash: string;
  params: string[];
  sanitizationHint?: string;
}

export type CalleeRef =
  | { kind: 'ident'; name: string }
  | { kind: 'member'; object: string; prop: string }
  | { kind: 'other'; text: string };

export interface CallFact {
  from: string | null; // decl qname or null for module scope
  callee: CalleeRef;
  line: number;
  /** true when the identifier was passed as a callback instead of being called directly */
  asReference?: boolean;
}

/** Suffix of the declaration recorded for a function returned by another function (handler factories). */
export const RETURNED_SUFFIX = '.<returned>';

export interface RouteFact {
  receiver: string;
  method: string;
  path: string;
  handler: { kind: 'ident'; name: string } | { kind: 'member'; object: string; prop: string } | { kind: 'inline'; qname: string }
    /** `app.get(path, makeHandler())`: the handler is the function that makeHandler returns */
    | { kind: 'factory'; ref: { kind: 'ident'; name: string } | { kind: 'member'; object: string; prop: string } }
    | null;
  middleware: string[];
  line: number;
  hash: string;
}

export interface MountFact {
  receiver: string;
  prefix: string;
  target: string; // identifier
  line: number;
}

export interface SinkFact {
  from: string | null;
  sinkKind: SinkKind;
  callee: string;
  line: number;
  ordinal: number;
  argText: string;
  directRequestInput: boolean;
  paramsUsed: string[];
}

export interface RequestFact {
  from: string | null;
  url: string;
  method: string;
  line: number;
}

/** A request input read directly inside a function whose first parameter is the request object (req.query.q, const { id } = req.params, req.body). */
export interface RequestInputFact {
  from: string;
  location: 'query' | 'path' | 'body' | 'header';
  name: string | null;   // null: the whole object is used (e.g. validate(req.body)), field names unknown
  line: number;
}

export interface RenderFact {
  from: string | null;
  tag: string;
  line: number;
}

export interface FileFacts {
  file: string;
  hash: string;
  language: string;
  isTest: boolean;
  isClient: boolean;
  imports: ImportBinding[];
  exports: Record<string, string>; // exportName -> local name
  decls: DeclFact[];
  objectVars: string[];
  routerVars: Record<string, 'app' | 'router'>;
  calls: CallFact[];
  routes: RouteFact[];
  mounts: MountFact[];
  sinks: SinkFact[];
  requests: RequestFact[];
  renders: RenderFact[];
  inputs?: RequestInputFact[];
  parseError?: string;
}

export interface ParseOptions {
  isClient: boolean;
}

export interface LanguageAdapter {
  id: string;
  extensions: string[];
  parse(file: string, text: string, opts: ParseOptions): FileFacts;
}
