// Contracts for the non-dependency scan categories (API testing, dynamic web scanning, template scanning,
// source-code analysis, secrets detection, infrastructure checks). One ScanKind per category; each kind owns
// its tools and turns their reports into tool-neutral observations. The shared ScanService persists runs,
// observations and findings and applies the same lifecycle rules to every category.
import type { Graph } from '../../analyzer/types.js';
import type { ProjectConfig } from '../../config.js';
import type { AppSeverity, Exec, Readiness, ToolRunRecord, Which } from '../types.js';

export type KindId = 'api' | 'web' | 'template' | 'code' | 'secrets' | 'iac';
export type KindCategory = 'api_testing' | 'web_dast' | 'template_scan' | 'source_code' | 'secrets' | 'iac';

/** A location a finding can be pinned to. File locations are project-relative. */
export interface ObsLocation {
  file?: string;
  line?: number;
  endLine?: number;
  url?: string;
  method?: string;
  operation?: string;  // e.g. "GET /api/items/{id}"
  param?: string;
  /** Git commit the finding was found in (history scans); absent for the working tree. */
  commit?: string;
  /** IaC resource address / name, as the tool reported it. */
  resource?: string;
}

/** One rule/check result from one tool in one run. */
export interface ScanObservation {
  tool: string;
  toolVersion: string | null;
  ruleId: string;                  // tool's own identifier (rule id, check code, plugin id, template id)
  ruleName: string | null;
  title: string;
  message: string | null;
  severity: AppSeverity;
  originalSeverity: string | null; // exactly as the tool reported it
  confidence: string | null;       // tool's confidence label, when it has one
  cwe: string[];
  references: string[];
  location: ObsLocation;
  evidence: Record<string, unknown>; // redacted before it reaches this object
  /** Same issue across tools/runs. Built from location + weakness class, never from tool-specific wording. */
  dedupeKey: string;
  /** Extra identifiers (CVE, CWE, rule aliases) kept for merging. */
  ids: string[];
}

export type KindCoverageStatus = 'covered' | 'partial' | 'not_applicable' | 'unavailable' | 'failed' | 'not_run';

export interface KindCoverage {
  status: KindCoverageStatus;
  reason: string | null;
  /** Category-specific scope description (operations tested, files scanned, URLs crawled, ...). */
  detail: Record<string, unknown>;
}

export interface KindRunResult {
  tools: ToolRunRecord[];
  observations: ScanObservation[];
  coverage: KindCoverage;
  reports: { tool: string; name: string; content: string }[];
  notes: string[];
  target?: { url: string; snapshotId: string; contentHash: string; log?: string } | null;
  /** Was a previously open finding inside the scope this run actually covered? Only then can absence mean anything. */
  inScope: (f: { location?: ObsLocation; scanners?: string[] }) => boolean;
}

export interface ManagedTarget {
  url: string;
  snapshotId: string;
  contentHash: string;
  log: () => string;
  stop: () => Promise<void>;
}

export interface KindContext {
  root: string;
  runDir: string;
  cfg: ProjectConfig;
  graph: Graph | null;
  exec: Exec;
  which: Which;
  signal: AbortSignal;
  readiness: Readiness[];
  startTarget: (signal: AbortSignal) => Promise<ManagedTarget>;
  onTool: (tool: string, phase: 'running' | 'done') => void;
  options: StartOptions;
}

export interface StartOptions {
  /** The user ticked "I am authorised to actively test this target" for this run. */
  confirmActive?: boolean;
  /** Kind-specific mode, e.g. ZAP 'passive' | 'active'. */
  mode?: string;
}

export interface ToolSpec {
  id: string;
  displayName: string;
  /** What the tool contacts besides the local target, shown in the UI. */
  networkHosts: string[];
  limitations: string[];
  readiness: (ctx: { cfg: ProjectConfig; exec: Exec; which: Which; root: string }) => Promise<Readiness>;
}

export interface ScanKind {
  id: KindId;
  category: KindCategory;
  label: string;           // "API testing"
  findingSource: string;   // graph_findings.source value
  description: string;
  /** Sends traffic to a running application. */
  dynamic: boolean;
  /** Has a mode that sends attack-style traffic and therefore needs explicit authorisation. */
  activeModes: string[];
  modes: string[];
  tools: ToolSpec[];
  enabled: (cfg: ProjectConfig) => boolean;
  /** Reasons the scan cannot start; empty when it can. */
  preconditions: (cfg: ProjectConfig, opts: StartOptions) => string[];
  run: (ctx: KindContext) => Promise<KindRunResult>;
}
