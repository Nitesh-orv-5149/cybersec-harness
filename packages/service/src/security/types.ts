// Common contracts for external security scanners. Each tool lives in its own adapter; the orchestrator
// only sees these types. Nothing here assumes a tool is installed, and an unavailable tool is never
// reported as "no findings".
import type { ProjectConfig } from '../config.js';

export type ScanCategory = 'dependency_vulns';
export type ToolId = 'osv-api' | 'osv-scanner' | 'npm-audit' | 'trivy';

export type ReadinessState =
  | 'ready'           // executable found and `--version` succeeded
  | 'not_installed'   // no executable on PATH / configured path
  | 'not_functional'  // executable found but the version check failed
  | 'unreachable'     // API adapter: the remote service did not answer a probe
  | 'needs_network'   // tool would contact a remote service and security.allowNetwork is false
  | 'disabled';       // turned off by configuration

export interface Readiness {
  tool: ToolId;
  state: ReadinessState;
  version: string | null;
  binary: string | null;
  reason: string | null;
  checkedAt: string;
}

export interface ExecResult {
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stdoutBytes: number;
  stdoutTruncated: boolean;
  stderrTail: string;
  timedOut: boolean;
  cancelled: boolean;
  spawnError: string | null;
  durationMs: number;
}

export interface ExecOptions {
  cwd: string;
  timeoutMs: number;
  maxOutputBytes: number;
  signal?: AbortSignal;
}

export type Exec = (binary: string, args: string[], opts: ExecOptions) => Promise<ExecResult>;
export type Which = (name: string, explicit?: string) => string | null;

/** One dependency manifest + lockfile pair to scan. */
export interface DependencyTarget {
  ecosystem: 'npm';
  root: string;          // absolute project root
  lockfile: string;      // relative path, e.g. package-lock.json
  manifest: string;      // relative path, e.g. package.json
  lockfileHash: string;
  manifestHash: string;
}

export type AppSeverity = 'high' | 'medium' | 'low' | 'info' | 'unknown';

/** One advisory reported by one tool for one installed package version. Tool-neutral, provenance-preserving. */
export interface AdvisoryObservation {
  tool: ToolId;
  toolVersion: string | null;
  ecosystem: string;
  packageName: string;
  installedVersion: string | null;   // null = the tool did not say and the lockfile did not resolve it
  advisoryId: string;                // the tool's primary identifier for the advisory
  aliases: string[];                 // identifiers the tool itself supplied (always includes advisoryId)
  toolRef: string | null;            // tool-internal reference (e.g. npm advisory source number)
  title: string | null;
  url: string | null;
  severity: AppSeverity;
  originalSeverity: string | null;   // exactly as the tool reported it
  cvssScore: number | null;
  cvssVector: string | null;
  cwe: string[];
  affectedRange: string | null;
  fixedVersions: string[] | null;    // null = not supplied by the tool
  remediation: string | null;
  lockfileNodes: string[];           // lockfile package paths, e.g. node_modules/qs
  sourceFile: string;                // which lockfile/target the tool attributed it to
}

export type ToolOutcome =
  | { status: 'completed'; observations: AdvisoryObservation[]; notes: string[] }
  | { status: 'failed' | 'inconclusive'; reason: string; notes: string[] };

export interface ApiRunContext {
  fetch: typeof fetch;
  packages: { name: string; version: string | null; dev: boolean }[];
  lockVersions: Map<string, string>;
  signal?: AbortSignal;
  timeoutMs: number;
}
export interface ApiRunResult { outcome: ToolOutcome; raw: string; durationMs: number; timedOut: boolean; cancelled: boolean }

export interface DependencyScannerAdapter {
  id: ToolId;
  /** 'api' adapters call a hosted service from the service process instead of running a binary. */
  kind?: 'process' | 'api';
  runApi?(target: DependencyTarget, ctx: ApiRunContext): Promise<ApiRunResult>;
  displayName: string;
  category: ScanCategory;
  outputFormat: string;
  executable: string;                                 // name searched on PATH
  /** Remote hosts the tool contacts in its configured mode (shown in the UI). */
  networkHosts(cfg: SecurityConfig): string[];
  supports(target: DependencyTarget): { ok: true } | { ok: false; reason: string };
  versionArgs: string[];
  parseVersion(stdout: string): string | null;
  buildArgs(target: DependencyTarget, cfg: SecurityConfig): string[];
  /** Turn the raw process result into an outcome. Never returns "completed" without a parsed report. */
  interpret(exec: ExecResult, target: DependencyTarget, toolVersion: string | null, ctx: InterpretContext): ToolOutcome;
  limitations: string[];
}

export interface InterpretContext {
  /** lockfile package path -> resolved version, used to fill in installed versions a tool omits */
  lockVersions: Map<string, string>;
}

export type SecurityConfig = ProjectConfig['security'];

export interface ToolRunRecord {
  tool: ToolId;
  displayName: string;
  version: string | null;
  readiness: ReadinessState;
  selected: boolean;
  status: 'completed' | 'failed' | 'inconclusive' | 'timed_out' | 'cancelled' | 'skipped' | 'unavailable';
  reason: string | null;
  exitCode: number | null;
  durationMs: number | null;
  observationCount: number | null;   // null when the tool did not complete
  stderrTail: string | null;
  reportRef: string | null;
  reportSha256: string | null;
  notes: string[];
  limitations: string[];
  networkHosts: string[];
}

export interface CoverageRecord {
  category: ScanCategory;
  ecosystem: string;
  lockfile: string;
  status: 'covered' | 'partial' | 'unavailable' | 'failed' | 'not_run';
  by: ToolId[];
  reason: string | null;
}
