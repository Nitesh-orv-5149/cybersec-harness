import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { sha256 } from './util.js';

const Step = z.union([
  z.object({ click: z.string() }),
  z.object({ fill: z.object({ selector: z.string(), value: z.string() }) }),
  z.object({ press: z.object({ selector: z.string(), key: z.string() }) }),
  z.object({ waitFor: z.string() }),
  z.object({ goto: z.string() }),
  z.object({ expectVisible: z.string() }),
  z.object({ expectHidden: z.string() }),
  z.object({ expectText: z.object({ selector: z.string(), contains: z.string() }) }),
  z.object({ expectNoHorizontalOverflow: z.literal(true) }),
  z.object({ expectStatus: z.object({ urlContains: z.string(), status: z.number() }) }),
]);
export type ScenarioStep = z.infer<typeof Step>;

const Viewport = z.object({ name: z.string(), width: z.number().int().min(200).max(4000), height: z.number().int().min(200).max(4000) });

const Scenario = z.object({
  id: z.string().regex(/^[a-z0-9-_]+$/i),
  name: z.string(),
  path: z.string().startsWith('/'),
  viewports: z.array(z.string()).optional(),
  steps: z.array(Step).default([]),
});
export type Scenario = z.infer<typeof Scenario>;

export const ProjectConfigSchema = z.object({
  language: z.string().default('javascript'),
  analysis: z.object({
    include: z.array(z.string()).default([]),
    exclude: z.array(z.string()).default([]),
  }).default({}),
  snapshot: z.object({
    exclude: z.array(z.string()).default(['node_modules', 'dist', '.git']),
    linkNodeModules: z.boolean().default(true),
    maxFiles: z.number().int().positive().default(5000),
    maxBytes: z.number().int().positive().default(50 * 1024 * 1024),
  }).default({}),
  run: z.object({
    build: z.string().optional(),
    start: z.string(),
    portEnv: z.string().default('PORT'),
    healthPath: z.string().default('/'),
    buildTimeoutMs: z.number().int().positive().default(120_000),
    startTimeoutMs: z.number().int().positive().default(30_000),
    env: z.record(z.string()).default({}),
  }).optional(),
  staticMap: z.record(z.string()).default({}),
  browser: z.object({
    viewports: z.array(Viewport).default([{ name: 'desktop', width: 1280, height: 800 }]),
    diffThreshold: z.number().min(0).max(1).default(0.001),
    pixelThreshold: z.number().min(0).max(1).default(0.1),
    mask: z.array(z.string()).default([]),
    scenarios: z.array(Scenario).default([]),
  }).default({}),
  verification: z.object({
    trigger: z.enum(['manual', 'on-save']).default('manual'),
    debounceMs: z.number().int().min(50).max(60_000).default(400),
  }).default({}),
  security: z.object({
    /** Scanners that contact remote services (advisory APIs, registries, DB downloads) run only when this is true. */
    allowNetwork: z.boolean().default(false),
    dependencies: z.object({
      enabled: z.boolean().default(true),
      /** first-available: run the first ready tool in `order` (falling back on failure); all-available: run every ready tool. */
      mode: z.enum(['first-available', 'all-available']).default('first-available'),
      order: z.array(z.enum(['osv-api', 'osv-scanner', 'npm-audit', 'trivy'])).min(1).default(['osv-api', 'npm-audit', 'osv-scanner', 'trivy']),
      fallbackOnFailure: z.boolean().default(true),
      includeDev: z.boolean().default(true),
      timeoutMs: z.number().int().min(5_000).max(30 * 60_000).default(180_000),
      maxOutputBytes: z.number().int().min(64 * 1024).max(256 * 1024 * 1024).default(32 * 1024 * 1024),
      /** Explicit executable paths; otherwise PATH is searched. Nothing is ever downloaded. */
      binaries: z.object({ 'osv-scanner': z.string().optional(), npm: z.string().optional(), trivy: z.string().optional() }).default({}),
      /** Use a locally cached OSV database instead of api.osv.dev (osv-scanner --offline-vulnerabilities). */
      osvOffline: z.boolean().default(false),
      /** Use Trivy's cached DB without updating it (--skip-db-update --offline-scan). */
      trivyOffline: z.boolean().default(false),
    }).default({}),
    /** Schema-driven API testing (Schemathesis) against a workbench-started local copy of the app. */
    api: z.object({
      enabled: z.boolean().default(true),
      /** Active testing sends generated and malformed requests. Off unless set here; every run must also be confirmed in the dashboard. */
      allowActiveTesting: z.boolean().default(false),
      /** auto: use `path` when set, otherwise derive an OpenAPI document from the code graph's endpoints. */
      schema: z.object({ source: z.enum(['auto', 'file', 'graph']).default('auto'), path: z.string().optional() }).default({}),
      /** Only these methods are tested. State-changing methods must be listed explicitly. */
      methods: z.array(z.enum(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'])).min(1).default(['GET', 'HEAD', 'OPTIONS']),
      checks: z.array(z.enum([
        'not_a_server_error', 'status_code_conformance', 'content_type_conformance', 'response_headers_conformance', 'response_schema_conformance',
        'negative_data_rejection', 'positive_data_acceptance', 'missing_required_header', 'unsupported_method', 'allow_header_conformance',
        'use_after_free', 'ensure_resource_availability', 'ignored_auth', 'object_level_authorization',
      ])).min(1).default(['not_a_server_error']),
      phases: z.array(z.enum(['examples', 'coverage', 'fuzzing', 'stateful'])).min(1).default(['examples', 'coverage', 'fuzzing']),
      maxExamples: z.number().int().min(1).max(1000).default(30),
      requestTimeoutSec: z.number().min(0.5).max(120).default(5),
      workers: z.number().int().min(1).max(8).default(1),
      rateLimit: z.string().regex(/^\d+\/(s|m|h)$/).optional(),
      seed: z.number().int().optional(),
      /** Extra headers sent with every request (e.g. a test-account token). Values are redacted in stored evidence. */
      headers: z.record(z.string()).default({}),
      timeoutMs: z.number().int().min(10_000).max(60 * 60_000).default(600_000),
      maxOutputBytes: z.number().int().min(64 * 1024).max(256 * 1024 * 1024).default(64 * 1024 * 1024),
      /** Explicit executable path; otherwise `schemathesis` then `st` are searched on PATH. Nothing is installed. */
      binary: z.string().optional(),
    }).default({}),
    /** Nuclei against a running web application (Website comparison → Security changes). Every scan must be confirmed. */
    nuclei: z.object({
      enabled: z.boolean().default(true),
      /** Explicit executable path; otherwise `nuclei` is searched on PATH. Nothing is installed or updated. */
      binary: z.string().optional(),
      /** Local nuclei-templates directory. Default: the directory the installed nuclei reports (`nuclei -tv`). */
      templatesDir: z.string().optional(),
      /** Template coverage. quick: misconfiguration, config exposures, technologies. standard: + all exposures, exposed panels,
       *  vulnerabilities and CVEs. full: every HTTP template. Every template is still vetted (see security/web/templates.ts). */
      profile: z.enum(['quick', 'standard', 'full']).default('standard'),
      /** Explicit template paths (relative to templatesDir, or absolute local folders). When set, they replace the profile. */
      templates: z.array(z.string().min(1)).min(1).optional(),
      /** Also scan the app's own GET routes (from the code graph, without path parameters) as targets, not only the root URL. */
      includeGraphEndpoints: z.boolean().default(true),
      maxGraphEndpoints: z.number().int().min(0).max(200).default(40),
      /** Extra tags to exclude on top of the built-in deny list (intrusive, dos, fuzz, brute force, rce, oast, ...). */
      excludeTags: z.array(z.string()).default([]),
      /** Template ids never to run. */
      excludeIds: z.array(z.string()).default([]),
      /** HTTP methods a template may use. State-changing methods must be listed explicitly. */
      methods: z.array(z.enum(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'])).min(1).default(['GET', 'HEAD', 'OPTIONS']),
      severities: z.array(z.enum(['info', 'low', 'medium', 'high', 'critical', 'unknown'])).optional(),
      /** Origins (scheme://host:port) that may be scanned besides loopback. Only list systems you are authorized to test. */
      authorizedTargets: z.array(z.string().url()).default([]),
      /** Prefilled URL for "scan a running application" (must be loopback or authorized). */
      defaultTarget: z.string().url().optional(),
      /** none: redirects are not followed (-dr). same-host: follow only on the same host (-fhr -mr 3). */
      redirects: z.enum(['none', 'same-host']).default('none'),
      /** Requests per second. Default: 50 for loopback targets (your own machine), 10 for other authorized targets. */
      rateLimit: z.number().int().min(1).max(200).optional(),
      concurrency: z.number().int().min(1).max(50).default(10),
      requestTimeoutSec: z.number().int().min(1).max(60).default(5),
      retries: z.number().int().min(0).max(3).default(0),
      maxHostErrors: z.number().int().min(1).max(1000).default(30),
      maxTemplates: z.number().int().min(1).max(20_000).default(12_000),
      maxResponseBytes: z.number().int().min(4096).max(10 * 1024 * 1024).default(1024 * 1024),
      /** Whole-scan limit per side. Default by profile: quick 10 min, standard 30 min, full 60 min. */
      timeoutMs: z.number().int().min(10_000).max(3 * 60 * 60_000).optional(),
      maxOutputBytes: z.number().int().min(64 * 1024).max(256 * 1024 * 1024).default(32 * 1024 * 1024),
      /** Incremental scanning (security/web/incremental.ts): each input is fingerprinted first, and a template is
       *  re-run on an input only when something it can observe changed, its cached result expired, or it matched
       *  last time. A clean negative is cached only from a completed nuclei run with no request error for it. */
      incremental: z.object({
        enabled: z.boolean().default(true),
        /** How long a clean negative stays trusted, by what the template observes (see TemplateReach). */
        ttlHours: z.object({
          self: z.number().min(0).max(24 * 90).default(168),
          subpath: z.number().min(0).max(24 * 90).default(24),
          origin: z.number().min(0).max(24 * 90).default(24),
        }).default({}),
        /** Upper bound on separate nuclei invocations per side; smaller plans are merged (running more is always safe). */
        maxGroups: z.number().int().min(1).max(20).default(6),
        fingerprintConcurrency: z.number().int().min(1).max(16).default(4),
        fingerprintTimeoutMs: z.number().int().min(500).max(60_000).default(5_000),
      }).default({}),
    }).default({}),
    /** Secrets detection with Gitleaks. Reads files only; secret values are redacted by Gitleaks before anything is stored. */
    secrets: z.object({
      enabled: z.boolean().default(true),
      /** Directories skipped in workspace mode, in addition to Gitleaks' own default allowlist (which already skips node_modules, lockfiles, images). */
      exclude: z.array(z.string().regex(/^[^\s'"]+$/)).default(['dist', 'build', 'coverage', '.next', '.workbench']),
      /** Files larger than this are skipped by Gitleaks (and reported as such in coverage). */
      maxTargetMegabytes: z.number().int().min(1).max(500).default(10),
      timeoutMs: z.number().int().min(10_000).max(60 * 60_000).default(300_000),
      /** Explicit executable path; otherwise `gitleaks` is searched on PATH. Nothing is installed. */
      binary: z.string().optional(),
    }).default({}),
    /** Infrastructure-as-code checks with Checkov. Runs offline: no Prisma Cloud API key is passed, guideline download and update checks are off. */
    iac: z.object({
      enabled: z.boolean().default(true),
      /** Directories skipped when looking for IaC files and passed to Checkov as --skip-path. */
      exclude: z.array(z.string().regex(/^[\w.@-]+$/)).default(['node_modules', '.git', 'dist', 'build', 'coverage', '.terraform', '.serverless', '.workbench']),
      /** Checkov check ids to skip (e.g. CKV_DOCKER_2). Inline `checkov:skip` comments in the files are honoured as well. */
      skipChecks: z.array(z.string().regex(/^[A-Z0-9_]+$/)).default([]),
      timeoutMs: z.number().int().min(10_000).max(60 * 60_000).default(600_000),
      /** Explicit executable path; otherwise `checkov` is searched on PATH. Nothing is installed. */
      binary: z.string().optional(),
    }).default({}),
  }).default({}),
});
export type ProjectConfig = z.infer<typeof ProjectConfigSchema>;

export const CONFIG_FILE = 'workbench.config.json';

export interface LoadedConfig {
  config: ProjectConfig;
  /** Hash of the run section; command approval is bound to it. */
  runHash: string | null;
  source: 'file' | 'default';
  error?: string;
  /** Problems that did not stop the rest of the file from applying (e.g. a browser scenario that was skipped). */
  warnings?: string[];
}

const STEP_FORMS = '{"click": sel}, {"fill": {"selector", "value"}}, {"press": {"selector", "key"}}, {"waitFor": sel}, {"goto": path}, '
  + '{"expectVisible": sel}, {"expectHidden": sel}, {"expectText": {"selector", "contains"}}, {"expectNoHorizontalOverflow": true}, {"expectStatus": {"urlContains", "status"}}';

const valueAt = (raw: unknown, p: (string | number)[]) => p.reduce<unknown>((v, k) => (v && typeof v === 'object' ? (v as Record<string | number, unknown>)[k] : undefined), raw);

function describeIssue(raw: unknown, i: z.ZodIssue): string {
  const where = i.path.map((k) => (typeof k === 'number' ? `[${k}]` : `.${k}`)).join('').replace(/^\./, '');
  const isStep = i.path.length >= 5 && i.path[0] === 'browser' && i.path[1] === 'scenarios' && i.path[3] === 'steps' && i.path.length === 5;
  if (isStep && i.code === 'invalid_union') {
    return `${where}: ${JSON.stringify(valueAt(raw, i.path)).slice(0, 120)} is not a supported step (supported: ${STEP_FORMS})`;
  }
  return `${where}: ${i.message}`;
}

export function loadProjectConfig(root: string): LoadedConfig {
  const p = path.join(root, CONFIG_FILE);
  if (!fs.existsSync(p)) {
    return { config: ProjectConfigSchema.parse({}), runHash: null, source: 'default' };
  }
  let raw: any;
  try { raw = JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (err) { return { config: ProjectConfigSchema.parse({}), runHash: null, source: 'default', error: `${CONFIG_FILE} is not valid JSON: ${(err as Error).message}` }; }
  const done = (config: ProjectConfig, warnings?: string[]): LoadedConfig =>
    ({ config, runHash: config.run ? sha256(JSON.stringify(config.run)).slice(0, 16) : null, source: 'file', ...(warnings?.length ? { warnings } : {}) });

  const first = ProjectConfigSchema.safeParse(raw);
  if (first.success) return done(first.data);

  // An invalid browser scenario only disables that scenario; the run commands and security settings still apply.
  const scenarioIssues = new Map<number, z.ZodIssue[]>();
  const other: z.ZodIssue[] = [];
  for (const i of first.error.issues) {
    if (i.path[0] === 'browser' && i.path[1] === 'scenarios' && typeof i.path[2] === 'number') (scenarioIssues.get(i.path[2]) ?? scenarioIssues.set(i.path[2], []).get(i.path[2])!).push(i);
    else other.push(i);
  }
  if (!other.length && scenarioIssues.size && Array.isArray(raw?.browser?.scenarios)) {
    const kept = { ...raw, browser: { ...raw.browser, scenarios: raw.browser.scenarios.filter((_: unknown, idx: number) => !scenarioIssues.has(idx)) } };
    const second = ProjectConfigSchema.safeParse(kept);
    if (second.success) {
      return done(second.data, [...scenarioIssues].map(([idx, iss]) =>
        `browser scenario ${JSON.stringify(raw.browser.scenarios[idx]?.id ?? idx)} was skipped: ${iss.map((x) => describeIssue(raw, x)).join('; ')}`));
    }
  }
  return { config: ProjectConfigSchema.parse({}), runHash: null, source: 'default', error: `${CONFIG_FILE} is invalid: ${first.error.issues.map((i) => describeIssue(raw, i)).join('; ')}` };
}

export interface ServiceConfig {
  host: string;
  port: number;
  mongoUri: string;
  mongoDb: string;
  dataDir: string;
  dashboardDir: string;
}

export function serviceConfig(overrides: Partial<ServiceConfig> = {}): ServiceConfig {
  const dataHome = process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share');
  return {
    host: '127.0.0.1',
    port: Number(process.env.WORKBENCH_PORT || 4317),
    mongoUri: process.env.WORKBENCH_MONGO_URI || 'mongodb://127.0.0.1:27017',
    mongoDb: process.env.WORKBENCH_MONGO_DB || 'workbench',
    dataDir: process.env.WORKBENCH_DATA_DIR || path.join(dataHome, 'workbench'),
    dashboardDir: path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'dashboard', 'dist'),
    ...overrides,
  };
}
