import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
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
}

export function loadProjectConfig(root: string): LoadedConfig {
  const p = path.join(root, CONFIG_FILE);
  if (!fs.existsSync(p)) {
    return { config: ProjectConfigSchema.parse({}), runHash: null, source: 'default' };
  }
  try {
    const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
    const config = ProjectConfigSchema.parse(raw);
    const runHash = config.run ? sha256(JSON.stringify(config.run)).slice(0, 16) : null;
    return { config, runHash, source: 'file' };
  } catch (err) {
    const msg = err instanceof z.ZodError ? err.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ') : String(err);
    return { config: ProjectConfigSchema.parse({}), runHash: null, source: 'default', error: `${CONFIG_FILE} is invalid: ${msg}` };
  }
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
    dashboardDir: path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..', 'dashboard', 'dist'),
    ...overrides,
  };
}
