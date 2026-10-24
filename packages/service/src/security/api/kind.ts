// API testing kind: Schemathesis against a workbench-started local copy of the project.
// Authorisation: security.api.allowActiveTesting must be true AND the run must be confirmed in the dashboard.
// The only target is the local copy the workbench builds and starts from a snapshot of the workspace with the
// approved run commands; arbitrary URLs are not accepted.
import fs from 'node:fs';
import path from 'node:path';
import type { Readiness, ToolRunRecord } from '../types.js';
import { probeBinary } from '../readiness.js';
import type { KindRunResult, ScanKind } from '../scan/types.js';
import { schemaFromFile, schemaFromGraph, type PreparedSchema } from './openapi.js';
import { displayArgs, parseSchemathesisVersion, readEvents, readRunSummary, schemathesisArgs } from './schemathesis.js';

const TOOL = 'schemathesis';
const LIMITATIONS = [
  'Sends generated and malformed requests to the local copy of the app; requests that change data are only sent for methods listed in security.api.methods.',
  'A graph-derived schema has no types or response contracts, so mostly server errors (5xx) are detected.',
  'Only endpoints the code graph resolves (Express routes with known mount prefixes) are tested.',
];

function record(rd: Readiness | undefined, patch: Partial<ToolRunRecord>): ToolRunRecord {
  return {
    tool: TOOL, displayName: 'Schemathesis', version: rd?.version ?? null, readiness: rd?.state ?? 'not_installed', selected: false, status: 'skipped',
    reason: null, exitCode: null, durationMs: null, observationCount: null, stderrTail: null, reportRef: null, reportSha256: null, notes: [],
    limitations: LIMITATIONS, networkHosts: [], ...patch,
  };
}

export const apiKind: ScanKind = {
  id: 'api', category: 'api_testing', label: 'API testing', findingSource: 'api',
  description: 'Schema-driven API testing with Schemathesis against a local copy of the app started by the workbench.',
  dynamic: true, modes: ['active'], activeModes: ['active'],
  tools: [{
    id: TOOL, displayName: 'Schemathesis', networkHosts: [], limitations: LIMITATIONS,
    readiness: async ({ cfg, exec, which, root }) => {
      const r = await probeBinary({ tool: TOOL, names: ['schemathesis', 'st'], explicit: cfg.security.api.binary, versionArgs: ['--version'], parseVersion: parseSchemathesisVersion, exec, which, cwd: root });
      if (r.state === 'ready' && Number(r.version!.split('.')[0]) < 4) return { ...r, state: 'not_functional', reason: `Schemathesis ${r.version} found; this integration reads the report format of version 4.x` };
      return r;
    },
  }],
  enabled: (cfg) => cfg.security.api.enabled,
  preconditions: (cfg, opts) => {
    const r: string[] = [];
    if (!cfg.security.api.allowActiveTesting) r.push('active API testing is not authorised: set security.api.allowActiveTesting to true in workbench.config.json');
    if (!opts.confirmActive) r.push('confirm in the dashboard that you are authorised to test this application');
    return r;
  },

  async run(ctx): Promise<KindRunResult> {
    const cfg = ctx.cfg.security.api;
    const rd = ctx.readiness.find((x) => x.tool === TOOL);
    const notes: string[] = [];
    const fail = (status: KindRunResult['coverage']['status'], reason: string, tools: ToolRunRecord[], detail: Record<string, unknown> = {}): KindRunResult =>
      ({ tools, observations: [], coverage: { status, reason, detail }, reports: [], notes, inScope: () => false });

    if (!rd || rd.state !== 'ready') return fail('unavailable', `Schemathesis is not usable: ${rd?.reason ?? 'readiness not checked'}`, [record(rd, { status: 'unavailable', reason: rd?.reason ?? null })]);

    // 1. schema
    let schema: PreparedSchema;
    const useFile = cfg.schema.source === 'file' || (cfg.schema.source === 'auto' && !!cfg.schema.path);
    try {
      if (useFile) {
        if (!cfg.schema.path) throw new Error('security.api.schema.source is "file" but no schema.path is set');
        schema = schemaFromFile(ctx.root, cfg.schema.path, ctx.graph, cfg.methods);
      } else {
        if (!ctx.graph) throw new Error('no code graph is available yet; wait for analysis to finish');
        schema = schemaFromGraph(ctx.graph, cfg.methods);
      }
    } catch (e) {
      return fail('failed', `could not prepare an API schema: ${(e as Error).message}`, [record(rd, { status: 'skipped', reason: 'no schema' })]);
    }
    notes.push(...schema.notes);
    const schemaDetail = { schemaSource: schema.source, schemaFile: schema.schemaFile, operations: schema.operations.map((o) => o.key), excluded: schema.excluded };
    if (!schema.operations.length) {
      return fail('not_run', `no API operations to test (${schema.excluded.length} excluded: ${schema.excluded.slice(0, 3).map((x) => `${x.key}: ${x.reason}`).join('; ')})`, [record(rd, { status: 'skipped', reason: 'no operations' })], schemaDetail);
    }
    const schemaPath = schema.source === 'file' ? path.resolve(ctx.root, schema.schemaFile!) : path.join(ctx.runDir, 'openapi.json');
    if (schema.source === 'graph') fs.writeFileSync(schemaPath, JSON.stringify(schema.document, null, 2));

    // 2. disposable local target
    let target;
    try { target = await ctx.startTarget(ctx.signal); }
    catch (e) {
      const err = e as Error & { step?: string; output?: string };
      return { ...fail('failed', `the local copy of the app did not start (${err.step ?? 'start'}): ${err.message}`, [record(rd, { status: 'skipped', reason: 'target did not start' })], schemaDetail), target: null };
    }

    // 3. run
    const runJson = path.join(ctx.runDir, 'schemathesis-run.json');
    const ndjson = path.join(ctx.runDir, 'schemathesis-events.ndjson');
    const args = schemathesisArgs({ schema: schemaPath, baseUrl: target.url, cfg, runJson, ndjson });
    ctx.onTool(TOOL, 'running');
    let exec;
    try {
      exec = await ctx.exec(rd.binary!, args, { cwd: ctx.runDir, timeoutMs: cfg.timeoutMs, maxOutputBytes: 4 * 1024 * 1024, signal: ctx.signal, localOnly: true });
    } finally {
      ctx.onTool(TOOL, 'done');
      await target.stop();
    }
    const targetInfo = { url: target.url, snapshotId: target.snapshotId, contentHash: target.contentHash, log: target.log() };
    const reports: KindRunResult['reports'] = [];
    const base = { selected: true, exitCode: exec.exitCode, durationMs: exec.durationMs, stderrTail: exec.stderrTail ? exec.stderrTail.slice(-2000) : null, notes: [`command: ${path.basename(rd.binary!)} ${displayArgs(args).join(' ')}`] };

    if (exec.spawnError || exec.timedOut || exec.cancelled) {
      const status = exec.cancelled ? 'cancelled' : exec.timedOut ? 'timed_out' : 'failed';
      const reason = exec.spawnError ? `could not start Schemathesis: ${exec.spawnError}` : exec.timedOut ? `timed out after ${Math.round(cfg.timeoutMs / 1000)}s` : 'cancelled';
      return { ...fail('failed', reason, [record(rd, { ...base, status, reason })], schemaDetail), target: targetInfo };
    }
    const summaryText = fs.existsSync(runJson) ? fs.readFileSync(runJson, 'utf8') : null;
    const eventsText = fs.existsSync(ndjson) ? fs.readFileSync(ndjson, 'utf8') : null;
    if (summaryText) reports.push({ tool: TOOL, name: 'run.json', content: summaryText });
    if (eventsText) reports.push({ tool: TOOL, name: 'events.ndjson', content: eventsText });
    if (schema.source === 'graph') reports.push({ tool: TOOL, name: 'openapi.json', content: JSON.stringify(schema.document, null, 2) });
    const summary = summaryText ? readRunSummary(summaryText) : { error: `Schemathesis wrote no run report (exit ${exec.exitCode})${exec.stdout ? `: ${exec.stdout.trim().split('\n').slice(-3).join(' ')}` : ''}` };
    if ('error' in summary) {
      return { ...fail('failed', summary.error, [record(rd, { ...base, status: 'failed', reason: summary.error })], schemaDetail), reports, target: targetInfo };
    }
    const events = eventsText ? readEvents(eventsText, { toolVersion: summary.version ?? rd.version, headerNames: Object.keys(cfg.headers) }) : null;
    if (!events) {
      return { ...fail('failed', 'Schemathesis wrote no event stream, so failures cannot be read with their evidence', [record(rd, { ...base, status: 'failed', reason: 'missing NDJSON report' })], schemaDetail), reports, target: targetInfo };
    }

    const op = summary.operations;
    const toolNotes = [...base.notes];
    if (events.malformedLines) toolNotes.push(`${events.malformedLines} malformed NDJSON line(s) ignored`);
    if (summary.errors.length) toolNotes.push(`${summary.errors.length} error(s) during the run: ${summary.errors.slice(0, 2).join(' | ')}`);
    const incomplete = !summary.complete || (summary.stopReason !== null && summary.stopReason !== 'completed');
    const toolStatus: ToolRunRecord['status'] = op.tested === 0 ? 'inconclusive' : 'completed';
    const coverageStatus = op.tested === 0 ? 'failed' : (incomplete || op.errored > 0 || op.tested < op.selected) ? 'partial' : 'covered';
    const tested = new Set(events.testedOperations);
    return {
      tools: [record(rd, {
        ...base, status: toolStatus, version: summary.version ?? rd.version,
        reason: op.tested === 0 ? 'no operation was tested' : incomplete ? `run did not complete (stop reason: ${summary.stopReason})` : null,
        observationCount: toolStatus === 'completed' ? events.observations.length : null, notes: toolNotes,
      })],
      observations: toolStatus === 'completed' ? events.observations : [],
      coverage: {
        status: coverageStatus,
        reason: coverageStatus === 'covered' ? null : coverageStatus === 'failed' ? 'Schemathesis tested no operation' : `tested ${op.tested} of ${op.selected} operation(s), ${op.errored} errored${incomplete ? `, stop reason ${summary.stopReason}` : ''}`,
        detail: { ...schemaDetail, tested: events.testedOperations, counts: op, generated: summary.generated, phases: summary.phases, checks: cfg.checks, methods: cfg.methods, seed: summary.seed, errors: summary.errors.slice(0, 10) },
      },
      reports, notes, target: targetInfo,
      inScope: (f) => !!f.location?.operation && tested.has(f.location.operation),
    };
  },
};
