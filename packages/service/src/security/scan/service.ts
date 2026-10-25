// One service instance per scan kind per project. Runs the kind in the background, stores raw reports on disk
// (MongoDB keeps references + hashes), records immutable per-run observations, and maintains canonical findings
// in graph_findings. Rules shared by every category:
//  - counts exist only for scopes that were actually covered; unavailable/failed/skipped runs have counts: null
//  - a finding absent from a later run becomes "not_currently_observed" only when a tool that reported it
//    completed again and the run covered the finding's location; it is never auto-"resolved"
//  - a finding reported again after that is flagged as a potential regression
import fs from 'node:fs';
import path from 'node:path';
import type { Store } from '../../store/mongo.js';
import type { ProjectConfig } from '../../config.js';
import type { Graph } from '../../analyzer/types.js';
import { GraphIndex } from '../../analyzer/query.js';
import { newId, sha256, shortHash } from '../../util.js';
import { log } from '../../log.js';
import type { Exec, Readiness, Which } from '../types.js';
import { execTool, which as defaultWhich } from '../exec.js';
import { SEVERITY_RANK_EXT } from '../deps/severity.js';
import { linkLocation } from './link.js';
import type { KindRunResult, ManagedTarget, ScanKind, ScanObservation, StartOptions } from './types.js';

export type KindRunStatus = 'running' | 'completed' | 'partial' | 'not_applicable' | 'unavailable' | 'failed' | 'cancelled' | 'not_run';

export interface ScanServiceContext {
  projectId: string;
  root: string;
  projectDir: string;
  store: Store;
  cfg: () => ProjectConfig;
  graph: () => Graph | null;
  graphVersion: () => number | null;
  sourceHash: () => string | null;
  emit: (kind: string, payload?: unknown) => void;
  /** Run commands configured and approved in the dashboard (needed to start a local copy of the app). */
  runApproved: () => { ok: boolean; reason: string | null };
  startTarget: (signal: AbortSignal) => Promise<ManagedTarget>;
  exec?: Exec;
  which?: Which;
}

const sevMax = (obs: ScanObservation[]) => obs.reduce((m, o) => (SEVERITY_RANK_EXT[o.severity] > SEVERITY_RANK_EXT[m] ? o.severity : m), obs[0]!.severity);

export class ScanService {
  job: { runId: string; startedAt: Date; tool: string | null; abort: AbortController } | null = null;
  lastRun: Record<string, unknown> | null = null;
  private cache: { at: number; key: string; value: Readiness[] } | null = null;
  readonly exec: Exec;
  readonly which: Which;

  constructor(readonly kind: ScanKind, private readonly ctx: ScanServiceContext) {
    this.exec = ctx.exec ?? execTool;
    this.which = ctx.which ?? defaultWhich;
  }

  async readiness(force = false): Promise<Readiness[]> {
    const cfg = this.ctx.cfg();
    const key = JSON.stringify(cfg.security);
    if (!force && this.cache && this.cache.key === key && Date.now() - this.cache.at < 60_000) return this.cache.value;
    const value = await Promise.all(this.kind.tools.map((t) => t.readiness({ cfg, exec: this.exec, which: this.which, root: this.ctx.root })));
    this.cache = { at: Date.now(), key, value };
    return value;
  }

  async tools(force = false) {
    const rd = await this.readiness(force);
    return this.kind.tools.map((t) => ({ ...rd.find((r) => r.tool === t.id)!, displayName: t.displayName, networkHosts: t.networkHosts, limitations: t.limitations }));
  }

  /** Why a run cannot start right now (shown before the user clicks Run). */
  blockers(opts: StartOptions = {}): string[] {
    const cfg = this.ctx.cfg();
    const reasons: string[] = [];
    if (!this.kind.enabled(cfg)) reasons.push(`${this.kind.label} is disabled in workbench.config.json`);
    reasons.push(...this.kind.preconditions(cfg, opts));
    if (this.kind.dynamic) { const a = this.ctx.runApproved(); if (!a.ok) reasons.push(a.reason!); }
    if (!this.ctx.store.available) reasons.push('MongoDB unavailable: results could not be recorded');
    if (this.job) reasons.push(`a ${this.kind.label} run is already in progress (${this.job.runId})`);
    return reasons;
  }

  status() {
    const cfg = this.ctx.cfg();
    return {
      kind: this.kind.id, category: this.kind.category, label: this.kind.label, description: this.kind.description,
      dynamic: this.kind.dynamic, modes: this.kind.modes, activeModes: this.kind.activeModes,
      enabled: this.kind.enabled(cfg),
      blockers: this.blockers({ confirmActive: true, mode: this.kind.modes[0] }),
      activeBlockers: this.kind.activeModes.length ? this.blockers({ confirmActive: true, mode: this.kind.activeModes[0] }) : [],
      job: this.job ? { runId: this.job.runId, startedAt: this.job.startedAt, tool: this.job.tool } : null,
      lastRun: this.lastRun ? { id: this.lastRun._id, status: this.lastRun.status, finishedAt: this.lastRun.finishedAt, counts: this.lastRun.counts ?? null } : null,
      readiness: this.cache?.value ?? null,
    };
  }

  async loadLastRun() {
    try {
      this.lastRun = await this.ctx.store.col('security_scan_runs').findOne({ projectId: this.ctx.projectId, category: this.kind.category, status: { $ne: 'running' } }, { sort: { startedAt: -1 } });
    } catch { /* store unavailable */ }
  }

  cancel(): boolean {
    if (!this.job) return false;
    this.job.abort.abort();
    return true;
  }

  async start(opts: StartOptions = {}, trigger = 'manual'): Promise<{ runId: string }> {
    const mode = opts.mode ?? this.kind.modes[0];
    if (mode && !this.kind.modes.includes(mode)) throw Object.assign(new Error(`unknown mode '${mode}' (expected ${this.kind.modes.join(', ')})`), { status: 400 });
    const o = { ...opts, mode };
    const blockers = this.blockers(o);
    if (blockers.length) throw Object.assign(new Error(blockers.join('; ')), { status: this.job ? 409 : 400, reasons: blockers });
    const cfg = this.ctx.cfg();
    const runs = this.ctx.store.col('security_scan_runs');
    const runId = newId('sec');
    const startedAt = new Date();
    const active = !!mode && this.kind.activeModes.includes(mode);
    await runs.insertOne({
      _id: runId as never, projectId: this.ctx.projectId, category: this.kind.category, kind: this.kind.id, trigger, status: 'running', startedAt,
      mode: mode ?? null, active, authorization: active ? { confirmedInDashboard: !!opts.confirmActive, at: startedAt } : null,
      graphVersion: this.ctx.graphVersion(), sourceHash: this.ctx.sourceHash(), configSecurity: redactCfg(cfg.security),
    });
    const abort = new AbortController();
    this.job = { runId, startedAt, tool: null, abort };
    this.ctx.emit('security', { kind: this.kind.id, runId, status: 'running' });
    void this.execute(runId, o, abort).catch(async (e) => {
      log.error(`${this.kind.label} run ${runId} crashed: ${(e as Error).stack ?? e}`);
      await runs.updateOne({ _id: runId as never }, { $set: { status: 'failed', finishedAt: new Date(), counts: null, error: String((e as Error).message ?? e).slice(0, 500) } }).catch(() => {});
    }).finally(async () => {
      this.job = null;
      await this.loadLastRun();
      this.ctx.emit('security', { kind: this.kind.id, runId, status: 'finished' });
      this.ctx.emit('findings');
    });
    return { runId };
  }

  private async execute(runId: string, opts: StartOptions, abort: AbortController) {
    const store = this.ctx.store;
    const runDir = path.join(this.ctx.projectDir, 'security', runId);
    fs.mkdirSync(runDir, { recursive: true });
    const readiness = await this.readiness(true);
    const graph = this.ctx.graph();
    let result: KindRunResult;
    let error: string | null = null;
    try {
      result = await this.kind.run({
        root: this.ctx.root, runDir, cfg: this.ctx.cfg(), graph, exec: this.exec, which: this.which, signal: abort.signal, readiness,
        startTarget: this.ctx.startTarget, options: opts,
        onTool: (tool, phase) => { if (this.job) this.job.tool = phase === 'running' ? tool : null; this.ctx.emit('security', { kind: this.kind.id, runId, tool, phase }); },
      });
    } catch (e) {
      error = String((e as Error).message ?? e).slice(0, 1000);
      result = { tools: [], observations: [], coverage: { status: 'failed', reason: error, detail: {} }, reports: [], notes: [], inScope: () => false };
    }

    for (const r of result.reports) {
      const file = path.join(runDir, `${r.tool}-${r.name}`.replace(/[^\w.-]+/g, '_'));
      fs.writeFileSync(file, r.content);
      const rec = result.tools.find((t) => t.tool === r.tool);
      if (rec && !rec.reportRef) { rec.reportRef = path.relative(this.ctx.projectDir, file); rec.reportSha256 = sha256(r.content); }
      else if (rec) rec.notes.push(`also stored: ${path.relative(this.ctx.projectDir, file)} (sha256 ${sha256(r.content).slice(0, 16)}…)`);
    }

    const cancelled = abort.signal.aborted;
    const cov = result.coverage;
    const status: KindRunStatus = cancelled ? 'cancelled'
      : cov.status === 'covered' ? 'completed'
      : cov.status === 'partial' ? 'partial'
      : cov.status === 'not_applicable' ? 'not_applicable'
      : cov.status === 'unavailable' ? 'unavailable'
      : cov.status === 'not_run' ? 'not_run' : 'failed';
    const scanned = status === 'completed' || status === 'partial';
    const sync = scanned ? await this.syncFindings(runId, result, graph) : null;

    await store.col('security_scan_runs').updateOne({ _id: runId as never }, {
      $set: {
        status, finishedAt: new Date(), tools: result.tools, coverage: cov, readiness, notes: result.notes, error,
        target: result.target ? { url: result.target.url, snapshotId: result.target.snapshotId, contentHash: result.target.contentHash, log: result.target.log?.slice(-8000) } : null,
        counts: scanned && sync ? sync.counts : null,
        findingIds: sync?.findingIds ?? [],
      },
    });
  }

  private async syncFindings(runId: string, result: KindRunResult, graph: Graph | null) {
    const store = this.ctx.store;
    const col = store.col('graph_findings');
    const obsCol = store.col('security_observations');
    const vr = store.col('verification_records');
    const now = new Date();
    const projectId = this.ctx.projectId;
    const source = this.kind.findingSource;
    const completed: string[] = result.tools.filter((t) => t.status === 'completed').map((t) => t.tool);
    const ix = graph ? new GraphIndex(graph) : null;
    const counts = { total: 0, bySeverity: {} as Record<string, number>, byTool: {} as Record<string, number>, new: 0, recurring: 0, regressions: 0, notCurrentlyObserved: 0, notRechecked: 0, graphLinked: 0 };
    const findingIds: string[] = [];

    const groups = new Map<string, ScanObservation[]>();
    for (const o of result.observations) (groups.get(o.dedupeKey) ?? groups.set(o.dedupeKey, []).get(o.dedupeKey)!).push(o);

    for (const [key, obs] of groups) {
      const first = obs[0]!;
      const id = `${this.kind.id}_${shortHash(`${projectId}|${this.kind.id}|${key}`, 16)}`;
      findingIds.push(id);
      const existing = await col.findOne({ _id: id as never });
      const link = linkLocation(graph, first.location, ix ?? undefined);
      const tools = [...new Set(obs.map((o) => o.tool))];
      const severity = sevMax(obs);
      const ruleIds = [...new Set(obs.map((o) => `${o.tool}:${o.ruleId}`))];
      const ids = [...new Set(obs.flatMap((o) => o.ids))];
      const cwe = [...new Set(obs.flatMap((o) => o.cwe))];
      const labels = [this.kind.dynamic ? 'observed_at_runtime' : 'scanner_detected', ...(link.how ? ['graph_linked'] : []), ...(link.sinks.length ? ['reaches_sensitive_sink'] : [])];
      const where = first.location.operation ?? (first.location.url ? `${first.location.method ?? ''} ${first.location.url}`.trim() : first.location.file ? `${first.location.file}:${first.location.line ?? ''}` : 'project');
      const explanation = [
        `${tools.join(' and ')} reported ${[...new Set(obs.map((o) => (o.ruleName && o.ruleName !== o.ruleId ? `${o.ruleId} (${o.ruleName})` : o.ruleId)))].join(', ')} at ${where}.`,
        `Severity as reported: ${obs.map((o) => `${o.tool}: ${o.originalSeverity ?? 'not supplied'}${o.confidence ? ` (confidence ${o.confidence})` : ''}`).join('; ')}.`,
        ...(first.message ? [first.message] : []),
        ...(link.how ? [`Code link: ${link.how}.`] : [`Code link: none (no matching ${first.location.file ? 'function' : 'endpoint'} in the code graph).`]),
        ...(link.sinks.length ? [`The linked code reaches ${link.sinks.length} sensitive call(s) in the graph: ${link.sinks.map((s) => ix?.nodes.get(s)?.label ?? s).slice(0, 5).join(', ')}.`] : []),
      ];
      const reopened = existing && existing.status !== 'open';
      await col.updateOne({ _id: id as never }, {
        $set: {
          projectId, source, category: this.kind.category, classification: this.kind.dynamic ? 'observed' : 'scanner_detected', labels,
          severity, severityRank: SEVERITY_RANK_EXT[severity], title: first.title, explanation,
          nodes: link.nodes, edges: [], paths: link.paths, locations: link.locations.length ? link.locations : (first.location.file && first.location.line ? [{ file: first.location.file, line: first.location.line }] : []),
          evidence: { ...first.evidence, severityByTool: obs.map((o) => ({ tool: o.tool, original: o.originalSeverity, confidence: o.confidence })), endpointId: link.endpointId, functionId: link.functionId, linkHow: link.how },
          location: first.location, ruleIds, ids, cwe, references: [...new Set(obs.flatMap((o) => o.references))].slice(0, 20),
          suggestedNextStep: suggestion(this.kind.id, first),
          confidence: first.confidence ?? 'unknown',
          confidenceNote: 'Confidence as reported by the tool. It is not a statement about exploitability.',
          limitations: limitationsFor(this.kind.id, link),
          lastTools: tools, status: 'open', resolvedAt: null, lastSeenAt: now, lastSeenSecurityRunId: runId, graphVersionAtScan: this.ctx.graphVersion(),
          ...(reopened ? { potentialRegression: true } : {}),
        },
        $addToSet: { scanners: { $each: tools } },
        $setOnInsert: { firstSeenAt: now, firstSeenSecurityRunId: runId, ...(reopened ? {} : { potentialRegression: false }) },
      }, { upsert: true });
      if (!existing) {
        counts.new++;
        await vr.insertOne({ _id: newId('ver') as never, projectId, findingId: id, action: 'observed', at: now, securityRunId: runId, result: tools.join(', '), notes: first.title });
      } else {
        counts.recurring++;
        if (reopened) {
          counts.regressions++;
          await vr.insertOne({ _id: newId('ver') as never, projectId, findingId: id, action: 'potential_regression', at: now, securityRunId: runId, result: `reported again by ${tools.join(', ')} after being ${existing.status}`, notes: first.title });
        }
      }
      counts.total++;
      if (link.how) counts.graphLinked++;
      counts.bySeverity[severity] = (counts.bySeverity[severity] ?? 0) + 1;
      for (const t of tools) counts.byTool[t] = (counts.byTool[t] ?? 0) + 1;

      const docs = obs.map((o) => ({
        _id: `obs_${shortHash(`${runId}|${o.tool}|${id}|${o.ruleId}|${JSON.stringify(o.location)}`, 20)}`,
        projectId, runId, findingId: id, category: this.kind.category, tool: o.tool, toolVersion: o.toolVersion, observedAt: now,
        ruleId: o.ruleId, ruleName: o.ruleName, title: o.title, message: o.message, severity: o.severity, originalSeverity: o.originalSeverity,
        confidence: o.confidence, cwe: o.cwe, ids: o.ids, references: o.references, location: o.location, evidence: o.evidence,
        advisoryId: o.ruleId,
      }));
      try { await obsCol.insertMany(docs as never[], { ordered: false }); }
      catch (e) { if ((e as { code?: number }).code !== 11000 && !String((e as Error).message).includes('E11000')) throw e; }
    }

    const seen = new Set(findingIds);
    const prior = await col.find({ projectId, source, status: 'open' }).toArray();
    for (const f of prior) {
      const fid = f._id as unknown as string;
      if (seen.has(fid)) continue;
      const rechecked = (f.scanners as string[] | undefined)?.some((t) => completed.includes(t)) && result.inScope({ location: f.location, scanners: f.scanners });
      if (!rechecked) { counts.notRechecked++; continue; }
      await col.updateOne({ _id: f._id }, { $set: { status: 'not_currently_observed', notObservedSince: now } });
      await vr.insertOne({ _id: newId('ver') as never, projectId, findingId: fid, action: 'not_currently_observed', at: now, securityRunId: runId, result: `not reported by ${completed.join(', ')} in a run that covered its location`, notes: f.title });
      counts.notCurrentlyObserved++;
    }
    return { counts, findingIds };
  }
}

function redactCfg(sec: ProjectConfig['security']) {
  const s = JSON.parse(JSON.stringify(sec)) as Record<string, any>;
  if (s.api?.headers) s.api.headers = Object.fromEntries(Object.keys(s.api.headers).map((k) => [k, '[redacted]']));
  if (s.web?.headers) s.web.headers = Object.fromEntries(Object.keys(s.web.headers).map((k) => [k, '[redacted]']));
  return s;
}

function suggestion(kind: string, o: ScanObservation): string {
  switch (kind) {
    case 'api': return `Replay the recorded request against a local copy, find why ${o.location.operation ?? 'the operation'} returns this response, and add a regression test with that input.`;
    case 'web':
    case 'template': return 'Reproduce with the recorded request/evidence on a local copy, confirm the behaviour, then fix and re-run the scan.';
    case 'code': return `Review ${o.location.file}:${o.location.line} against rule ${o.ruleId}; fix or document why it is safe.`;
    case 'secrets': return 'Treat the value as exposed: rotate it at its issuer, remove it from the code (and history if committed), and load it from the environment.';
    case 'iac': return `Apply the configuration change described by ${o.ruleId}, or record a justified suppression.`;
    default: return 'Review the evidence and re-run the scan after a fix.';
  }
}

function limitationsFor(kind: string, link: { how: string | null; sinks: string[] }): string[] {
  const common = link.how ? ['The code link is structural (route/location match). It does not prove which code produced the behaviour.'] : [];
  switch (kind) {
    case 'api': return ['The failure was observed against a local copy of the app with generated input. A server error shows unhandled input, not that the input is exploitable.', ...common];
    case 'web': return ['Alerts come from ZAP rules and include false positives; check the evidence before acting. Passive alerts are based on observed responses only.', ...common];
    case 'template': return ['Template matches show that a response matched a template\'s matchers; review the matched evidence before treating it as confirmed.', ...common];
    case 'code': return ['Static pattern match. The rule does not know whether input is attacker-controlled in practice.', ...common];
    case 'secrets': return ['Pattern/entropy match. The value may be a test fixture or already revoked; the scanner cannot tell.', ...common];
    case 'iac': return ['Configuration check against a policy; whether it matters depends on how the infrastructure is deployed.', ...common];
    default: return common;
  }
}
