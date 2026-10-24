// Web security scanning (nuclei) for one project. Runs are persisted in security_scan_runs (category 'web_dast'),
// every per-run result in security_observations, and canonical findings in graph_findings with source 'web'.
//
// Two target modes:
//  - 'snapshots': the baseline snapshot and a fresh snapshot of the current files are built and started in throwaway
//    copies (exactly as Website comparison does) and each is scanned on its own loopback port. This gives a real
//    baseline-vs-current security comparison of the same code the website comparison exercises.
//  - 'url': an already running application at a loopback URL or an explicitly authorized origin. The scan is
//    compared with the previous completed scan of the same target, template set and endpoint list.
//
// Each scan targets the root URL plus the app's own GET routes from the code graph (without path parameters), so
// templates also probe the routes the code actually serves. While nuclei runs, its statistics, log lines and each
// result as it arrives are kept as a live activity feed (and stored with the run afterwards).
//
// Incremental scanning (incremental.ts, on by default): every input is fingerprinted first and only the (input,
// template) pairs whose observable context changed, whose cached clean result expired, or that matched last time
// are sent to nuclei, in as few invocations as possible. The rest are clean negatives from earlier completed scans.
//
// Honesty rules: a failed, cancelled, timed-out or incomplete scan never makes a finding "not currently observed";
// a finding is only considered absent when a completed scan of the same scope ran the template that reported it
// against the same input URL (pairs with a finding, of any status, are therefore always re-run, never cached). Scanner
// results are evidence of a matched template, not proof of exploitability.
import fs from 'node:fs';
import path from 'node:path';
import type { Store } from '../../store/mongo.js';
import type { Graph } from '../../analyzer/types.js';
import type { RunningApp } from '../../runner.js';
import { newId, sha256, shortHash } from '../../util.js';
import { log } from '../../log.js';
import type { Exec, ExecResult, Which } from '../types.js';
import { execTool, which as defaultWhich } from '../exec.js';
import { SEVERITY_RANK_EXT } from '../deps/severity.js';
import {
  buildArgs, checkNuclei, effectiveSettings, NUCLEI_ENV, parseErrorLog, parseNucleiJsonl, parseStatsLine, PROFILE_TEMPLATES, readStderr, SETUP_INSTRUCTIONS, targetHostPort,
  type EffectiveSettings, type NucleiConfig, type NucleiReadiness, type ScanProfile, type ScanStats, type StderrFacts, type WebObservation,
} from './nuclei.js';
import { selectTemplates, stageTemplates, type TemplateSelection } from './templates.js';
import { authorizeTarget, probeTarget, type AuthorizedTarget } from './target.js';
import { correlate, type WebCorrelation } from './correlate.js';
import { redactUrl } from './redact.js';
import { fingerprintInputs, throttle, type EndpointFingerprint, type SiteFingerprint } from './fingerprint.js';
import {
  cacheScope, codeHashes, inputOfUrl, knownFindingPairs, loadState, pairKey, planScan, recordResults, recordSurface, scanContextHash,
  type CodeHashes, type LoadedState, type PlanTemplate, type ScanPlan,
} from './incremental.js';

export type WebRunStatus = 'running' | 'completed' | 'incomplete' | 'failed' | 'cancelled' | 'unavailable';
export type WebSideStatus = 'pending' | 'starting' | 'scanning' | 'completed' | 'incomplete' | 'failed' | 'timed_out' | 'cancelled';
export type SideName = 'baseline' | 'candidate' | 'target';

/** Supplied by ProjectSession: builds/starts the baseline and current snapshots the same way Website comparison does. */
export interface SnapshotTargets {
  baseline: { snapshotId: string; contentHash: string };
  candidate: { snapshotId: string; contentHash: string };
  candidateGraph: Graph;
  baselineGraph?: Graph | null;
  start(side: 'baseline' | 'candidate', signal: AbortSignal, onPhase: (phase: string) => void): Promise<RunningApp & { cleanup: () => void }>;
  isStale(): boolean;
  notes: string[];
}

export interface WebScanContext {
  projectId: string;
  projectDir: string;
  store: Store;
  cfg: () => NucleiConfig;
  graph: () => Graph | null;
  graphVersion: () => number | null;
  sourceHash: () => string | null;
  /** readiness for snapshot mode (run approval, baseline) */
  snapshotReadiness: () => { ok: boolean; reasons: string[] };
  prepareSnapshots: () => Promise<SnapshotTargets>;
  emit: (kind: string, payload?: unknown) => void;
  exec?: Exec;
  which?: Which;
  fetch?: typeof fetch;
}

export interface StartRequest { mode: 'snapshots' | 'url'; url?: string; trigger?: string; profile?: ScanProfile; /** ignore the incremental cache (it is refreshed) */ fullScan?: boolean }

export interface ActivityEvent { at: string; side: SideName | null; kind: 'phase' | 'info' | 'match' | 'warn' | 'error' | 'command'; text: string; severity?: string; templateId?: string }

interface SideRecord {
  status: WebSideStatus;
  phase: string | null;
  url: string | null;
  inputs: string[];                  // endpoint paths scanned (root + graph routes)
  startedAt: Date | null;
  finishedAt: Date | null;
  durationMs: number | null;
  exitCode: number | null;
  templatesLoaded: number | null;
  targetsLoaded: number | null;
  stats: ScanStats | null;           // nuclei's final statistics (requests sent, errors, ...)
  findings: number | null;           // null unless the side produced a usable result
  bySeverity: Record<string, number> | null;
  malformedLines: number;
  outOfScope: { templateId: string; matchedAt: string }[];
  toolErrors: string[];
  warnings: string[];
  reason: string | null;
  command: string | null;
  stderrTail: string | null;
  appLog: string | null;
  reportRef: string | null;
  reportSha256: string | null;
  /** change detection, plan and cache effect of an incremental scan (null for a plain full scan) */
  incremental: Record<string, unknown> | null;
}

/** One nuclei invocation of a side (a subset of templates against a subset of inputs). */
interface GroupRun {
  status: WebSideStatus; reasons: string[]; inputs: string[]; templateIds: string[];
  r: ExecResult; facts: StderrFacts; matched: Set<string>; errored: Set<string>; attributed: boolean;
}

interface SideResult {
  status: WebSideStatus;
  observations: WebObservation[] | null;
  templatesVersion: string | null;
  /** did (template, input) run in this side's nuclei invocations; null when nothing ran */
  ran: ((templateId: string, input: string) => boolean) | null;
}

const emptySide = (): SideRecord => ({
  status: 'pending', phase: null, url: null, inputs: [], startedAt: null, finishedAt: null, durationMs: null, exitCode: null, templatesLoaded: null, targetsLoaded: null, stats: null,
  findings: null, bySeverity: null, malformedLines: 0, outOfScope: [], toolErrors: [], warnings: [], reason: null, command: null, stderrTail: null, appLog: null, reportRef: null, reportSha256: null, incremental: null,
});

const USABLE: WebSideStatus[] = ['completed', 'incomplete'];
const MAX_ACTIVITY = 400;

/** The app's own GET routes without path parameters, as URL paths (from one or more graphs). */
export function graphEndpointPaths(graphs: (Graph | null | undefined)[], max: number): string[] {
  const out = new Set<string>();
  for (const g of graphs) {
    for (const n of g?.nodes ?? []) {
      if (n.kind !== 'endpoint' || n.meta.mountResolved === false) continue;
      const m = String(n.meta.method ?? '').toUpperCase();
      const p = String(n.meta.path ?? '');
      if (!['GET', 'ALL'].includes(m) || !p.startsWith('/') || p === '/' || /[:*()?+]/.test(p)) continue;
      out.add(p.replace(/\/+$/, ''));
    }
  }
  return [...out].sort().slice(0, max);
}

interface Job {
  runId: string; startedAt: Date; side: SideName | null; phase: string | null; findingsSoFar: number; abort: AbortController;
  progress: ScanStats | null; activity: ActivityEvent[]; profile: string;
}

export class WebScanService {
  job: Job | null = null;
  lastRun: Record<string, unknown> | null = null;
  templateUpdate: { running: boolean; startedAt: Date; finishedAt: Date | null; ok: boolean | null; output: string } | null = null;
  private readinessCache: { at: number; key: string; value: NucleiReadiness } | null = null;
  private readonly exec: Exec;
  private readonly which: Which;
  private lastEmit = 0;

  constructor(private readonly ctx: WebScanContext) {
    this.exec = ctx.exec ?? execTool;
    this.which = ctx.which ?? defaultWhich;
  }

  async readiness(force = false): Promise<NucleiReadiness> {
    const cfg = this.ctx.cfg();
    const key = JSON.stringify([cfg.enabled, cfg.binary, cfg.templatesDir]);
    if (!force && this.readinessCache && this.readinessCache.key === key && Date.now() - this.readinessCache.at < 60_000) return this.readinessCache.value;
    const value = await checkNuclei(cfg, this.exec, this.which, this.ctx.projectDir);
    this.readinessCache = { at: Date.now(), key, value };
    return value;
  }

  /** Readiness + the vetted template set per profile + target options, for the dashboard. */
  async overview(force = false) {
    const cfg = this.ctx.cfg();
    const r = await this.readiness(force);
    const profiles: Record<string, ReturnType<typeof summarizeSelection> | null> = {};
    let templateError: string | null = null;
    if (r.templates.state === 'ready' && r.templates.dir) {
      const names: (ScanProfile | 'custom')[] = cfg.templates ? ['custom'] : ['quick', 'standard', 'full'];
      for (const p of names) {
        try { profiles[p] = summarizeSelection(this.select(r.templates.dir, p === 'custom' ? cfg.templates! : PROFILE_TEMPLATES[p])); }
        catch (e) { templateError = String((e as Error).message ?? e); profiles[p] = null; }
      }
    }
    const defaultProfile = cfg.templates ? 'custom' : cfg.profile;
    const templates = profiles[defaultProfile] ?? null;
    const snap = this.ctx.snapshotReadiness();
    const usable = r.state === 'ready' && r.templates.state === 'ready' && !!templates && templates.approved > 0;
    const graphEndpoints = cfg.includeGraphEndpoints ? graphEndpointPaths([this.ctx.graph()], cfg.maxGraphEndpoints) : [];
    return {
      readiness: r, templates, profiles, defaultProfile, templateError, usable,
      reasons: [
        ...(r.state !== 'ready' ? [r.reason ?? r.state] : []),
        ...(r.state === 'ready' && r.templates.state !== 'ready' ? [r.templates.reason ?? 'templates unavailable'] : []),
        ...(templates && templates.approved === 0 ? ['no template in the selected profile passed the safety checks'] : []),
        ...(templateError ? [templateError] : []),
      ],
      setup: usable ? [] : SETUP_INSTRUCTIONS,
      templateUpdate: this.templateUpdate,
      targets: {
        snapshots: snap,
        defaultTarget: cfg.defaultTarget ?? 'http://127.0.0.1:3000',
        authorizedTargets: cfg.authorizedTargets,
        graphEndpoints,
      },
      settings: { ...settingsOf(cfg, effectiveSettings(cfg, true)), remoteRateLimit: effectiveSettings(cfg, false).rateLimit },
      configFile: configFileNote(),
    };
  }

  private select(dir: string, templates: string[]): TemplateSelection {
    const cfg = this.ctx.cfg();
    return selectTemplates(dir, templates, { methods: cfg.methods, excludeTags: cfg.excludeTags, excludeIds: cfg.excludeIds, severities: cfg.severities }, cfg.maxTemplates);
  }

  status() {
    const cfg = this.ctx.cfg();
    const j = this.job;
    return {
      enabled: cfg.enabled,
      job: j ? { runId: j.runId, startedAt: j.startedAt, side: j.side, phase: j.phase, findingsSoFar: j.findingsSoFar, progress: j.progress, profile: j.profile, activity: j.activity.slice(-60) } : null,
      lastRun: this.lastRun ? { id: this.lastRun._id, status: this.lastRun.status, mode: this.lastRun.mode, finishedAt: this.lastRun.finishedAt } : null,
      readiness: this.readinessCache ? { state: this.readinessCache.value.state, version: this.readinessCache.value.version, templates: this.readinessCache.value.templates.state } : null,
      templateUpdate: this.templateUpdate ? { running: this.templateUpdate.running, ok: this.templateUpdate.ok } : null,
    };
  }

  async loadLastRun() {
    try {
      this.lastRun = await this.ctx.store.col('security_scan_runs').findOne({ projectId: this.ctx.projectId, category: 'web_dast', status: { $ne: 'running' } }, { sort: { startedAt: -1 } });
    } catch { /* store unavailable */ }
  }

  cancel(): boolean {
    if (!this.job) return false;
    this.job.abort.abort();
    return true;
  }

  /**
   * Download or update the public nuclei-templates with `nuclei -ut`. Only ever started by an explicit, confirmed user
   * action (never during a scan). Runs in the background; progress is reported through overview()/status().
   */
  async updateTemplates(): Promise<{ started: boolean }> {
    if (this.templateUpdate?.running) throw httpError(409, 'a template update is already running');
    if (this.job) throw httpError(409, 'wait for the running scan to finish before updating templates');
    const r = await this.readiness(true);
    if (r.state !== 'ready' || !r.binary) throw httpError(409, `nuclei is ${r.state.replace('_', ' ')}: ${r.reason}`);
    const cfg = this.ctx.cfg();
    const args = ['-ut', '-nc', ...(cfg.templatesDir ? ['-ud', cfg.templatesDir] : [])];
    this.templateUpdate = { running: true, startedAt: new Date(), finishedAt: null, ok: null, output: '' };
    this.ctx.emit('websec', { templateUpdate: 'running' });
    void this.exec(r.binary, args, { cwd: this.ctx.projectDir, timeoutMs: 15 * 60_000, maxOutputBytes: 4 * 1024 * 1024, stderrTailBytes: 8000 })
      .then((x) => {
        const out = `${x.stdout}\n${x.stderrTail}`.split('\n').filter((l) => l.trim() && !/sonic|^\s*[/_\\ ]+.*$|projectdiscovery\.io/.test(l)).slice(-30).join('\n');
        this.templateUpdate = { running: false, startedAt: this.templateUpdate!.startedAt, finishedAt: new Date(), ok: x.exitCode === 0 && !x.timedOut && !x.spawnError, output: x.spawnError ?? (x.timedOut ? 'timed out after 15 minutes' : out) };
      })
      .catch((e) => { this.templateUpdate = { running: false, startedAt: this.templateUpdate!.startedAt, finishedAt: new Date(), ok: false, output: String((e as Error).message ?? e) }; })
      .finally(() => { this.readinessCache = null; this.ctx.emit('websec', { templateUpdate: 'finished' }); });
    return { started: true };
  }

  /** Validate, persist and start a scan. Throws {status} errors for requests that must not start at all. */
  async start(req: StartRequest): Promise<{ runId: string; status: WebRunStatus }> {
    if (this.job) throw httpError(409, `a security scan is already running (${this.job.runId})`);
    if (this.templateUpdate?.running) throw httpError(409, 'templates are being updated; start the scan when the update has finished');
    const cfg = this.ctx.cfg();
    if (!cfg.enabled) throw httpError(400, 'nuclei scanning is disabled (security.nuclei.enabled = false)');
    let target: AuthorizedTarget | null = null;
    if (req.mode === 'url') {
      const chk = authorizeTarget(req.url ?? '', cfg.authorizedTargets);
      if (!chk.ok) throw httpError(400, `target not authorized: ${chk.reason}`);
      target = chk.target;
    } else {
      const snap = this.ctx.snapshotReadiness();
      if (!snap.ok) throw Object.assign(httpError(409, 'baseline/current snapshots cannot be started'), { reasons: snap.reasons });
    }
    const eff = effectiveSettings(cfg, target?.loopback ?? true, req.profile);
    const runs = this.ctx.store.col('security_scan_runs'); // StoreUnavailableError -> 503: results must be persisted
    const runId = newId('web');
    const startedAt = new Date();
    const r = await this.readiness(true);
    let selection: TemplateSelection | null = null;
    let unavailable: string | null = null;
    if (r.state !== 'ready') unavailable = `nuclei ${r.state.replace('_', ' ')}: ${r.reason}`;
    else if (r.templates.state !== 'ready' || !r.templates.dir) unavailable = `templates ${r.templates.state}: ${r.templates.reason}`;
    else {
      try { selection = this.select(r.templates.dir, eff.templates); } catch (e) { unavailable = `template selection failed: ${(e as Error).message}`; }
      if (selection && !selection.approved.length) unavailable = 'no template in the selected profile passed the safety checks';
    }
    const sideNames: SideName[] = req.mode === 'snapshots' ? ['baseline', 'candidate'] : ['target'];
    const doc = {
      _id: runId as never, projectId: this.ctx.projectId, category: 'web_dast', tool: 'nuclei', trigger: req.trigger ?? 'manual', mode: req.mode, profile: eff.profile,
      status: (unavailable ? 'unavailable' : 'running') as WebRunStatus, startedAt, confirmedAt: startedAt,
      acknowledgement: 'User confirmed that HTTP requests will be sent to the target and that they are authorized to test it.',
      toolVersion: r.version, binary: r.binary,
      target: target ? { url: target.url, origin: target.origin, loopback: target.loopback, scopeKey: target.scopeKey } : { scopeKey: 'snapshots', loopback: true },
      templateSet: selection ? templateSetDoc(selection, r) : { dir: r.templates.dir, version: r.templates.version, hash: null, approvedCount: 0 },
      settings: settingsOf(cfg, eff),
      sides: Object.fromEntries(sideNames.map((s) => [s, emptySide()])),
      graphVersion: this.ctx.graphVersion(), sourceHash: this.ctx.sourceHash(),
      ...(unavailable ? { finishedAt: startedAt, durationMs: 0, error: unavailable, setup: SETUP_INSTRUCTIONS } : {}),
    };
    await runs.insertOne(doc);
    if (unavailable) {
      await this.loadLastRun();
      this.ctx.emit('websec', { runId, status: 'unavailable' });
      return { runId, status: 'unavailable' };
    }
    const abort = new AbortController();
    this.job = { runId, startedAt, side: null, phase: 'preparing', findingsSoFar: 0, abort, progress: null, activity: [], profile: eff.profile };
    this.activity(null, 'phase', `Scan started (${eff.profile} profile, ${selection!.approved.length} vetted templates, ${selection!.rejected.length} excluded by the safety checks)`);
    this.ctx.emit('websec', { runId, status: 'running' });
    void this.execute(runId, req.mode, target, selection!, r, eff, abort, req.fullScan ? 'full scan requested: the cache was ignored and refreshed' : null).catch(async (e) => {
      log.error(`web scan ${runId} crashed: ${(e as Error).stack ?? e}`);
      await runs.updateOne({ _id: runId as never }, { $set: { status: 'failed', finishedAt: new Date(), error: String((e as Error).message ?? e).slice(0, 500) } }).catch(() => {});
    }).finally(async () => {
      await runs.updateOne({ _id: runId as never }, { $set: { activity: this.job?.activity.slice(-MAX_ACTIVITY) ?? [] } }).catch(() => {});
      this.job = null;
      await this.loadLastRun();
      this.ctx.emit('websec', { runId, status: 'finished' });
      this.ctx.emit('findings');
    });
    return { runId, status: 'running' };
  }

  private activity(side: SideName | null, kind: ActivityEvent['kind'], text: string, extra: Partial<ActivityEvent> = {}) {
    if (!this.job) return;
    this.job.activity.push({ at: new Date().toISOString(), side, kind, text: text.slice(0, 500), ...extra });
    if (this.job.activity.length > MAX_ACTIVITY * 2) this.job.activity.splice(0, this.job.activity.length - MAX_ACTIVITY);
    this.emitThrottled();
  }

  private emitThrottled(force = false) {
    const now = Date.now();
    if (!force && now - this.lastEmit < 700) return;
    this.lastEmit = now;
    if (this.job) this.ctx.emit('websec', { runId: this.job.runId, live: true });
  }

  private async setSide(runId: string, side: SideName, patch: Partial<SideRecord>) {
    const $set = Object.fromEntries(Object.entries(patch).map(([k, v]) => [`sides.${side}.${k}`, v]));
    await this.ctx.store.col('security_scan_runs').updateOne({ _id: runId as never }, { $set });
    if (this.job?.runId === runId) { this.job.side = side; if (patch.phase !== undefined) this.job.phase = patch.phase; }
    if (patch.phase) this.activity(side, 'phase', patch.phase);
    this.ctx.emit('websec', { runId, side, ...(patch.status ? { status: patch.status } : {}), ...(patch.phase ? { phase: patch.phase } : {}) });
  }

  private async execute(runId: string, mode: StartRequest['mode'], urlTarget: AuthorizedTarget | null, selection: TemplateSelection, readiness: NucleiReadiness, eff: EffectiveSettings, abort: AbortController, full: string | null) {
    const cfg = this.ctx.cfg();
    const runs = this.ctx.store.col('security_scan_runs');
    const runDir = path.join(this.ctx.projectDir, 'websec', runId);
    const staged = stageTemplates(selection, path.join(runDir, 'templates'));
    const notes: string[] = [];
    const results = new Map<SideName, WebObservation[]>();
    const ranBy = new Map<SideName, SideResult['ran']>();
    const sideStatus = new Map<SideName, WebSideStatus>();
    let snapshots: SnapshotTargets | null = null;
    let graph: Graph | null = this.ctx.graph();
    const scopeKey = urlTarget?.scopeKey ?? 'snapshots';
    let endpoints: string[] = [];
    let templatesVersion: string | null = readiness.templates.version;

    try {
      if (mode === 'snapshots') {
        await this.setSide(runId, 'baseline', { phase: 'snapshotting your current files' });
        snapshots = await this.ctx.prepareSnapshots();
        graph = snapshots.candidateGraph;
        notes.push(...snapshots.notes);
        await runs.updateOne({ _id: runId as never }, { $set: { 'target.baselineSnapshotId': snapshots.baseline.snapshotId, 'target.candidateSnapshotId': snapshots.candidate.snapshotId, 'target.baselineContentHash': snapshots.baseline.contentHash, 'target.candidateContentHash': snapshots.candidate.contentHash } });
        // Same endpoint list on both sides (union of both graphs) so the two scans are comparable.
        endpoints = cfg.includeGraphEndpoints ? graphEndpointPaths([snapshots.baselineGraph, snapshots.candidateGraph], cfg.maxGraphEndpoints) : [];
      } else {
        notes.push('Graph links and the scanned route list use the current working-tree graph; the running application may have been started from different code.');
        endpoints = cfg.includeGraphEndpoints ? graphEndpointPaths([graph], cfg.maxGraphEndpoints) : [];
      }
      const inputsHash = sha256(endpoints.join('\n')).slice(0, 16);
      await runs.updateOne({ _id: runId as never }, { $set: { 'target.endpoints': endpoints, 'target.inputsHash': inputsHash } });
      if (endpoints.length) this.activity(null, 'info', `Scanning the root URL plus ${endpoints.length} GET route(s) from the code graph: ${endpoints.slice(0, 12).join(', ')}${endpoints.length > 12 ? ', …' : ''}`);

      const sides: SideName[] = mode === 'snapshots' ? ['baseline', 'candidate'] : ['target'];
      for (const side of sides) {
        if (abort.signal.aborted) { sideStatus.set(side, 'cancelled'); await this.setSide(runId, side, { status: 'cancelled', phase: null, reason: 'cancelled by user' }); continue; }
        let app: (RunningApp & { cleanup: () => void }) | null = null;
        const started = new Date();
        try {
          let target = urlTarget;
          if (snapshots) {
            await this.setSide(runId, side, { status: 'starting', phase: `building and starting the ${side === 'baseline' ? 'baseline' : 'current'} app`, startedAt: started });
            try {
              app = await snapshots.start(side as 'baseline' | 'candidate', abort.signal, (phase) => void this.setSide(runId, side, { phase: `${side === 'baseline' ? 'baseline' : 'current'} app: ${phase}` }));
            } catch (e) {
              const err = e as Error & { output?: string };
              const st: WebSideStatus = abort.signal.aborted ? 'cancelled' : 'failed';
              sideStatus.set(side, st);
              this.activity(side, 'error', `${side === 'baseline' ? 'Baseline' : 'Current'} app could not be started: ${err.message}`);
              await this.setSide(runId, side, { status: st, phase: null, finishedAt: new Date(), reason: `${side === 'baseline' ? 'baseline' : 'current'} app could not be started: ${err.message}`, appLog: (err.output ?? '').slice(-6000) });
              continue;
            }
            const chk = authorizeTarget(app.url, []);
            if (!chk.ok) throw new Error(`workbench-started app URL rejected: ${chk.reason}`);
            target = { ...chk.target, scopeKey: 'snapshots' };
          }
          const result = await this.scanSide(runId, side, target!, endpoints, staged, selection, readiness, cfg, eff, abort.signal, started, { scopeKey, graph: side === 'baseline' ? snapshots?.baselineGraph ?? null : graph, full });
          sideStatus.set(side, result.status);
          ranBy.set(side, result.ran);
          if (result.templatesVersion) templatesVersion = result.templatesVersion;
          if (result.observations) results.set(side, result.observations);
          if (app) await this.setSide(runId, side, { appLog: app.log().slice(-6000) });
        } finally {
          await app?.stop().catch(() => {});
          app?.cleanup();
        }
      }
    } finally {
      fs.rmSync(staged, { recursive: true, force: true });
    }

    // ---- outcome
    const currentSide: SideName = mode === 'snapshots' ? 'candidate' : 'target';
    const cur = sideStatus.get(currentSide) ?? 'failed';
    const all = [...sideStatus.values()];
    let status: WebRunStatus;
    if (abort.signal.aborted) status = 'cancelled';
    else if (!USABLE.includes(cur)) status = 'failed';
    else if (all.length === (mode === 'snapshots' ? 2 : 1) && all.every((s) => s === 'completed')) status = 'completed';
    else status = 'incomplete';
    const stale = snapshots?.isStale() ?? false;
    if (stale) notes.push('Your files changed while this scan was running; the current-side results describe the snapshot taken at the start.');

    // ---- persistence: observations for every usable side, lifecycle from the current side only
    let sync: Awaited<ReturnType<WebScanService['syncFindings']>> | null = null;
    const currentObs = results.get(currentSide);
    const inputs = new Set(['/', ...endpoints]);
    if (status !== 'cancelled') {
      for (const [side, obs] of results) await this.persistObservations(runId, side, scopeKey, obs, readiness.version);
      if (currentObs && USABLE.includes(cur)) {
        const templateIds = new Set(selection.approved.map((a) => a.id));
        const ran = ranBy.get(currentSide) ?? ((tid: string, input: string) => templateIds.has(tid) && inputs.has(input));
        sync = await this.syncFindings(runId, scopeKey, currentObs, { mayMarkAbsent: cur === 'completed' && !stale, ran, graph, basePath: urlTarget?.basePath ?? '/', mode });
      }
    }
    const comparison = status === 'cancelled' ? null : await this.compare(runId, mode, scopeKey, selection.setHash, sha256(endpoints.join('\n')).slice(0, 16), sideStatus, results, sync);
    const finishedAt = new Date();
    this.activity(null, 'phase', `Scan ${status}${currentObs ? `: ${currentObs.length} finding(s) on the ${mode === 'snapshots' ? 'current app' : 'target'}` : ''}`);
    await runs.updateOne({ _id: runId as never }, {
      $set: {
        status, finishedAt, durationMs: finishedAt.getTime() - (this.job?.startedAt.getTime() ?? finishedAt.getTime()), staleAtFinish: stale, notes,
        'templateSet.version': templatesVersion,
        counts: sync && currentObs ? { total: currentObs.length, bySeverity: countBy(currentObs), ...sync.counts } : null,
        findingIds: sync?.findingIds ?? [], comparison,
      },
    });
  }

  private async scanSide(runId: string, side: SideName, target: AuthorizedTarget, endpoints: string[], staged: string, selection: TemplateSelection, readiness: NucleiReadiness, cfg: NucleiConfig, eff: EffectiveSettings, signal: AbortSignal, started: Date, opts: { scopeKey: string; graph: Graph | null; full: string | null }): Promise<SideResult> {
    await this.setSide(runId, side, { status: 'scanning', phase: `checking that ${target.origin} answers`, url: target.url, startedAt: started });
    const fetchImpl = this.ctx.fetch ?? fetch;
    const probe = await probeTarget(target.url, 10_000, fetchImpl);
    if (!probe.ok) {
      this.activity(side, 'error', `${target.url} did not answer (${probe.reason})`);
      await this.setSide(runId, side, { status: 'failed', phase: null, finishedAt: new Date(), durationMs: Date.now() - started.getTime(), reason: `target did not answer before the scan (${probe.reason}). Nothing was scanned; this is not a clean result.` });
      return { status: 'failed', observations: null, templatesVersion: null, ran: null };
    }
    this.activity(side, 'info', `${target.url} answered with HTTP ${probe.status}`);
    const inputs = ['/', ...endpoints];
    await this.setSide(runId, side, { inputs });

    // ---- incremental planning: fingerprint every input, then decide which (input, template) pairs must run
    const templates = new Map<string, PlanTemplate>(selection.approved.map((a) => [a.id, { id: a.id, sha: a.sha, reach: a.reach }]));
    let inc: { plan: ScanPlan; scope: string; prev: LoadedState; fingerprints: Map<string, EndpointFingerprint>; site: SiteFingerprint | null; code: Map<string, CodeHashes>; fingerprintMs: number } | null = null;
    if (cfg.incremental.enabled) {
      await this.setSide(runId, side, { phase: `fingerprinting ${inputs.length} input(s) to find what changed since the last scan` });
      const t0 = Date.now();
      try {
        const scope = cacheScope(opts.scopeKey, side);
        const fpr = await fingerprintInputs(target.url, target.origin, inputs, {
          fetchImpl, timeoutMs: cfg.incremental.fingerprintTimeoutMs, maxBytes: cfg.maxResponseBytes, concurrency: cfg.incremental.fingerprintConcurrency, throttle: throttle(eff.rateLimit), signal,
        });
        const [prev, knownFindings] = await Promise.all([loadState(this.ctx.store, this.ctx.projectId, scope), knownFindingPairs(this.ctx.store, this.ctx.projectId, opts.scopeKey)]);
        const code = codeHashes(opts.graph, inputs, cfg.methods);
        const plan = planScan({
          inputs, templates: [...templates.values()], fingerprints: fpr.endpoints, site: fpr.site, prevSite: prev.site, prevEndpoints: prev.endpoints, cache: prev.cache,
          knownFindings, scanCtx: scanContextHash(readiness.version, cfg), code, now: new Date(), full: opts.full, maxGroups: cfg.incremental.maxGroups,
        });
        inc = { plan, scope, prev, fingerprints: fpr.endpoints, site: fpr.site, code, fingerprintMs: Date.now() - t0 };
        const e = plan.endpoints;
        this.activity(side, 'info', `Change detection (${Math.round(inc.fingerprintMs / 100) / 10}s): ${e.added.length} new, ${e.changed.length} changed, ${e.unchanged} unchanged, ${e.removed.length} removed input(s)${e.unstable.length ? `, ${e.unstable.length} too dynamic to cache` : ''}${e.unreachable.length ? `, ${e.unreachable.length} unreachable` : ''}`);
        for (const c of e.changed.slice(0, 10)) this.activity(side, 'info', `${c.input} changed: ${c.what.join(', ')}`);
        for (const r of plan.reasons) this.activity(side, 'info', r);
        this.activity(side, 'info', `Plan: ${plan.pairs.toRun} of ${plan.pairs.applicable} template×input checks need to run, ${plan.pairs.cached} served from cache (a full scan would send ${plan.pairs.naive}); ${plan.groups.length} nuclei invocation(s)`);
      } catch (e) {
        if (signal.aborted) { await this.setSide(runId, side, { status: 'cancelled', phase: null, finishedAt: new Date(), reason: 'cancelled by user' }); return { status: 'cancelled', observations: null, templatesVersion: null, ran: null }; }
        this.activity(side, 'warn', `Change detection failed (${(e as Error).message}); running every template on every input`);
        inc = null;
      }
    }
    let groups = inc ? inc.plan.groups : [{ inputs, templateIds: selection.approved.map((a) => a.id) }];
    // A nuclei build without -l can only scan one URL per invocation.
    if (inc && readiness.missingOptionalFlags.includes('l')) groups = groups.flatMap((g) => g.inputs.map((i) => ({ inputs: [i], templateIds: g.templateIds })));

    // Live feed: results as they arrive (stdout) and statistics / log lines (stderr).
    let outBuf = '';
    let errBuf = '';
    let matches = 0;
    // nuclei's log lines for the current invocation, from the stream: the bounded stderr tail fills up with one
    // statistics line per second, so on long scans it no longer contains "Templates loaded for current scan".
    let logLines: string[] = [];
    const onOut = (chunk: string, flush = false) => {
      outBuf += chunk;
      let i: number;
      while ((i = outBuf.indexOf('\n')) >= 0 || (flush && outBuf.trim())) {
        if (i < 0) i = outBuf.length;
        const line = outBuf.slice(0, i).trim();
        outBuf = outBuf.slice(i + 1);
        if (!line) continue;
        matches++;
        if (this.job?.runId === runId) this.job.findingsSoFar = matches;
        try {
          const e = JSON.parse(line) as Record<string, any>;
          const sev = String(e.info?.severity ?? 'unknown');
          this.activity(side, 'match', `${e['template-id']} matched ${redactUrl(String(e['matched-at'] ?? e.host ?? ''))}`, { severity: sev, templateId: String(e['template-id'] ?? '') });
        } catch { /* counted as malformed when parsed at the end */ }
      }
    };
    const onErr = (chunk: string) => {
      errBuf += chunk;
      let i: number;
      while ((i = errBuf.indexOf('\n')) >= 0) {
        const line = errBuf.slice(0, i).replace(/\x1b\[[0-9;]*m/g, '').trim();
        errBuf = errBuf.slice(i + 1);
        const st = parseStatsLine(line);
        if (st) { if (this.job?.runId === runId) { this.job.progress = st; this.emitThrottled(); } continue; }
        if (line && logLines.length < 5000) logLines.push(line);
        if (/Templates loaded for|Targets loaded for|Scan completed in|No results found|nuclei-templates version/i.test(line)) this.activity(side, 'info', line.replace(/^\[INF\]\s*/, ''));
        else if (/^\[WRN\]/.test(line)) this.activity(side, 'warn', line.replace(/^\[WRN\]\s*/, ''));
        else if (/^\[(ERR|FTL)\]/.test(line) && !/nuclei-ignore/i.test(line)) this.activity(side, 'error', line.replace(/^\[(ERR|FTL)\]\s*/, ''));
      }
    };

    const base = target.url.replace(/\/+$/, '');
    const work = path.dirname(staged);
    const runs: GroupRun[] = [];
    for (const [gi, g] of groups.entries()) {
      if (signal.aborted) break;
      const tag = groups.length > 1 ? `invocation ${gi + 1}/${groups.length}: ` : '';
      const subset = g.templateIds.length !== selection.approved.length;
      const gDir = subset ? stageTemplates(selection, path.join(work, `templates-${side}-${gi}`), new Set(g.templateIds)) : staged;
      try {
        const urls = g.inputs.map((i) => (i === '/' ? target.url : `${base}${i}`));
        // One URL: pass it with -u (it may be a route, not the root). Several: a target list.
        const argTarget = urls.length === 1 ? { ...target, url: urls[0]! } : target;
        let listFile: string | undefined;
        if (urls.length > 1) {
          listFile = path.join(work, `targets-${side}${groups.length > 1 ? `-${gi}` : ''}.txt`);
          fs.writeFileSync(listFile, urls.join('\n') + '\n');
        }
        const errorLog = path.join(work, `errors-${side}-${gi}.jsonl`);
        fs.rmSync(errorLog, { force: true });
        await this.setSide(runId, side, { phase: `${tag}running ${g.templateIds.length} templates against ${urls.length} URL(s) at ${eff.rateLimit} req/s` });
        const args = buildArgs(argTarget, gDir, cfg, readiness.missingOptionalFlags, eff, listFile, errorLog);
        const command = `nuclei ${args.map((a) => (a === gDir ? '<vetted-templates>' : a === listFile ? '<targets.txt>' : a === errorLog ? '<errors.jsonl>' : /[\s,]/.test(a) && a.length > 60 ? `'${a.slice(0, 57)}…'` : a)).join(' ')}`;
        if (gi === 0) await this.setSide(runId, side, { command: groups.length > 1 ? `${command} (+${groups.length - 1} more invocation(s) with other template/input subsets)` : command });
        this.activity(side, 'command', `${tag}${command}`);
        logLines = [];
        const r = await this.exec(readiness.binary!, args, {
          cwd: work, timeoutMs: eff.timeoutMs, maxOutputBytes: cfg.maxOutputBytes, signal, localOnly: target.loopback,
          extraEnv: NUCLEI_ENV, stderrTailBytes: 64 * 1024, onStdout: onOut, onStderr: onErr,
        });
        onOut('', true); // a last result line without a trailing newline
        onErr('\n');
        const facts = readStderr(r.stderrTail);
        const streamed = readStderr(logLines.join('\n'));
        facts.templatesLoaded ??= streamed.templatesLoaded;
        facts.targetsLoaded ??= streamed.targetsLoaded;
        facts.templatesVersion ??= streamed.templatesVersion;
        facts.hostSkipped ||= streamed.hostSkipped;
        facts.skippedHosts = [...new Set([...facts.skippedHosts, ...streamed.skippedHosts])];
        facts.fatal ??= streamed.fatal;
        const judged = await this.judge(r, facts, g.templateIds.length, target, cfg, eff, side);
        // Which pairs matched, and which requests failed (-elog: template file + request URL).
        const matched = new Set<string>();
        for (const l of r.stdout.split('\n')) {
          if (!l.trim()) continue;
          try {
            const e = JSON.parse(l);
            if (!e['template-id'] || e.error) continue;
            // `url` is the scan input; without it the input is unknown, so the match counts for every input here
            if (typeof e.url === 'string' && /^https?:\/\//i.test(e.url)) matched.add(pairKey(String(e['template-id']), inputOfUrl(e.url, g.inputs, target.basePath)));
            else for (const i of g.inputs) matched.add(pairKey(String(e['template-id']), i));
          } catch { /* malformed: counted by the parser */ }
        }
        const attributed = !readiness.missingOptionalFlags.includes('elog');
        const errored = new Set<string>();
        if (attributed) {
          const relToId = new Map(selection.approved.map((a) => [a.rel, a.id]));
          const prefixes = [gDir, fs.existsSync(gDir) ? fs.realpathSync(gDir) : gDir].map((p) => p + path.sep);
          let text = '';
          try { text = fs.readFileSync(errorLog, 'utf8'); } catch { /* no request failed */ }
          for (const e of parseErrorLog(text)) {
            const pre = prefixes.find((p) => e.template.startsWith(p));
            const id = pre ? relToId.get(e.template.slice(pre.length)) : undefined;
            if (id) errored.add(pairKey(id, inputOfUrl(e.url, g.inputs, target.basePath)));
            else for (const tid of g.templateIds) errored.add(pairKey(tid, inputOfUrl(e.url, g.inputs, target.basePath))); // unknown template: distrust the input
          }
          if (errored.size) this.activity(side, 'warn', `${tag}${errored.size} template×input check(s) had request errors; their results are not cached`);
        }
        runs.push({ ...judged, inputs: g.inputs, templateIds: g.templateIds, r, facts, matched, errored, attributed });
      } finally {
        if (subset) fs.rmSync(gDir, { recursive: true, force: true });
      }
    }
    if (this.job?.runId === runId) this.job.progress = null;

    // ---- side outcome: the worst invocation decides
    const RANK: Record<string, number> = { completed: 0, incomplete: 1, timed_out: 2, failed: 3, cancelled: 4 };
    let st: WebSideStatus = 'completed';
    const reasons: string[] = [];
    if (signal.aborted && runs.length < groups.length) { st = 'cancelled'; reasons.push('cancelled by user'); }
    for (const [i, g] of runs.entries()) {
      if (RANK[g.status]! > RANK[st]!) st = g.status;
      reasons.push(...g.reasons.map((x) => (runs.length > 1 ? `invocation ${i + 1}: ${x}` : x)));
    }
    const parsed = parseNucleiJsonl(runs.map((g) => g.r.stdout).join('\n'), target);
    if (parsed.truncatedFindings && st === 'completed') { st = 'incomplete'; reasons.push('more findings than the per-scan limit; the rest were not recorded'); }
    if (parsed.malformed) reasons.push(`${parsed.malformed} output line(s) could not be parsed and were ignored`);
    if (parsed.outOfScope.length) reasons.push(`${parsed.outOfScope.length} result(s) pointed outside ${target.origin} and were not recorded as findings`);
    if (inc && !groups.length) reasons.push(`nothing changed that any template can observe: all ${inc.plan.pairs.applicable} checks were served from completed earlier scans`);
    // A timed-out scan still produced evidence for what it matched; keep those observations but never treat absence as meaningful.
    const usableObs = st === 'completed' || st === 'incomplete' || st === 'timed_out' ? parsed.observations : null;
    let reportRef: string | null = null;
    let reportSha: string | null = null;
    if (usableObs) {
      const body = usableObs.map((o) => JSON.stringify(o)).join('\n');
      const file = path.join(this.ctx.projectDir, 'websec', runId, `nuclei-${side}.redacted.jsonl`);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, body);
      reportRef = path.relative(this.ctx.projectDir, file);
      reportSha = sha256(body);
    }

    // ---- what this side learned: cache entries per pair, and the surface (endpoints + site) state
    let incremental: Record<string, unknown> | null = null;
    if (inc) {
      const now = new Date();
      let written = { cachedNegatives: 0, recordedMatches: 0, skippedForErrors: 0 };
      try {
        written = await recordResults(this.ctx.store, {
          projectId: this.ctx.projectId, scope: inc.scope, runId, now, ttl: cfg.incremental.ttlHours, templates, contexts: inc.plan.contexts,
          groups: runs.map((g) => ({ inputs: g.inputs, templateIds: g.templateIds, completed: g.status === 'completed', errorsAttributed: g.attributed, requestErrors: g.facts.stats ? g.facts.stats.errors : null, matched: g.matched, errored: g.errored })),
        });
        if (usableObs) {
          const observedTech = new Map<string, string[]>();
          for (const o of usableObs) if (isTechDetection(o)) { const i = inputOfUrl(o.url ?? o.matchedAt, inputs, target.basePath); observedTech.set(i, [...new Set([...(observedTech.get(i) ?? []), `${o.templateId}${o.matcherName ? `:${o.matcherName}` : ''}`])].sort()); }
          await recordSurface(this.ctx.store, { projectId: this.ctx.projectId, scope: inc.scope, runId, now, plan: inc.plan, prev: inc.prev, fingerprints: inc.fingerprints, site: inc.site, code: inc.code, observedTech });
        }
      } catch (e) {
        this.activity(side, 'warn', `Could not store incremental scan state (${(e as Error).message}); the next scan will re-run these checks`);
      }
      const p = inc.plan;
      incremental = {
        mode: p.mode, scope: inc.scope, reasons: p.reasons, fingerprintMs: inc.fingerprintMs, fingerprintRequests: inputs.length * 4,
        site: p.site, endpoints: p.endpoints, pairs: p.pairs, cache: written,
        groups: runs.map((g) => ({ inputs: g.inputs.length, templates: g.templateIds.length, status: g.status, requests: g.facts.stats?.requests ?? null, errors: g.facts.stats?.errors ?? null, durationMs: g.r.durationMs })),
      };
    }

    const finished = new Date();
    const stats = sumStats(runs.map((g) => g.facts.stats));
    const allLoaded = runs.every((g) => g.facts.templatesLoaded === g.templateIds.length);
    await this.setSide(runId, side, {
      status: st, phase: null, finishedAt: finished, durationMs: finished.getTime() - started.getTime(), exitCode: runs.find((g) => g.r.exitCode !== 0)?.r.exitCode ?? (runs.length ? 0 : null),
      templatesLoaded: runs.length === 1 ? runs[0]!.facts.templatesLoaded : allLoaded ? new Set(runs.flatMap((g) => g.templateIds)).size : runs.reduce((n, g) => n + (g.facts.templatesLoaded ?? 0), 0),
      targetsLoaded: runs.length ? runs.reduce((n, g) => n + (g.facts.targetsLoaded ?? 0), 0) : 0, stats,
      findings: usableObs ? usableObs.length : null, bySeverity: usableObs ? countBy(usableObs) : null,
      malformedLines: parsed.malformed, outOfScope: parsed.outOfScope.slice(0, 50), toolErrors: [...parsed.toolErrors, ...runs.flatMap((g) => g.facts.errors)].slice(0, 30), warnings: runs.flatMap((g) => g.facts.warnings).slice(-20),
      reason: reasons.join(' · ') || null, stderrTail: runs.map((g) => g.r.stderrTail).join('\n').slice(-6000) || null, reportRef, reportSha256: reportSha, incremental,
    });
    this.activity(side, st === 'completed' ? 'info' : 'warn', `${side === 'target' ? 'Target' : side === 'baseline' ? 'Baseline' : 'Current app'} scan ${st.replace('_', ' ')}${stats ? `: ${stats.requests} requests, ${stats.errors} errors` : ''}${usableObs ? `, ${usableObs.length} finding(s)` : ''}${inc ? ` (${inc.plan.pairs.cached} checks from cache)` : ''}`);
    // Pairs that actually ran (absence of a finding is only meaningful for those). Origin checks cover every input.
    const ranPairs = new Set(runs.flatMap((g) => g.inputs.flatMap((i) => g.templateIds.map((t) => pairKey(t, i)))));
    const ran = (tid: string, input: string) => ranPairs.has(pairKey(tid, input)) || (templates.get(tid)?.reach === 'origin' && ranPairs.has(pairKey(tid, '/')));
    return { status: st === 'timed_out' ? 'incomplete' : st, observations: usableObs, templatesVersion: runs.map((g) => g.facts.templatesVersion).find(Boolean) ?? null, ran };
  }

  /** Status of one nuclei invocation. Only 'completed' lets its clean negatives be cached or findings be marked absent. */
  private async judge(r: ExecResult, facts: StderrFacts, expected: number, target: AuthorizedTarget, cfg: NucleiConfig, eff: EffectiveSettings, side: SideName): Promise<{ status: WebSideStatus; reasons: string[] }> {
    const reasons: string[] = [];
    let st: WebSideStatus;
    if (r.cancelled) { st = 'cancelled'; reasons.push('cancelled by user'); }
    else if (r.spawnError) { st = 'failed'; reasons.push(`nuclei could not be started: ${r.spawnError}`); }
    else if (r.timedOut) { st = 'timed_out'; reasons.push(`nuclei did not finish within ${Math.round(eff.timeoutMs / 60_000)} min and was stopped; results are partial`); }
    else if (facts.fatal) { st = 'failed'; reasons.push(facts.fatal); }
    else if (r.exitCode !== 0) { st = 'failed'; reasons.push(`nuclei exited with code ${r.exitCode}${facts.errors[0] ? `: ${facts.errors[0]}` : ''}`); }
    else if (facts.templatesLoaded === 0) { st = 'failed'; reasons.push('nuclei loaded 0 templates'); }
    else st = 'completed';
    if (st === 'completed') {
      if (r.stdoutTruncated) { st = 'incomplete'; reasons.push(`output exceeded ${cfg.maxOutputBytes} bytes; nuclei was stopped`); }
      const targetHp = targetHostPort(target);
      const otherPorts = facts.skippedHosts.filter((x) => x !== '?' && x !== targetHp);
      if (otherPorts.length) reasons.push(`some templates probe other ports of this host; nuclei gave up on ${otherPorts.slice(0, 5).join(', ')}${otherPorts.length > 5 ? ', …' : ''} (closed or filtered). The target itself was not skipped, and those checks are not cached`);
      if (facts.hostSkipped && (!facts.skippedHosts.length || facts.skippedHosts.some((x) => x === '?' || x === targetHp))) {
        st = 'incomplete';
        // Did the application itself go down? A request during the scan may have crashed it.
        const after = await probeTarget(target.url, 5_000, this.ctx.fetch ?? fetch);
        if (!after.ok) {
          reasons.push(`the application stopped responding during the scan (${after.reason}); it may have crashed on one of the requests. Results cover only what was scanned before that. Check the application's log, fix the crash and scan again`);
          this.activity(side, 'error', `${target.origin} no longer answers: the application stopped responding during the scan (possibly crashed)`);
        } else {
          reasons.push(`nuclei stopped sending requests to the target after repeated errors (host marked unresponsive${facts.skippedHosts.length ? `: ${facts.skippedHosts.join(', ')}` : ''}), although it answers again now`);
        }
      }
      if (facts.templatesLoaded === null) { st = 'incomplete'; reasons.push('nuclei did not report how many templates it loaded; coverage cannot be confirmed'); }
      else if (facts.templatesLoaded < expected) { st = 'incomplete'; reasons.push(`nuclei loaded ${facts.templatesLoaded} of ${expected} approved templates; the rest were rejected by nuclei (see warnings)`); }
    }
    return { status: st, reasons };
  }

  private findingId(scopeKey: string, fp: string) {
    return `web_${shortHash(`${this.ctx.projectId}|${scopeKey}|${fp}`, 20)}`;
  }

  private async persistObservations(runId: string, side: SideName, scopeKey: string, obs: WebObservation[], toolVersion: string | null) {
    if (!obs.length) return;
    const now = new Date();
    const docs = obs.map((o) => ({
      _id: `nob_${shortHash(`${runId}|${side}|${o.fingerprint}`, 20)}`, projectId: this.ctx.projectId, runId, side, category: 'web_dast', tool: 'nuclei', toolVersion,
      findingId: this.findingId(scopeKey, o.fingerprint), scopeKey, observedAt: now, ...o,
    }));
    try { await this.ctx.store.col('security_observations').insertMany(docs as never[], { ordered: false }); }
    catch (e) { if ((e as { code?: number }).code !== 11000 && !String((e as Error).message).includes('E11000')) throw e; }
  }

  private async syncFindings(runId: string, scopeKey: string, obs: WebObservation[], opts: { mayMarkAbsent: boolean; ran: (templateId: string, input: string) => boolean; graph: Graph | null; basePath: string; mode: StartRequest['mode'] }) {
    const store = this.ctx.store;
    const col = store.col('graph_findings');
    const vr = store.col('verification_records');
    const projectId = this.ctx.projectId;
    const now = new Date();
    const counts = { new: 0, recurring: 0, regressions: 0, notCurrentlyObserved: 0, notRechecked: 0, linked: 0 };
    const findingIds: string[] = [];
    const returned: string[] = [];
    for (const o of obs) {
      const id = this.findingId(scopeKey, o.fingerprint);
      findingIds.push(id);
      const existing = await col.findOne({ _id: id as never });
      const corr: WebCorrelation = correlate(opts.graph, o.method, o.endpoint, opts.basePath);
      if (corr.status === 'linked') counts.linked++;
      const reopened = !!existing && existing.status !== 'open';
      const title = `${o.name ?? o.templateId} at ${o.endpoint}`;
      await col.updateOne({ _id: id as never }, {
        $set: {
          projectId, source: 'web', category: 'web_scanner', classification: 'scanner_detected',
          labels: ['scanner_detected', corr.status === 'linked' ? 'graph_linked' : 'unlinked_web_finding', ...(isTechDetection(o) ? ['technology'] : [])],
          severity: o.severity, severityRank: SEVERITY_RANK_EXT[o.severity], title,
          explanation: [
            `Nuclei template ${o.templateId}${o.name ? ` ("${o.name}")` : ''} matched ${o.method ?? 'a request to'} ${o.matchedAt}${o.matcherName ? ` (matcher "${o.matcherName}")` : ''}.`,
            `Severity as published in the template: ${o.originalSeverity ?? 'not supplied'}.`,
            ...(o.description ? [`Template description: ${o.description}`] : []),
            corr.status === 'linked' ? `Code graph: ${corr.reason}` : `Not linked to the code graph: ${corr.reason}`,
          ],
          nodes: corr.endpointId ? [corr.endpointId, ...corr.handlers] : [], edges: [], paths: corr.endpointId && corr.handlers.length ? [[corr.endpointId, corr.handlers[0]!]] : [],
          locations: corr.handlerLocations.slice(0, 5),
          evidence: { templateId: o.templateId, matchedAt: o.matchedAt, method: o.method, matcherName: o.matcherName, extractedResults: o.extractedResults, type: o.type },
          web: {
            scopeKey, mode: opts.mode, templateId: o.templateId, templatePath: o.templatePath, templateName: o.name, tags: o.tags, endpoint: o.endpoint, matchedAt: o.matchedAt, input: o.input,
            host: o.host, method: o.method, matcherName: o.matcherName, extractorName: o.extractorName, classification: o.classification, originalSeverity: o.originalSeverity,
            correlation: corr,
          },
          references: o.references, cwe: o.classification.cwe, ids: [o.templateId, ...o.classification.cve],
          suggestedNextStep: corr.status === 'linked'
            ? `Review the handler for ${corr.endpointId?.replace(/^ep:/, '')} and reproduce the request from the evidence before changing code.`
            : `Reproduce the request from the evidence and check which part of the application serves ${o.endpoint}.`,
          confidence: 'scanner', confidenceNote: 'A nuclei template matched the response. This is evidence of the matched condition, not proof that it is exploitable.',
          limitations: [
            'Nuclei reports that a template\'s matchers matched; it does not prove exploitability or impact.',
            'Only the vetted templates were run; untested checks and pages may still have issues.',
            ...(corr.status === 'unlinked' ? ['This URL could not be tied to a route in the code graph.'] : ['The graph link is a route match on the URL path, not a trace of the request through the code.']),
          ],
          scanners: ['nuclei'], lastTools: ['nuclei'],
          status: 'open', resolvedAt: null, lastSeenAt: now, lastSeenSecurityRunId: runId, graphVersionAtScan: this.ctx.graphVersion(),
          ...(reopened ? { potentialRegression: true } : {}),
        },
        $setOnInsert: { firstSeenAt: now, firstSeenSecurityRunId: runId, ...(reopened ? {} : { potentialRegression: false }) },
      }, { upsert: true });
      if (!existing) {
        counts.new++;
        await vr.insertOne({ _id: newId('ver') as never, projectId, findingId: id, action: 'observed', at: now, securityRunId: runId, result: `nuclei ${o.templateId}`, notes: title });
      } else {
        counts.recurring++;
        if (reopened) {
          counts.regressions++;
          returned.push(id);
          await vr.insertOne({ _id: newId('ver') as never, projectId, findingId: id, action: 'potential_regression', at: now, securityRunId: runId, result: `matched again after being ${existing.status}`, notes: title });
        }
      }
    }
    // Absence: only after a completed scan of the same scope that ran the template that reported the finding against
    // the same input URL.
    const seen = new Set(findingIds);
    const prior = await col.find({ projectId, source: 'web', 'web.scopeKey': scopeKey, status: 'open' }).toArray();
    const absent: string[] = [];
    for (const f of prior) {
      const fid = f._id as unknown as string;
      if (seen.has(fid)) continue;
      const input = (f.web?.input as string | undefined) ?? '/';
      if (!opts.mayMarkAbsent || !opts.ran(f.web?.templateId, input)) { counts.notRechecked++; continue; }
      await col.updateOne({ _id: f._id }, { $set: { status: 'not_currently_observed', notObservedSince: now } });
      await vr.insertOne({ _id: newId('ver') as never, projectId, findingId: fid, action: 'not_currently_observed', at: now, securityRunId: runId, result: `template ${f.web?.templateId} ran against ${input} in a completed scan of the same target and did not match`, notes: f.title });
      counts.notCurrentlyObserved++;
      absent.push(fid);
    }
    return { counts, findingIds, returned, absent };
  }

  private async compare(runId: string, mode: StartRequest['mode'], scopeKey: string, setHash: string, inputsHash: string, sideStatus: Map<SideName, WebSideStatus>, results: Map<SideName, WebObservation[]>, sync: { returned: string[]; absent: string[] } | null) {
    const ids = (obs: WebObservation[] | undefined) => new Set((obs ?? []).map((o) => this.findingId(scopeKey, o.fingerprint)));
    const reasons: string[] = [];
    if (mode === 'snapshots') {
      const b = sideStatus.get('baseline');
      const c = sideStatus.get('candidate');
      if (b !== 'completed') reasons.push(`baseline scan ${b ?? 'did not run'}`);
      if (c !== 'completed') reasons.push(`current scan ${c ?? 'did not run'}`);
      const base = ids(results.get('baseline'));
      const cur = ids(results.get('candidate'));
      const comparable = reasons.length === 0;
      return {
        against: { kind: 'baseline_snapshot', runId }, comparable, reasons,
        new: comparable ? [...cur].filter((x) => !base.has(x)) : [],
        recurring: comparable ? [...cur].filter((x) => base.has(x)) : [],
        absent: comparable ? [...base].filter((x) => !cur.has(x)) : [],
        returned: sync?.returned ?? [],
        current: [...cur], baseline: [...base],
      };
    }
    const prev = await this.ctx.store.col('security_scan_runs').findOne(
      { projectId: this.ctx.projectId, category: 'web_dast', mode: 'url', 'target.scopeKey': scopeKey, status: 'completed', _id: { $ne: runId as never } },
      { sort: { startedAt: -1 }, projection: { _id: 1, startedAt: 1, 'templateSet.hash': 1, 'target.inputsHash': 1, findingIds: 1 } },
    );
    const t = sideStatus.get('target');
    if (t !== 'completed') reasons.push(`this scan is ${t}`);
    if (!prev) reasons.push('no earlier completed scan of this target');
    else {
      if (prev.templateSet?.hash !== setHash) reasons.push('the template set differs from the earlier scan (another profile, or templates were added, removed or changed)');
      if ((prev.target?.inputsHash ?? sha256('').slice(0, 16)) !== inputsHash) reasons.push('the scanned route list differs from the earlier scan (routes were added or removed in the code graph)');
    }
    const cur = ids(results.get('target'));
    const base = new Set<string>((prev?.findingIds as string[] | undefined) ?? []);
    const comparable = reasons.length === 0;
    return {
      against: prev ? { kind: 'previous_scan', runId: prev._id, startedAt: prev.startedAt } : null, comparable, reasons,
      new: comparable ? [...cur].filter((x) => !base.has(x)) : [],
      recurring: comparable ? [...cur].filter((x) => base.has(x)) : [],
      absent: comparable ? [...base].filter((x) => !cur.has(x)) : [],
      returned: sync?.returned ?? [],
      current: [...cur], baseline: [...base],
    };
  }
}

/** Technology fingerprints (tech-detect and friends) are inventory, not vulnerabilities; the UI lists them separately. */
export function isTechDetection(o: { tags: string[]; templateId: string; severity: string }): boolean {
  return o.severity === 'info' && (o.tags.includes('tech') || /tech-detect|fingerprint/.test(o.templateId));
}

function countBy(obs: WebObservation[]) {
  const c: Record<string, number> = {};
  for (const o of obs) c[o.severity] = (c[o.severity] ?? 0) + 1;
  return c;
}

function httpError(status: number, message: string) { return Object.assign(new Error(message), { status }); }

function settingsOf(cfg: NucleiConfig, eff: EffectiveSettings) {
  return {
    profile: eff.profile, rateLimit: eff.rateLimit, concurrency: cfg.concurrency, requestTimeoutSec: cfg.requestTimeoutSec, retries: cfg.retries, redirects: cfg.redirects,
    methods: cfg.methods, timeoutMs: eff.timeoutMs, maxOutputBytes: cfg.maxOutputBytes, maxHostErrors: cfg.maxHostErrors, templates: eff.templates,
    excludeTags: cfg.excludeTags, severities: cfg.severities ?? null, includeGraphEndpoints: cfg.includeGraphEndpoints,
    incremental: { enabled: cfg.incremental.enabled, ttlHours: cfg.incremental.ttlHours, maxGroups: cfg.incremental.maxGroups },
  };
}

function sumStats(all: (ScanStats | null)[]): ScanStats | null {
  const s = all.filter((x): x is ScanStats => !!x);
  if (!s.length) return null;
  const sum = (k: keyof ScanStats) => s.reduce((n, x) => n + (x[k] as number), 0);
  return { requests: sum('requests'), total: sum('total'), percent: Math.min(...s.map((x) => x.percent)), matched: sum('matched'), errors: sum('errors'), rps: Math.max(...s.map((x) => x.rps)), duration: s.map((x) => x.duration).join(' + '), hosts: Math.max(...s.map((x) => x.hosts)), templates: sum('templates') };
}

function templateSetDoc(sel: TemplateSelection, r: NucleiReadiness) {
  return {
    dir: sel.templatesDir, version: r.templates.version, hash: sel.setHash, approvedCount: sel.approved.length, rejectedCount: sel.rejected.length,
    missing: sel.missing, truncated: sel.truncated, templateIds: sel.approved.slice(0, 20_000).map((a) => a.id),
    rejectedSample: sel.rejected.slice(0, 200), rejectedByReason: groupReasons(sel.rejected),
  };
}

export function summarizeSelection(sel: TemplateSelection) {
  const bySeverity: Record<string, number> = {};
  for (const a of sel.approved) bySeverity[a.severity ?? 'unknown'] = (bySeverity[a.severity ?? 'unknown'] ?? 0) + 1;
  return {
    dir: sel.templatesDir, hash: sel.setHash, approved: sel.approved.length, rejected: sel.rejected.length, missing: sel.missing, truncated: sel.truncated,
    bySeverity, rejectedByReason: groupReasons(sel.rejected), sample: sel.approved.slice(0, 25).map((a) => ({ id: a.id, name: a.name, severity: a.severity, rel: a.rel })),
  };
}

function groupReasons(rej: TemplateSelection['rejected']) {
  const m = new Map<string, number>();
  for (const r of rej) { const k = r.reason.replace(/"[^"]*"/, '"…"').replace(/\d+/g, 'N'); m.set(k, (m.get(k) ?? 0) + 1); }
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 15).map(([reason, count]) => ({ reason, count }));
}

/** nuclei's user config: NUCLEI_CONFIG_DIR, else the platform config dir (XDG on Linux, ~/Library/Application Support on macOS). */
export function nucleiConfigCandidates(env = process.env): string[] {
  const dirs = [
    env.NUCLEI_CONFIG_DIR,
    env.XDG_CONFIG_HOME && path.join(env.XDG_CONFIG_HOME, 'nuclei'),
    env.HOME && path.join(env.HOME, '.config', 'nuclei'),
    env.HOME && path.join(env.HOME, 'Library', 'Application Support', 'nuclei'),
  ].filter(Boolean) as string[];
  return [...new Set(dirs)].map((d) => path.join(d, 'config.yaml'));
}

function configFileNote(): string | null {
  for (const p of nucleiConfigCandidates()) {
    try {
      const meaningful = fs.readFileSync(p, 'utf8').split('\n').some((l) => l.trim() && !l.trim().startsWith('#'));
      if (meaningful) return `${p} has settings; nuclei applies them to workbench scans unless the workbench passes the same flag explicitly.`;
    } catch { /* not there */ }
  }
  return null;
}

