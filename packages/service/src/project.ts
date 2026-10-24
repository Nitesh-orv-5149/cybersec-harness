// One monitored workspace: watcher -> debounce/coalesce -> incremental analysis -> graph/findings,
// plus explicit baseline capture and browser verification of immutable snapshots.
import fs from 'node:fs';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import chokidar, { type FSWatcher } from 'chokidar';
import type { Browser } from 'playwright';
import { Analyzer, analyzeDirectory, PARSER_VERSION, type AnalyzerOptions } from './analyzer/index.js';
import { GraphIndex, diffGraphs, impactOf, type GraphDiff, type ImpactSummary } from './analyzer/query.js';
import type { Graph } from './analyzer/types.js';
import { CONFIG_FILE, loadProjectConfig, type LoadedConfig, type ProjectConfig } from './config.js';
import { Store, StoreUnavailableError } from './store/mongo.js';
import { captureSnapshot, collectFiles, manifestDiff, prepareWorkspace, type SnapshotInfo, type ManifestEntry } from './snapshots.js';
import { buildAndStart, StepError, type RunningApp } from './runner.js';
import { browserAvailable, launchBrowser, runScenario, type ScenarioResult } from './browser.js';
import { classify, diffScreenshots, type ComparisonItem } from './compare.js';
import { graphFindings, runtimeFindings, type FindingDraft } from './findings.js';
import { log } from './log.js';
import { newId, sha256, shortHash } from './util.js';
import { DependencyScanService } from './security/deps/service.js';
import { WebScanService, type SnapshotTargets } from './security/web/service.js';
import type { Exec, Which } from './security/types.js';
import { ScanService } from './security/scan/service.js';
import { SCAN_KINDS } from './security/scan/registry.js';
import type { KindId, ManagedTarget } from './security/scan/types.js';

export type BrowserRunStatus = 'pending' | 'building' | 'browser_running' | 'comparing' | 'completed' | 'failed' | 'inconclusive' | 'cancelled';

interface PendingChange { type: 'add' | 'change' | 'unlink' | 'refresh'; source: 'fs' | 'editor' | 'manual' }

interface BaselineState {
  snapshotId: string;
  contentHash: string;
  createdAt: Date;
  manifest: ManifestEntry[];
  storagePath: string;
  graph: Graph;
}

export interface LiveState {
  graphVersion: number;
  graph: Graph;
  graphHash: string;
  sourceHash: string;
  lastDiff: GraphDiff | null;
  lastImpact: ImpactSummary | null;
  lastRunId: string | null;
  lastChangedFiles: string[];
  analyzedAt: Date;
}

const MANIFEST_FILES = new Set(['package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'tsconfig.json']);

export class ProjectSession extends EventEmitter {
  readonly id: string;
  readonly name: string;
  loaded: LoadedConfig;
  private analyzer!: Analyzer;
  live: LiveState | null = null;
  baseline: BaselineState | null = null;
  monitoring = false;
  analysisStatus: 'idle' | 'pending' | 'analyzing' | 'failed' = 'idle';
  analysisError: string | null = null;
  private watcher: FSWatcher | null = null;
  private pending = new Map<string, PendingChange>();
  private debounceTimer: NodeJS.Timeout | null = null;
  private analyzing = false;
  private rerun = false;
  private lastEventByPath = new Map<string, string>();
  private lastFileHash = new Map<string, string>();
  runApproval: { hash: string; approvedAt: Date } | null = null;

  browserJob: { runId: string; status: BrowserRunStatus; abort: AbortController; candidateSnapshotId?: string; startedAt: Date; phase?: string } | null = null;
  private verifyQueued = false;
  lastBrowserRun: Record<string, unknown> | null = null;
  readonly deps: DependencyScanService;
  readonly web: WebScanService;
  readonly scans = new Map<KindId, ScanService>();

  constructor(readonly root: string, private readonly store: Store, private readonly dataDir: string, scannerHooks: { exec?: Exec; which?: Which; fetch?: typeof fetch } = {}) {
    super();
    this.root = fs.realpathSync(root);
    this.id = `prj_${shortHash(this.root, 16)}`;
    this.name = path.basename(this.root);
    this.loaded = loadProjectConfig(this.root);
    this.makeAnalyzer();
    this.deps = new DependencyScanService({
      projectId: this.id, root: this.root, projectDir: this.projectDir, store: this.store,
      cfg: () => this.cfg.security, graph: () => this.live?.graph ?? null, facts: () => this.analyzer.factsList(),
      graphVersion: () => this.live?.graphVersion ?? null, sourceHash: () => this.live?.sourceHash ?? null,
      emit: (kind, payload) => this.emitState(kind, payload), ...scannerHooks,
    });
    this.web = new WebScanService({
      projectId: this.id, projectDir: this.projectDir, store: this.store,
      cfg: () => this.cfg.security.nuclei, graph: () => this.live?.graph ?? null,
      graphVersion: () => this.live?.graphVersion ?? null, sourceHash: () => this.live?.sourceHash ?? null,
      snapshotReadiness: () => this.snapshotTargetReadiness(), prepareSnapshots: () => this.prepareSnapshotTargets(),
      emit: (kind, payload) => this.emitState(kind, payload), ...scannerHooks,
    });
    for (const k of SCAN_KINDS) {
      this.scans.set(k.id, new ScanService(k, {
        projectId: this.id, root: this.root, projectDir: this.projectDir, store: this.store,
        cfg: () => this.cfg, graph: () => this.live?.graph ?? null,
        graphVersion: () => this.live?.graphVersion ?? null, sourceHash: () => this.live?.sourceHash ?? null,
        emit: (kind, payload) => this.emitState(kind, payload),
        runApproved: () => this.runApprovedForTargets(),
        startTarget: (signal) => this.startManagedTarget(signal),
        ...scannerHooks,
      }));
    }
  }

  /** Dynamic scanners only ever test a copy of this project started with the approved run commands. */
  runApprovedForTargets(): { ok: boolean; reason: string | null } {
    if (this.loaded.error) return { ok: false, reason: this.loaded.error };
    if (!this.cfg.run) return { ok: false, reason: `no "run" section in ${CONFIG_FILE}: the workbench needs build/start commands to start a local copy to test` };
    if (!this.runApproval || this.runApproval.hash !== this.loaded.runHash) return { ok: false, reason: 'run commands have not been approved in the dashboard (or changed since approval)' };
    return { ok: true, reason: null };
  }

  /** Snapshot the workspace, build and start it on a free loopback port, and hand back a stop() that cleans up. */
  async startManagedTarget(signal: AbortSignal): Promise<ManagedTarget> {
    const ok = this.runApprovedForTargets();
    if (!ok.ok) throw new Error(ok.reason!);
    const cfg = this.cfg;
    const snap = captureSnapshot(this.root, cfg, path.join(this.projectDir, 'snapshots'), this.id);
    await this.persistSnapshot(snap, 'security-target');
    const work = prepareWorkspace(snap.storagePath, this.root, cfg, path.join(this.projectDir, 'work', newId('sectgt')));
    try {
      const app = await buildAndStart(work, cfg.run!, () => {}, signal);
      return {
        url: app.url, snapshotId: snap.snapshotId, contentHash: snap.contentHash, log: app.log,
        stop: async () => { await app.stop(); fs.rmSync(work, { recursive: true, force: true }); },
      };
    } catch (e) {
      fs.rmSync(work, { recursive: true, force: true });
      throw e;
    }
  }

  get cfg(): ProjectConfig { return this.loaded.config; }
  private get projectDir() { return path.join(this.dataDir, 'projects', this.id); }

  private analyzerOptions(root = this.root): AnalyzerOptions {
    return {
      root,
      include: this.cfg.analysis.include,
      exclude: this.cfg.analysis.exclude,
      clientDirs: Object.values(this.cfg.staticMap),
    };
  }

  private makeAnalyzer() {
    this.analyzer = new Analyzer(this.analyzerOptions());
  }

  private emitState(kind: string, payload: unknown = {}) {
    this.emit('update', { kind, projectId: this.id, at: new Date().toISOString(), payload });
  }

  // ------------------------------------------------------------------ lifecycle

  async init() {
    fs.mkdirSync(this.projectDir, { recursive: true });
    await this.persistProject();
    await this.loadPersistedState();
    await this.migrateFindingIds();
    await this.deps.loadLastRun();
    await this.web.loadLastRun();
    for (const sc of this.scans.values()) await sc.loadLastRun();
    await this.runAnalysis([], 'initial', true);
  }

  private async safe<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
    try { return await fn(); }
    catch (e) {
      if (e instanceof StoreUnavailableError) { log.warn(`persistence skipped: ${e.message}`); return fallback; }
      throw e;
    }
  }

  async persistProject() {
    await this.safe(async () => {
      const col = this.store.col('projects');
      await col.updateOne(
        { _id: this.id as never },
        {
          $set: {
            root: this.root, name: this.name, language: this.cfg.language, config: this.cfg, configSource: this.loaded.source,
            configError: this.loaded.error ?? null, runHash: this.loaded.runHash, monitoring: this.monitoring, updatedAt: new Date(),
          },
          $setOnInsert: { createdAt: new Date() },
        },
        { upsert: true },
      );
    }, undefined);
  }

  private async loadPersistedState() {
    await this.safe(async () => {
      const doc = await this.store.col('projects').findOne({ _id: this.id as never });
      if (doc?.runApproval && doc.runApproval.hash === this.loaded.runHash) this.runApproval = doc.runApproval;
      if (doc?.baselineSnapshotId) {
        const snap = await this.store.col('source_snapshots').findOne({ _id: doc.baselineSnapshotId });
        if (snap && fs.existsSync(path.join(snap.storagePath, 'src'))) {
          this.baseline = {
            snapshotId: snap._id as unknown as string, contentHash: snap.contentHash, createdAt: snap.createdAt,
            manifest: snap.manifest, storagePath: snap.storagePath,
            graph: analyzeDirectory(this.analyzerOptions(path.join(snap.storagePath, 'src'))),
          };
        }
      }
      const lastRun = await this.store.col('browser_runs').find({ projectId: this.id }).sort({ startedAt: -1 }).limit(1).next();
      this.lastBrowserRun = lastRun;
    }, undefined);
  }

  async startMonitoring() {
    if (this.watcher) return;
    this.watcher = chokidar.watch(this.root, {
      ignoreInitial: true,
      ignored: (p: string) => /(^|[/\\])(node_modules|\.git|dist|build|coverage|\.workbench)([/\\]|$)/.test(p),
      awaitWriteFinish: { stabilityThreshold: 120, pollInterval: 40 },
    });
    const handler = (type: PendingChange['type']) => (abs: string) => {
      const rel = path.relative(this.root, abs).split(path.sep).join('/');
      if (rel === CONFIG_FILE || MANIFEST_FILES.has(rel) || this.analyzer.isTracked(rel) || this.isStaticAsset(rel)) this.enqueue(rel, type, 'fs');
    };
    this.watcher.on('add', handler('add')).on('change', handler('change')).on('unlink', handler('unlink'));
    this.watcher.on('error', (e) => log.warn(`watcher error: ${String(e)}`));
    await new Promise<void>((r) => this.watcher!.once('ready', () => r()));
    this.monitoring = true;
    await this.persistProject();
    this.emitState('status');
    log.info(`monitoring ${this.root}`);
  }

  async stopMonitoring() {
    await this.watcher?.close();
    this.watcher = null;
    this.monitoring = false;
    await this.persistProject();
    this.emitState('status');
  }

  async dispose() {
    this.browserJob?.abort.abort();
    this.deps.cancel();
    this.web.cancel();
    for (const sc of this.scans.values()) sc.cancel();
    await this.stopMonitoring().catch(() => {});
  }

  private isStaticAsset(rel: string) {
    return Object.values(this.cfg.staticMap).some((d) => rel.startsWith(`${d}/`)) && /\.(css|html?|svg)$/.test(rel);
  }

  // ------------------------------------------------------------------ change pipeline

  enqueue(rel: string, type: PendingChange['type'], source: PendingChange['source']) {
    this.pending.set(rel, { type, source });
    this.analysisStatus = this.analyzing ? 'analyzing' : 'pending';
    if (this.debounceTimer) clearTimeout(this.debounceTimer);
    this.debounceTimer = setTimeout(() => void this.flush(), this.cfg.verification.debounceMs);
    this.emitState('pending', { files: [...this.pending.keys()] });
  }

  private async flush() {
    this.debounceTimer = null;
    if (this.analyzing) { this.rerun = true; return; }
    const batch = [...this.pending.entries()];
    this.pending.clear();
    if (!batch.length) return;
    await this.runAnalysis(batch, batch.some(([, c]) => c.source === 'editor') ? 'editor' : 'fs', false);
    if (this.rerun || this.pending.size) { this.rerun = false; await this.flush(); }
  }

  /** Unsaved editor buffer (from the IDE extension). `null` content clears the overlay (closed/saved/reverted). */
  async setBuffer(rel: string, content: string | null) {
    if (!this.analyzer.isTracked(rel)) return { accepted: false, reason: 'file type or location is not analysed by this project configuration' };
    this.analyzer.setOverlay(rel, content);
    this.enqueue(rel, 'change', 'editor');
    return { accepted: true };
  }

  async requestRefresh(full: boolean) {
    if (full) { this.loaded = loadProjectConfig(this.root); this.makeAnalyzer(); await this.persistProject(); }
    await this.runAnalysis([[full ? '*full-rescan*' : '*refresh*', { type: 'refresh', source: 'manual' }]], full ? 'full' : 'manual', full);
  }

  private async recordEvents(batch: [string, PendingChange][], runId: string) {
    const ids: string[] = [];
    for (const [rel, ch] of batch) {
      let contentHash: string | null = null;
      if (ch.source === 'editor') contentHash = this.analyzer.overlayHash(rel);
      else if (ch.type === 'add' || ch.type === 'change') {
        try { contentHash = shortHash(fs.readFileSync(path.join(this.root, rel))); } catch { contentHash = null; }
      }
      const memoKey = `${ch.source}:${rel}`;
      // A save that produces identical bytes (or a duplicate notification) is not a new logical update.
      if (ch.source !== 'manual' && ch.type !== 'unlink' && contentHash && this.lastFileHash.get(memoKey) === contentHash) continue;
      if (contentHash) this.lastFileHash.set(memoKey, contentHash);
      if (ch.type === 'unlink') this.lastFileHash.delete(memoKey);
      const prevEvent = this.lastEventByPath.get(rel) ?? 'none';
      const dedupeKey = sha256(`${this.id}|${rel}|${ch.type}|${ch.source}|${contentHash ?? '-'}|${ch.source === 'manual' ? runId : prevEvent}`);
      const eventId = `evt_${dedupeKey.slice(0, 20)}`;
      this.lastEventByPath.set(rel, eventId);
      ids.push(eventId);
      await this.safe(async () => {
        await this.store.col('file_events').updateOne(
          { projectId: this.id, dedupeKey },
          {
            $setOnInsert: { _id: eventId as never, projectId: this.id, path: rel, type: ch.type, source: ch.source, contentHash, receivedAt: new Date(), dedupeKey, bufferState: ch.source === 'editor' ? (this.analyzer.overlayFiles().has(rel) ? 'unsaved' : 'cleared') : 'on_disk' },
            $set: { status: 'analyzing', analysisRunId: runId },
            $inc: { occurrences: 1 },
          },
          { upsert: true },
        );
      }, undefined);
    }
    return ids;
  }

  private async runAnalysis(batch: [string, PendingChange][], trigger: string, full: boolean) {
    this.analyzing = true;
    this.analysisStatus = 'analyzing';
    const runId = newId('run');
    const startedAt = new Date();
    this.emitState('analysis', { runId, status: 'analyzing', files: batch.map(([p]) => p) });
    const eventIds = await this.recordEvents(batch, runId);
    if (batch.length && !eventIds.length) {
      this.analyzing = false;
      this.analysisStatus = 'idle';
      this.emitState('analysis', { runId, status: 'skipped', reason: 'no content change' });
      return;
    }
    await this.safe(() => this.store.col('analysis_runs').insertOne({ _id: runId as never, projectId: this.id, trigger, status: 'analyzing', startedAt, files: batch.map(([p]) => p), eventIds, provider: PARSER_VERSION }), undefined);
    try {
      let needsFull = full;
      for (const [rel] of batch) {
        if (rel === CONFIG_FILE) { this.loaded = loadProjectConfig(this.root); this.makeAnalyzer(); needsFull = true; await this.persistProject(); }
        if (MANIFEST_FILES.has(rel)) needsFull = true;
      }
      const changedFiles: string[] = [];
      if (needsFull || !this.live) {
        this.analyzer.fullScan();
      } else {
        for (const [rel, ch] of batch) {
          if (!this.analyzer.isTracked(rel)) continue;
          const changed = ch.type === 'unlink' ? this.analyzer.removeFile(rel) : this.analyzer.parseFile(rel);
          if (changed) changedFiles.push(rel);
        }
      }
      const graph = this.analyzer.build();
      const prev = this.live?.graph ?? null;
      const diff = diffGraphs(prev, graph);
      const changedIds = prev ? [...diff.changedNodes, ...diff.addedNodes] : [];
      const impact = prev && changedIds.length ? impactOf(new GraphIndex(graph), changedIds) : null;
      const graphHash = sha256(JSON.stringify(graph.nodes.map((n) => [n.id, n.hash])) + JSON.stringify(graph.edges.map((e) => e.id))).slice(0, 24);
      const sourceHash = sha256(JSON.stringify(this.analyzer.fileHashes()) + [...this.analyzer.overlayFiles()].join(',')).slice(0, 24);
      this.live = {
        graphVersion: (this.live?.graphVersion ?? 0) + 1, graph, graphHash, sourceHash, lastDiff: prev ? diff : null,
        lastImpact: impact, lastRunId: runId, lastChangedFiles: batch.map(([p]) => p), analyzedAt: new Date(),
      };
      const graphSnapshotId = await this.persistGraph(graph, graphHash, sourceHash, 'live');
      const findings = graphFindings(graph, this.changedSinceBaseline(graph));
      await this.safe(() => this.syncFindings(findings, 'graph', { analysisRunId: runId }), undefined);
      const summary = {
        nodes: graph.nodes.length, edges: graph.edges.length,
        addedNodes: diff.addedNodes.length, removedNodes: diff.removedNodes.length, changedNodes: diff.changedNodes.length,
        addedEdges: diff.addedEdges.length, removedEdges: diff.removedEdges.length,
        affectedEndpoints: impact?.affectedEndpoints.length ?? 0, unsavedBuffers: [...this.analyzer.overlayFiles()],
      };
      await this.safe(async () => {
        await this.store.col('analysis_runs').updateOne({ _id: runId as never }, {
          $set: {
            status: 'completed', finishedAt: new Date(), sourceHash, graphSnapshotId, filesAnalysed: needsFull ? graph.stats.files : changedFiles.length,
            fullScan: needsFull, summary,
            diff: { changedNodes: diff.changedNodes.slice(0, 200), addedNodes: prev ? diff.addedNodes.slice(0, 200) : [], removedNodes: diff.removedNodes.slice(0, 200), addedEdges: prev ? diff.addedEdges.slice(0, 200) : [], removedEdges: diff.removedEdges.slice(0, 200) },
            impact: impact ? { ...impact, paths: impact.paths.slice(0, 20) } : null,
            parseErrors: graph.stats.parseErrors,
          },
        });
        if (eventIds.length) await this.store.col('file_events').updateMany({ _id: { $in: eventIds as never[] } }, { $set: { status: 'analyzed', processedAt: new Date(), sourceHash } });
      }, undefined);
      this.analysisStatus = 'idle';
      this.analysisError = null;
      this.emitState('graph', { runId, graphVersion: this.live.graphVersion, summary });
      const savedChange = batch.some(([, c]) => c.source === 'fs');
      if (savedChange && this.cfg.verification.trigger === 'on-save' && this.verificationReady().ok) void this.verify('on-save');
    } catch (err) {
      const message = String((err as Error).stack ?? err);
      log.error(`analysis ${runId} failed`, message);
      this.analysisStatus = 'failed';
      this.analysisError = String((err as Error).message ?? err);
      await this.safe(async () => {
        await this.store.col('analysis_runs').updateOne({ _id: runId as never }, { $set: { status: 'failed', finishedAt: new Date(), error: this.analysisError } });
        if (eventIds.length) await this.store.col('file_events').updateMany({ _id: { $in: eventIds as never[] } }, { $set: { status: 'failed', error: this.analysisError, processedAt: new Date() } });
      }, undefined);
      this.emitState('analysis', { runId, status: 'failed', error: this.analysisError });
    } finally {
      this.analyzing = false;
    }
  }

  private async persistGraph(graph: Graph, graphHash: string, sourceHash: string, label: string): Promise<string> {
    // Project-scoped id: identical code in two projects sharing one database must not collide on _id.
    let id = `graph_${shortHash(`${this.id}|${graphHash}`, 24)}`;
    await this.safe(async () => {
      const json = JSON.stringify(graph);
      let body: Record<string, unknown> = { graph };
      if (json.length > 4_000_000) {
        const p = path.join(this.projectDir, 'graphs', `${id}.json`);
        fs.mkdirSync(path.dirname(p), { recursive: true });
        fs.writeFileSync(p, json);
        body = { storagePath: p };
      }
      const doc = await this.store.col('graph_snapshots').findOneAndUpdate(
        { projectId: this.id, graphHash },
        { $setOnInsert: { _id: id as never, projectId: this.id, graphHash, sourceHash, parserVersion: graph.provider, nodeCount: graph.nodes.length, edgeCount: graph.edges.length, stats: graph.stats, createdAt: new Date(), ...body }, $addToSet: { labels: label } },
        { upsert: true, returnDocument: 'after', projection: { _id: 1 } },
      );
      if (doc) id = doc._id as unknown as string; // an earlier snapshot of this project may use the old id format
    }, undefined);
    return id;
  }

  private changedSinceBaseline(graph: Graph): Set<string> {
    if (!this.baseline) return new Set();
    const d = diffGraphs(this.baseline.graph, graph);
    return new Set([...d.changedNodes, ...d.addedNodes]);
  }

  baselineDiff(): (GraphDiff & { impact: ImpactSummary | null }) | null {
    if (!this.baseline || !this.live) return null;
    const d = diffGraphs(this.baseline.graph, this.live.graph);
    const changed = [...d.changedNodes, ...d.addedNodes].filter((id) => !id.startsWith('mod:'));
    return { ...d, impact: changed.length ? impactOf(new GraphIndex(this.live.graph), changed) : null };
  }

  // ------------------------------------------------------------------ findings lifecycle

  /** Finding ids from findings.ts depend only on the code; suffix the project so shared databases do not mix projects. */
  private scopeFindings(drafts: FindingDraft[]): FindingDraft[] {
    return drafts.map((d) => ({ ...d, _id: `${d._id}_${this.id.slice(4, 12)}` }));
  }

  /** One-time move of this project's graph/runtime findings from the old unscoped ids to scoped ids. */
  private async migrateFindingIds() {
    await this.safe(async () => {
      const col = this.store.col('graph_findings');
      const old = await col.find({ projectId: this.id, source: { $in: ['graph', 'runtime'] }, _id: { $regex: /^(gf|rf)_[0-9a-f]{16}$/ } as never }).toArray();
      for (const f of old) {
        const oldId = f._id as unknown as string;
        const newId = `${oldId}_${this.id.slice(4, 12)}`;
        await col.updateOne({ _id: newId as never }, { $setOnInsert: { ...f, _id: newId } }, { upsert: true });
        await this.store.col('verification_records').updateMany({ projectId: this.id, findingId: oldId }, { $set: { findingId: newId } });
        await col.deleteOne({ _id: f._id, projectId: this.id });
      }
      if (old.length) log.info(`migrated ${old.length} finding id(s) to project-scoped ids`);
    }, undefined);
  }

  private async syncFindings(drafts: FindingDraft[], source: 'graph' | 'runtime', ctx: { analysisRunId?: string; browserRunId?: string; coveredScenarios?: { id: string; viewport: string; candidateStatus: string }[] }) {
    const col = this.store.col('graph_findings');
    const vr = this.store.col('verification_records');
    const now = new Date();
    const seen = new Set<string>();
    drafts = this.scopeFindings(drafts);
    for (const d of drafts) {
      seen.add(d._id);
      const existing = await col.findOne({ _id: d._id as never });
      const { _id, ...rest } = d;
      await col.updateOne({ _id: _id as never }, {
        $set: { ...rest, projectId: this.id, status: 'open', lastSeenAt: now, lastSeenAnalysisRunId: ctx.analysisRunId ?? existing?.lastSeenAnalysisRunId ?? null, lastSeenBrowserRunId: ctx.browserRunId ?? existing?.lastSeenBrowserRunId ?? null, resolvedAt: null },
        $setOnInsert: { firstSeenAt: now, firstSeenAnalysisRunId: ctx.analysisRunId ?? null, firstSeenBrowserRunId: ctx.browserRunId ?? null },
      }, { upsert: true });
      if (!existing || existing.status === 'resolved') {
        await vr.insertOne({ _id: newId('ver') as never, projectId: this.id, findingId: d._id, action: existing ? 'reopened' : 'observed', at: now, analysisRunId: ctx.analysisRunId ?? null, browserRunId: ctx.browserRunId ?? null, result: d.classification, notes: d.title });
      }
    }
    // Resolve open findings of this source that are no longer produced, but only when the producing check actually covered them.
    const open = await col.find({ projectId: this.id, source, status: 'open' }).toArray();
    for (const f of open) {
      if (seen.has(f._id as unknown as string)) continue;
      if (source === 'runtime') {
        const cov = ctx.coveredScenarios?.find((s) => s.id === f.scenario?.id && s.viewport === f.scenario?.viewport);
        if (!cov || cov.candidateStatus !== 'passed') continue; // not re-verified by this run: stays open
      }
      await col.updateOne({ _id: f._id }, { $set: { status: 'resolved', resolvedAt: now } });
      await vr.insertOne({
        _id: newId('ver') as never, projectId: this.id, findingId: f._id, at: now,
        action: source === 'runtime' ? 'verified_fixed' : 'resolved_by_analysis',
        analysisRunId: ctx.analysisRunId ?? null, browserRunId: ctx.browserRunId ?? null,
        result: source === 'runtime' ? 'scenario passed on candidate' : 'path no longer present in graph',
        notes: f.title,
      });
    }
    this.emitState('findings');
  }

  // ------------------------------------------------------------------ baseline + verification

  async markBaseline() {
    const snap = captureSnapshot(this.root, this.cfg, path.join(this.projectDir, 'snapshots'), this.id);
    const graph = analyzeDirectory(this.analyzerOptions(path.join(snap.storagePath, 'src')));
    await this.persistSnapshot(snap, 'baseline');
    const graphHash = sha256(JSON.stringify(graph.nodes.map((n) => [n.id, n.hash])) + JSON.stringify(graph.edges.map((e) => e.id))).slice(0, 24);
    await this.persistGraph(graph, graphHash, snap.contentHash.slice(0, 24), 'baseline');
    this.baseline = { snapshotId: snap.snapshotId, contentHash: snap.contentHash, createdAt: new Date(), manifest: snap.manifest, storagePath: snap.storagePath, graph };
    await this.safe(() => this.store.col('projects').updateOne({ _id: this.id as never }, { $set: { baselineSnapshotId: snap.snapshotId, baselineSetAt: new Date() } }), undefined);
    if (this.live) await this.safe(() => this.syncFindings(graphFindings(this.live!.graph, this.changedSinceBaseline(this.live!.graph)), 'graph', { analysisRunId: this.live!.lastRunId ?? undefined }), undefined);
    const unsaved = [...this.analyzer.overlayFiles()];
    this.emitState('baseline', { snapshotId: snap.snapshotId });
    return { snapshotId: snap.snapshotId, contentHash: snap.contentHash, fileCount: snap.fileCount, reused: snap.reused, unsavedBuffersExcluded: unsaved };
  }

  private async persistSnapshot(snap: SnapshotInfo, label: string) {
    await this.safe(() => this.store.col('source_snapshots').updateOne(
      { projectId: this.id, contentHash: snap.contentHash },
      {
        $setOnInsert: { _id: snap.snapshotId as never, projectId: this.id, contentHash: snap.contentHash, manifest: snap.manifest.slice(0, 5000), fileCount: snap.fileCount, totalBytes: snap.totalBytes, storagePath: snap.storagePath, createdAt: new Date(), runConfigHash: this.loaded.runHash },
        $addToSet: { labels: label },
      },
      { upsert: true },
    ), undefined);
  }

  async approveRunConfig(hash: string) {
    if (!this.loaded.runHash || hash !== this.loaded.runHash) throw new Error('run configuration changed; review it again before approving');
    this.runApproval = { hash, approvedAt: new Date() };
    await this.safe(() => this.store.col('projects').updateOne({ _id: this.id as never }, { $set: { runApproval: this.runApproval } }), undefined);
    this.emitState('status');
  }

  verificationReady(): { ok: boolean; reasons: string[] } {
    const reasons: string[] = [];
    if (this.loaded.error) reasons.push(this.loaded.error);
    if (!this.cfg.run) reasons.push(`no "run" section in ${CONFIG_FILE}: build/start commands must be configured explicitly`);
    else if (!this.runApproval || this.runApproval.hash !== this.loaded.runHash) reasons.push('run commands have not been approved in the dashboard (or changed since approval)');
    if (!this.cfg.browser.scenarios.length) reasons.push('no browser scenarios configured');
    if (!this.baseline) reasons.push('no baseline snapshot yet: mark the current working state as baseline first');
    const b = browserAvailable();
    if (!b.ok) reasons.push(`browser unavailable: ${b.reason}`);
    if (!this.store.available) reasons.push('MongoDB unavailable: verification results could not be recorded');
    return { ok: reasons.length === 0, reasons };
  }

  /** Can the baseline and current snapshots be started for a security scan? (Browser scenarios are not needed.) */
  snapshotTargetReadiness(): { ok: boolean; reasons: string[] } {
    const reasons: string[] = [];
    if (this.loaded.error) reasons.push(this.loaded.error);
    if (!this.cfg.run) reasons.push(`no "run" section in ${CONFIG_FILE}: build/start commands must be configured explicitly`);
    else if (!this.runApproval || this.runApproval.hash !== this.loaded.runHash) reasons.push('run commands have not been approved in the dashboard (or changed since approval)');
    if (!this.baseline) reasons.push('no baseline snapshot yet: mark the current working state as baseline first');
    if (!this.store.available) reasons.push('MongoDB unavailable: scan results could not be recorded');
    return { ok: reasons.length === 0, reasons };
  }

  /** Snapshot the current files and hand out start functions for both sides, mirroring executeVerification. */
  private async prepareSnapshotTargets(): Promise<SnapshotTargets> {
    const cfg = this.cfg;
    const run = cfg.run!;
    const baseline = this.baseline!;
    const unsaved = [...this.analyzer.overlayFiles()];
    const candidate = captureSnapshot(this.root, cfg, path.join(this.projectDir, 'snapshots'), this.id);
    await this.persistSnapshot(candidate, 'candidate');
    const candidateGraph = analyzeDirectory(this.analyzerOptions(path.join(candidate.storagePath, 'src')));
    const files = manifestDiff(baseline.manifest, candidate.manifest);
    const depsChanged = [...files.modified, ...files.added, ...files.removed].filter((f) => MANIFEST_FILES.has(f));
    const notes: string[] = [];
    if (unsaved.length) notes.push(`Unsaved editor buffers are NOT included in this scan: ${unsaved.join(', ')}`);
    if (depsChanged.length && cfg.snapshot.linkNodeModules) notes.push(`Dependency manifests differ (${depsChanged.join(', ')}); both sides use the workspace's current node_modules.`);
    const tag = newId('wsec');
    return {
      baseline: { snapshotId: baseline.snapshotId, contentHash: baseline.contentHash },
      candidate: { snapshotId: candidate.snapshotId, contentHash: candidate.contentHash },
      candidateGraph, baselineGraph: baseline.graph, notes,
      start: async (side, signal, onPhase) => {
        const snapPath = side === 'baseline' ? baseline.storagePath : candidate.storagePath;
        const work = prepareWorkspace(snapPath, this.root, cfg, path.join(this.projectDir, 'work', `${tag}-${side}`));
        const cleanup = () => fs.rmSync(work, { recursive: true, force: true });
        try {
          const app = await buildAndStart(work, run, (phase) => onPhase(phase), signal);
          return { ...app, cleanup };
        } catch (e) {
          cleanup();
          throw Object.assign(new Error((e as Error).message), { output: e instanceof StepError ? e.output : '' });
        }
      },
      isStale: () => { try { return captureContentHash(this.root, cfg) !== candidate.contentHash; } catch { return false; } },
    };
  }

  cancelVerification() {
    if (!this.browserJob) return false;
    this.verifyQueued = false;
    this.browserJob.abort.abort();
    return true;
  }

  /** Start a verification run, or queue exactly one follow-up if one is already running. */
  async verify(trigger: string): Promise<{ runId?: string; queued?: boolean; error?: string; reasons?: string[] }> {
    const ready = this.verificationReady();
    if (!ready.ok) return { error: 'verification is not available', reasons: ready.reasons };
    if (this.browserJob) { this.verifyQueued = true; this.emitState('browser', { queued: true }); return { queued: true }; }
    const runId = newId('brun');
    const abort = new AbortController();
    this.browserJob = { runId, status: 'pending', abort, startedAt: new Date() };
    void this.executeVerification(runId, trigger, abort).finally(() => {
      this.browserJob = null;
      if (this.verifyQueued) { this.verifyQueued = false; void this.verify('coalesced-follow-up'); }
    });
    return { runId };
  }

  private async setRun(runId: string, patch: Record<string, unknown>) {
    if (this.browserJob && this.browserJob.runId === runId && typeof patch.status === 'string') this.browserJob.status = patch.status as BrowserRunStatus;
    await this.safe(() => this.store.col('browser_runs').updateOne({ _id: runId as never }, { $set: patch }), undefined);
    this.emitState('browser', { runId, ...patch });
  }

  private async executeVerification(runId: string, trigger: string, abort: AbortController) {
    const cfg = this.cfg;
    const run = cfg.run!;
    const runDir = path.join(this.projectDir, 'runs', runId);
    const baseline = this.baseline!;
    const unsavedAtStart = [...this.analyzer.overlayFiles()];
    let candidate: SnapshotInfo;
    try {
      candidate = captureSnapshot(this.root, cfg, path.join(this.projectDir, 'snapshots'), this.id);
    } catch (e) {
      await this.safe(() => this.store.col('browser_runs').insertOne({ _id: runId as never, projectId: this.id, status: 'failed', trigger, startedAt: new Date(), finishedAt: new Date(), error: `could not snapshot workspace: ${(e as Error).message}` }), undefined);
      this.emitState('browser', { runId, status: 'failed' });
      return;
    }
    await this.persistSnapshot(candidate, 'candidate');
    if (this.browserJob) this.browserJob.candidateSnapshotId = candidate.snapshotId;
    const candidateGraph = analyzeDirectory(this.analyzerOptions(path.join(candidate.storagePath, 'src')));
    const files = manifestDiff(baseline.manifest, candidate.manifest);
    const depsChanged = [...files.modified, ...files.added, ...files.removed].filter((f) => MANIFEST_FILES.has(f));
    const scenarios = cfg.browser.scenarios;
    const viewports = cfg.browser.viewports;
    const plan = scenarios.flatMap((s) => viewports.filter((v) => !s.viewports || s.viewports.includes(v.name)).map((v) => ({ s, v })));
    const coverageNotes: string[] = [];
    if (unsavedAtStart.length) coverageNotes.push(`Unsaved editor buffers are NOT included in this run: ${unsavedAtStart.join(', ')}`);
    if (depsChanged.length && cfg.snapshot.linkNodeModules) coverageNotes.push(`Dependency manifests differ (${depsChanged.join(', ')}); both sides use the workspace's current node_modules.`);

    await this.safe(() => this.store.col('browser_runs').insertOne({
      _id: runId as never, projectId: this.id, trigger, status: 'pending', startedAt: new Date(),
      baselineSnapshotId: baseline.snapshotId, baselineContentHash: baseline.contentHash,
      candidateSnapshotId: candidate.snapshotId, candidateContentHash: candidate.contentHash,
      filesChanged: files, scenarios: plan.map(({ s, v }) => ({ id: s.id, name: s.name, viewport: v.name })),
      runConfigHash: this.loaded.runHash, coverageNotes, unsavedBuffersAtStart: unsavedAtStart,
      sides: { baseline: { status: 'pending' }, candidate: { status: 'pending' } },
    }), undefined);
    this.emitState('browser', { runId, status: 'pending' });

    let browser: Browser | null = null;
    const results: Record<'baseline' | 'candidate', ScenarioResult[]> = { baseline: [], candidate: [] };
    try {
      browser = await launchBrowser();
      await this.setRun(runId, { browserVersion: browser.version() });
      for (const side of ['baseline', 'candidate'] as const) {
        const snapPath = side === 'baseline' ? baseline.storagePath : candidate.storagePath;
        const work = prepareWorkspace(snapPath, this.root, cfg, path.join(this.projectDir, 'work', `${runId}-${side}`));
        let app: RunningApp | null = null;
        try {
          app = await buildAndStart(work, run, (phase) => void this.setRun(runId, { status: phase === 'ready' ? 'browser_running' : 'building', [`sides.${side}.status`]: phase }), abort.signal);
          const outDir = path.join(runDir, side);
          for (const { s, v } of plan) {
            if (abort.signal.aborted) throw new StepError('start', 'cancelled', '');
            const r = await runScenario(browser, app.url, s, v, cfg, outDir);
            results[side].push(r);
            await this.safe(() => this.store.col('browser_results').insertOne({
              _id: newId('bres') as never, projectId: this.id, browserRunId: runId, side, snapshotId: side === 'baseline' ? baseline.snapshotId : candidate.snapshotId,
              createdAt: new Date(), ...r, screenshot: r.screenshot ? path.relative(this.projectDir, r.screenshot) : null,
            }), undefined);
            this.emitState('browser', { runId, progress: { side, scenario: s.id, viewport: v.name, status: r.status } });
          }
          await this.setRun(runId, { [`sides.${side}.status`]: 'completed', [`sides.${side}.log`]: app.log().slice(-8000) });
        } catch (e) {
          const se = e instanceof StepError ? e : new StepError('start', String((e as Error).message ?? e), '');
          await this.setRun(runId, { [`sides.${side}.status`]: 'failed', [`sides.${side}.failedStep`]: se.step, [`sides.${side}.error`]: se.message, [`sides.${side}.log`]: se.output.slice(-8000) });
          if (abort.signal.aborted) { await this.setRun(runId, { status: 'cancelled', finishedAt: new Date(), error: 'cancelled by user' }); return; }
          const msg = side === 'baseline'
            ? `baseline ${se.step} failed: ${se.message}. A valid comparison is unavailable.`
            : `candidate ${se.step} failed: ${se.message}. No browser result reflects the current source.`;
          await this.setRun(runId, { status: side === 'baseline' ? 'inconclusive' : 'failed', finishedAt: new Date(), error: msg });
          return;
        } finally {
          await app?.stop();
          fs.rmSync(work, { recursive: true, force: true });
        }
      }

      await this.setRun(runId, { status: 'comparing' });
      const items: ComparisonItem[] = [];
      fs.mkdirSync(path.join(runDir, 'diff'), { recursive: true });
      for (const { s, v } of plan) {
        const b = results.baseline.find((r) => r.scenarioId === s.id && r.viewport === v.name);
        const c = results.candidate.find((r) => r.scenarioId === s.id && r.viewport === v.name);
        let visual = null;
        if (b?.screenshot && c?.screenshot) {
          visual = diffScreenshots(b.screenshot, c.screenshot, path.join(runDir, 'diff', `${s.id}--${v.name}.png`), cfg.browser.pixelThreshold);
          visual.diffImage = path.relative(this.projectDir, visual.diffImage);
        }
        const item = classify(b, c, visual, cfg.browser.diffThreshold);
        (item as unknown as Record<string, unknown>).baselineScreenshot = b?.screenshot ? path.relative(this.projectDir, b.screenshot) : null;
        (item as unknown as Record<string, unknown>).candidateScreenshot = c?.screenshot ? path.relative(this.projectDir, c.screenshot) : null;
        items.push(item);
      }
      const graphDiff = diffGraphs(baseline.graph, candidateGraph);
      const changedNodes = [...graphDiff.changedNodes, ...graphDiff.addedNodes].filter((id) => !id.startsWith('mod:'));
      const drafts = runtimeFindings(items, results.candidate, {
        candidateGraph, changedNodes, changedFiles: [...files.modified, ...files.added], staticMap: cfg.staticMap,
      });
      const counts = items.reduce<Record<string, number>>((acc, i) => { acc[i.classification] = (acc[i.classification] ?? 0) + 1; return acc; }, {});
      const comparisonId = `cmp_${runId.slice(5)}`;
      const nowHash = (() => { try { return captureContentHash(this.root, cfg); } catch { return null; } })();
      const stale = nowHash !== null && nowHash !== candidate.contentHash;
      await this.safe(async () => {
        await this.store.col('comparisons').insertOne({
          _id: comparisonId as never, projectId: this.id, browserRunId: runId,
          baselineSnapshotId: baseline.snapshotId, candidateSnapshotId: candidate.snapshotId,
          items, summary: counts, filesChanged: files,
          graphChanges: { changedNodes: graphDiff.changedNodes, addedNodes: graphDiff.addedNodes.filter((n) => !n.startsWith('mod:')), removedNodes: graphDiff.removedNodes.filter((n) => !n.startsWith('mod:')) },
          correlatedFindingIds: this.scopeFindings(drafts).map((d) => d._id),
          confidence: items.some((i) => i.classification === 'inconclusive') ? 'partial' : 'complete',
          limitations: [
            'Only configured scenarios and viewports were exercised; untested pages may still regress.',
            'Visual differences are reported as observations unless an assertion fails.',
            ...coverageNotes,
          ],
          createdAt: new Date(),
        });
        await this.syncFindings(drafts, 'runtime', { browserRunId: runId, coveredScenarios: items.map((i) => ({ id: i.scenarioId, viewport: i.viewport, candidateStatus: i.candidateStatus })) });
      }, undefined);
      const anyInconclusive = items.some((i) => i.classification === 'inconclusive');
      await this.setRun(runId, { status: anyInconclusive ? 'inconclusive' : 'completed', finishedAt: new Date(), comparisonId, summary: counts, staleAtFinish: stale });
    } catch (e) {
      await this.setRun(runId, { status: abort.signal.aborted ? 'cancelled' : 'failed', finishedAt: new Date(), error: String((e as Error).message ?? e).split('\n')[0] });
    } finally {
      await browser?.close().catch(() => {});
      this.lastBrowserRun = await this.safe(() => this.store.col('browser_runs').findOne({ _id: runId as never }), null);
    }
  }

  // ------------------------------------------------------------------ status

  status() {
    const ready = this.verificationReady();
    return {
      id: this.id, name: this.name, root: this.root,
      monitoring: this.monitoring,
      analysis: { status: this.analysisStatus, error: this.analysisError, pendingFiles: [...this.pending.keys()] },
      config: { source: this.loaded.source, error: this.loaded.error ?? null, warnings: this.loaded.warnings ?? [], run: this.cfg.run ?? null, runHash: this.loaded.runHash, runApproved: !!this.runApproval && this.runApproval.hash === this.loaded.runHash, verificationTrigger: this.cfg.verification.trigger, scenarios: this.cfg.browser.scenarios.map((s) => ({ id: s.id, name: s.name, path: s.path })), viewports: this.cfg.browser.viewports },
      parser: { provider: PARSER_VERSION, languages: ['javascript', 'typescript'], framework: 'express' },
      live: this.live ? {
        graphVersion: this.live.graphVersion, graphHash: this.live.graphHash, sourceHash: this.live.sourceHash, analyzedAt: this.live.analyzedAt,
        lastRunId: this.live.lastRunId, lastChangedFiles: this.live.lastChangedFiles, stats: this.live.graph.stats,
        nodeCount: this.live.graph.nodes.length, edgeCount: this.live.graph.edges.length,
      } : null,
      unsavedBuffers: [...this.analyzer.overlayFiles()],
      baseline: this.baseline ? { snapshotId: this.baseline.snapshotId, contentHash: this.baseline.contentHash, createdAt: this.baseline.createdAt, fileCount: this.baseline.manifest.length } : null,
      browser: { available: browserAvailable(), job: this.browserJob ? { runId: this.browserJob.runId, status: this.browserJob.status, candidateSnapshotId: this.browserJob.candidateSnapshotId, startedAt: this.browserJob.startedAt } : null, queued: this.verifyQueued },
      verification: ready,
      lastBrowserRun: this.lastBrowserRun ? { id: this.lastBrowserRun._id, status: this.lastBrowserRun.status, candidateSnapshotId: this.lastBrowserRun.candidateSnapshotId, finishedAt: this.lastBrowserRun.finishedAt, error: this.lastBrowserRun.error ?? null } : null,
      store: { available: this.store.available, error: this.store.lastError },
      security: { dependencies: this.deps.status(), web: this.web.status(), scans: Object.fromEntries([...this.scans].map(([k, v]) => [k, v.status()])) },
    };
  }

  artifactPath(rel: string): string | null {
    const abs = path.resolve(this.projectDir, rel);
    if (!abs.startsWith(this.projectDir + path.sep) || !fs.existsSync(abs)) return null;
    return abs;
  }
}

function captureContentHash(root: string, cfg: ProjectConfig): string {
  // Lightweight re-hash to detect whether the workspace moved on while a run was executing.
  const { files } = collectFiles(root, cfg);
  const manifest = files.map((f) => ({ path: f.rel, hash: sha256(f.data).slice(0, 16) }));
  return sha256(manifest.map((m) => `${m.path}\0${m.hash}`).join('\n'));
}
