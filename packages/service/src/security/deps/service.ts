// Dependency-scan service for one project: readiness cache, run lifecycle, MongoDB persistence of runs,
// immutable per-run observations and canonical findings (in the existing graph_findings collection with
// source 'dependency'), plus finding lifecycle that never treats "not run" as "fixed".
import fs from 'node:fs';
import path from 'node:path';
import type { Store } from '../../store/mongo.js';
import type { FileFacts, Graph } from '../../analyzer/types.js';
import { GraphIndex } from '../../analyzer/query.js';
import { newId, sha256, shortHash } from '../../util.js';
import { log } from '../../log.js';
import type { CoverageRecord, Exec, Readiness, SecurityConfig, ToolId, ToolRunRecord, Which } from '../types.js';
import { execTool, which as defaultWhich } from '../exec.js';
import { checkReadiness, runDependencyScan, DEPENDENCY_ADAPTERS, ALL_TOOLS } from './orchestrator.js';
import { detectTargets, hasInstalled, lockVersions, parseLockfile, type LockModel } from './lockfile.js';
import { mergeObservations, type MergedAdvisory } from './merge.js';
import { buildUsageIndex, packageUse, USE_LABEL, type PackageUse } from './packageUse.js';
import { SEVERITY_RANK_EXT } from './severity.js';

export type SecurityRunStatus = 'running' | 'completed' | 'partial' | 'unavailable' | 'failed' | 'cancelled' | 'not_run';

export interface DependencyServiceContext {
  projectId: string;
  root: string;
  projectDir: string;
  store: Store;
  cfg: () => SecurityConfig;
  graph: () => Graph | null;
  facts: () => FileFacts[];
  graphVersion: () => number | null;
  sourceHash: () => string | null;
  emit: (kind: string, payload?: unknown) => void;
  exec?: Exec;
  which?: Which;
  fetch?: typeof fetch;
}

const TOOL_NAMES: Record<ToolId, string> = { 'osv-api': 'OSV.dev (web API)', 'osv-scanner': 'OSV-Scanner', 'npm-audit': 'npm audit', trivy: 'Trivy' };

export class DependencyScanService {
  job: { runId: string; startedAt: Date; tool: ToolId | null; abort: AbortController } | null = null;
  lastRun: Record<string, unknown> | null = null;
  private readinessCache: { at: number; key: string; value: Readiness[] } | null = null;
  private readonly exec: Exec;
  private readonly which: Which;

  constructor(private readonly ctx: DependencyServiceContext) {
    this.exec = ctx.exec ?? execTool;
    this.which = ctx.which ?? defaultWhich;
  }

  async readiness(force = false): Promise<Readiness[]> {
    const cfg = this.ctx.cfg();
    const key = JSON.stringify(cfg);
    if (!force && this.readinessCache && this.readinessCache.key === key && Date.now() - this.readinessCache.at < 60_000) return this.readinessCache.value;
    const value = await checkReadiness(cfg, this.exec, this.which, this.ctx.root, ALL_TOOLS, this.ctx.fetch ?? globalThis.fetch);
    this.readinessCache = { at: Date.now(), key, value };
    return value;
  }

  /** Scanner panel data: live readiness plus static adapter metadata. */
  async scanners(force = false) {
    const cfg = this.ctx.cfg();
    const rd = await this.readiness(force);
    return ALL_TOOLS.map((t) => {
      const a = DEPENDENCY_ADAPTERS[t];
      return { ...rd.find((r) => r.tool === t)!, displayName: a.displayName, category: a.category, outputFormat: a.outputFormat, networkHosts: a.networkHosts(cfg), limitations: a.limitations };
    });
  }

  status() {
    const cfg = this.ctx.cfg();
    const { targets } = detectTargets(this.ctx.root);
    const lastHashes = (this.lastRun?.targets as { lockfile: string; lockfileHash: string }[] | undefined) ?? [];
    const lockfileChanged = targets.some((t) => { const prev = lastHashes.find((p) => p.lockfile === t.lockfile); return !!prev && prev.lockfileHash !== t.lockfileHash; });
    return {
      enabled: cfg.dependencies.enabled, allowNetwork: cfg.allowNetwork, mode: cfg.dependencies.mode, order: cfg.dependencies.order,
      job: this.job ? { runId: this.job.runId, startedAt: this.job.startedAt, tool: this.job.tool } : null,
      lastRun: this.lastRun ? { id: this.lastRun._id, status: this.lastRun.status, finishedAt: this.lastRun.finishedAt, counts: this.lastRun.counts ?? null } : null,
      lockfileChangedSinceLastScan: lockfileChanged,
      readiness: this.readinessCache?.value ?? null,
    };
  }

  async loadLastRun() {
    try {
      this.lastRun = await this.ctx.store.col('security_scan_runs').findOne({ projectId: this.ctx.projectId, category: 'dependency_vulns', status: { $ne: 'running' } }, { sort: { startedAt: -1 } });
    } catch { /* store unavailable: nothing to restore */ }
  }

  cancel(): boolean {
    if (!this.job) return false;
    this.job.abort.abort();
    return true;
  }

  /** Starts a scan in the background and returns its id. Requires MongoDB (results must be persisted).
   *  `tools` restricts the run to exactly those scanners (each one that is ready runs); omitted, the configured policy applies. */
  async start(trigger = 'manual', tools?: ToolId[]): Promise<{ runId: string }> {
    if (this.job) throw Object.assign(new Error(`a dependency scan is already running (${this.job.runId})`), { status: 409 });
    const base = this.ctx.cfg();
    if (!base.dependencies.enabled) throw Object.assign(new Error('dependency scanning is disabled (security.dependencies.enabled = false)'), { status: 400 });
    const notConfigured = (tools ?? []).filter((t) => !base.dependencies.order.includes(t));
    if (notConfigured.length) throw Object.assign(new Error(`not listed in security.dependencies.order: ${notConfigured.join(', ')}`), { status: 400 });
    const cfg: SecurityConfig = tools?.length
      ? { ...base, dependencies: { ...base.dependencies, order: [...new Set(tools)], mode: 'all-available' } }
      : base;
    const runs = this.ctx.store.col('security_scan_runs'); // throws StoreUnavailableError -> 503
    const runId = newId('sec');
    const startedAt = new Date();
    await runs.insertOne({
      _id: runId as never, projectId: this.ctx.projectId, category: 'dependency_vulns', trigger, status: 'running', startedAt,
      policy: { mode: cfg.dependencies.mode, order: cfg.dependencies.order, fallbackOnFailure: cfg.dependencies.fallbackOnFailure, includeDev: cfg.dependencies.includeDev },
      network: { allowed: cfg.allowNetwork }, graphVersion: this.ctx.graphVersion(), sourceHash: this.ctx.sourceHash(),
    });
    const abort = new AbortController();
    this.job = { runId, startedAt, tool: null, abort };
    this.ctx.emit('security', { runId, status: 'running' });
    void this.execute(runId, cfg, abort).catch(async (e) => {
      log.error(`dependency scan ${runId} crashed: ${(e as Error).stack ?? e}`);
      await runs.updateOne({ _id: runId as never }, { $set: { status: 'failed', finishedAt: new Date(), error: String((e as Error).message ?? e).slice(0, 500) } }).catch(() => {});
    }).finally(async () => {
      this.job = null;
      await this.loadLastRun();
      this.ctx.emit('security', { runId, status: 'finished' });
      this.ctx.emit('findings');
    });
    return { runId };
  }

  private async execute(runId: string, cfg: SecurityConfig, abort: AbortController) {
    const store = this.ctx.store;
    const { targets, unsupported } = detectTargets(this.ctx.root);
    const readiness = await this.readiness(true);
    const models = new Map<string, LockModel | null>();
    const notes: string[] = [];
    for (const t of targets) {
      try {
        models.set(t.lockfile, parseLockfile(fs.readFileSync(path.join(t.root, t.lockfile), 'utf8'), fs.readFileSync(path.join(t.root, t.manifest), 'utf8')));
      } catch (e) {
        models.set(t.lockfile, null);
        notes.push(`${t.lockfile} could not be parsed locally (${(e as Error).message}); installed versions and dependency paths may be missing.`);
      }
    }
    const result = await runDependencyScan(cfg, targets, unsupported, readiness, {
      exec: this.exec,
      lockVersions: (t) => { const m = models.get(t.lockfile); return m ? lockVersions(m) : new Map(); },
      lockPackages: (t) => { const m = models.get(t.lockfile); return m ? [...m.packages.values()].map((p) => ({ name: p.name, version: p.version, dev: p.dev })) : null; },
      fetch: this.ctx.fetch,
      signal: abort.signal,
      onTool: (tool, phase) => { if (this.job) this.job.tool = phase === 'running' ? tool : null; this.ctx.emit('security', { runId, tool, phase }); },
    });

    // Raw reports (dependency reports carry no secrets) are kept on disk; MongoDB stores references + hashes.
    const reportDir = path.join(this.ctx.projectDir, 'security', runId);
    for (const r of result.reports) {
      fs.mkdirSync(reportDir, { recursive: true });
      const file = path.join(reportDir, `${r.tool}.json`);
      fs.writeFileSync(file, r.stdout);
      const rec = result.tools.find((t) => t.tool === r.tool && t.selected);
      if (rec) { rec.reportRef = path.relative(this.ctx.projectDir, file); rec.reportSha256 = sha256(r.stdout); }
    }

    const cancelled = abort.signal.aborted;
    const covered = result.coverage.filter((c) => c.status === 'covered' || c.status === 'partial');
    const merged = mergeObservations(result.observations);
    const graph = this.ctx.graph();
    const ix = graph ? new GraphIndex(graph) : null;
    const usage = graph ? buildUsageIndex(this.ctx.facts(), graph) : null;
    const sync = cancelled ? null : await this.syncFindings(runId, merged, result.coverage, result.tools, targets.map((t) => ({ lockfile: t.lockfile, model: models.get(t.lockfile) ?? null })), ix, usage);

    // Was the lockfile modified while the tools were running? Then results describe the earlier bytes.
    const after = detectTargets(this.ctx.root).targets;
    const stale = targets.some((t) => after.find((a) => a.lockfile === t.lockfile)?.lockfileHash !== t.lockfileHash);

    let status: SecurityRunStatus;
    if (cancelled) status = 'cancelled';
    else if (!targets.length && !unsupported.length) status = 'not_run';
    else if (!covered.length) status = result.tools.some((t) => t.selected) ? 'failed' : 'unavailable';
    else if (covered.length < result.coverage.length || covered.some((c) => c.status === 'partial')) status = 'partial';
    else status = 'completed';

    await store.col('security_scan_runs').updateOne({ _id: runId as never }, {
      $set: {
        status, finishedAt: new Date(), tools: result.tools, coverage: result.coverage,
        targets: targets.map((t) => ({ ecosystem: t.ecosystem, lockfile: t.lockfile, manifest: t.manifest, lockfileHash: t.lockfileHash, manifestHash: t.manifestHash })),
        readiness, notes, staleAtFinish: stale,
        // Counts exist only for what was actually scanned; an unavailable or failed scan has no counts at all.
        counts: covered.length && sync ? sync.counts : null,
        findingIds: sync?.findingIds ?? [],
      },
    });
  }

  private async syncFindings(
    runId: string, merged: MergedAdvisory[], coverage: CoverageRecord[], tools: ToolRunRecord[],
    lockfiles: { lockfile: string; model: LockModel | null }[], ix: GraphIndex | null, usage: ReturnType<typeof buildUsageIndex> | null,
  ) {
    const store = this.ctx.store;
    const col = store.col('graph_findings');
    const obsCol = store.col('security_observations');
    const vr = store.col('verification_records');
    const now = new Date();
    const projectId = this.ctx.projectId;
    const completedTools = tools.filter((t) => t.status === 'completed').map((t) => t.tool);
    const counts = { total: 0, bySeverity: {} as Record<string, number>, byUse: {} as Record<string, number>, new: 0, recurring: 0, regressions: 0, notCurrentlyObserved: 0, resolvedVersionRemoved: 0, notRechecked: 0 };
    const findingIds: string[] = [];

    for (const m of merged) {
      const lf = m.observations[0].sourceFile;
      const model = lockfiles.find((l) => l.lockfile === lf)?.model ?? lockfiles[0]?.model ?? null;
      const use: PackageUse | null = ix && usage ? packageUse(m.packageName, m.lockfileNodes, model, usage, ix) : null;
      const existing = await col.findOne({ projectId, source: 'dependency', 'pkg.ecosystem': m.ecosystem, 'pkg.name': m.packageName, 'pkg.version': m.installedVersion, ids: { $in: m.ids } }, { sort: { firstSeenAt: 1 } });
      const id = (existing?._id as unknown as string) ?? `dep_${shortHash(`${projectId}|${m.ecosystem}|${m.packageName}|${m.installedVersion}|${m.canonicalId}`, 16)}`;
      findingIds.push(id);
      const labels = ['scanner_detected', ...(use && (use.importers.length || use.callers.length) ? ['graph_linked'] : []), ...(use?.endpoints.length ? ['reachable_path'] : [])];
      const sevText = m.severityByTool.map((s) => `${TOOL_NAMES[s.tool]}: ${s.original ?? 'not supplied'}`).join('; ');
      const title = `${m.packageName}@${m.installedVersion ?? '?'}: ${m.title ?? m.canonicalId}`;
      const explanation = [
        `${m.tools.map((t) => TOOL_NAMES[t]).join(' and ')} reported ${m.canonicalId}${m.ids.length > 1 ? ` (also ${m.ids.filter((x) => x !== m.canonicalId).join(', ')})` : ''} for the installed version ${m.packageName}@${m.installedVersion ?? 'unknown'}.`,
        `Severity as published: ${sevText}.`,
        ...(m.affectedRanges.length ? [`Affected range: ${[...new Set(m.affectedRanges.map((r) => r.range))].join(' | ')}.`] : []),
        ...(m.fixedVersions ? [m.fixedVersions.length ? `Fixed in: ${m.fixedVersions.join(', ')}.` : 'No fixed version listed.'] : []),
        ...(use ? [`Use in this project: ${use.summary}`] : ['Use in this project: unknown (no code graph available at scan time).']),
      ];
      const limitations = [
        'A version with a published advisory is installed. The scanners do not determine whether the vulnerable code path is used or exploitable.',
        ...(use?.evidence === 'called_from_analysed_code' ? ['Call evidence shows code calls into the package, not that it calls the affected function.'] : []),
        ...(use?.evidence === 'declared_not_imported' ? ['Only files under analysis.include were checked for imports; dynamic requires and files outside the analysed folders are not seen.'] : []),
        ...m.tools.flatMap((t) => (t === 'npm-audit' ? ['npm audit does not report CVE identifiers; none are inferred.'] : [])),
      ];
      const severityRank = SEVERITY_RANK_EXT[m.severity];
      const reopened = existing && existing.status !== 'open';
      await col.updateOne({ _id: id as never }, {
        $set: {
          projectId, source: 'dependency', category: 'vulnerable_dependency', classification: 'scanner_detected', labels,
          severity: m.severity, severityRank, title, explanation,
          nodes: use ? [...new Set([...use.endpoints, ...use.callers, ...use.importers])] : [], edges: [], paths: use?.paths ?? [],
          locations: (usage?.importSites.get(m.packageName) ?? []).slice(0, 10),
          evidence: { canonicalId: m.canonicalId, severityByTool: m.severityByTool, cvssScore: m.cvssScore, url: m.url },
          suggestedNextStep: m.remediation.length ? m.remediation.map((r) => `${TOOL_NAMES[r.tool]}: ${r.text}`).join(' ') : `Upgrade ${m.packageName} to a version outside the affected range.`,
          confidence: 'high', confidenceNote: 'Confidence that the installed version matches the advisory\'s affected range, as reported by the tool. It says nothing about exploitability.',
          limitations, ids: m.ids, canonicalId: m.canonicalId, cwe: m.cwe,
          pkg: {
            ecosystem: m.ecosystem, name: m.packageName, version: m.installedVersion, lockfile: lf, lockfileNodes: m.lockfileNodes,
            affectedRanges: m.affectedRanges, fixedVersions: m.fixedVersions,
            direct: use?.direct ?? null, devOnly: use?.devOnly ?? null, declaredAs: use?.declaredAs ?? null,
            use: use ? { evidence: use.evidence, label: USE_LABEL[use.evidence], summary: use.summary, importers: use.importers, callers: use.callers, endpoints: use.endpoints, introducedBy: use.introducedBy } : null,
          },
          lastTools: m.tools, references: m.url ? [m.url] : [],
          status: 'open', resolvedAt: null, lastSeenAt: now, lastSeenSecurityRunId: runId, graphVersionAtScan: this.ctx.graphVersion(),
          ...(reopened ? { potentialRegression: true } : {}),
        },
        $addToSet: { scanners: { $each: m.tools } },
        $setOnInsert: { firstSeenAt: now, firstSeenSecurityRunId: runId, ...(reopened ? {} : { potentialRegression: false }) },
      }, { upsert: true });
      if (!existing) {
        counts.new++;
        await vr.insertOne({ _id: newId('ver') as never, projectId, findingId: id, action: 'observed', at: now, securityRunId: runId, result: m.tools.join(', '), notes: title });
      } else {
        counts.recurring++;
        if (reopened) {
          counts.regressions++;
          await vr.insertOne({ _id: newId('ver') as never, projectId, findingId: id, action: 'potential_regression', at: now, securityRunId: runId, result: `reported again by ${m.tools.join(', ')} after being ${existing.status}`, notes: title });
        }
      }
      counts.total++;
      counts.bySeverity[m.severity] = (counts.bySeverity[m.severity] ?? 0) + 1;
      if (use) counts.byUse[use.evidence] = (counts.byUse[use.evidence] ?? 0) + 1;

      // Immutable, idempotent per-run observations (one per tool report line).
      const docs = m.observations.map((o) => ({
        _id: `obs_${shortHash(`${runId}|${o.tool}|${id}|${o.advisoryId}|${o.installedVersion}`, 20)}`,
        projectId, runId, findingId: id, tool: o.tool, toolVersion: o.toolVersion, observedAt: now,
        advisoryId: o.advisoryId, aliases: o.aliases, toolRef: o.toolRef, package: { ecosystem: o.ecosystem, name: o.packageName, version: o.installedVersion },
        severity: o.severity, originalSeverity: o.originalSeverity, cvssScore: o.cvssScore, cwe: o.cwe, affectedRange: o.affectedRange, fixedVersions: o.fixedVersions,
        remediation: o.remediation, lockfileNodes: o.lockfileNodes, sourceFile: o.sourceFile, url: o.url, title: o.title,
      }));
      if (docs.length) {
        try { await obsCol.insertMany(docs as never[], { ordered: false }); }
        catch (e) { if ((e as { code?: number }).code !== 11000 && !String((e as Error).message).includes('E11000')) throw e; }
      }
    }

    // Findings not reported this time. Only lockfiles that were actually covered are considered, and a finding
    // is marked "not currently observed" only if a tool that previously reported it completed in this run.
    const seen = new Set(findingIds);
    for (const c of coverage.filter((x) => x.status === 'covered' || x.status === 'partial')) {
      const model = lockfiles.find((l) => l.lockfile === c.lockfile)?.model ?? null;
      const prior = await col.find({ projectId, source: 'dependency', 'pkg.lockfile': c.lockfile, status: { $in: ['open', 'not_currently_observed'] } }).toArray();
      for (const f of prior) {
        const fid = f._id as unknown as string;
        if (seen.has(fid)) continue;
        if (model && !hasInstalled(model, f.pkg.name, f.pkg.version)) {
          await col.updateOne({ _id: f._id }, { $set: { status: 'resolved', resolvedAt: now, resolution: 'version_removed' } });
          await vr.insertOne({ _id: newId('ver') as never, projectId, findingId: fid, action: 'version_removed', at: now, securityRunId: runId, result: `${f.pkg.name}@${f.pkg.version} is no longer in ${c.lockfile}`, notes: f.title });
          counts.resolvedVersionRemoved++;
          continue;
        }
        if (f.status !== 'open') continue;
        const rechecked = (f.scanners as ToolId[] | undefined)?.some((t) => completedTools.includes(t));
        if (rechecked) {
          await col.updateOne({ _id: f._id }, { $set: { status: 'not_currently_observed', notObservedSince: now } });
          await vr.insertOne({ _id: newId('ver') as never, projectId, findingId: fid, action: 'not_currently_observed', at: now, securityRunId: runId, result: `not reported by ${completedTools.join(', ')}; the installed version is unchanged`, notes: f.title });
          counts.notCurrentlyObserved++;
        } else {
          counts.notRechecked++;
        }
      }
    }
    return { counts, findingIds };
  }
}
