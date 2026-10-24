// MongoDB persistence. All history lives here; the service keeps only the *current* live graph in memory.
import { MongoClient, type Collection, type Db, type Document } from 'mongodb';
import { log } from '../log.js';

export class StoreUnavailableError extends Error {
  constructor(msg = 'MongoDB is unavailable') { super(msg); this.name = 'StoreUnavailableError'; }
}

export const COLLECTIONS = [
  'projects', 'file_events', 'source_snapshots', 'graph_snapshots', 'analysis_runs',
  'graph_findings', 'browser_runs', 'browser_results', 'comparisons', 'verification_records',
  'security_scan_runs', 'security_observations', 'agent_events', 'web_endpoints', 'web_scan_cache',
] as const;
export type CollectionName = (typeof COLLECTIONS)[number];

export class Store {
  private client: MongoClient | null = null;
  private db: Db | null = null;
  available = false;
  lastError: string | null = null;
  private retryTimer: NodeJS.Timeout | null = null;
  onStatus: (available: boolean) => void = () => {};

  constructor(private readonly uri: string, private readonly dbName: string) {}

  async connect(): Promise<boolean> {
    try {
      this.client = new MongoClient(this.uri, { serverSelectionTimeoutMS: 3000, appName: 'workbench-service' });
      await this.client.connect();
      this.db = this.client.db(this.dbName);
      await this.db.command({ ping: 1 });
      await this.ensureIndexes();
      this.setAvailable(true, null);
      this.client.on('serverHeartbeatFailed', () => this.setAvailable(false, 'heartbeat failed'));
      this.client.on('serverHeartbeatSucceeded', () => { if (!this.available) this.setAvailable(true, null); });
      return true;
    } catch (err) {
      this.setAvailable(false, String((err as Error).message ?? err));
      await this.client?.close().catch(() => {});
      this.client = null;
      this.db = null;
      this.scheduleRetry();
      return false;
    }
  }

  private setAvailable(v: boolean, err: string | null) {
    const changed = v !== this.available;
    this.available = v;
    this.lastError = err;
    if (changed) {
      log.info(v ? 'mongodb connected' : `mongodb unavailable: ${err}`);
      this.onStatus(v);
    }
  }

  private scheduleRetry() {
    if (this.retryTimer) return;
    this.retryTimer = setTimeout(async () => {
      this.retryTimer = null;
      await this.connect();
    }, 10_000);
    this.retryTimer.unref();
  }

  async close() {
    if (this.retryTimer) clearTimeout(this.retryTimer);
    await this.client?.close().catch(() => {});
  }

  col<T extends Document = Document>(name: CollectionName): Collection<T> {
    if (!this.db || !this.available) throw new StoreUnavailableError(this.lastError ? `MongoDB is unavailable: ${this.lastError}` : undefined);
    return this.db.collection<T>(name);
  }

  private async ensureIndexes() {
    const db = this.db!;
    await Promise.all([
      db.collection('projects').createIndex({ root: 1 }, { unique: true }),
      db.collection('file_events').createIndex({ projectId: 1, dedupeKey: 1 }, { unique: true }),
      db.collection('file_events').createIndex({ projectId: 1, receivedAt: -1 }),
      db.collection('file_events').createIndex({ projectId: 1, status: 1 }),
      db.collection('source_snapshots').createIndex({ projectId: 1, contentHash: 1 }, { unique: true }),
      db.collection('source_snapshots').createIndex({ projectId: 1, createdAt: -1 }),
      db.collection('graph_snapshots').createIndex({ projectId: 1, graphHash: 1 }, { unique: true }),
      db.collection('analysis_runs').createIndex({ projectId: 1, startedAt: -1 }),
      db.collection('graph_findings').createIndex({ projectId: 1, status: 1, severityRank: -1 }),
      db.collection('graph_findings').createIndex({ projectId: 1, lastSeenAt: -1 }),
      db.collection('browser_runs').createIndex({ projectId: 1, startedAt: -1 }),
      db.collection('browser_results').createIndex({ browserRunId: 1, side: 1, scenarioId: 1, viewport: 1 }, { unique: true }),
      db.collection('browser_results').createIndex({ projectId: 1, scenarioId: 1, createdAt: -1 }),
      db.collection('comparisons').createIndex({ projectId: 1, createdAt: -1 }),
      db.collection('comparisons').createIndex({ browserRunId: 1 }, { unique: true }),
      db.collection('verification_records').createIndex({ projectId: 1, findingId: 1, at: -1 }),
      db.collection('graph_findings').createIndex({ projectId: 1, source: 1, 'pkg.name': 1, 'pkg.version': 1 }),
      db.collection('graph_findings').createIndex({ projectId: 1, ids: 1 }),
      db.collection('security_scan_runs').createIndex({ projectId: 1, category: 1, startedAt: -1 }),
      db.collection('security_scan_runs').createIndex({ projectId: 1, status: 1 }),
      db.collection('security_observations').createIndex({ projectId: 1, findingId: 1, observedAt: -1 }),
      db.collection('security_observations').createIndex({ runId: 1, tool: 1 }),
      db.collection('security_observations').createIndex({ projectId: 1, 'package.name': 1, advisoryId: 1 }),
      db.collection('agent_events').createIndex({ projectId: 1, at: -1 }),
      db.collection('security_observations').createIndex({ runId: 1, side: 1 }),
      db.collection('graph_findings').createIndex({ projectId: 1, source: 1, 'web.scopeKey': 1, status: 1 }),
      // Incremental web scanning (security/web/incremental.ts). _id is a hash of (project, scope, input), so a point
      // lookup is by _id; a scan loads a whole scope with one indexed query. The TTL index drops cache buckets whose
      // newest entry has expired (e.g. a route that was removed); lookups still check each entry's own expiry.
      db.collection('web_endpoints').createIndex({ projectId: 1, scope: 1, kind: 1 }),
      db.collection('web_scan_cache').createIndex({ projectId: 1, scope: 1 }),
      db.collection('web_scan_cache').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    ]);
  }

  // ---- aggregation pipelines used by the dashboard ----

  /** Per scenario/viewport: run count, pass/fail counts and the latest candidate outcome. */
  scenarioHistory(projectId: string) {
    return this.col('browser_results').aggregate([
      { $match: { projectId, side: 'candidate' } },
      { $sort: { createdAt: 1 } },
      {
        $group: {
          _id: { scenarioId: '$scenarioId', viewport: '$viewport' },
          scenarioName: { $last: '$scenarioName' },
          runs: { $sum: 1 },
          passed: { $sum: { $cond: [{ $eq: ['$status', 'passed'] }, 1, 0] } },
          failed: { $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] } },
          errored: { $sum: { $cond: [{ $eq: ['$status', 'error'] }, 1, 0] } },
          lastStatus: { $last: '$status' },
          lastRunId: { $last: '$browserRunId' },
          lastAt: { $last: '$createdAt' },
          statuses: { $push: { status: '$status', runId: '$browserRunId', at: '$createdAt' } },
        },
      },
      { $project: { _id: 0, scenarioId: '$_id.scenarioId', viewport: '$_id.viewport', scenarioName: 1, runs: 1, passed: 1, failed: 1, errored: 1, lastStatus: 1, lastRunId: 1, lastAt: 1, recent: { $slice: ['$statuses', -12] } } },
      { $sort: { scenarioId: 1, viewport: 1 } },
    ]).toArray();
  }

  /** Findings grouped by status and severity plus file-event activity per hour (last 24h). */
  async dashboardSummary(projectId: string) {
    const since = new Date(Date.now() - 24 * 3600 * 1000);
    const [findings] = await this.col('graph_findings').aggregate([
      { $match: { projectId } },
      {
        $facet: {
          bySeverity: [{ $match: { status: 'open' } }, { $group: { _id: '$severity', count: { $sum: 1 } } }, { $sort: { _id: 1 } }],
          byClassification: [{ $match: { status: 'open' } }, { $group: { _id: '$classification', count: { $sum: 1 } } }],
          byStatus: [{ $group: { _id: '$status', count: { $sum: 1 } } }],
        },
      },
    ]).toArray();
    const activity = await this.col('file_events').aggregate([
      { $match: { projectId, receivedAt: { $gte: since } } },
      { $group: { _id: { $dateTrunc: { date: '$receivedAt', unit: 'hour' } }, events: { $sum: 1 }, failed: { $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] } } } },
      { $sort: { _id: 1 } },
    ]).toArray();
    const runs = await this.col('browser_runs').aggregate([
      { $match: { projectId } },
      { $group: { _id: '$status', count: { $sum: 1 } } },
    ]).toArray();
    return { findings, activity, browserRunsByStatus: runs };
  }

  /** Dependency findings by lifecycle, severity, use evidence and reporting tool, plus scan runs by status. */
  async dependencySummary(projectId: string) {
    const [f] = await this.col('graph_findings').aggregate([
      { $match: { projectId, source: 'dependency' } },
      {
        $facet: {
          byStatus: [{ $group: { _id: '$status', count: { $sum: 1 } } }],
          openBySeverity: [{ $match: { status: 'open' } }, { $group: { _id: '$severity', count: { $sum: 1 } } }],
          openByUse: [{ $match: { status: 'open' } }, { $group: { _id: '$pkg.use.evidence', count: { $sum: 1 } } }],
          openByTool: [{ $match: { status: 'open' } }, { $unwind: '$scanners' }, { $group: { _id: '$scanners', count: { $sum: 1 } } }],
          regressions: [{ $match: { status: 'open', potentialRegression: true } }, { $count: 'count' }],
        },
      },
    ]).toArray();
    const runs = await this.col('security_scan_runs').aggregate([
      { $match: { projectId, category: 'dependency_vulns' } },
      { $group: { _id: '$status', count: { $sum: 1 }, last: { $max: '$startedAt' } } },
    ]).toArray();
    return { findings: f, runsByStatus: runs };
  }
}
