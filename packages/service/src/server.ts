// Local HTTP + WebSocket API. Binds to loopback only and rejects cross-site requests.
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import express, { type NextFunction, type Request, type Response } from 'express';
import { WebSocketServer, type WebSocket } from 'ws';
import { z } from 'zod';
import type { ServiceConfig } from './config.js';
import { Store } from './store/mongo.js';
import { ProjectSession } from './project.js';
import { GraphIndex, impactOf } from './analyzer/query.js';
import { graphFindings } from './findings.js';
import { browserAvailable } from './browser.js';
import { newId } from './util.js';
import { log } from './log.js';

export class Service {
  readonly store: Store;
  readonly sessions = new Map<string, ProjectSession>();
  private server: http.Server | null = null;
  private wss: WebSocketServer | null = null;
  private clients = new Set<WebSocket>();

  constructor(readonly cfg: ServiceConfig) {
    this.store = new Store(cfg.mongoUri, cfg.mongoDb);
    this.store.onStatus = () => this.broadcast({ kind: 'service', at: new Date().toISOString() });
  }

  broadcast(msg: unknown) {
    const s = JSON.stringify(msg);
    for (const c of this.clients) if (c.readyState === c.OPEN) c.send(s);
  }

  async addProject(root: string, monitor = true): Promise<ProjectSession> {
    const abs = path.resolve(root);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isDirectory()) throw new Error(`not a directory: ${abs}`);
    const existing = [...this.sessions.values()].find((s) => s.root === fs.realpathSync(abs));
    if (existing) { if (monitor && !existing.monitoring) await existing.startMonitoring(); return existing; }
    const s = new ProjectSession(abs, this.store, this.cfg.dataDir);
    s.on('update', (m) => this.broadcast(m));
    this.sessions.set(s.id, s);
    await s.init();
    if (monitor) await s.startMonitoring();
    return s;
  }

  private session(req: Request): ProjectSession {
    const s = this.sessions.get(String(req.params.id));
    if (!s) throw Object.assign(new Error('unknown project'), { status: 404 });
    return s;
  }

  app() {
    const app = express();
    const allowedHosts = new Set([`127.0.0.1:${this.cfg.port}`, `localhost:${this.cfg.port}`]);
    app.disable('x-powered-by');
    app.use((req, res, next) => {
      // DNS-rebinding and CSRF protection for a loopback service.
      if (!allowedHosts.has(String(req.headers.host))) return res.status(403).json({ error: 'forbidden host' });
      const origin = req.headers.origin;
      if (origin && req.method !== 'GET' && !allowedHosts.has(origin.replace(/^https?:\/\//, ''))) return res.status(403).json({ error: 'cross-origin request rejected' });
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Referrer-Policy', 'no-referrer');
      next();
    });
    app.use(express.json({ limit: '2mb' }));

    const h = (fn: (req: Request, res: Response) => Promise<unknown> | unknown) =>
      (req: Request, res: Response, next: NextFunction) => Promise.resolve(fn(req, res)).then((v) => { if (!res.headersSent) res.json(v ?? { ok: true }); }).catch(next);

    app.get('/api/health', h(() => ({
      ok: true, mongo: { available: this.store.available, error: this.store.lastError }, browser: browserAvailable(),
      projects: [...this.sessions.keys()],
    })));

    app.get('/api/projects', h(() => [...this.sessions.values()].map((s) => s.status())));

    app.post('/api/projects', h(async (req) => {
      const body = z.object({ root: z.string().min(1), monitor: z.boolean().default(true) }).parse(req.body);
      const s = await this.addProject(body.root, body.monitor);
      return s.status();
    }));

    app.get('/api/projects/:id/status', h((req) => this.session(req).status()));

    app.post('/api/projects/:id/monitoring', h(async (req) => {
      const { enabled } = z.object({ enabled: z.boolean() }).parse(req.body);
      const s = this.session(req);
      if (enabled) await s.startMonitoring(); else await s.stopMonitoring();
      return s.status();
    }));

    app.post('/api/projects/:id/refresh', h(async (req) => {
      const { full } = z.object({ full: z.boolean().default(false) }).parse(req.body ?? {});
      await this.session(req).requestRefresh(full);
      return this.session(req).status();
    }));

    app.post('/api/projects/:id/buffer', h(async (req) => {
      const body = z.object({ path: z.string().min(1), content: z.string().max(1_000_000).nullable() }).parse(req.body);
      const rel = path.posix.normalize(body.path.split(path.sep).join('/'));
      if (rel.startsWith('..') || path.isAbsolute(rel)) throw Object.assign(new Error('path must be inside the project'), { status: 400 });
      return this.session(req).setBuffer(rel, body.content);
    }));

    app.get('/api/projects/:id/graph', h((req) => {
      const s = this.session(req);
      if (!s.live) return { graph: null };
      return { graph: s.live.graph, graphVersion: s.live.graphVersion, graphHash: s.live.graphHash, sourceHash: s.live.sourceHash, lastDiff: s.live.lastDiff, lastImpact: s.live.lastImpact, lastChangedFiles: s.live.lastChangedFiles, baselineDiff: s.baselineDiff() };
    }));

    app.get('/api/projects/:id/impact', h((req) => {
      const s = this.session(req);
      const node = z.string().parse(req.query.node);
      if (!s.live) return null;
      const ix = new GraphIndex(s.live.graph);
      const impact = impactOf(ix, [node]);
      const down = ix.downstream([node]);
      const up = ix.upstream([node]);
      return { node, impact, upstream: [...up.entries()], downstream: [...down.entries()] };
    }));

    app.get('/api/projects/:id/reachability', h((req) => {
      const s = this.session(req);
      if (!s.live) return [];
      const changed = new Set(s.baselineDiff() ? [...s.baselineDiff()!.changedNodes, ...s.baselineDiff()!.addedNodes] : []);
      return graphFindings(s.live.graph, changed);
    }));

    app.get('/api/projects/:id/findings', h(async (req) => {
      const s = this.session(req);
      const status = typeof req.query.status === 'string' ? req.query.status : undefined;
      return this.store.col('graph_findings').find({ projectId: s.id, ...(status ? { status } : {}) }).sort({ status: 1, severityRank: -1, lastSeenAt: -1 }).limit(200).toArray();
    }));

    app.get('/api/projects/:id/findings/:fid', h(async (req) => {
      const s = this.session(req);
      const finding = await this.store.col('graph_findings').findOne({ _id: req.params.fid as never, projectId: s.id });
      const records = await this.store.col('verification_records').find({ projectId: s.id, findingId: req.params.fid }).sort({ at: -1 }).limit(50).toArray();
      return { finding, records };
    }));

    // ---- dependency vulnerability scanning (external tools; never downloaded or installed by the service) ----
    app.get('/api/projects/:id/security/scanners', h(async (req) => this.session(req).deps.scanners(req.query.refresh === '1')));

    app.post('/api/projects/:id/security/dependency-scans', h(async (req, res) => {
      const { tools, trigger } = z.object({
        tools: z.array(z.enum(['osv-api', 'npm-audit', 'osv-scanner', 'trivy'])).min(1).optional(),
        trigger: z.enum(['manual', 'agent']).default('manual'),
      }).parse(req.body ?? {});
      const r = await this.session(req).deps.start(trigger, tools);
      res.status(202);
      return r;
    }));

    app.post('/api/projects/:id/security/dependency-scans/cancel', h((req) => ({ cancelled: this.session(req).deps.cancel() })));

    app.get('/api/projects/:id/security/dependency-scans', h(async (req) => {
      const s = this.session(req);
      return this.store.col('security_scan_runs').find({ projectId: s.id, category: 'dependency_vulns' }, { projection: { readiness: 0 } }).sort({ startedAt: -1 }).limit(30).toArray();
    }));

    app.get('/api/projects/:id/security/dependency-scans/:rid', h(async (req) => {
      const s = this.session(req);
      const run = await this.store.col('security_scan_runs').findOne({ _id: req.params.rid as never, projectId: s.id });
      const observations = await this.store.col('security_observations').find({ runId: req.params.rid, projectId: s.id }).limit(2000).toArray();
      return { run, observations };
    }));

    app.get('/api/projects/:id/security/summary', h(async (req) => this.store.dependencySummary(this.session(req).id)));

    // ---- AI agent activity log (the LLM orchestrator reports its decisions and tool runs here) ----
    app.post('/api/projects/:id/agent/events', h(async (req, res) => {
      const s = this.session(req);
      const body = z.object({
        type: z.enum(['change', 'decision', 'tool_result', 'scan', 'info']),
        endpoint: z.string().nullish(),
        tool: z.string().nullish(),
        severity: z.enum(['high', 'medium', 'low', 'info', 'unknown']).nullish(),
        title: z.string().max(500),
        detail: z.string().max(4000).nullish(),
        data: z.record(z.unknown()).nullish(),
      }).parse(req.body ?? {});
      const doc = { _id: newId('age') as never, projectId: s.id, at: new Date(), ...body };
      await this.store.col('agent_events').insertOne(doc);
      this.broadcast({ kind: 'agent', projectId: s.id, at: new Date().toISOString() });
      res.status(202);
      return { id: doc._id };
    }));

    app.get('/api/projects/:id/agent/events', h(async (req) => {
      const s = this.session(req);
      const limit = Math.min(500, Number(req.query.limit) || 200);
      const rows = await this.store.col('agent_events').find({ projectId: s.id }).sort({ at: -1 }).limit(limit).toArray();
      return rows.reverse(); // oldest-first for a readable log
    }));

    app.post('/api/projects/:id/agent/events/clear', h(async (req) => {
      const s = this.session(req);
      const { deletedCount } = await this.store.col('agent_events').deleteMany({ projectId: s.id });
      this.broadcast({ kind: 'agent', projectId: s.id, at: new Date().toISOString() });
      return { deleted: deletedCount };
    }));

    app.get('/api/projects/:id/findings/:fid/observations', h(async (req) => {
      const s = this.session(req);
      return this.store.col('security_observations').find({ projectId: s.id, findingId: req.params.fid }).sort({ observedAt: -1 }).limit(200).toArray();
    }));

    app.post('/api/projects/:id/baseline', h(async (req) => this.session(req).markBaseline()));

    app.post('/api/projects/:id/approve-run', h(async (req) => {
      const { hash } = z.object({ hash: z.string() }).parse(req.body);
      await this.session(req).approveRunConfig(hash);
      return this.session(req).status();
    }));

    app.post('/api/projects/:id/verify', h(async (req, res) => {
      const r = await this.session(req).verify('manual');
      if (r.error) res.status(409);
      return r;
    }));

    app.post('/api/projects/:id/verify/cancel', h((req) => ({ cancelled: this.session(req).cancelVerification() })));

    app.get('/api/projects/:id/browser-runs', h(async (req) => {
      const s = this.session(req);
      return this.store.col('browser_runs').find({ projectId: s.id }, { projection: { 'sides.baseline.log': 0, 'sides.candidate.log': 0 } }).sort({ startedAt: -1 }).limit(50).toArray();
    }));

    app.get('/api/projects/:id/browser-runs/:rid', h(async (req) => {
      const s = this.session(req);
      const run = await this.store.col('browser_runs').findOne({ _id: req.params.rid as never, projectId: s.id });
      const results = await this.store.col('browser_results').find({ browserRunId: req.params.rid }).toArray();
      const comparison = await this.store.col('comparisons').findOne({ browserRunId: req.params.rid });
      return { run, results, comparison };
    }));

    app.get('/api/projects/:id/history', h(async (req) => {
      const s = this.session(req);
      const q = { projectId: s.id };
      const [events, snapshots, analysisRuns, browserRuns, comparisons, verifications, graphs, scenarioHistory, summary] = await Promise.all([
        this.store.col('file_events').find(q).sort({ receivedAt: -1 }).limit(100).toArray(),
        this.store.col('source_snapshots').find(q, { projection: { manifest: 0 } }).sort({ createdAt: -1 }).limit(50).toArray(),
        this.store.col('analysis_runs').find(q, { projection: { impact: 0, diff: 0 } }).sort({ startedAt: -1 }).limit(100).toArray(),
        this.store.col('browser_runs').find(q, { projection: { 'sides.baseline.log': 0, 'sides.candidate.log': 0 } }).sort({ startedAt: -1 }).limit(50).toArray(),
        this.store.col('comparisons').find(q, { projection: { items: 0 } }).sort({ createdAt: -1 }).limit(50).toArray(),
        this.store.col('verification_records').find(q).sort({ at: -1 }).limit(100).toArray(),
        this.store.col('graph_snapshots').find(q, { projection: { graph: 0 } }).sort({ createdAt: -1 }).limit(50).toArray(),
        this.store.scenarioHistory(s.id),
        this.store.dashboardSummary(s.id),
      ]);
      return { events, snapshots, analysisRuns, browserRuns, comparisons, verifications, graphs, scenarioHistory, summary };
    }));

    app.get('/api/projects/:id/analysis-runs/:rid', h(async (req) => {
      const s = this.session(req);
      return this.store.col('analysis_runs').findOne({ _id: req.params.rid as never, projectId: s.id });
    }));

    app.get('/api/projects/:id/source', h((req) => {
      const s = this.session(req);
      const file = z.string().parse(req.query.file);
      const line = Number(req.query.line || 1);
      const abs = path.resolve(s.root, file);
      if (!abs.startsWith(s.root + path.sep) || /(^|\/)(\.env|node_modules|\.git)(\/|$|\.)/.test(file)) throw Object.assign(new Error('not allowed'), { status: 403 });
      if (!fs.existsSync(abs)) throw Object.assign(new Error('file not found'), { status: 404 });
      const lines = fs.readFileSync(abs, 'utf8').split('\n');
      const from = Math.max(1, line - 6);
      const to = Math.min(lines.length, line + 14);
      return { file, from, to, line, lines: lines.slice(from - 1, to) };
    }));

    // Ask connected IDE clients to reveal a location.
    app.post('/api/projects/:id/open-in-editor', h((req) => {
      const body = z.object({ file: z.string(), line: z.number().int().positive() }).parse(req.body);
      const s = this.session(req);
      this.broadcast({ kind: 'open-in-editor', projectId: s.id, root: s.root, file: body.file, line: body.line });
      return { sent: true };
    }));

    app.get('/api/projects/:id/artifacts/*', (req, res) => {
      try {
        const s = this.session(req);
        const rel = String((req.params as Record<string, string>)[0] ?? '');
        const abs = s.artifactPath(rel);
        if (!abs || !abs.endsWith('.png')) return res.status(404).end();
        res.setHeader('Cache-Control', 'private, max-age=31536000, immutable');
        res.sendFile(abs);
      } catch { res.status(404).end(); }
    });

    if (fs.existsSync(this.cfg.dashboardDir)) {
      app.use(express.static(this.cfg.dashboardDir));
      app.get(/^\/(?!api\/).*/, (_req, res) => res.sendFile(path.join(this.cfg.dashboardDir, 'index.html')));
    } else {
      app.get('/', (_req, res) => res.type('text/plain').send('Dashboard not built. Run: npm run build'));
    }

    app.use((err: Error & { status?: number }, _req: Request, res: Response, _next: NextFunction) => {
      void _next;
      if (err instanceof z.ZodError) return res.status(400).json({ error: 'invalid request', issues: err.issues });
      const unavailable = err.name === 'StoreUnavailableError' || /^Mongo(Network|ServerSelection|NotConnected|Topology)/.test(err.name);
      const status = err.status ?? (unavailable ? 503 : 500);
      if (status >= 500) log.error(`request failed: ${err.message}`);
      res.status(status).json({ error: err.message });
    });
    return app;
  }

  async start() {
    await this.store.connect();
    const app = this.app();
    this.server = http.createServer(app);
    this.wss = new WebSocketServer({ noServer: true });
    this.server.on('upgrade', (req, socket, head) => {
      const host = String(req.headers.host);
      const origin = req.headers.origin;
      const ok = host === `127.0.0.1:${this.cfg.port}` || host === `localhost:${this.cfg.port}`;
      const originOk = !origin || origin.replace(/^https?:\/\//, '') === host;
      if (!ok || !originOk || req.url !== '/ws') { socket.destroy(); return; }
      this.wss!.handleUpgrade(req, socket, head, (ws) => {
        this.clients.add(ws);
        ws.on('close', () => this.clients.delete(ws));
      });
    });
    await new Promise<void>((resolve, reject) => {
      this.server!.once('error', reject);
      this.server!.listen(this.cfg.port, this.cfg.host, () => resolve());
    });
    log.info(`service listening on http://${this.cfg.host}:${this.cfg.port}`);
  }

  async stop() {
    for (const s of this.sessions.values()) await s.dispose();
    for (const c of this.clients) c.close();
    await new Promise<void>((r) => (this.server ? this.server.close(() => r()) : r()));
    await this.store.close();
  }
}
