// Agent memory: runs (the task), events (episodic trace of every step) and memories (long-term, evidence-backed hints).
// Everything is written through this module; the HTTP routes at the bottom are a thin wrapper.
import type { Express, NextFunction, Request, RequestHandler, Response } from 'express';
import type { Store } from './store/mongo.js';
import { newId, sha256 } from './util.js';
import {
  validateEventInput, validateFinishInput, validateMemoryInput, validateRunInput, MEMORY_KINDS,
  type MemoryKind,
} from './store/agentMemory.js';

const fail = (status: number, message: string) => Object.assign(new Error(message), { status });
const bad = (errors: string[]) => fail(400, errors.join('; '));

export class AgentMemory {
  constructor(private readonly store: Store) {}

  async startRun(projectId: string, body: unknown) {
    const v = validateRunInput({ ...(body as object), projectId });
    if (!v.ok) throw bad(v.errors);
    const doc = { _id: newId('arun'), ...v.value, status: 'running', startedAt: new Date(), eventCount: 0, errorCount: 0, toolCallCount: 0 };
    await this.store.col('agent_runs').insertOne(doc as never);
    return doc;
  }

  /** Append one step. Without `seq` the next number is taken atomically; with `seq`, sending the same step twice is a harmless duplicate. */
  async recordEvent(projectId: string, runId: string, body: unknown) {
    const v = validateEventInput(body);
    if (!v.ok) throw bad(v.errors);
    const runs = this.store.col('agent_runs');
    const run = await runs.findOne({ _id: runId as never, projectId });
    if (!run) throw fail(404, 'unknown agent run');
    if (run.status !== 'running') throw fail(409, `run is already ${run.status}; start a new run`);
    let seq = v.value.seq;
    if (seq === undefined) {
      const bumped = await runs.findOneAndUpdate({ _id: runId as never }, { $inc: { eventCount: 1 } }, { returnDocument: 'after' });
      seq = Number(bumped?.eventCount);
    } else {
      await runs.updateOne({ _id: runId as never }, { $max: { eventCount: seq } });
    }
    const { seq: _omit, ...rest } = v.value;
    void _omit;
    const doc = { _id: `${runId}:${seq}`, projectId, runId, seq, ...rest, at: new Date() };
    try {
      await this.store.col('agent_events').insertOne(doc as never);
    } catch (e) {
      if ((e as { code?: number }).code === 11000) return { duplicate: true, _id: doc._id, seq };
      throw e;
    }
    const inc: Record<string, number> = {};
    if (v.value.status === 'error') inc.errorCount = 1;
    if (v.value.type === 'tool_call') inc.toolCallCount = 1;
    if (Object.keys(inc).length) await runs.updateOne({ _id: runId as never }, { $inc: inc });
    return doc;
  }

  async finishRun(projectId: string, runId: string, body: unknown) {
    const v = validateFinishInput(body);
    if (!v.ok) throw bad(v.errors);
    const runs = this.store.col('agent_runs');
    const finishedAt = new Date();
    const r = await runs.findOneAndUpdate(
      { _id: runId as never, projectId, status: 'running' },
      { $set: { ...v.value, finishedAt } },
      { returnDocument: 'after' },
    );
    if (!r) throw fail(409, 'run not found or already finished');
    const durationMs = finishedAt.getTime() - new Date(r.startedAt).getTime();
    await runs.updateOne({ _id: runId as never }, { $set: { durationMs } });
    return { ...r, durationMs };
  }

  async listRuns(projectId: string) {
    return this.store.col('agent_runs').find({ projectId }).sort({ startedAt: -1 }).limit(50).toArray();
  }

  async runTrace(projectId: string, runId: string) {
    const run = await this.store.col('agent_runs').findOne({ _id: runId as never, projectId });
    if (!run) throw fail(404, 'unknown agent run');
    const events = await this.store.col('agent_events').find({ runId }).sort({ seq: 1 }).limit(1000).toArray();
    return { run, events };
  }

  /** Aggregation: compare two runs (typically a good one and a failed one) step by step. */
  async compareRuns(projectId: string, a: string, b: string) {
    const rows = await this.store.col('agent_events').aggregate([
      { $match: { projectId, runId: { $in: [a, b] } } },
      { $group: {
        _id: '$runId', events: { $sum: 1 },
        errors: { $sum: { $cond: [{ $eq: ['$status', 'error'] }, 1, 0] } },
        toolCalls: { $sum: { $cond: [{ $eq: ['$type', 'tool_call'] }, 1, 0] } },
        memoryReads: { $sum: { $cond: [{ $eq: ['$type', 'memory_read'] }, 1, 0] } },
        totalMs: { $sum: { $ifNull: ['$durationMs', 0] } },
        tools: { $addToSet: '$tool' },
        firstErrorSeq: { $min: { $cond: [{ $eq: ['$status', 'error'] }, '$seq', null] } },
      } },
    ]).toArray();
    const runs = await this.store.col('agent_runs').find({ projectId, _id: { $in: [a, b] as never[] } }).toArray();
    const side = async (id: string) => {
      const stats = rows.find((r) => r._id === id) ?? null;
      const run = runs.find((r) => (r._id as unknown as string) === id) ?? null;
      const firstError = stats?.firstErrorSeq != null ? await this.store.col('agent_events').findOne({ _id: `${id}:${stats.firstErrorSeq}` as never }) : null;
      const tools: string[] = ((stats?.tools ?? []) as (string | null)[]).filter((t): t is string => !!t).sort();
      return { runId: id, status: run?.status ?? 'unknown', goal: run?.goal ?? null, stats: stats ? { events: stats.events, errors: stats.errors, toolCalls: stats.toolCalls, memoryReads: stats.memoryReads, totalMs: stats.totalMs, tools } : null, firstError: firstError ? { seq: firstError.seq, tool: firstError.tool ?? null, outputSummary: firstError.outputSummary ?? null } : null };
    };
    const [left, right] = [await side(a), await side(b)];
    const lt = new Set(left.stats?.tools ?? []);
    const rt = new Set(right.stats?.tools ?? []);
    return {
      a: left, b: right,
      difference: { onlyInA: [...lt].filter((t) => !rt.has(t)), onlyInB: [...rt].filter((t) => !lt.has(t)) },
    };
  }

  /** Store or update a memory. Same project + kind + subject + content = same document (version goes up), so it is never duplicated. */
  async remember(projectId: string, body: unknown) {
    const v = validateMemoryInput({ ...(body as object), projectId });
    if (!v.ok) throw bad(v.errors);
    const m = v.value;
    const unverified = m.source === 'agent' && m.evidence.length === 0;
    const status = unverified ? 'unverified' : 'active';
    const confidence = unverified ? 'low' : m.confidence;
    const id = `mem_${sha256([projectId, m.kind, m.subject.type, m.subject.key, m.content].join('|')).slice(0, 20)}`;
    const now = new Date();
    const col = this.store.col('agent_memories');
    await col.updateOne(
      { _id: id as never },
      {
        $set: {
          projectId, kind: m.kind, content: m.content, subject: m.subject, evidence: m.evidence, confidence, status, source: m.source,
          createdBy: m.createdBy, createdByRun: m.createdByRun, supersedes: m.supersedes, updatedAt: now,
          ...(m.ttlHours ? { expiresAt: new Date(now.getTime() + m.ttlHours * 3_600_000) } : {}),
        },
        $inc: { version: 1 },
        $setOnInsert: { createdAt: now, recallCount: 0 },
      },
      { upsert: true },
    );
    if (m.supersedes && m.supersedes !== id) {
      await col.updateOne({ _id: m.supersedes as never, projectId }, { $set: { status: 'superseded', supersededBy: id, updatedAt: now } });
    }
    return col.findOne({ _id: id as never });
  }

  /** Recall memories as HINTS. They never replace scan results or human review. */
  async recall(projectId: string, q: { subjectKey?: string; kind?: string; text?: string; includeUnverified?: boolean; limit?: number }) {
    const now = new Date();
    const filter: Record<string, unknown> = {
      projectId,
      status: q.includeUnverified ? { $in: ['active', 'unverified'] } : 'active',
      $or: [{ expiresAt: { $exists: false } }, { expiresAt: { $gt: now } }],
    };
    if (q.kind) {
      if (!(MEMORY_KINDS as readonly string[]).includes(q.kind)) throw bad([`kind must be one of: ${MEMORY_KINDS.join(', ')}`]);
      filter.kind = q.kind as MemoryKind;
    }
    if (q.subjectKey) filter['subject.key'] = q.subjectKey;
    if (q.text) filter.$text = { $search: q.text };
    const limit = Math.min(Math.max(q.limit ?? 10, 1), 50);
    const memories = await this.store.col('agent_memories').find(filter).sort({ updatedAt: -1 }).limit(limit).toArray();
    if (memories.length) {
      await this.store.col('agent_memories').updateMany({ _id: { $in: memories.map((m) => m._id) } }, { $set: { lastRecalledAt: now }, $inc: { recallCount: 1 } });
    }
    return { memories, note: 'Memories are hints written by earlier runs or people. Scan results and human review always outrank them; check the evidence before relying on one.' };
  }

  async retire(projectId: string, memoryId: string) {
    const r = await this.store.col('agent_memories').updateOne({ _id: memoryId as never, projectId }, { $set: { status: 'retired', updatedAt: new Date() } });
    if (!r.matchedCount) throw fail(404, 'unknown memory');
    return { ok: true };
  }
}

type HandlerWrap = (fn: (req: Request, res: Response) => Promise<unknown> | unknown) => (req: Request, res: Response, next: NextFunction) => void;

/** One call from server.ts registers every agent route. `projectOf` resolves (and 404s) the project in the URL. */
export function registerAgentRoutes(app: Express, h: HandlerWrap, store: Store, projectOf: (req: Request) => string) {
  const mem = new AgentMemory(store);
  const str = (v: unknown) => (typeof v === 'string' && v ? v : undefined);
  const base = '/api/projects/:id/agent';
  const route = (handler: RequestHandler) => handler;

  app.post(`${base}/runs`, route(h((req) => mem.startRun(projectOf(req), req.body))));
  app.get(`${base}/runs`, route(h((req) => mem.listRuns(projectOf(req)))));
  app.get(`${base}/runs/:rid`, route(h((req) => mem.runTrace(projectOf(req), String(req.params.rid)))));
  app.post(`${base}/runs/:rid/events`, route(h((req) => mem.recordEvent(projectOf(req), String(req.params.rid), req.body))));
  app.post(`${base}/runs/:rid/finish`, route(h((req) => mem.finishRun(projectOf(req), String(req.params.rid), req.body))));
  app.get(`${base}/compare`, route(h((req) => {
    const a = str(req.query.a); const b = str(req.query.b);
    if (!a || !b) throw bad(['query parameters a and b (two run ids) are required']);
    return mem.compareRuns(projectOf(req), a, b);
  })));
  app.post(`${base}/memories`, route(h((req) => mem.remember(projectOf(req), req.body))));
  app.get(`${base}/memories`, route(h((req) => mem.recall(projectOf(req), {
    subjectKey: str(req.query.subject), kind: str(req.query.kind), text: str(req.query.q),
    includeUnverified: req.query.includeUnverified === 'true', limit: req.query.limit ? Number(req.query.limit) : undefined,
  }))));
  app.post(`${base}/memories/:mid/retire`, route(h((req) => mem.retire(projectOf(req), String(req.params.mid)))));
}