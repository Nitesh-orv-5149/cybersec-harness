// Agent memory: schemas, validators and database setup for agent_runs / agent_events / agent_memories.
// Dependency-free validation runs BEFORE any write; the $jsonSchema validators below are the second safety net inside MongoDB.
import type { Db, Document } from 'mongodb';
import { log } from '../log.js';

export const RUN_KINDS = ['triage_finding', 'dependency_review', 'impact_review', 'custom'] as const;
export const RUN_STATUSES = ['running', 'completed', 'failed', 'cancelled'] as const;
export const EVENT_TYPES = ['plan', 'tool_call', 'observation', 'decision', 'error', 'memory_read', 'memory_write'] as const;
export const EVENT_STATUSES = ['ok', 'error', 'skipped'] as const;
export const MEMORY_KINDS = ['fact', 'procedure', 'feedback'] as const;
export const MEMORY_STATUSES = ['active', 'unverified', 'superseded', 'retired'] as const;
export const MEMORY_SOURCES = ['agent', 'human'] as const;
export const SUBJECT_TYPES = ['finding', 'endpoint', 'package', 'tool', 'project'] as const;
export const EVIDENCE_KINDS = ['finding', 'event', 'scan_run', 'graph', 'file', 'human'] as const;
export const CONFIDENCES = ['high', 'medium', 'low'] as const;

export type RunKind = (typeof RUN_KINDS)[number];
export type EventType = (typeof EVENT_TYPES)[number];
export type EventStatus = (typeof EVENT_STATUSES)[number];
export type MemoryKind = (typeof MEMORY_KINDS)[number];
export type SubjectType = (typeof SUBJECT_TYPES)[number];
export type EvidenceKind = (typeof EVIDENCE_KINDS)[number];
export type Confidence = (typeof CONFIDENCES)[number];
export type Validation<T> = { ok: true; value: T } | { ok: false; errors: string[] };

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const oneOf = <T extends string>(list: readonly T[], v: unknown): v is T => typeof v === 'string' && (list as readonly string[]).includes(v);
const text = (v: unknown, max: number): v is string => typeof v === 'string' && v.trim().length > 0 && v.length <= max;
const int = (v: unknown, min: number, max: number): v is number => typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max;

// ---------------------------------------------------------------- runs

export interface RunInput {
  projectId: string;
  goal: string;
  kind: RunKind;
  model: string;
  subject: { findingId?: string; scanRunId?: string; graphHash?: string };
}

export function validateRunInput(input: unknown): Validation<RunInput> {
  const errors: string[] = [];
  if (!isObj(input)) return { ok: false, errors: ['run must be an object'] };
  if (!text(input.projectId, 200)) errors.push('projectId is required');
  if (!text(input.goal, 1000)) errors.push('goal is required (up to 1000 characters): what is this agent run trying to do?');
  const kind = input.kind ?? 'custom';
  if (!oneOf(RUN_KINDS, kind)) errors.push(`kind must be one of: ${RUN_KINDS.join(', ')}`);
  const model = input.model ?? 'scripted';
  if (!text(model, 100)) errors.push('model must be a non-empty string (use "scripted" when no LLM is involved)');
  const subject: RunInput['subject'] = {};
  if (input.subject !== undefined) {
    if (!isObj(input.subject)) errors.push('subject must be an object');
    else for (const k of ['findingId', 'scanRunId', 'graphHash'] as const) {
      const v = input.subject[k];
      if (v === undefined) continue;
      if (!text(v, 200)) errors.push(`subject.${k} must be a non-empty string`);
      else subject[k] = v;
    }
  }
  if (errors.length) return { ok: false, errors };
  return { ok: true, value: { projectId: input.projectId as string, goal: input.goal as string, kind: kind as RunKind, model: model as string, subject } };
}

// ---------------------------------------------------------------- events (episodic memory)

export interface EventInput {
  type: EventType;
  status: EventStatus;
  seq?: number;
  tool?: string;
  input?: Obj;
  outputSummary?: string;
  durationMs?: number;
  refs?: { findingId?: string; memoryIds?: string[] };
}

export function validateEventInput(input: unknown): Validation<EventInput> {
  const errors: string[] = [];
  if (!isObj(input)) return { ok: false, errors: ['event must be an object'] };
  if (!oneOf(EVENT_TYPES, input.type)) errors.push(`type must be one of: ${EVENT_TYPES.join(', ')}`);
  const status = input.status ?? 'ok';
  if (!oneOf(EVENT_STATUSES, status)) errors.push(`status must be one of: ${EVENT_STATUSES.join(', ')}`);
  if (input.seq !== undefined && !int(input.seq, 1, 1_000_000)) errors.push('seq must be a whole number from 1 up');
  if (input.tool !== undefined && !text(input.tool, 100)) errors.push('tool must be a non-empty string up to 100 characters');
  if (input.type === 'tool_call' && !text(input.tool, 100)) errors.push('a tool_call event needs the tool name');
  if (input.input !== undefined && !isObj(input.input)) errors.push('input must be an object');
  if (input.input !== undefined && JSON.stringify(input.input).length > 20_000) errors.push('input is too large (20000 characters max): store a summary, not the whole payload');
  if (input.outputSummary !== undefined && !text(input.outputSummary, 2000)) errors.push('outputSummary must be a non-empty string up to 2000 characters');
  if (input.durationMs !== undefined && !int(input.durationMs, 0, 86_400_000)) errors.push('durationMs must be a whole number of milliseconds');
  if (input.type === 'error' && status !== 'error') errors.push('an error event must have status "error"');
  let refs: EventInput['refs'];
  if (input.refs !== undefined) {
    if (!isObj(input.refs)) errors.push('refs must be an object');
    else {
      refs = {};
      if (input.refs.findingId !== undefined) { if (text(input.refs.findingId, 200)) refs.findingId = input.refs.findingId; else errors.push('refs.findingId must be a non-empty string'); }
      if (input.refs.memoryIds !== undefined) {
        const m = input.refs.memoryIds;
        if (Array.isArray(m) && m.length <= 50 && m.every((x) => text(x, 200))) refs.memoryIds = m as string[];
        else errors.push('refs.memoryIds must be an array of at most 50 ids');
      }
    }
  }
  if (errors.length) return { ok: false, errors };
  return {
    ok: true,
    value: {
      type: input.type as EventType, status: status as EventStatus,
      ...(input.seq !== undefined ? { seq: input.seq as number } : {}),
      ...(input.tool !== undefined ? { tool: input.tool as string } : {}),
      ...(input.input !== undefined ? { input: input.input as Obj } : {}),
      ...(input.outputSummary !== undefined ? { outputSummary: input.outputSummary as string } : {}),
      ...(input.durationMs !== undefined ? { durationMs: input.durationMs as number } : {}),
      ...(refs ? { refs } : {}),
    },
  };
}

export interface FinishInput { status: 'completed' | 'failed' | 'cancelled'; summary?: string; error?: string }

export function validateFinishInput(input: unknown): Validation<FinishInput> {
  const errors: string[] = [];
  if (!isObj(input)) return { ok: false, errors: ['body must be an object'] };
  if (!oneOf(['completed', 'failed', 'cancelled'] as const, input.status)) errors.push('status must be completed, failed or cancelled');
  if (input.summary !== undefined && !text(input.summary, 4000)) errors.push('summary must be a non-empty string up to 4000 characters');
  if (input.error !== undefined && !text(input.error, 4000)) errors.push('error must be a non-empty string up to 4000 characters');
  if (input.status === 'failed' && input.error === undefined) errors.push('a failed run must say why: error is required');
  if (errors.length) return { ok: false, errors };
  return { ok: true, value: { status: input.status as FinishInput['status'], ...(input.summary !== undefined ? { summary: input.summary as string } : {}), ...(input.error !== undefined ? { error: input.error as string } : {}) } };
}

// ---------------------------------------------------------------- memories (long-term)

export interface MemoryInput {
  projectId: string;
  kind: MemoryKind;
  content: string;
  subject: { type: SubjectType; key: string };
  evidence: { kind: EvidenceKind; id: string }[];
  confidence: Confidence;
  source: 'agent' | 'human';
  createdBy: string | null;
  createdByRun: string | null;
  ttlHours: number | null;
  supersedes: string | null;
}

/**
 * Honesty rules, enforced here:
 *  - an agent-written memory with no evidence is stored as "unverified" with low confidence (a guess, not a fact);
 *  - a human-written memory must name the person (createdBy);
 *  - memories are hints for the agent. A scan result or a human review always outranks them.
 */
export function validateMemoryInput(input: unknown): Validation<MemoryInput> {
  const errors: string[] = [];
  if (!isObj(input)) return { ok: false, errors: ['memory must be an object'] };
  if (!text(input.projectId, 200)) errors.push('projectId is required');
  if (!oneOf(MEMORY_KINDS, input.kind)) errors.push(`kind must be one of: ${MEMORY_KINDS.join(', ')}`);
  if (!text(input.content, 2000)) errors.push('content is required (up to 2000 characters)');
  const s = input.subject;
  if (!isObj(s) || !oneOf(SUBJECT_TYPES, s.type) || !text(s.key, 300)) errors.push(`subject is required: { type: ${SUBJECT_TYPES.join('|')}, key } so a memory can be found again`);
  const evidence: MemoryInput['evidence'] = [];
  if (input.evidence !== undefined) {
    if (!Array.isArray(input.evidence) || input.evidence.length > 20) errors.push('evidence must be an array of at most 20 items');
    else for (const e of input.evidence) {
      if (isObj(e) && oneOf(EVIDENCE_KINDS, e.kind) && text(e.id, 300)) evidence.push({ kind: e.kind, id: e.id });
      else errors.push(`each evidence item needs { kind: ${EVIDENCE_KINDS.join('|')}, id }`);
    }
  }
  const confidence = input.confidence ?? 'low';
  if (!oneOf(CONFIDENCES, confidence)) errors.push(`confidence must be one of: ${CONFIDENCES.join(', ')}`);
  const source = input.source ?? 'agent';
  if (!oneOf(MEMORY_SOURCES, source)) errors.push('source must be agent or human');
  if (source === 'human' && !text(input.createdBy, 200)) errors.push('a human memory must name who wrote it: createdBy is required');
  if (input.createdByRun !== undefined && input.createdByRun !== null && !text(input.createdByRun, 200)) errors.push('createdByRun must be a run id');
  if (input.ttlHours !== undefined && input.ttlHours !== null && !int(input.ttlHours, 1, 720)) errors.push('ttlHours must be a whole number from 1 to 720');
  if (input.supersedes !== undefined && input.supersedes !== null && !text(input.supersedes, 200)) errors.push('supersedes must be a memory id');
  if (errors.length) return { ok: false, errors };
  const subj = s as Obj;
  return {
    ok: true,
    value: {
      projectId: input.projectId as string, kind: input.kind as MemoryKind, content: (input.content as string).trim(),
      subject: { type: subj.type as SubjectType, key: subj.key as string }, evidence, confidence: confidence as Confidence,
      source: source as 'agent' | 'human', createdBy: source === 'human' ? (input.createdBy as string) : text(input.createdBy, 200) ? (input.createdBy as string) : null,
      createdByRun: (input.createdByRun as string | null | undefined) ?? null, ttlHours: (input.ttlHours as number | null | undefined) ?? null,
      supersedes: (input.supersedes as string | null | undefined) ?? null,
    },
  };
}

// ---------------------------------------------------------------- MongoDB $jsonSchema validators + indexes

const RUN_SCHEMA = {
  bsonType: 'object',
  required: ['_id', 'projectId', 'goal', 'kind', 'status', 'model', 'startedAt', 'eventCount'],
  properties: {
    _id: { bsonType: 'string' }, projectId: { bsonType: 'string', minLength: 1 }, goal: { bsonType: 'string', minLength: 1 },
    kind: { enum: [...RUN_KINDS] }, status: { enum: [...RUN_STATUSES] }, model: { bsonType: 'string', minLength: 1 },
    startedAt: { bsonType: 'date' }, eventCount: { bsonType: 'number', minimum: 0 },
  },
};

const EVENT_SCHEMA = {
  bsonType: 'object',
  required: ['_id', 'projectId', 'runId', 'seq', 'type', 'status', 'at'],
  properties: {
    _id: { bsonType: 'string' }, projectId: { bsonType: 'string', minLength: 1 }, runId: { bsonType: 'string', minLength: 1 },
    seq: { bsonType: 'number', minimum: 1 }, type: { enum: [...EVENT_TYPES] }, status: { enum: [...EVENT_STATUSES] }, at: { bsonType: 'date' },
  },
};

const MEMORY_SCHEMA = {
  bsonType: 'object',
  required: ['_id', 'projectId', 'kind', 'content', 'subject', 'evidence', 'confidence', 'status', 'source', 'version', 'createdAt', 'updatedAt'],
  properties: {
    _id: { bsonType: 'string' }, projectId: { bsonType: 'string', minLength: 1 }, kind: { enum: [...MEMORY_KINDS] },
    content: { bsonType: 'string', minLength: 1 },
    subject: { bsonType: 'object', required: ['type', 'key'], properties: { type: { enum: [...SUBJECT_TYPES] }, key: { bsonType: 'string', minLength: 1 } } },
    evidence: { bsonType: 'array' }, confidence: { enum: [...CONFIDENCES] }, status: { enum: [...MEMORY_STATUSES] }, source: { enum: [...MEMORY_SOURCES] },
    version: { bsonType: 'number', minimum: 1 }, createdAt: { bsonType: 'date' }, updatedAt: { bsonType: 'date' },
  },
};

/** Build one index without ever taking down the whole Store: a bad index on one collection (e.g. stray
 *  documents left over from a previous use of the collection name) is logged, not fatal.
 *  Exported for reuse by Store.ensureIndexes() in ../store/mongo.ts, which needs the same guard
 *  for every collection it indexes, not just the agent-memory ones. */
export async function safeIndex(db: Db, name: string, spec: Document, options?: Document) {
  try {
    await db.collection(name).createIndex(spec, options);
  } catch (e) {
    log.warn(`could not build index ${JSON.stringify(spec)} on ${name}: ${String((e as Error).message ?? e)}`);
  }
}

async function applyValidator(db: Db, name: string, schema: object) {
  const validator = { $jsonSchema: schema as Document };
  try {
    const exists = (await db.listCollections({ name }).toArray()).length > 0;
    if (exists) await db.command({ collMod: name, validator, validationLevel: 'strict', validationAction: 'error' });
    else await db.createCollection(name, { validator, validationLevel: 'strict', validationAction: 'error' });
  } catch (e) {
    // e.g. the database user lacks the collMod privilege: keep running, the in-code validators still protect every write.
    log.warn(`could not apply MongoDB schema validator to ${name}: ${String((e as Error).message ?? e)}`);
  }
}

/** Called once from Store.ensureIndexes(): creates the three collections with validators, then their indexes. */
export async function ensureAgentMemory(db: Db) {
  await applyValidator(db, 'agent_runs', RUN_SCHEMA);
  await applyValidator(db, 'agent_events', EVENT_SCHEMA);
  await applyValidator(db, 'agent_memories', MEMORY_SCHEMA);
  await Promise.all([
    safeIndex(db, 'agent_runs', { projectId: 1, startedAt: -1 }),
    safeIndex(db, 'agent_runs', { projectId: 1, status: 1 }),
    // (runId, seq) unique: the same step can never be recorded twice.
    safeIndex(db, 'agent_events', { runId: 1, seq: 1 }, { unique: true }),
    safeIndex(db, 'agent_events', { projectId: 1, type: 1, status: 1, at: -1 }),
    safeIndex(db, 'agent_memories', { projectId: 1, status: 1, 'subject.key': 1 }),
    safeIndex(db, 'agent_memories', { content: 'text' }),
    // Optional short-lived memories: MongoDB deletes a document once its expiresAt has passed.
    safeIndex(db, 'agent_memories', { expiresAt: 1 }, { expireAfterSeconds: 0 }),
  ]);
}