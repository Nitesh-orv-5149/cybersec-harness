// Allowed values and validation for the MongoDB storage layer (requirements, finding review, verification).
// Dependency-free on purpose: validation runs BEFORE any database write, so bad data never reaches MongoDB.
// Values mirror the existing conventions in findings.ts and project.ts; keep them in sync if those change.
import type { Severity } from '../findings.js';

export const SEVERITIES = ['high', 'medium', 'low', 'info'] as const satisfies readonly Severity[];
export const CONFIDENCES = ['high', 'medium', 'low'] as const;
export const FINDING_STATUSES = ['open', 'resolved'] as const;
export const VERIFICATION_ACTIONS = ['observed', 'reopened', 'verified_fixed', 'resolved_by_analysis'] as const;

export const REQUIREMENT_STATUSES = ['proposed', 'confirmed', 'deprecated'] as const;
export const REQUIREMENT_PRIORITIES = ['must', 'should', 'could'] as const;
export const REQUIREMENT_SOURCE_KINDS = ['readme', 'spec', 'teammate', 'other'] as const;

export const REVIEW_STATUSES = ['unreviewed', 'approved', 'rejected', 'needs_changes'] as const;
export const LABEL_SOURCES = ['none', 'human_review', 'verified_fix'] as const;

export type VerificationAction = (typeof VERIFICATION_ACTIONS)[number];
export type RequirementStatus = (typeof REQUIREMENT_STATUSES)[number];
export type RequirementPriority = (typeof REQUIREMENT_PRIORITIES)[number];
export type RequirementSourceKind = (typeof REQUIREMENT_SOURCE_KINDS)[number];
export type ReviewStatus = (typeof REVIEW_STATUSES)[number];
export type LabelSource = (typeof LABEL_SOURCES)[number];
export type Confidence = (typeof CONFIDENCES)[number];

export type Validation<T> = { ok: true; value: T } | { ok: false; errors: string[] };

// ---------------------------------------------------------------- helpers

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const oneOf = <T extends string>(list: readonly T[], v: unknown): v is T => typeof v === 'string' && (list as readonly string[]).includes(v);
const text = (v: unknown, max: number): v is string => typeof v === 'string' && v.trim().length > 0 && v.length <= max;

function optText(o: Obj, key: string, max: number, errors: string[]): string | undefined {
  const v = o[key];
  if (v === undefined || v === null) return undefined;
  if (!text(v, max)) errors.push(`${key} must be a non-empty string of at most ${max} characters`);
  return v as string;
}

function optStrings(o: Obj, key: string, errors: string[]): string[] | undefined {
  const v = o[key];
  if (v === undefined || v === null) return undefined;
  if (!Array.isArray(v) || v.length > 50 || !v.every((x) => text(x, 1000))) {
    errors.push(`${key} must be an array of at most 50 non-empty strings (each up to 1000 characters)`);
    return undefined;
  }
  return v as string[];
}

// ---------------------------------------------------------------- agent requirements

export interface RequirementSource { kind: RequirementSourceKind; document: string; section?: string }

export interface RequirementInput {
  projectId: string;
  category: string;
  title: string;
  description: string;
  expectedBehavior?: string;
  inputRequirements?: string[];
  outputRequirements?: string[];
  constraints?: string[];
  acceptanceCriteria?: string[];
  priority: RequirementPriority;
  status: RequirementStatus;
  source: RequirementSource;
}

export function validateRequirementInput(input: unknown): Validation<RequirementInput> {
  const errors: string[] = [];
  if (!isObj(input)) return { ok: false, errors: ['requirement must be an object'] };
  if (!text(input.projectId, 200)) errors.push('projectId is required');
  if (!text(input.category, 64)) errors.push('category is required (up to 64 characters)');
  if (!text(input.title, 200)) errors.push('title is required (up to 200 characters)');
  if (!text(input.description, 4000)) errors.push('description is required (up to 4000 characters)');
  if (!oneOf(REQUIREMENT_PRIORITIES, input.priority)) errors.push(`priority must be one of: ${REQUIREMENT_PRIORITIES.join(', ')}`);
  if (!oneOf(REQUIREMENT_STATUSES, input.status)) errors.push(`status must be one of: ${REQUIREMENT_STATUSES.join(', ')}`);
  const src = input.source;
  if (!isObj(src) || !oneOf(REQUIREMENT_SOURCE_KINDS, src.kind) || !text(src.document, 300)) {
    errors.push('source is required: { kind, document, section? } so every requirement can be traced to where it came from');
  }
  const expectedBehavior = optText(input, 'expectedBehavior', 4000, errors);
  const inputRequirements = optStrings(input, 'inputRequirements', errors);
  const outputRequirements = optStrings(input, 'outputRequirements', errors);
  const constraints = optStrings(input, 'constraints', errors);
  const acceptanceCriteria = optStrings(input, 'acceptanceCriteria', errors);
  if (errors.length) return { ok: false, errors };
  const s = src as Obj;
  return {
    ok: true,
    value: {
      projectId: input.projectId as string, category: input.category as string, title: input.title as string, description: input.description as string,
      priority: input.priority as RequirementPriority, status: input.status as RequirementStatus,
      source: { kind: s.kind as RequirementSourceKind, document: s.document as string, ...(text(s.section, 300) ? { section: s.section } : {}) },
      ...(expectedBehavior ? { expectedBehavior } : {}),
      ...(inputRequirements ? { inputRequirements } : {}),
      ...(outputRequirements ? { outputRequirements } : {}),
      ...(constraints ? { constraints } : {}),
      ...(acceptanceCriteria ? { acceptanceCriteria } : {}),
    },
  };
}

/** Database-level validator (MongoDB $jsonSchema) for the agent_requirements collection: a second safety net. */
export const REQUIREMENT_JSON_SCHEMA = {
  bsonType: 'object',
  required: ['_id', 'projectId', 'category', 'title', 'description', 'priority', 'status', 'source', 'version', 'createdAt', 'updatedAt'],
  properties: {
    _id: { bsonType: 'string' },
    projectId: { bsonType: 'string', minLength: 1 },
    category: { bsonType: 'string', minLength: 1 },
    title: { bsonType: 'string', minLength: 1 },
    description: { bsonType: 'string', minLength: 1 },
    priority: { enum: [...REQUIREMENT_PRIORITIES] },
    status: { enum: [...REQUIREMENT_STATUSES] },
    source: {
      bsonType: 'object',
      required: ['kind', 'document'],
      properties: { kind: { enum: [...REQUIREMENT_SOURCE_KINDS] }, document: { bsonType: 'string', minLength: 1 } },
    },
    version: { bsonType: 'number', minimum: 1 },
    createdAt: { bsonType: 'date' },
    updatedAt: { bsonType: 'date' },
  },
} as const;

// ---------------------------------------------------------------- finding review / training fields

export interface FindingReview {
  reviewed: boolean;
  reviewStatus: ReviewStatus;
  reviewedBy: string | null;
  reviewedAt: Date | null;
  labelSource: LabelSource;
  labelConfidence: Confidence | null;
  expectedOutput: string | null;
  remediation: string | null;
  trainingEligible: boolean;
}

/** Every new finding starts here: detected automatically, never reviewed, never training-eligible. */
export const DEFAULT_REVIEW: FindingReview = {
  reviewed: false, reviewStatus: 'unreviewed', reviewedBy: null, reviewedAt: null,
  labelSource: 'none', labelConfidence: null, expectedOutput: null, remediation: null, trainingEligible: false,
};

/**
 * Training-eligibility rule (documented, enforced here):
 * a record may be trainingEligible only if a named person approved it (reviewed + approved + reviewedBy + reviewedAt),
 * its label has a real source (human_review or verified_fix), and it carries an expectedOutput or remediation to learn from.
 * Nothing is ever eligible just because an analyzer produced it.
 */
export function validateFindingReview(input: unknown): Validation<FindingReview> {
  const errors: string[] = [];
  if (!isObj(input)) return { ok: false, errors: ['review must be an object'] };
  if (typeof input.reviewed !== 'boolean') errors.push('reviewed must be true or false');
  if (!oneOf(REVIEW_STATUSES, input.reviewStatus)) errors.push(`reviewStatus must be one of: ${REVIEW_STATUSES.join(', ')}`);
  if (!oneOf(LABEL_SOURCES, input.labelSource)) errors.push(`labelSource must be one of: ${LABEL_SOURCES.join(', ')}`);
  if (input.labelConfidence != null && !oneOf(CONFIDENCES, input.labelConfidence)) errors.push(`labelConfidence must be one of: ${CONFIDENCES.join(', ')}`);
  if (typeof input.trainingEligible !== 'boolean') errors.push('trainingEligible must be true or false');
  const reviewedBy = input.reviewedBy == null ? null : text(input.reviewedBy, 200) ? input.reviewedBy : (errors.push('reviewedBy must be a non-empty string'), null);
  const reviewedAt = input.reviewedAt == null ? null : input.reviewedAt instanceof Date && !isNaN(input.reviewedAt.getTime()) ? input.reviewedAt : (errors.push('reviewedAt must be a valid date'), null);
  const expectedOutput = input.expectedOutput == null ? null : text(input.expectedOutput, 8000) ? input.expectedOutput : (errors.push('expectedOutput must be a non-empty string up to 8000 characters'), null);
  const remediation = input.remediation == null ? null : text(input.remediation, 8000) ? input.remediation : (errors.push('remediation must be a non-empty string up to 8000 characters'), null);
  if (errors.length) return { ok: false, errors };
  if (input.trainingEligible === true) {
    const why: string[] = [];
    if (input.reviewed !== true || input.reviewStatus !== 'approved') why.push('it must be reviewed and approved');
    if (!reviewedBy || !reviewedAt) why.push('reviewedBy and reviewedAt are required');
    if (input.labelSource === 'none') why.push('labelSource must be human_review or verified_fix');
    if (!expectedOutput && !remediation) why.push('expectedOutput or remediation must be present (labels are never fabricated)');
    if (why.length) return { ok: false, errors: [`trainingEligible cannot be true: ${why.join('; ')}`] };
  }
  return {
    ok: true,
    value: {
      reviewed: input.reviewed as boolean, reviewStatus: input.reviewStatus as ReviewStatus, reviewedBy, reviewedAt,
      labelSource: input.labelSource as LabelSource, labelConfidence: (input.labelConfidence ?? null) as Confidence | null,
      expectedOutput, remediation, trainingEligible: input.trainingEligible as boolean,
    },
  };
}

// ---------------------------------------------------------------- verification records

export interface VerificationInput {
  projectId: string;
  findingId: string;
  action: VerificationAction;
  result?: string;
  analysisRunId?: string | null;
  browserRunId?: string | null;
  notes?: string;
  verifiedBy?: string;
}

/** A finding may only be recorded as fixed with evidence: verified_fixed needs a result and the browser run that re-tested it. */
export function validateVerificationInput(input: unknown): Validation<VerificationInput> {
  const errors: string[] = [];
  if (!isObj(input)) return { ok: false, errors: ['verification record must be an object'] };
  if (!text(input.projectId, 200)) errors.push('projectId is required');
  if (!text(input.findingId, 200)) errors.push('findingId is required');
  if (!oneOf(VERIFICATION_ACTIONS, input.action)) errors.push(`action must be one of: ${VERIFICATION_ACTIONS.join(', ')}`);
  const result = optText(input, 'result', 2000, errors);
  const notes = optText(input, 'notes', 2000, errors);
  const verifiedBy = optText(input, 'verifiedBy', 200, errors);
  const analysisRunId = text(input.analysisRunId, 200) ? input.analysisRunId : null;
  const browserRunId = text(input.browserRunId, 200) ? input.browserRunId : null;
  if (input.action === 'verified_fixed' && (!result || !browserRunId)) errors.push('verified_fixed requires result and browserRunId (evidence from a run that re-tested the finding)');
  if (input.action === 'resolved_by_analysis' && !analysisRunId) errors.push('resolved_by_analysis requires analysisRunId');
  if (errors.length) return { ok: false, errors };
  return {
    ok: true,
    value: {
      projectId: input.projectId as string, findingId: input.findingId as string, action: input.action as VerificationAction,
      ...(result ? { result } : {}), analysisRunId, browserRunId, ...(notes ? { notes } : {}), ...(verifiedBy ? { verifiedBy } : {}),
    },
  };
}