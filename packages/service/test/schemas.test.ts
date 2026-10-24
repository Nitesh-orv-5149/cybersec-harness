import { describe, expect, it } from 'vitest';
import { DEFAULT_REVIEW, REQUIREMENT_JSON_SCHEMA, validateFindingReview, validateRequirementInput, validateVerificationInput } from '../src/store/schemas.js';

const goodReq = {
  projectId: 'p1', category: 'honesty', title: 'Sinks are never called vulnerable',
  description: 'Static sinks are described as sensitive, not vulnerable.', priority: 'must', status: 'confirmed',
  source: { kind: 'readme', document: 'README.md', section: 'Honesty rules' },
};

describe('requirement validation', () => {
  it('accepts a valid requirement and keeps its source', () => {
    const r = validateRequirementInput(goodReq);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value.source.section).toBe('Honesty rules');
  });
  it('rejects a missing source, bad priority and non-objects', () => {
    const { source: _s, ...noSource } = goodReq;
    const r = validateRequirementInput({ ...noSource, priority: 'urgent' });
    expect(r.ok).toBe(false);
    if (!r.ok) { expect(r.errors.length).toBe(2); }
    expect(validateRequirementInput('nope').ok).toBe(false);
  });
  it('rejects bad list fields', () => {
    expect(validateRequirementInput({ ...goodReq, constraints: [1, 2] }).ok).toBe(false);
  });
  it('exposes a MongoDB $jsonSchema that requires a source', () => {
    expect(REQUIREMENT_JSON_SCHEMA.required).toContain('source');
  });
});

describe('finding review / training eligibility', () => {
  const approved = { ...DEFAULT_REVIEW, reviewed: true, reviewStatus: 'approved', reviewedBy: 'harini', reviewedAt: new Date(), labelSource: 'human_review', remediation: 'Use parameterised queries.', trainingEligible: true };
  it('defaults are never training-eligible', () => {
    expect(DEFAULT_REVIEW.trainingEligible).toBe(false);
    expect(validateFindingReview(DEFAULT_REVIEW).ok).toBe(true);
  });
  it('allows eligibility only after named human approval with a real label', () => {
    expect(validateFindingReview(approved).ok).toBe(true);
  });
  it('blocks eligibility for unreviewed, unlabeled or empty records', () => {
    expect(validateFindingReview({ ...DEFAULT_REVIEW, trainingEligible: true }).ok).toBe(false);
    expect(validateFindingReview({ ...approved, labelSource: 'none' }).ok).toBe(false);
    expect(validateFindingReview({ ...approved, remediation: null, expectedOutput: null }).ok).toBe(false);
    expect(validateFindingReview({ ...approved, reviewedBy: null }).ok).toBe(false);
  });
});

describe('verification record validation', () => {
  const base = { projectId: 'p1', findingId: 'gf_abc' };
  it('accepts the repo actions', () => {
    expect(validateVerificationInput({ ...base, action: 'observed' }).ok).toBe(true);
    expect(validateVerificationInput({ ...base, action: 'reopened' }).ok).toBe(true);
  });
  it('rejects unknown actions', () => {
    expect(validateVerificationInput({ ...base, action: 'fixed' }).ok).toBe(false);
  });
  it('never allows verified_fixed without evidence', () => {
    expect(validateVerificationInput({ ...base, action: 'verified_fixed' }).ok).toBe(false);
    expect(validateVerificationInput({ ...base, action: 'verified_fixed', result: 'scenario passed on candidate' }).ok).toBe(false);
    expect(validateVerificationInput({ ...base, action: 'verified_fixed', result: 'scenario passed on candidate', browserRunId: 'brun_1' }).ok).toBe(true);
  });
  it('requires an analysis run for resolved_by_analysis', () => {
    expect(validateVerificationInput({ ...base, action: 'resolved_by_analysis' }).ok).toBe(false);
    expect(validateVerificationInput({ ...base, action: 'resolved_by_analysis', analysisRunId: 'run_1' }).ok).toBe(true);
  });
});