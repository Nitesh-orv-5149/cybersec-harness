// Pure tests (no database): validation rules and secret scrubbing for agent memory.
import { describe, expect, it } from 'vitest';
import { validateEventInput, validateFinishInput, validateMemoryInput, validateRunInput } from '../src/store/agentMemory.js';
import { scrub } from '../src/agentMemory.js';

describe('agent run and event validation', () => {
  it('accepts a minimal run and fills safe defaults', () => {
    const r = validateRunInput({ projectId: 'p1', goal: 'triage a dependency finding' });
    expect(r.ok).toBe(true);
    if (r.ok) { expect(r.value.kind).toBe('custom'); expect(r.value.model).toBe('scripted'); }
  });
  it('rejects a run without a goal or with an unknown kind', () => {
    expect(validateRunInput({ projectId: 'p1' }).ok).toBe(false);
    expect(validateRunInput({ projectId: 'p1', goal: 'x', kind: 'hacking' }).ok).toBe(false);
  });
  it('requires the tool name on a tool_call and status "error" on an error event', () => {
    expect(validateEventInput({ type: 'tool_call' }).ok).toBe(false);
    expect(validateEventInput({ type: 'tool_call', tool: 'osv-api' }).ok).toBe(true);
    expect(validateEventInput({ type: 'error', status: 'ok' }).ok).toBe(false);
    expect(validateEventInput({ type: 'error', status: 'error', outputSummary: 'timeout' }).ok).toBe(true);
  });
  it('refuses oversized event input instead of storing whole payloads', () => {
    expect(validateEventInput({ type: 'observation', input: { blob: 'x'.repeat(25_000) } }).ok).toBe(false);
  });
  it('a failed run must say why', () => {
    expect(validateFinishInput({ status: 'failed' }).ok).toBe(false);
    expect(validateFinishInput({ status: 'failed', error: 'scanner unavailable' }).ok).toBe(true);
    expect(validateFinishInput({ status: 'completed' }).ok).toBe(true);
  });
});

describe('memory validation', () => {
  const base = { projectId: 'p1', kind: 'fact', content: 'lodash 4.17.20 was flagged by osv-api', subject: { type: 'package', key: 'lodash' } };
  it('accepts an agent memory without evidence (it will be stored as unverified later)', () => {
    expect(validateMemoryInput(base).ok).toBe(true);
  });
  it('a human memory must name the person', () => {
    expect(validateMemoryInput({ ...base, source: 'human' }).ok).toBe(false);
    expect(validateMemoryInput({ ...base, source: 'human', createdBy: 'harini' }).ok).toBe(true);
  });
  it('needs a subject so the memory can be found again, and valid evidence items', () => {
    expect(validateMemoryInput({ ...base, subject: undefined }).ok).toBe(false);
    expect(validateMemoryInput({ ...base, evidence: [{ kind: 'finding' }] }).ok).toBe(false);
    expect(validateMemoryInput({ ...base, evidence: [{ kind: 'finding', id: 'gf_1' }] }).ok).toBe(true);
  });
  it('bounds time-to-live', () => {
    expect(validateMemoryInput({ ...base, ttlHours: 0 }).ok).toBe(false);
    expect(validateMemoryInput({ ...base, ttlHours: 24 }).ok).toBe(true);
  });
});

describe('scrub (secrets never reach the memory collections)', () => {
  it('redacts credentials in strings and in secret-named keys, without mutating the input', () => {
    const input = { note: 'called https://user:hunter2@example.com?api_key=SECRET123', token: 'abc', nested: [{ auth: 'Bearer abc.def.ghi' }], when: new Date(0) };
    const out = scrub(input);
    const json = JSON.stringify(out);
    expect(json.includes('hunter2')).toBe(false);
    expect(json.includes('SECRET123')).toBe(false);
    expect(json.includes('abc.def.ghi')).toBe(false);
    expect(out.token).toBe('***');
    expect(out.when instanceof Date).toBe(true);
    expect(input.token).toBe('abc');
  });
});