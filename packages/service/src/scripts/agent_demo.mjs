// Scripted "triage agent" demo for the agent-memory collections. No LLM: every step is real API traffic recorded in MongoDB.
// Usage (service must be running):  node scripts/agent-demo.mjs
const BASE = process.env.WORKBENCH_URL ?? 'http://127.0.0.1:4317';

async function api(method, path, body) {
  const res = await fetch(`${BASE}${path}`, { method, headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

const projects = (await api('GET', '/api/projects')).data;
if (!projects.length) throw new Error('no project registered: start the service with --project ./sample-app');
const pid = projects[0].id;
const A = `/api/projects/${pid}/agent`;
const findings = (await api('GET', `/api/projects/${pid}/findings?status=open`)).data;
if (!Array.isArray(findings) || !findings.length) throw new Error('no open findings yet: wait for the first analysis, or mark a baseline');
const f = findings[0];
console.log(`project ${pid}\nfinding  ${f._id}: ${f.title}\n`);

async function step(runId, event) {
  const r = await api('POST', `${A}/runs/${runId}/events`, event);
  if (r.status >= 400) console.log(`  event REJECTED (${r.status}): ${r.data.error}`);
  return r;
}

// ---------------------------------------------------------------- run 1: no memory yet
const run1 = (await api('POST', `${A}/runs`, { goal: `Triage finding ${f._id}`, kind: 'triage_finding', subject: { findingId: f._id } })).data;
console.log('run 1 started:', run1._id);
const recalled1 = (await api('GET', `${A}/memories?subject=${encodeURIComponent(f._id)}`)).data;
await step(run1._id, { type: 'memory_read', status: 'ok', outputSummary: `${recalled1.memories.length} memories found for this finding` });
await step(run1._id, { type: 'plan', outputSummary: 'Read the finding, check its graph paths, decide whether a human must review it.' });
const t0 = Date.now();
const detail = await api('GET', `/api/projects/${pid}/findings/${encodeURIComponent(f._id)}`);
await step(run1._id, { type: 'tool_call', tool: 'getFinding', status: detail.status === 200 ? 'ok' : 'error', input: { findingId: f._id }, outputSummary: `HTTP ${detail.status}; severity ${f.severity}; ${(f.paths ?? []).length} path(s)`, durationMs: Date.now() - t0 });
await step(run1._id, { type: 'decision', outputSummary: `Severity ${f.severity}, classification ${f.classification}: needs human review before any label is trusted.` });
// A deliberately invalid step: the validator rejects it and nothing is stored.
await step(run1._id, { type: 'tool_call' });
const mem = (await api('POST', `${A}/memories`, {
  kind: 'fact', content: `Finding "${f.title}" is ${f.severity} severity and was waiting for human review.`,
  subject: { type: 'finding', key: f._id }, evidence: [{ kind: 'finding', id: f._id }], confidence: 'medium', source: 'agent', createdByRun: run1._id,
})).data;
await step(run1._id, { type: 'memory_write', outputSummary: `stored memory ${mem._id}`, refs: { findingId: f._id, memoryIds: [mem._id] } });
await api('POST', `${A}/runs/${run1._id}/finish`, { status: 'completed', summary: 'Triaged; recommended human review.' });

// ---------------------------------------------------------------- run 2: recalls the memory, then hits a failing tool
const run2 = (await api('POST', `${A}/runs`, { goal: `Re-check finding ${f._id}`, kind: 'triage_finding', subject: { findingId: f._id } })).data;
console.log('run 2 started:', run2._id);
const recalled2 = (await api('GET', `${A}/memories?subject=${encodeURIComponent(f._id)}`)).data;
await step(run2._id, { type: 'memory_read', status: 'ok', outputSummary: `${recalled2.memories.length} memories found (hints only)`, refs: { memoryIds: recalled2.memories.map((m) => m._id) } });
const bad = await api('GET', `/api/projects/${pid}/findings/no-such-finding/observations`);
await step(run2._id, { type: 'tool_call', tool: 'getObservations', status: 'error', input: { findingId: 'no-such-finding' }, outputSummary: `HTTP ${bad.status}: tool failed`, durationMs: 5 });
await step(run2._id, { type: 'error', status: 'error', outputSummary: 'Could not gather scanner observations; cannot confirm anything.' });
await api('POST', `${A}/runs/${run2._id}/finish`, { status: 'failed', error: 'getObservations failed' });

// ---------------------------------------------------------------- compare
const cmp = (await api('GET', `${A}/compare?a=${run1._id}&b=${run2._id}`)).data;
console.log('\ncompare (aggregation over agent_events):');
console.log(JSON.stringify(cmp, null, 2));
console.log('\nNow open Atlas: agent_runs, agent_events, agent_memories.');
