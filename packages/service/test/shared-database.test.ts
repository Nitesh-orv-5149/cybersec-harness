// Two projects with identical code writing to ONE database (e.g. teammates sharing an Atlas cluster). Before the
// fix, ids derived only from content (graph_<hash>, snap_<hash>, gf_<hash>) collided: analysis failed with E11000 on
// graph_snapshots and graph findings were overwritten across projects. Uses the in-memory store (a fake, not MongoDB);
// its upsert raises E11000 on a clashing _id exactly like MongoDB does.
import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ProjectSession } from '../src/project.js';
import { captureSnapshot } from '../src/snapshots.js';
import { ProjectConfigSchema } from '../src/config.js';
import { MemoryStore } from './helpers/memoryStore.js';

const SAMPLE = path.resolve(__dirname, '../../../sample-app');
function copyProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wb-shared-'));
  for (const f of ['src', 'public', 'tests', 'workbench.config.json', 'package.json']) fs.cpSync(path.join(SAMPLE, f), path.join(dir, f), { recursive: true });
  return dir;
}
const session = (root: string, store: MemoryStore) => new ProjectSession(root, store as never, fs.mkdtempSync(path.join(os.tmpdir(), 'wb-shared-data-')));

describe('projects sharing one database', () => {
  it('two identical projects both analyse and persist without duplicate-key errors or mixing findings', async () => {
    const store = new MemoryStore();
    const a = session(copyProject(), store);
    const b = session(copyProject(), store);
    await a.init();
    await b.init();
    expect(a.analysisStatus).toBe('idle');
    expect(b.analysisStatus).toBe('idle');
    expect(a.analysisError).toBeNull();
    expect(b.analysisError).toBeNull();
    const graphs = await store.col('graph_snapshots').find({}).toArray();
    expect(graphs).toHaveLength(2);
    expect(new Set(graphs.map((g: any) => g.graphHash)).size).toBe(1); // same code ...
    expect(new Set(graphs.map((g: any) => g._id)).size).toBe(2);       // ... separate documents
    const fa = await store.col('graph_findings').find({ projectId: a.id }).toArray();
    const fb = await store.col('graph_findings').find({ projectId: b.id }).toArray();
    expect(fa.length).toBeGreaterThan(0);
    expect(fb.length).toBe(fa.length);
    expect(fa.some((f: any) => fb.some((g: any) => g._id === f._id))).toBe(false);
    const runs = await store.col('analysis_runs').find({}).toArray();
    expect(runs.every((r: any) => r.status === 'completed')).toBe(true);
    await a.markBaseline();
    await b.markBaseline();
    expect((await store.col('source_snapshots').find({}).toArray())).toHaveLength(2);
    await a.dispose(); await b.dispose();
  });

  it('migrates this project\'s findings from the old unscoped ids and keeps their history', async () => {
    const store = new MemoryStore();
    const root = copyProject();
    const s = session(root, store);
    await store.col('graph_findings').insertOne({ _id: 'gf_0123456789abcdef', projectId: s.id, source: 'graph', status: 'open', title: 'old', severity: 'high' });
    await store.col('graph_findings').insertOne({ _id: 'gf_fedcba9876543210', projectId: 'prj_someone_else', source: 'graph', status: 'open', title: 'theirs' });
    await store.col('verification_records').insertOne({ _id: 'ver_1', projectId: s.id, findingId: 'gf_0123456789abcdef', action: 'observed', at: new Date() });
    await s.init();
    const scoped = `gf_0123456789abcdef_${s.id.slice(4, 12)}`;
    expect(await store.col('graph_findings').findOne({ _id: 'gf_0123456789abcdef' })).toBeNull();
    expect(await store.col('graph_findings').findOne({ _id: scoped })).toMatchObject({ title: 'old', projectId: s.id });
    expect(await store.col('graph_findings').findOne({ _id: 'gf_fedcba9876543210' })).toMatchObject({ projectId: 'prj_someone_else' }); // not ours: untouched
    expect(await store.col('verification_records').findOne({ _id: 'ver_1' })).toMatchObject({ findingId: scoped });
    await s.dispose();
  });

  it('snapshot ids depend on the project when a scope is given', () => {
    const cfg = ProjectConfigSchema.parse({});
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wb-snapid-'));
    const p = copyProject();
    expect(captureSnapshot(p, cfg, dir, 'prj_a').snapshotId).not.toBe(captureSnapshot(p, cfg, dir, 'prj_b').snapshotId);
    expect(captureSnapshot(p, cfg, dir, 'prj_a').snapshotId).toBe(captureSnapshot(p, cfg, dir, 'prj_a').snapshotId);
  });
});
