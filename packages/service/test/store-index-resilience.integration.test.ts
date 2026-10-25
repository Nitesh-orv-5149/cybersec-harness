// Integration test against a real MongoDB (skipped when unreachable).
//   WORKBENCH_TEST_MONGO=mongodb://127.0.0.1:27017 npx vitest run
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { MongoClient } from 'mongodb';
import { Store } from '../src/store/mongo.js';

const URI = process.env.WORKBENCH_TEST_MONGO || 'mongodb://127.0.0.1:27017';
const DB = `workbench_test_idx_${Date.now()}`;

let reachable = false;

beforeAll(async () => {
  const probe = new MongoClient(URI, { serverSelectionTimeoutMS: 1500 });
  reachable = await probe.connect().then(() => true).catch(() => false);
  if (reachable) {
    // Pre-existing data that conflicts with a unique index Store.ensureIndexes() tries to
    // build (comparisons: { browserRunId: 1 }, unique) — simulates the exact shape of bug
    // that previously took down the whole Store (agent_events had legacy non-conforming docs).
    await probe.db(DB).collection('comparisons').insertMany([
      { browserRunId: 'dup', createdAt: new Date() },
      { browserRunId: 'dup', createdAt: new Date() },
    ]);
  }
  await probe.close().catch(() => {});
}, 15_000);

afterAll(async () => {
  if (!reachable) return;
  const c = new MongoClient(URI);
  await c.connect();
  await c.db(DB).dropDatabase();
  await c.close();
});

describe('Store.connect() index-build resilience', () => {
  it('stays available even when one bulk index build fails on pre-existing conflicting data', async () => {
    if (!reachable) return;
    const store = new Store(URI, DB);
    const ok = await store.connect();
    expect(ok).toBe(true);
    expect(store.available).toBe(true);
    await store.close();
  });
});
