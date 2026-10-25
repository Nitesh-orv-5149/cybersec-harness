// Integration test against a real HTTP server (Express route dispatch order matters here,
// which a unit test calling handlers directly cannot catch).
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Service } from '../src/server.js';
import { serviceConfig } from '../src/config.js';

const PORT = 24317;
const BASE = `http://127.0.0.1:${PORT}`;
const SAMPLE = path.resolve(__dirname, '../../../sample-app');

let service: Service;
let projectId: string;

beforeAll(async () => {
  service = new Service(serviceConfig({ port: PORT, mongoUri: 'mongodb://127.0.0.1:1', dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'wb-data-')) }));
  await service.start();
  const session = await service.addProject(SAMPLE, false);
  projectId = session.id;
  // Stub the one call that would otherwise spawn real scanner binaries; this test is only
  // about which route handler Express dispatches to, not about the scan itself.
  (session.deps as unknown as { start: (...a: unknown[]) => unknown }).start = async (trigger: unknown, tools: unknown) => ({ trigger, tools });
}, 15_000);

afterAll(async () => {
  await service.stop();
});

describe('POST /security/dependency-scans route registration', () => {
  it('rejects an unknown tool name with 400, proving only the validating handler is registered', async () => {
    const res = await fetch(`${BASE}/api/projects/${projectId}/security/dependency-scans`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ tools: ['not-a-real-tool'] }),
    });
    expect(res.status).toBe(400);
  });

  it('passes the requested tools subset through to deps.start, not a silently-ignored body', async () => {
    const res = await fetch(`${BASE}/api/projects/${projectId}/security/dependency-scans`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ tools: ['osv-api'], trigger: 'agent' }),
    });
    expect(res.status).toBe(202);
    const body = await res.json();
    expect(body).toEqual({ trigger: 'agent', tools: ['osv-api'] });
  });
});
