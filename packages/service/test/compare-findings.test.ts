import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { PNG } from 'pngjs';
import { classify, diffScreenshots } from '../src/compare.js';
import { graphFindings, runtimeFindings, staticAssetToFile } from '../src/findings.js';
import { analyzeDirectory } from '../src/analyzer/index.js';
import type { ScenarioResult } from '../src/browser.js';
import { captureSnapshot, manifestDiff } from '../src/snapshots.js';
import { ProjectConfigSchema } from '../src/config.js';

const SAMPLE = path.resolve(__dirname, '../../../sample-app');
const graph = analyzeDirectory({ root: SAMPLE, include: ['src', 'public/js', 'tests'], exclude: [], clientDirs: ['public'] });

function png(file: string, w: number, h: number, paint?: (x: number, y: number) => boolean) {
  const p = new PNG({ width: w, height: h });
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const i = (y * w + x) * 4;
    const on = paint?.(x, y);
    p.data[i] = on ? 0 : 255; p.data[i + 1] = on ? 0 : 255; p.data[i + 2] = on ? 0 : 255; p.data[i + 3] = 255;
  }
  fs.writeFileSync(file, PNG.sync.write(p));
}

const result = (over: Partial<ScenarioResult>): ScenarioResult => ({
  scenarioId: 's', scenarioName: 'S', viewport: 'desktop', status: 'passed', assertions: [], consoleErrors: [], failedRequests: [],
  apiRequests: [], scriptsLoaded: [], screenshot: null, durationMs: 1, ...over,
});

describe('screenshot diff', () => {
  it('reports zero for identical images and a region for a changed block', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wb-diff-'));
    png(`${dir}/a.png`, 200, 100);
    png(`${dir}/b.png`, 200, 100);
    png(`${dir}/c.png`, 200, 120, (x, y) => x > 50 && x < 90 && y > 20 && y < 40);
    expect(diffScreenshots(`${dir}/a.png`, `${dir}/b.png`, `${dir}/d1.png`, 0.1).ratio).toBe(0);
    const d = diffScreenshots(`${dir}/a.png`, `${dir}/c.png`, `${dir}/d2.png`, 0.1);
    expect(d.ratio).toBeGreaterThan(0);
    expect(d.sizeChanged).toEqual({ from: [200, 100], to: [200, 120] });
    expect(d.regions.length).toBeGreaterThanOrEqual(1);
    expect(d.regions[0].x).toBeLessThanOrEqual(51);
  });
});

describe('classification', () => {
  it('only calls it a regression when baseline passed and candidate failed', () => {
    expect(classify(result({}), result({ status: 'failed', assertions: [{ step: 'x', ok: false, message: 'm' }] }), null, 0.001).classification).toBe('confirmed_test_failure');
    expect(classify(result({ status: 'failed' }), result({ status: 'failed' }), null, 0.001).classification).toBe('pre_existing_failure');
    expect(classify(result({ status: 'failed' }), result({}), null, 0.001).classification).toBe('fixed');
    expect(classify(result({}), result({ status: 'error', error: 'boom' }), null, 0.001).classification).toBe('inconclusive');
  });
  it('treats pixel differences with passing assertions as observations', () => {
    const vis = { ratio: 0.01, mismatchedPixels: 10, width: 10, height: 10, sizeChanged: null, regions: [], diffImage: 'x' };
    const c = classify(result({}), result({}), vis, 0.001);
    expect(c.classification).toBe('observed');
    expect(c.severity).toBe('low');
    expect(classify(result({}), result({}), { ...vis, ratio: 0.0005 }, 0.001).classification).toBe('unchanged');
  });
});

describe('graph findings', () => {
  const f = graphFindings(graph, new Set());
  it('never assigns critical and never claims a confirmed vulnerability', () => {
    expect(f.every((x) => ['high', 'medium', 'low', 'info'].includes(x.severity))).toBe(true);
    expect(f.every((x) => x.classification === 'security_sensitive_path')).toBe(true);
    expect(f.every((x) => x.limitations[0].includes('does not prove'))).toBe(true);
  });
  it('lowers severity when every reaching endpoint has auth or sanitisation is observed', () => {
    const exec = f.find((x) => x.category === 'command_exec')!;
    expect(exec.severity).toBe('medium'); // behind requireAuth
    const userSql = f.find((x) => x.category === 'sql_dynamic' && String(x.evidence.sink).includes('findUserByName'))!;
    expect(userSql.severity).toBe('medium'); // .replace(/.../) observed
    const orderSql = f.find((x) => x.category === 'sql_dynamic' && String(x.evidence.sink).includes('orderService.fetch'))!;
    expect(orderSql.severity).toBe('high');
    expect(orderSql.paths.every((p) => p[0].startsWith('ep:'))).toBe(true);
  });
  it('produces stable ids', () => {
    expect(graphFindings(graph, new Set()).map((x) => x._id)).toEqual(f.map((x) => x._id));
  });
});

describe('runtime correlation', () => {
  const item = classify(result({ scenarioId: 'orders' }), result({ scenarioId: 'orders', status: 'failed', assertions: [{ step: 'expectText', ok: false, message: 'm' }] }), null, 0.001);
  const cand = [result({ scenarioId: 'orders', status: 'failed', apiRequests: [{ method: 'GET', path: '/api/orders', status: 200 }], scriptsLoaded: ['/orders.html', '/js/orders.js'] })];
  it('links a failure to changed code only through an observed request path', () => {
    const [r] = runtimeFindings([item], cand, { candidateGraph: graph, changedNodes: ['fn:src/lib/format.js#formatCurrency'], changedFiles: ['src/lib/format.js'], staticMap: { '/': 'public' } });
    expect(r.classification).toBe('confirmed_test_failure');
    expect(r.correlation!.status).toBe('potentially_related');
    expect(r.correlation!.paths[0][0]).toBe('ep:GET /api/orders');
    expect(r.correlation!.paths[0].at(-1)).toBe('fn:src/lib/format.js#formatCurrency');
  });
  it('does not claim a connection when no path exists', () => {
    const [r] = runtimeFindings([item], cand, { candidateGraph: graph, changedNodes: ['fn:src/routes/tools.js#previewUrl'], changedFiles: ['src/routes/tools.js'], staticMap: { '/': 'public' } });
    expect(r.correlation!.status).toBe('no_supporting_path');
    expect(r.confidence).not.toBe('high');
  });
  it('maps static URLs to source files', () => {
    expect(staticAssetToFile('/js/nav.js', { '/': 'public' })).toBe('public/js/nav.js');
    expect(staticAssetToFile('/', { '/': 'public' })).toBe('public/index.html');
  });
});

describe('snapshots', () => {
  it('are content-addressed, exclude node_modules and are reused when identical', () => {
    const cfg = ProjectConfigSchema.parse({ snapshot: { exclude: ['dist'] } });
    const store = fs.mkdtempSync(path.join(os.tmpdir(), 'wb-snap-'));
    const a = captureSnapshot(SAMPLE, cfg, store);
    const b = captureSnapshot(SAMPLE, cfg, store);
    expect(a.snapshotId).toBe(b.snapshotId);
    expect(b.reused).toBe(true);
    expect(a.manifest.some((m) => m.path.startsWith('node_modules/'))).toBe(false);
    expect(fs.existsSync(path.join(a.storagePath, 'src', 'src/lib/format.js'))).toBe(true);
    const changed = a.manifest.map((m) => (m.path === 'src/lib/format.js' ? { ...m, hash: 'x' } : m));
    expect(manifestDiff(a.manifest, changed)).toEqual({ added: [], removed: [], modified: ['src/lib/format.js'] });
  });
});
