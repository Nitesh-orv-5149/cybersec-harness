// Screenshot diffing and per-scenario classification of baseline vs candidate results.
import fs from 'node:fs';
import { PNG } from 'pngjs';
import pixelmatch from 'pixelmatch';
import type { ScenarioResult } from './browser.js';

export interface Region { x: number; y: number; width: number; height: number }

export interface VisualDiff {
  ratio: number;
  mismatchedPixels: number;
  width: number;
  height: number;
  sizeChanged: { from: [number, number]; to: [number, number] } | null;
  regions: Region[];
  diffImage: string;
}

function pad(png: PNG, w: number, h: number): PNG {
  if (png.width === w && png.height === h) return png;
  const out = new PNG({ width: w, height: h });
  out.data.fill(255);
  PNG.bitblt(png, out, 0, 0, png.width, png.height, 0, 0);
  return out;
}

export function diffScreenshots(a: string, b: string, out: string, pixelThreshold: number): VisualDiff {
  const pa = PNG.sync.read(fs.readFileSync(a));
  const pb = PNG.sync.read(fs.readFileSync(b));
  const w = Math.max(pa.width, pb.width);
  const h = Math.max(pa.height, pb.height);
  const A = pad(pa, w, h);
  const B = pad(pb, w, h);
  const diff = new PNG({ width: w, height: h });
  const mismatched = pixelmatch(A.data, B.data, diff.data, w, h, { threshold: pixelThreshold, includeAA: false, alpha: 0.25, diffColor: [255, 40, 80] });
  fs.writeFileSync(out, PNG.sync.write(diff));

  // Changed regions: mark 24px grid cells containing differing pixels, then merge connected cells.
  const cell = 24;
  const gw = Math.ceil(w / cell);
  const gh = Math.ceil(h / cell);
  const grid = new Uint8Array(gw * gh);
  if (mismatched) {
    for (let y = 0; y < h; y++) {
      for (let x = 0; x < w; x++) {
        const i = (y * w + x) * 4;
        if (diff.data[i] === 255 && diff.data[i + 1] === 40 && diff.data[i + 2] === 80) grid[Math.floor(y / cell) * gw + Math.floor(x / cell)] = 1;
      }
    }
  }
  const regions: Region[] = [];
  const seen = new Uint8Array(gw * gh);
  for (let i = 0; i < grid.length; i++) {
    if (!grid[i] || seen[i]) continue;
    let minx = Infinity, miny = Infinity, maxx = -1, maxy = -1;
    const stack = [i];
    seen[i] = 1;
    while (stack.length) {
      const c = stack.pop()!;
      const cx = c % gw, cy = Math.floor(c / gw);
      minx = Math.min(minx, cx); maxx = Math.max(maxx, cx); miny = Math.min(miny, cy); maxy = Math.max(maxy, cy);
      for (const [dx, dy] of [[1, 0], [-1, 0], [0, 1], [0, -1]]) {
        const nx = cx + dx, ny = cy + dy;
        if (nx < 0 || ny < 0 || nx >= gw || ny >= gh) continue;
        const n = ny * gw + nx;
        if (grid[n] && !seen[n]) { seen[n] = 1; stack.push(n); }
      }
    }
    regions.push({ x: minx * cell, y: miny * cell, width: Math.min(w, (maxx + 1) * cell) - minx * cell, height: Math.min(h, (maxy + 1) * cell) - miny * cell });
  }
  regions.sort((r1, r2) => r2.width * r2.height - r1.width * r1.height);
  return {
    ratio: mismatched / (w * h), mismatchedPixels: mismatched, width: w, height: h,
    sizeChanged: pa.width !== pb.width || pa.height !== pb.height ? { from: [pa.width, pa.height], to: [pb.width, pb.height] } : null,
    regions: regions.slice(0, 12), diffImage: out,
  };
}

export type ItemClassification =
  | 'confirmed_test_failure' // passed on baseline, fails on candidate
  | 'observed'               // visual or runtime difference without a failing assertion
  | 'fixed'                  // failed on baseline, passes on candidate
  | 'pre_existing_failure'   // fails on both
  | 'inconclusive'           // one side could not be executed
  | 'unchanged';

export interface ComparisonItem {
  scenarioId: string;
  scenarioName: string;
  viewport: string;
  baselineStatus: ScenarioResult['status'] | 'missing';
  candidateStatus: ScenarioResult['status'] | 'missing';
  classification: ItemClassification;
  severity: 'high' | 'medium' | 'low' | 'info';
  failedAssertions: { step: string; message: string }[];
  newConsoleErrors: string[];
  newFailedRequests: string[];
  visual: Omit<VisualDiff, 'diffImage'> & { diffImage: string } | null;
  notes: string[];
}

export function classify(b: ScenarioResult | undefined, c: ScenarioResult | undefined, visual: VisualDiff | null, diffThreshold: number): ComparisonItem {
  const base = (b ?? c)!;
  const notes: string[] = [];
  const item: ComparisonItem = {
    scenarioId: base.scenarioId, scenarioName: base.scenarioName, viewport: base.viewport,
    baselineStatus: b?.status ?? 'missing', candidateStatus: c?.status ?? 'missing',
    classification: 'unchanged', severity: 'info',
    failedAssertions: (c?.assertions ?? []).filter((a) => !a.ok).map((a) => ({ step: a.step, message: a.message })),
    newConsoleErrors: (c?.consoleErrors ?? []).filter((e) => !(b?.consoleErrors ?? []).includes(e)),
    newFailedRequests: (c?.failedRequests ?? []).map((r) => `${r.status ?? r.error} ${r.url}`).filter((r) => !(b?.failedRequests ?? []).map((x) => `${x.status ?? x.error} ${x.url}`).includes(r)),
    visual: visual,
    notes,
  };
  if (!b || !c || b.status === 'error' || c.status === 'error') {
    item.classification = 'inconclusive';
    if (b?.status === 'error') notes.push(`baseline could not be executed: ${b.error}`);
    if (c?.status === 'error') notes.push(`candidate could not be executed: ${c.error}`);
    return item;
  }
  const visuallyDifferent = !!visual && visual.ratio > diffThreshold;
  if (visual && visual.sizeChanged) notes.push(`page size changed from ${visual.sizeChanged.from.join('×')} to ${visual.sizeChanged.to.join('×')}`);
  if (b.status === 'passed' && c.status === 'failed') {
    item.classification = 'confirmed_test_failure';
    item.severity = 'high';
    notes.push('assertion passed on baseline and fails on candidate');
  } else if (b.status === 'failed' && c.status === 'passed') {
    item.classification = 'fixed';
    notes.push('assertion failed on baseline and passes on candidate');
  } else if (b.status === 'failed' && c.status === 'failed') {
    item.classification = 'pre_existing_failure';
    item.severity = 'low';
    notes.push('fails on both baseline and candidate; not introduced by this change');
  } else if (item.newConsoleErrors.length || item.newFailedRequests.length) {
    item.classification = 'observed';
    item.severity = 'medium';
    notes.push('new console errors or failed requests on candidate; assertions still pass');
  } else if (visuallyDifferent) {
    item.classification = 'observed';
    item.severity = visual!.ratio > 0.05 ? 'medium' : 'low';
    notes.push(`visual difference of ${(visual!.ratio * 100).toFixed(2)}% of pixels; assertions pass, so its meaning is unverified`);
  }
  return item;
}
