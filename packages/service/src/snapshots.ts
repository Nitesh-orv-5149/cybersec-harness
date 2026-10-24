// Content-addressed source snapshots. Baseline and candidate code are copied out of the
// developer's working tree so builds and servers never touch (or depend on) their live files.
import fs from 'node:fs';
import path from 'node:path';
import { sha256 } from './util.js';
import type { ProjectConfig } from './config.js';

export interface ManifestEntry { path: string; hash: string; size: number }

export interface SnapshotInfo {
  snapshotId: string;
  contentHash: string;
  manifest: ManifestEntry[];
  fileCount: number;
  totalBytes: number;
  storagePath: string;
  reused: boolean;
}

const ALWAYS = new Set(['.git', 'node_modules']);

export function collectFiles(root: string, cfg: ProjectConfig): { files: { rel: string; data: Buffer }[]; totalBytes: number } {
  const exclude = new Set(cfg.snapshot.exclude);
  const files: { rel: string; data: Buffer }[] = [];
  let totalBytes = 0;
  const walk = (dir: string) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const abs = path.join(dir, e.name);
      const rel = path.relative(root, abs).split(path.sep).join('/');
      if (ALWAYS.has(e.name) || exclude.has(rel) || exclude.has(e.name)) continue;
      if (e.isSymbolicLink()) continue; // never follow links out of the workspace
      if (e.isDirectory()) { walk(abs); continue; }
      if (!e.isFile()) continue;
      const data = fs.readFileSync(abs);
      totalBytes += data.length;
      if (files.length >= cfg.snapshot.maxFiles) throw new Error(`snapshot exceeds ${cfg.snapshot.maxFiles} files; narrow snapshot.exclude`);
      if (totalBytes > cfg.snapshot.maxBytes) throw new Error(`snapshot exceeds ${cfg.snapshot.maxBytes} bytes; narrow snapshot.exclude`);
      files.push({ rel, data });
    }
  };
  walk(root);
  return { files, totalBytes };
}

export function captureSnapshot(root: string, cfg: ProjectConfig, storeDir: string): SnapshotInfo {
  const { files, totalBytes } = collectFiles(root, cfg);
  const manifest = files.map((f) => ({ path: f.rel, hash: sha256(f.data).slice(0, 16), size: f.data.length }));
  const contentHash = sha256(manifest.map((m) => `${m.path}\0${m.hash}`).join('\n'));
  const snapshotId = `snap_${contentHash.slice(0, 16)}`;
  const target = path.join(storeDir, snapshotId);
  if (fs.existsSync(path.join(target, 'manifest.json'))) {
    return { snapshotId, contentHash, manifest, fileCount: files.length, totalBytes, storagePath: target, reused: true };
  }
  const tmp = `${target}.tmp-${process.pid}-${Date.now()}`;
  fs.mkdirSync(path.join(tmp, 'src'), { recursive: true });
  for (const f of files) {
    const out = path.join(tmp, 'src', f.rel);
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, f.data);
  }
  fs.writeFileSync(path.join(tmp, 'manifest.json'), JSON.stringify({ contentHash, manifest }, null, 0));
  fs.rmSync(target, { recursive: true, force: true });
  fs.renameSync(tmp, target);
  return { snapshotId, contentHash, manifest, fileCount: files.length, totalBytes, storagePath: target, reused: false };
}

/** Materialise a throwaway working copy of a snapshot for building/running. */
export function prepareWorkspace(snapshotPath: string, projectRoot: string, cfg: ProjectConfig, workDir: string): string {
  fs.rmSync(workDir, { recursive: true, force: true });
  fs.mkdirSync(path.dirname(workDir), { recursive: true });
  fs.cpSync(path.join(snapshotPath, 'src'), workDir, { recursive: true });
  const nm = path.join(projectRoot, 'node_modules');
  if (cfg.snapshot.linkNodeModules && fs.existsSync(nm)) fs.symlinkSync(nm, path.join(workDir, 'node_modules'), 'dir');
  return workDir;
}

export function manifestDiff(a: ManifestEntry[], b: ManifestEntry[]) {
  const am = new Map(a.map((m) => [m.path, m.hash]));
  const bm = new Map(b.map((m) => [m.path, m.hash]));
  return {
    added: [...bm.keys()].filter((k) => !am.has(k)),
    removed: [...am.keys()].filter((k) => !bm.has(k)),
    modified: [...bm.keys()].filter((k) => am.has(k) && am.get(k) !== bm.get(k)),
  };
}
