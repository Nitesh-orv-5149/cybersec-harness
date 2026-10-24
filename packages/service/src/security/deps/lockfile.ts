// npm lockfile model: which versions are installed where, dev/prod flags, and how each package is pulled
// in from the root. Used to fill installed versions, build dependency paths and judge package use.
import fs from 'node:fs';
import path from 'node:path';
import { sha256 } from '../../util.js';
import type { DependencyTarget } from '../types.js';

export interface LockPackage {
  path: string;                       // '' for the root, otherwise node_modules/... path
  name: string;
  version: string | null;
  dev: boolean;
  optional: boolean;
  deps: string[];                     // names this package depends on (prod + optional + peer)
}

export interface LockModel {
  lockfileVersion: number;
  root: { name: string | null; deps: { name: string; type: 'prod' | 'dev' | 'optional' | 'peer' }[] };
  packages: Map<string, LockPackage>;
}

export function nameFromPath(p: string): string {
  const i = p.lastIndexOf('node_modules/');
  return i === -1 ? p : p.slice(i + 'node_modules/'.length);
}

export function parseLockfile(text: string, manifestText?: string): LockModel {
  const lock = JSON.parse(text);
  if (!lock || typeof lock !== 'object') throw new Error('lockfile is not a JSON object');
  const version = Number(lock.lockfileVersion ?? 1);
  const packages = new Map<string, LockPackage>();
  const manifest = manifestText ? JSON.parse(manifestText) : null;
  const rootSrc = lock.packages?.[''] ?? manifest ?? {};
  const rootDeps: LockModel['root']['deps'] = [];
  for (const [field, type] of [['dependencies', 'prod'], ['devDependencies', 'dev'], ['optionalDependencies', 'optional'], ['peerDependencies', 'peer']] as const) {
    for (const n of Object.keys(rootSrc[field] ?? {})) if (!rootDeps.some((d) => d.name === n)) rootDeps.push({ name: n, type });
  }
  if (version >= 2 && lock.packages) {
    for (const [p, e] of Object.entries<any>(lock.packages)) {
      if (p === '') continue;
      if (!p.includes('node_modules/')) continue; // workspace links etc.
      packages.set(p, {
        path: p, name: e.name ?? nameFromPath(p), version: e.version ?? null, dev: !!e.dev || !!e.devOptional, optional: !!e.optional,
        deps: [...Object.keys(e.dependencies ?? {}), ...Object.keys(e.optionalDependencies ?? {}), ...Object.keys(e.peerDependencies ?? {})],
      });
    }
  } else if (lock.dependencies) {
    // lockfileVersion 1: nested tree
    const walk = (deps: Record<string, any>, prefix: string) => {
      for (const [n, e] of Object.entries<any>(deps)) {
        const p = `${prefix}node_modules/${n}`;
        packages.set(p, { path: p, name: n, version: e.version ?? null, dev: !!e.dev, optional: !!e.optional, deps: Object.keys(e.requires ?? {}) });
        if (e.dependencies) walk(e.dependencies, `${p}/`);
      }
    };
    walk(lock.dependencies, '');
  }
  return { lockfileVersion: version, root: { name: rootSrc.name ?? lock.name ?? null, deps: rootDeps }, packages };
}

/** Node-style resolution of `dep` required from the package at `from` ('' = root). */
export function resolveDep(model: LockModel, from: string, dep: string): string | null {
  let base = from;
  for (;;) {
    const candidate = base ? `${base}/node_modules/${dep}` : `node_modules/${dep}`;
    if (model.packages.has(candidate)) return candidate;
    if (!base) return null;
    const i = base.lastIndexOf('/node_modules/');
    base = i === -1 ? '' : base.slice(0, i);
  }
}

export interface DependencyChain { introducedBy: string; chain: string[] } // package names, root excluded

/** Shortest chain(s) from each direct dependency to the package at `target`. */
export function chainsTo(model: LockModel, target: string, maxChains = 5): DependencyChain[] {
  const out: DependencyChain[] = [];
  for (const d of model.root.deps) {
    const start = resolveDep(model, '', d.name);
    if (!start) continue;
    const prev = new Map<string, string | null>([[start, null]]);
    const queue = [start];
    let found = false;
    while (queue.length && !found) {
      const cur = queue.shift()!;
      if (cur === target) { found = true; break; }
      for (const dn of model.packages.get(cur)?.deps ?? []) {
        const nxt = resolveDep(model, cur, dn);
        if (nxt && !prev.has(nxt)) { prev.set(nxt, cur); queue.push(nxt); }
      }
    }
    if (!found) continue;
    const chain: string[] = [];
    for (let c: string | null = target; c; c = prev.get(c) ?? null) chain.unshift(model.packages.get(c)?.name ?? nameFromPath(c));
    out.push({ introducedBy: d.name, chain });
    if (out.length >= maxChains) break;
  }
  return out.sort((a, b) => a.chain.length - b.chain.length);
}

export function lockVersions(model: LockModel): Map<string, string> {
  const m = new Map<string, string>();
  for (const p of model.packages.values()) if (p.version) m.set(p.path, p.version);
  return m;
}

export function hasInstalled(model: LockModel, name: string, version: string | null): boolean {
  for (const p of model.packages.values()) if (p.name === name && (version === null || p.version === version)) return true;
  return false;
}

const OTHER_MANIFESTS: [string, string][] = [
  ['yarn.lock', 'npm (yarn)'], ['pnpm-lock.yaml', 'npm (pnpm)'], ['requirements.txt', 'PyPI'], ['poetry.lock', 'PyPI'], ['Pipfile.lock', 'PyPI'],
  ['go.mod', 'Go'], ['Cargo.lock', 'crates.io'], ['Gemfile.lock', 'RubyGems'], ['composer.lock', 'Packagist'], ['pom.xml', 'Maven'], ['build.gradle', 'Maven'],
];

export interface DetectedTargets {
  targets: DependencyTarget[];
  unsupported: { file: string; ecosystem: string; reason: string }[];
}

/** Root-level manifests only. Nested workspaces and other ecosystems are reported, not scanned. */
export function detectTargets(root: string): DetectedTargets {
  const exists = (f: string) => fs.existsSync(path.join(root, f));
  const read = (f: string) => fs.readFileSync(path.join(root, f));
  const targets: DependencyTarget[] = [];
  const unsupported: DetectedTargets['unsupported'] = [];
  const lock = exists('package-lock.json') ? 'package-lock.json' : exists('npm-shrinkwrap.json') ? 'npm-shrinkwrap.json' : null;
  if (exists('package.json') && lock) {
    targets.push({ ecosystem: 'npm', root, lockfile: lock, manifest: 'package.json', lockfileHash: sha256(read(lock)), manifestHash: sha256(read('package.json')) });
  } else if (exists('package.json')) {
    unsupported.push({ file: 'package.json', ecosystem: 'npm', reason: 'no package-lock.json; installed versions cannot be determined without a lockfile' });
  }
  for (const [f, eco] of OTHER_MANIFESTS) {
    if (exists(f)) unsupported.push({ file: f, ecosystem: eco, reason: 'detected, but no dependency adapter in this workbench is configured for it yet' });
  }
  return { targets, unsupported };
}
