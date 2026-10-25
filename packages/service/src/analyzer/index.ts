// Incremental analyzer: caches per-file facts by content hash and re-links the graph cheaply.
import fs from 'node:fs';
import path from 'node:path';
import { jsAdapter } from './js-adapter.js';
import { link } from './linker.js';
import type { FileFacts, Graph, LanguageAdapter } from './types.js';
import { shortHash } from '../util.js';

export const ADAPTERS: LanguageAdapter[] = [jsAdapter];
export const PARSER_VERSION = 'js-ts-express@2';

export interface AnalyzerOptions {
  root: string;
  include: string[];
  exclude: string[];
  clientDirs: string[];
  maxFiles?: number;
  maxFileBytes?: number;
}

export function adapterFor(file: string): LanguageAdapter | undefined {
  return ADAPTERS.find((a) => a.extensions.some((e) => file.endsWith(e)));
}

const ALWAYS_EXCLUDE = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage', '.workbench']);

export class Analyzer {
  private facts = new Map<string, FileFacts>();
  private overlays = new Map<string, string>(); // unsaved editor buffers: rel path -> text
  unsupportedFiles = 0;

  constructor(readonly opts: AnalyzerOptions) {}

  isTracked(rel: string): boolean {
    const norm = rel.split(path.sep).join('/');
    if (norm.split('/').some((seg) => ALWAYS_EXCLUDE.has(seg) || this.opts.exclude.includes(seg))) return false;
    if (this.opts.exclude.some((e) => norm === e || norm.startsWith(`${e}/`))) return false;
    if (this.opts.include.length && !this.opts.include.some((i) => norm === i || norm.startsWith(`${i}/`))) return false;
    return !!adapterFor(norm);
  }

  listFiles(): string[] {
    const out: string[] = [];
    const max = this.opts.maxFiles ?? 5000;
    let unsupported = 0;
    const walk = (dir: string) => {
      let entries: fs.Dirent[];
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
      for (const e of entries) {
        if (out.length >= max) return;
        const abs = path.join(dir, e.name);
        const rel = path.relative(this.opts.root, abs).split(path.sep).join('/');
        if (e.isDirectory()) { if (!ALWAYS_EXCLUDE.has(e.name) && !this.opts.exclude.includes(rel)) walk(abs); continue; }
        if (!e.isFile()) continue;
        if (this.isTracked(rel)) out.push(rel);
        else if (this.opts.include.some((i) => rel.startsWith(`${i}/`)) && /\.(py|go|rb|java|php|rs|cs)$/.test(rel)) unsupported++;
      }
    };
    walk(this.opts.root);
    this.unsupportedFiles = unsupported;
    return out.sort();
  }

  private isClient(rel: string) {
    return this.opts.clientDirs.some((d) => rel === d || rel.startsWith(`${d}/`));
  }

  /** (Re)parse one file from disk or overlay. Returns true if its facts changed. */
  parseFile(rel: string): boolean {
    const adapter = adapterFor(rel);
    if (!adapter) return false;
    let text = this.overlays.get(rel);
    if (text === undefined) {
      const abs = path.join(this.opts.root, rel);
      try {
        const st = fs.statSync(abs);
        if (st.size > (this.opts.maxFileBytes ?? 1_000_000)) { this.facts.delete(rel); return true; }
        text = fs.readFileSync(abs, 'utf8');
      } catch {
        const had = this.facts.delete(rel);
        return had;
      }
    }
    const prev = this.facts.get(rel);
    const h = shortHash(text);
    if (prev && prev.hash === h) return false;
    this.facts.set(rel, adapter.parse(rel, text, { isClient: this.isClient(rel) }));
    return true;
  }

  removeFile(rel: string): boolean {
    this.overlays.delete(rel);
    return this.facts.delete(rel);
  }

  setOverlay(rel: string, text: string | null): boolean {
    if (text === null) this.overlays.delete(rel);
    else this.overlays.set(rel, text);
    return this.parseFile(rel);
  }

  overlayHash(rel: string): string | null {
    const t = this.overlays.get(rel);
    return t === undefined ? null : shortHash(t);
  }

  overlayFiles(): Set<string> {
    return new Set(this.overlays.keys());
  }

  fullScan(): void {
    const files = new Set(this.listFiles());
    for (const k of [...this.facts.keys()]) if (!files.has(k)) this.facts.delete(k);
    for (const f of files) this.parseFile(f);
  }

  /** Read-only view of the current per-file facts (used by security correlation). */
  factsList(): FileFacts[] {
    return [...this.facts.values()];
  }

  fileHashes(): Record<string, string> {
    return Object.fromEntries([...this.facts.values()].map((f) => [f.file, f.hash]));
  }

  build(): Graph {
    const g = link([...this.facts.values()].sort((a, b) => a.file.localeCompare(b.file)), PARSER_VERSION, this.overlayFiles());
    g.stats.unsupportedFiles = this.unsupportedFiles;
    return g;
  }
}

/** One-shot analysis of a directory (used for baseline snapshots). */
export function analyzeDirectory(opts: AnalyzerOptions): Graph {
  const a = new Analyzer(opts);
  a.fullScan();
  return a.build();
}
