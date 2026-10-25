// Curated template selection. The configured paths are expanded from the LOCAL template directory only, and
// every template is inspected before it is allowed to run: tags alone are not trusted. A template is rejected
// unless it is a plain HTTP template that uses only the allowed methods and has none of the high-impact features
// (out-of-band interaction, fuzzing, payload lists / brute force, race requests, unsafe raw requests, code,
// headless, JavaScript, file, network or workflow execution). Approved templates are copied into a per-scan
// directory and nuclei is pointed at that directory, so nothing else can load.
//
// The inspection is a conservative line-based reading of the YAML (no YAML library is used): anything it cannot
// classify confidently is rejected, never allowed.
import fs from 'node:fs';
import path from 'node:path';
import { sha256 } from '../../util.js';

/** Tags that are never run, whatever the configuration says. */
export const DENY_TAGS = [
  'intrusive', 'dos', 'fuzz', 'fuzzing', 'dast', 'bruteforce', 'brute-force', 'default-login', 'rce', 'oast', 'oob', 'interactsh',
  'code', 'headless', 'file', 'network', 'javascript', 'sqli', 'xss', 'ssrf', 'lfi', 'rfi', 'ssti', 'xxe', 'injection',
  'cmd-injection', 'command-injection', 'deserialization', 'upload', 'file-upload', 'race', 'race-condition', 'takeover', 'spam',
];

/** Top-level keys that mean a non-HTTP protocol or orchestration. */
const FORBIDDEN_TOP = ['code', 'javascript', 'headless', 'file', 'network', 'tcp', 'dns', 'ssl', 'websocket', 'whois', 'flow', 'workflows', 'multi-protocol'];
const HTTP_TOP = ['http', 'requests'];
const FORBIDDEN_FEATURES: { re: RegExp; reason: string }[] = [
  { re: /\{\{\s*interactsh-url\s*\}\}|interactsh_(protocol|request|response)/i, reason: 'uses out-of-band interaction (interactsh)' },
  { re: /^\s*fuzzing\s*:/m, reason: 'is a fuzzing (DAST) template' },
  { re: /^\s*payloads\s*:/m, reason: 'uses payload lists (brute force / spraying)' },
  { re: /^\s*attack\s*:/m, reason: 'uses an attack mode (payload iteration)' },
  { re: /^\s*race(_count)?\s*:/m, reason: 'sends race-condition requests' },
  { re: /^\s*unsafe\s*:\s*true/m, reason: 'uses unsafe raw requests' },
  { re: /^\s*self-contained\s*:\s*true/m, reason: 'is self-contained (ignores the target)' },
  { re: /^\s*threads\s*:\s*\d{2,}/m, reason: 'requests high per-template concurrency' },
  { re: /^\s*pipeline\s*:\s*true/m, reason: 'uses HTTP pipelining' },
  { re: /^\s*(host-redirects|redirects)\s*:\s*true/m, reason: 'follows redirects on its own' },
];
const METHOD_LINE = /^[ \t-]*method[ \t]*:[ \t]*['"]?([A-Za-z]+)/gm;
const RAW_REQUEST_LINE = /^\s*(?:\|\s*)?(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|TRACE|CONNECT|PROPFIND|MOVE|COPY|MKCOL|LOCK|UNLOCK|PURGE|DEBUG)\s+\S+\s+HTTP\/\d/gm;

export interface TemplateMeta {
  id: string | null;
  name: string | null;
  severity: string | null;
  tags: string[];
  methods: string[];
}

export interface VetResult { ok: boolean; reason: string | null; meta: TemplateMeta }

export function readTemplateMeta(text: string): TemplateMeta {
  const id = text.match(/^id[ \t]*:[ \t]*['"]?([^\s'"#]+)/m)?.[1] ?? null;
  const info = infoBlock(text);
  const name = info.match(/^[ \t]+name[ \t]*:[ \t]*['"]?(.+?)['"]?[ \t]*$/m)?.[1] ?? null;
  const severity = info.match(/^[ \t]+severity[ \t]*:[ \t]*['"]?([A-Za-z]+)/m)?.[1]?.toLowerCase() ?? null;
  let tags: string[] = [];
  const inline = info.match(/^[ \t]+tags[ \t]*:[ \t]*(.+)$/m);
  if (inline && inline[1]!.trim() && !inline[1]!.trim().startsWith('#')) {
    tags = inline[1]!.replace(/^\[|\]$/g, '').split(',').map((t) => t.trim().replace(/^['"]|['"]$/g, '').toLowerCase()).filter(Boolean);
  } else {
    const list = info.match(/^([ \t]+)tags[ \t]*:[ \t]*\n((?:\1[ \t]*-[ \t]*.+\n?)+)/m);
    if (list) tags = list[2]!.split('\n').map((l) => l.replace(/^\s*-\s*/, '').trim().replace(/^['"]|['"]$/g, '').toLowerCase()).filter(Boolean);
  }
  const methods = new Set<string>();
  for (const m of text.matchAll(METHOD_LINE)) methods.add(m[1]!.toUpperCase());
  for (const m of text.matchAll(RAW_REQUEST_LINE)) methods.add(m[1]!.toUpperCase());
  return { id, name, severity, tags, methods: [...methods] };
}

function infoBlock(text: string): string {
  const m = text.match(/^info\s*:\s*\n([\s\S]*?)(?=^\S|(?![\s\S]))/m);
  return m ? m[1]! : '';
}

function topLevelKeys(text: string): string[] {
  return [...text.matchAll(/^([A-Za-z][\w-]*)\s*:/gm)].map((m) => m[1]!);
}

export interface VetPolicy { methods: string[]; excludeTags: string[]; excludeIds: string[]; severities?: string[] }

export function vetTemplate(text: string, policy: VetPolicy): VetResult {
  const meta = readTemplateMeta(text);
  const fail = (reason: string): VetResult => ({ ok: false, reason, meta });
  if (!meta.id) return fail('no template id');
  if (policy.excludeIds.includes(meta.id)) return fail('template id is excluded by configuration');
  const top = topLevelKeys(text);
  const bad = top.find((k) => FORBIDDEN_TOP.includes(k));
  if (bad) return fail(`uses the ${bad} protocol, not plain HTTP`);
  if (!top.some((k) => HTTP_TOP.includes(k))) return fail('has no http request block');
  const deny = new Set([...DENY_TAGS, ...policy.excludeTags.map((t) => t.toLowerCase())]);
  const deniedTag = meta.tags.find((t) => deny.has(t));
  if (deniedTag) return fail(`tagged "${deniedTag}"`);
  for (const f of FORBIDDEN_FEATURES) if (f.re.test(text)) return fail(f.reason);
  const methods = meta.methods.length ? meta.methods : ['GET'];
  const badMethod = methods.find((m) => !policy.methods.includes(m));
  if (badMethod) return fail(`sends ${badMethod} requests (allowed: ${policy.methods.join(', ')})`);
  if (policy.severities?.length && !policy.severities.includes(meta.severity ?? 'unknown')) return fail(`severity ${meta.severity ?? 'unknown'} is not selected`);
  return { ok: true, reason: null, meta };
}

/**
 * What a template's requests can observe, from its request paths (verified against nuclei v3 with a request-logging
 * server: {{BaseURL}}/x and raw paths are merged onto the input URL, {{RootURL}}/x always hits the origin root):
 *  - 'self': every request is {{BaseURL}} or {{BaseURL}}/ — the outcome depends only on the input's own response.
 *  - 'origin': every request starts at {{RootURL}} — the same requests whatever the input; run once, at the root.
 *  - 'subpath': anything else (probes below the input, mixed or unrecognized paths). The conservative default.
 */
export type TemplateReach = 'self' | 'subpath' | 'origin';

export function classifyReach(text: string): TemplateReach {
  const paths = [...text.matchAll(/\{\{\s*(BaseURL|RootURL)\s*\}\}([^"'\s]*)/g)];
  if (!paths.length || /^\s*raw\s*:/m.test(text)) return 'subpath';
  if (paths.every((m) => m[1] === 'RootURL')) return 'origin';
  if (paths.every((m) => m[1] === 'BaseURL' && (m[2] === '' || m[2] === '/'))) return 'self';
  return 'subpath';
}

export interface TemplateSelection {
  templatesDir: string;
  approved: { rel: string; abs: string; id: string; name: string | null; severity: string | null; tags: string[]; sha: string; reach: TemplateReach }[];
  rejected: { rel: string; id: string | null; reason: string }[];
  missing: string[];        // configured paths that do not exist locally
  truncated: boolean;       // more templates than maxTemplates
  setHash: string;          // identity of the approved set (ids + content hashes)
}

const MAX_TEMPLATE_BYTES = 256 * 1024;

/** Expand configured paths under the local template dir and vet every template file. */
export function selectTemplates(templatesDir: string, paths: string[], policy: VetPolicy, maxTemplates: number): TemplateSelection {
  const root = fs.realpathSync(templatesDir);
  const approved: TemplateSelection['approved'] = [];
  const rejected: TemplateSelection['rejected'] = [];
  const missing: string[] = [];
  const seen = new Set<string>();
  let truncated = false;
  const files: { abs: string; rel: string }[] = [];
  for (const p of paths) {
    const abs = path.isAbsolute(p) ? p : path.resolve(root, p);
    if (!fs.existsSync(abs)) { missing.push(p); continue; }
    const real = fs.realpathSync(abs);
    if (!path.isAbsolute(p) && real !== root && !real.startsWith(root + path.sep)) { missing.push(`${p} (outside the template directory)`); continue; }
    walk(real, (f) => files.push({ abs: f, rel: real.startsWith(root + path.sep) || real === root ? path.relative(root, f) : path.join('_local', path.basename(real), path.relative(real, f)) }));
  }
  files.sort((a, b) => a.rel.localeCompare(b.rel));
  for (const f of files) {
    if (seen.has(f.abs)) continue;
    seen.add(f.abs);
    const st = fs.statSync(f.abs);
    if (st.size > MAX_TEMPLATE_BYTES) { rejected.push({ rel: f.rel, id: null, reason: 'file is larger than 256 KB' }); continue; }
    const text = fs.readFileSync(f.abs, 'utf8');
    const v = vetTemplate(text, policy);
    if (!v.ok) { rejected.push({ rel: f.rel, id: v.meta.id, reason: v.reason! }); continue; }
    if (approved.some((a) => a.id === v.meta.id)) { rejected.push({ rel: f.rel, id: v.meta.id, reason: 'duplicate template id' }); continue; }
    if (approved.length >= maxTemplates) { truncated = true; rejected.push({ rel: f.rel, id: v.meta.id, reason: `over the security.nuclei.maxTemplates limit (${maxTemplates})` }); continue; }
    approved.push({ rel: f.rel, abs: f.abs, id: v.meta.id!, name: v.meta.name, severity: v.meta.severity, tags: v.meta.tags, sha: sha256(text).slice(0, 16), reach: classifyReach(text) });
  }
  const setHash = sha256(approved.map((a) => `${a.id}@${a.sha}`).sort().join('\n')).slice(0, 24);
  return { templatesDir: root, approved, rejected, missing, truncated, setHash };
}

function walk(p: string, onFile: (f: string) => void, depth = 0) {
  if (depth > 12) return;
  const st = fs.lstatSync(p);
  if (st.isSymbolicLink()) return;
  if (st.isFile()) { if (/\.ya?ml$/i.test(p)) onFile(p); return; }
  if (!st.isDirectory()) return;
  for (const e of fs.readdirSync(p)) {
    if (e.startsWith('.')) continue;
    walk(path.join(p, e), onFile, depth + 1);
  }
}

/** Copy approved templates (or the subset with the given ids) into a fresh directory; nuclei is pointed only at it. */
export function stageTemplates(sel: TemplateSelection, dir: string, only?: Set<string>): string {
  fs.rmSync(dir, { recursive: true, force: true });
  for (const a of sel.approved) {
    if (only && !only.has(a.id)) continue;
    const dest = path.join(dir, a.rel);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(a.abs, dest);
  }
  return dir;
}
