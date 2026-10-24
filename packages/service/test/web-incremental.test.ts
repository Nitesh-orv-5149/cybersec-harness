// Incremental nuclei scanning: change detection (fingerprint.ts), planning and cache rules (incremental.ts), and the
// service flow with a fake nuclei process, a scripted HTTP surface (fake fetch) and the in-memory store. The real
// binary is exercised by web-nuclei.real.test.ts; real MongoDB by web-nuclei.integration.test.ts.
import { beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ProjectConfigSchema } from '../src/config.js';
import type { Exec, ExecResult, Which } from '../src/security/types.js';
import { OPTIONAL_FLAGS, parseErrorLog, REQUIRED_FLAGS } from '../src/security/web/nuclei.js';
import { classifyReach } from '../src/security/web/templates.js';
import { compareFetches, cookieShape, diffSite, headerSignature, normalizeBody, siteFingerprint, skeletonOf, type EndpointFingerprint, type RawResponse } from '../src/security/web/fingerprint.js';
import { codeHashes, contextsFor, expiryFor, inputOfUrl, mergeGroups, pairKey, planScan, type CacheBucket, type PlanArgs } from '../src/security/web/incremental.js';
import { WebScanService } from '../src/security/web/service.js';
import type { Graph } from '../src/analyzer/types.js';
import { MemoryStore } from './helpers/memoryStore.js';
import { sleep } from '../src/util.js';

const raw = (body: string, headers: [string, string][] = [['content-type', 'text/html']], status = 200): RawResponse => ({ status, headers, body });

// ------------------------------------------------------------------ change detection

describe('fingerprints ignore per-request noise but not real changes', () => {
  it('normalizes timestamps, dates, UUIDs, tokens, nonces, CSRF values, the origin and the canary', () => {
    const page = (ts: string, id: string, nonce: string, csrf: string, port: number) =>
      `<html><script nonce="${nonce}"></script><p>Rendered ${ts} req ${id}</p><input type="hidden" name="_csrf" value="${csrf}"><a href="http://127.0.0.1:${port}/x">x</a></html>`;
    const a = normalizeBody(page('2026-10-24T10:00:00.123Z', '6f1c2b8e-4c1d-4e2a-9a0b-1c2d3e4f5a6b', 'r4nd0m', 'tok1', 41001), { origin: 'http://127.0.0.1:41001' });
    const b = normalizeBody(page('2026-10-24T10:00:01.456Z', '0e9d8c7b-6a5f-4e3d-8c2b-1a0f9e8d7c6b', 'other', 'tok2', 41002), { origin: 'http://127.0.0.1:41002' });
    expect(a).toBe(b);
    expect(normalizeBody('version 4.5.6')).not.toBe(normalizeBody('version 4.5.7'));
    expect(normalizeBody(`etag ${'ab12'.repeat(8)} at 1761300000`)).toBe(normalizeBody(`etag ${'cd34'.repeat(8)} at 1761300099`));
  });

  it('classifies two fetches as stable, volatile (structure only) or unstable', () => {
    expect(compareFetches(raw('<p>hello</p>'), raw('<p>hello</p>'), {}).stability).toBe('stable');
    const v = compareFetches(raw('<ul><li>visits: 41</li></ul>'), raw('<ul><li>visits: 42</li></ul>'), {});
    expect(v.stability).toBe('volatile');
    expect(v.sig.bodySig).toMatch(/^skel:/);
    expect(compareFetches(raw('<ul><li>a</li></ul>'), raw('<div>b</div>'), {}).stability).toBe('unstable');
    expect(compareFetches(raw('x', [], 200), raw('x', [], 500), {}).stability).toBe('unstable');
    // a canary echoed in a 404 page is not a difference
    expect(compareFetches(raw('Cannot GET /api/wb-nf-aaa'), raw('Cannot GET /api/wb-nf-bbb'), { canaries: ['wb-nf-aaa', 'wb-nf-bbb'] }).stability).toBe('stable');
  });

  it('keeps header values that matter, drops volatile ones and cookie values', () => {
    const r1 = raw('', [['Date', 'Mon, 01 Jan 2026 00:00:00 GMT'], ['X-Frame-Options', 'DENY'], ['X-Request-Id', 'a1'], ['X-Trace', 'one'], ['Set-Cookie', 'sid=SECRET1; HttpOnly; Path=/']]);
    const r2 = raw('', [['Date', 'Mon, 01 Jan 2026 00:00:09 GMT'], ['X-Frame-Options', 'DENY'], ['X-Request-Id', 'b2'], ['X-Trace', 'two'], ['Set-Cookie', 'sid=SECRET2; HttpOnly; Path=/']]);
    const s = headerSignature(r1, r2);
    expect(s.volatile).toEqual(['x-trace']);
    expect(s.sig).toBe(headerSignature(r2, r1).sig);
    const r3 = raw('', [...r1.headers.filter(([k]) => k !== 'X-Frame-Options'), ['X-Frame-Options', 'SAMEORIGIN']]);
    expect(headerSignature(r3, r3).sig).not.toBe(headerSignature(r1, r1).sig);
    expect(cookieShape('sid=SECRET; Path=/; HttpOnly; Expires=Wed, 21 Oct 2026 07:28:00 GMT')).toBe('sid; expires; httponly; path=/');
    expect(cookieShape('sid=x; Secure')).not.toBe(cookieShape('sid=x'));
  });

  it('builds structural skeletons for HTML and JSON', () => {
    expect(skeletonOf('{"items":[{"id":1,"name":"a"}],"total":1}', 'application/json')).toBe(skeletonOf('{"total":9,"items":[{"id":7,"name":"zz"},{"id":8,"name":"y"}]}', 'application/json'));
    expect(skeletonOf('{"items":[],"debug":true}', 'application/json')).not.toBe(skeletonOf('{"items":[]}', 'application/json'));
    expect(skeletonOf('<div class="a" id="x">hi</div>', 'text/html')).toBe(skeletonOf('<div id="y" class="b">bye</div>', 'text/html'));
    expect(skeletonOf('<div><form action="/login"></form></div>', 'text/html')).not.toBe(skeletonOf('<div></div>', 'text/html'));
  });

  it('separates site infrastructure from global security headers', () => {
    const root = (server: string, extra: [string, string][] = []) => raw('', [['Server', server], ['X-Powered-By', 'Express'], ['Set-Cookie', 'connect.sid=abc; HttpOnly'], ...extra]);
    const a = siteFingerprint(root('nginx/1.25'), null);
    expect(a.infra).toMatchObject({ server: 'nginx/1.25', poweredBy: 'Express', tech: ['express', 'express-session', 'nginx'] });
    const b = siteFingerprint(root('nginx/1.27'), null);
    expect(diffSite(a, b).infra).toEqual(['server: nginx/1.25 → nginx/1.27']);
    const c = siteFingerprint(root('nginx/1.25', [['Strict-Transport-Security', 'max-age=1'], ['cf-ray', '123']]), null);
    expect(diffSite(a, c)).toEqual({ infra: ['CDN: (none) → cloudflare'], headers: ['strict-transport-security added'] });
    expect(diffSite(a, siteFingerprint(root('nginx/1.25'), null))).toEqual({ infra: [], headers: [] });
  });
});

// ------------------------------------------------------------------ template reach

describe('template reach (what a template can observe)', () => {
  it('distinguishes self, sub-path and origin templates; anything unclear is sub-path', () => {
    expect(classifyReach('http:\n  - method: GET\n    path:\n      - "{{BaseURL}}"\n')).toBe('self');
    expect(classifyReach('http:\n  - method: GET\n    path:\n      - "{{BaseURL}}/"\n')).toBe('self');
    expect(classifyReach('http:\n  - method: GET\n    path:\n      - "{{BaseURL}}/.git/config"\n')).toBe('subpath');
    expect(classifyReach('http:\n  - method: GET\n    path:\n      - "{{RootURL}}/robots.txt"\n')).toBe('origin');
    expect(classifyReach('http:\n  - method: GET\n    path:\n      - "{{RootURL}}/a"\n      - "{{BaseURL}}/b"\n')).toBe('subpath');
    expect(classifyReach('http:\n  - raw:\n      - |\n        GET / HTTP/1.1\n        Host: {{Hostname}}\n')).toBe('subpath');
  });
});

// ------------------------------------------------------------------ planning

const fp = (input: string, o: { body?: string; nf?: string; headers?: string; stability?: EndpointFingerprint['stability']; ok?: boolean } = {}): EndpointFingerprint => ({
  input, ok: o.ok ?? true, error: null, stability: o.stability ?? 'stable', volatileHeaders: [], tech: [],
  self: { status: 200, contentType: 'text/html', headerSig: o.headers ?? 'h', bodySig: o.body ?? `b${input}`, skeletonSig: `s${input}` },
  notFound: { status: 404, contentType: 'text/html', headerSig: o.headers ?? 'h', bodySig: o.nf ?? 'nf', skeletonSig: 'snf' },
});
const SITE = siteFingerprint(raw('', [['X-Powered-By', 'Express']]), null);
const TPL = [
  { id: 'tech-detect', sha: 't1', reach: 'self' as const },
  { id: 'git-config', sha: 'g1', reach: 'subpath' as const },
  { id: 'robots', sha: 'r1', reach: 'origin' as const },
];
const INPUTS = ['/', '/api/orders', '/api/users'];

function args(over: Partial<PlanArgs> = {}): PlanArgs {
  return {
    inputs: INPUTS, templates: TPL, fingerprints: new Map(INPUTS.map((i) => [i, fp(i)])), site: SITE, prevSite: SITE,
    prevEndpoints: new Map(INPUTS.map((i) => [i, { input: i, fingerprint: { self: fp(i).self, notFound: fp(i).notFound, stability: 'stable', code: null, subtreeCode: null } }])),
    cache: new Map(), knownFindings: new Map(), scanCtx: 'ctx', code: new Map(), now: new Date('2026-10-24T12:00:00Z'), full: null, maxGroups: 6, ...over,
  };
}

/** A cache that holds clean negatives for every applicable pair under the contexts of `a`. */
function warmCache(a: PlanArgs, exp = new Date('2026-11-01T00:00:00Z')): Map<string, CacheBucket> {
  const cache = new Map<string, CacheBucket>();
  for (const i of a.inputs) {
    const c = contextsFor(a.scanCtx, a.site, a.fingerprints.get(i), a.code.get(i), a.fingerprints.get('/'))!;
    const b: CacheBucket = {};
    for (const t of a.templates) if (t.reach !== 'origin' || i === '/') b[t.id] = { s: t.sha, c: c[t.reach]!, r: 'no_match', at: a.now, exp, run: 'web_prev' };
    cache.set(i, b);
  }
  return cache;
}
const pairsOf = (p: ReturnType<typeof planScan>) => p.groups.flatMap((g) => g.inputs.flatMap((i) => g.templateIds.map((t) => `${t}@${i}`))).sort();

describe('scan planning and blast radius', () => {
  it('a first scan runs everything, but origin templates only once at the root', () => {
    const p = planScan(args({ prevSite: null, prevEndpoints: new Map() }));
    expect(p.mode).toBe('full');
    expect(p.pairs).toMatchObject({ applicable: 7, toRun: 7, cached: 0, naive: 9 });
    expect(p.pairs.byReason).toEqual({ no_entry: 7 });
    expect(pairsOf(p)).toContain('robots@/');
    // the two duplicate origin checks are cheaper than a second nuclei process, so the planner folds them in
    expect(p.groups).toHaveLength(1);
    expect(p.pairs.scheduled).toBe(9);
    const many = Array.from({ length: 200 }, (_, i) => ({ id: `origin-${i}`, sha: 'x', reach: 'origin' as const }));
    const p2 = planScan(args({ prevSite: null, prevEndpoints: new Map(), templates: [...TPL, ...many] }));
    expect(p2.groups).toHaveLength(2);
    expect(p2.groups.find((g) => g.inputs.length === 1)!.inputs).toEqual(['/']);
    expect(p.endpoints.added).toEqual(INPUTS);
  });

  it('nothing changed: every pair comes from the cache and nuclei is not run at all', () => {
    const a = args();
    const p = planScan({ ...a, cache: warmCache(a) });
    expect(p).toMatchObject({ mode: 'delta', groups: [], pairs: { toRun: 0, cached: 7 } });
    expect(p.endpoints).toMatchObject({ unchanged: 3, changed: [], added: [], removed: [] });
  });

  it('a changed endpoint re-runs only its own templates', () => {
    const a = args();
    const cache = warmCache(a);
    const fps = new Map(a.fingerprints).set('/api/orders', fp('/api/orders', { body: 'new body' }));
    const p = planScan({ ...a, cache, fingerprints: fps });
    expect(pairsOf(p)).toEqual(['tech-detect@/api/orders']); // sub-path checks depend on structure + not-found, not text
    expect(p.endpoints.changed).toEqual([{ input: '/api/orders', what: ['content'] }]);
    const nf = new Map(a.fingerprints).set('/api/users', fp('/api/users', { nf: 'catch-all now' }));
    expect(pairsOf(planScan({ ...a, cache, fingerprints: nf }))).toEqual(['git-config@/api/users']);
  });

  it('a global header shift reaches every input; an infrastructure change re-runs the whole scope', () => {
    const a = args();
    const cache = warmCache(a);
    const hdr = new Map(INPUTS.map((i) => [i, fp(i, { headers: 'h2' })]));
    const ph = planScan({ ...a, cache, fingerprints: hdr, site: siteFingerprint(raw('', [['X-Powered-By', 'Express'], ['X-Frame-Options', 'DENY']]), null) });
    expect(ph.pairs.cached).toBe(0);
    expect(ph.reasons.join(' ')).toContain('global header change');
    const pi = planScan({ ...a, cache, site: siteFingerprint(raw('', [['X-Powered-By', 'Koa']]), null) });
    expect(pi).toMatchObject({ mode: 'full', pairs: { toRun: 7, cached: 0 } });
    expect(pi.reasons.join(' ')).toContain('site-wide change');
  });

  it('a code change re-runs the route it touches and sub-path checks of the routes above it', () => {
    const g = (handlerHash: string): Graph => ({
      provider: 't', stats: { files: 1, parsedFiles: 1, parseErrors: [], unresolvedCalls: 0, unsupportedFiles: 0 },
      nodes: [
        { id: 'ep:GET /api/orders', kind: 'endpoint', label: '', hash: 'e1', meta: { method: 'GET', path: '/api/orders' } },
        { id: 'ep:GET /api/orders/:id', kind: 'endpoint', label: '', hash: 'e2', meta: { method: 'GET', path: '/api/orders/:id' } },
        { id: 'ep:GET /api/users', kind: 'endpoint', label: '', hash: 'e3', meta: { method: 'GET', path: '/api/users' } },
        { id: 'fn:getOrder', kind: 'function', label: '', hash: handlerHash, meta: {} },
        { id: 'fn:listUsers', kind: 'function', label: '', hash: 'u', meta: {} },
      ],
      edges: [
        { id: 'x1', source: 'ep:GET /api/orders/:id', target: 'fn:getOrder', kind: 'route_to_handler', certainty: 'static', confidence: 1, derivation: '' },
        { id: 'x2', source: 'ep:GET /api/users', target: 'fn:listUsers', kind: 'route_to_handler', certainty: 'static', confidence: 1, derivation: '' },
      ],
    });
    const before = codeHashes(g('v1'), INPUTS, ['GET']);
    const after = codeHashes(g('v2'), INPUTS, ['GET']);
    expect(after.get('/api/orders')!.self).toBe(before.get('/api/orders')!.self);       // GET /api/orders itself did not change
    expect(after.get('/api/orders')!.subtree).not.toBe(before.get('/api/orders')!.subtree); // /api/orders/:id below it did
    expect(after.get('/api/users')).toEqual(before.get('/api/users'));
    const a = args({ code: before });
    a.prevEndpoints = new Map([...a.prevEndpoints].map(([i, e]) => [i, { ...e, fingerprint: { ...e.fingerprint!, code: before.get(i)!.self, subtreeCode: before.get(i)!.subtree } }]));
    const p = planScan({ ...a, cache: warmCache(a), code: after });
    expect(pairsOf(p)).toEqual(['git-config@/', 'git-config@/api/orders']);
    expect(p.endpoints.changed.map((c) => [c.input, c.what])).toEqual([['/', ['code of routes below it']], ['/api/orders', ['code of routes below it']]]);
  });

  it('re-verifies matches and open findings, and runs new, changed and expired templates', () => {
    const a = args();
    const cache = warmCache(a);
    cache.get('/api/users')!['tech-detect']!.r = 'matched';
    const open = new Map([['git-config', new Set(['/api/orders'])], ['robots', new Set(['/api/users'])]]); // a legacy origin finding at another input
    const t = [...TPL.map((x) => (x.id === 'tech-detect' ? { ...x, sha: 't2' } : x)), { id: 'brand-new', sha: 'n', reach: 'self' as const }];
    const p = planScan({ ...a, cache, knownFindings: open, templates: t });
    expect(p.pairs.byReason).toMatchObject({ rerun_matched: 3, template_changed: 2, no_entry: 3 });
    expect(pairsOf(p)).toEqual(expect.arrayContaining(['git-config@/api/orders', 'robots@/', 'tech-detect@/api/users', 'brand-new@/']));
    const later = planScan({ ...a, cache, now: new Date('2026-11-02T00:00:00Z') });
    expect(later.pairs).toMatchObject({ cached: 0, byReason: { expired: 6, rerun_matched: 1 } });
  });

  it('never trusts the cache for unstable or unreachable inputs, or when the root cannot be fingerprinted', () => {
    const a = args();
    const cache = warmCache(a);
    const fps = new Map(a.fingerprints).set('/api/orders', fp('/api/orders', { stability: 'unstable' })).set('/api/users', fp('/api/users', { ok: false }));
    const p = planScan({ ...a, cache, fingerprints: fps });
    expect(pairsOf(p)).toEqual(['git-config@/api/orders', 'git-config@/api/users', 'tech-detect@/api/orders', 'tech-detect@/api/users']);
    expect(p.endpoints).toMatchObject({ unstable: ['/api/orders'], unreachable: ['/api/users'] });
    expect(planScan({ ...a, cache, site: null }).pairs.cached).toBe(0);
  });

  it('a forced full scan runs everything; removed inputs are reported', () => {
    const a = args();
    const p = planScan({ ...a, cache: warmCache(a), full: 'full scan requested' });
    expect(p.pairs).toMatchObject({ toRun: 7, cached: 0 });
    const gone = planScan({ ...a, inputs: ['/', '/api/users'] });
    expect(gone.endpoints.removed).toEqual(['/api/orders']);
  });

  it('expiry is jittered per template, between 80 and 100 % of the TTL', () => {
    const now = new Date('2026-10-24T00:00:00Z');
    const e = ['a', 'b', 'c', 'd'].map((t) => (expiryFor(now, 10, t).getTime() - now.getTime()) / 3600_000);
    for (const h of e) { expect(h).toBeGreaterThanOrEqual(8); expect(h).toBeLessThanOrEqual(10); }
    expect(new Set(e).size).toBeGreaterThan(1);
    expect(expiryFor(now, 10, 'a')).toEqual(expiryFor(now, 10, 'a'));
  });
});

describe('grouping into nuclei invocations', () => {
  it('shares an invocation between inputs with the same templates and never drops a pair', () => {
    const all = Array.from({ length: 400 }, (_, i) => `t${i}`);
    const sets = new Map<string, string[]>([['/', all], ['/a', all], ['/b', ['t1', 't2']], ['/c', ['t3']], ['/d', all.slice(0, 200)]]);
    const groups = mergeGroups(sets, 6);
    const covered = new Set(groups.flatMap((g) => g.inputs.flatMap((i) => g.templateIds.map((t) => pairKey(t, i)))));
    for (const [i, ids] of sets) for (const t of ids) expect(covered.has(pairKey(t, i))).toBe(true);
    expect(groups.find((g) => g.inputs.includes('/'))!.inputs).toContain('/a');
    // tiny sets are folded together (cheaper than another process); the 200-template input stays separate
    expect(groups.length).toBeLessThan(sets.size);
    expect(groups.some((g) => g.inputs.length === 1 && g.inputs[0] === '/d')).toBe(true);
  });

  it('respects maxGroups by merging the cheapest pairs', () => {
    const sets = new Map(Array.from({ length: 30 }, (_, i) => [`/r${i}`, Array.from({ length: 300 }, (_, j) => `t${(i * 300 + j) % 2000}`)] as [string, string[]]));
    expect(mergeGroups(sets, 4).length).toBeLessThanOrEqual(4);
    expect(mergeGroups(new Map(), 4)).toEqual([]);
  });
});

describe('attribution helpers', () => {
  it('maps request URLs back to the scan input they were derived from', () => {
    const inputs = ['/', '/api', '/api/orders'];
    expect(inputOfUrl('http://h:1/api/orders/.git/config', inputs)).toBe('/api/orders');
    expect(inputOfUrl('http://h:1/api/ordersX', inputs)).toBe('/api');
    expect(inputOfUrl('http://h:1/.env', inputs)).toBe('/');
    expect(inputOfUrl('http://h:1/app/api/x', inputs, '/app/')).toBe('/api');
  });

  it('parses the -elog error log and tolerates a torn last line', () => {
    const text = '{"template":"/s/http/a.yaml","type":"http","input":"http://h/api/a/probe","error":"cause=\\"EOF\\"","kind":"unknown-error"}\n{"template":"/s/b.ya';
    expect(parseErrorLog(text)).toEqual([{ template: '/s/http/a.yaml', url: 'http://h/api/a/probe', error: 'cause="EOF"' }]);
  });
});

// ------------------------------------------------------------------ service flow (fake nuclei, scripted surface)

const TEMPLATES = path.resolve(__dirname, 'fixtures/web/templates');
const res = (p: Partial<ExecResult>): ExecResult => ({ exitCode: 0, signal: null, stdout: '', stdoutBytes: 0, stdoutTruncated: false, stderrTail: '', timedOut: false, cancelled: false, spawnError: null, durationMs: 5, ...p });
const G: Graph = {
  provider: 't', stats: { files: 1, parsedFiles: 1, parseErrors: [], unresolvedCalls: 0, unsupportedFiles: 0 },
  nodes: [
    { id: 'ep:GET /api/orders', kind: 'endpoint', label: 'GET /api/orders', hash: 'o', meta: { method: 'GET', path: '/api/orders' } },
    { id: 'ep:GET /api/users', kind: 'endpoint', label: 'GET /api/users', hash: 'u', meta: { method: 'GET', path: '/api/users' } },
  ],
  edges: [],
};

interface Surface { pages: Record<string, { body: string; headers?: Record<string, string>; status?: number }>; notFound: (p: string) => string; global: Record<string, string> }
type Call = { inputs: string[]; templates: string[] };

function harness(opts: { nuclei?: Record<string, unknown>; missingElog?: boolean } = {}) {
  const store = new MemoryStore();
  const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wb-inc-'));
  const surface: Surface = {
    pages: { '/': { body: '<html><body><h1>Shop</h1></body></html>' }, '/api/orders': { body: '{"orders":[]}', headers: { 'content-type': 'application/json' } }, '/api/users': { body: '{"users":[]}', headers: { 'content-type': 'application/json' } } },
    notFound: (p) => `Cannot GET ${p}`,
    global: { 'x-powered-by': 'Express' },
  };
  let counter = 0;
  const fetchImpl = (async (url: string) => {
    const u = new URL(url);
    const page = surface.pages[u.pathname] ?? (u.pathname === '/' ? undefined : surface.pages[u.pathname.replace(/\/+$/, '')]);
    const headers = { 'content-type': 'text/html', date: new Date(Date.now() + counter++ * 1000).toUTCString(), 'x-request-id': String(counter), ...surface.global, ...(page?.headers ?? {}) };
    return new Response(page ? page.body : surface.notFound(u.pathname), { status: page ? page.status ?? 200 : 404, headers });
  }) as unknown as typeof fetch;
  const help = [...REQUIRED_FLAGS, ...OPTIONAL_FLAGS.filter((f) => !(opts.missingElog && f === 'elog'))].map((f) => `   -${f}, -long-${f} string   d`).join('\n');
  const which: Which = (n) => `/fake/bin/${n}`;
  const calls: Call[] = [];
  // per call: what nuclei "finds" and which requests fail; templates are read from the staged directory
  const behaviour: { match: (templateId: string, input: string) => boolean; errors: (templateId: string, input: string) => boolean; stderr: string; requestErrors: number; tailLost?: boolean } = { match: () => false, errors: () => false, stderr: '', requestErrors: 0 };
  const exec: Exec = async (_b, a, o) => {
    if (a[0] === '-version') return res({ stderrTail: '[INF] Nuclei Engine Version: v3.11.1' });
    if (a[0] === '-h') return res({ stdout: help });
    if (a[0] === '-tv') return res({ stderrTail: `[INF] Public nuclei-templates version: v10.3.1 (${TEMPLATES})` });
    const urls = a.includes('-l') ? fs.readFileSync(a[a.indexOf('-l') + 1]!, 'utf8').trim().split('\n') : [a[a.indexOf('-u') + 1]!];
    const staged = a[a.indexOf('-t') + 1]!;
    const files = (fs.readdirSync(staged, { recursive: true }) as string[]).filter((f) => String(f).endsWith('.yaml'));
    const ids = files.map((f) => fs.readFileSync(path.join(staged, f), 'utf8').match(/^id:\s*(\S+)/m)![1]!);
    const inputs = urls.map((u) => new URL(u).pathname.replace(/(.)\/$/, '$1'));
    calls.push({ inputs, templates: [...ids].sort() });
    const out: string[] = [];
    const elog: string[] = [];
    for (const [k, id] of ids.entries()) for (const [j, input] of inputs.entries()) {
      if (behaviour.errors(id, input)) elog.push(JSON.stringify({ template: path.join(staged, files[k]!), input: `${urls[j]!.replace(/\/$/, '')}/probe`, error: 'cause="EOF"' }));
      else if (behaviour.match(id, input)) out.push(JSON.stringify({ 'template-id': id, info: { name: id, severity: 'medium' }, type: 'http', host: urls[j], url: urls[j], 'matched-at': `${urls[j]!.replace(/\/$/, '')}/canary`, request: 'GET /canary HTTP/1.1\r\n\r\n' }));
    }
    if (a.includes('-elog')) fs.writeFileSync(a[a.indexOf('-elog') + 1]!, elog.join('\n'));
    const errs = elog.length + behaviour.requestErrors;
    const stats = `{"duration":"0:00:01","errors":"${errs}","hosts":"1","matched":"${out.length}","percent":"100","requests":"${ids.length * inputs.length}","rps":"10","templates":"${ids.length}","total":"${ids.length * inputs.length}"}`;
    const log = `[INF] Templates loaded for current scan: ${ids.length}\n${stats}\n${behaviour.stderr}`;
    o.onStderr?.(log);
    // a long scan: the bounded tail holds only statistics lines by the end
    return res({ stdout: out.join('\n'), stderrTail: behaviour.tailLost ? `${stats}\n`.repeat(3) : log });
  };
  const cfg = () => ProjectConfigSchema.parse({ security: { nuclei: { templatesDir: TEMPLATES, templates: ['http'], ...opts.nuclei } } }).security.nuclei;
  const svc = new WebScanService({
    projectId: 'prj_inc', projectDir, store: store as never, cfg, graph: () => G, graphVersion: () => 1, sourceHash: () => 'h',
    snapshotReadiness: () => ({ ok: false, reasons: ['n/a'] }), prepareSnapshots: async () => { throw new Error('n/a'); },
    emit: () => {}, exec, which, fetch: fetchImpl,
  });
  const run = async (req: Partial<Parameters<WebScanService['start']>[0]> = {}) => {
    const before = calls.length;
    const { runId } = await svc.start({ mode: 'url', url: 'http://127.0.0.1:4555', ...req });
    const end = Date.now() + 5000;
    while (svc.job && Date.now() < end) await sleep(5);
    const doc = await store.col('security_scan_runs').findOne({ _id: runId });
    return { doc, side: doc.sides.target, inc: doc.sides.target.incremental, calls: calls.slice(before) };
  };
  const pairs = (cs: Call[]) => cs.flatMap((c) => c.inputs.flatMap((i) => c.templates.map((t) => `${t}@${i}`))).sort();
  return { svc, store, surface, behaviour, run, pairs, findings: () => store.col('graph_findings').find({ source: 'web' }).toArray() };
}

const T = ['workbench-canary-header', 'workbench-debug-page']; // both fixture templates probe sub-paths

describe('incremental web scans (fake nuclei, scripted surface, in-memory store)', () => {
  let h: ReturnType<typeof harness>;
  beforeEach(() => { h = harness(); });

  it('scans everything first, then nothing when nothing changed, and keeps the result complete', async () => {
    const first = await h.run();
    expect(first.doc.status).toBe('completed');
    expect(first.inc).toMatchObject({ mode: 'full', pairs: { applicable: 6, toRun: 6, cached: 0 }, cache: { cachedNegatives: 6 } });
    expect(h.pairs(first.calls)).toHaveLength(6);
    const second = await h.run();
    expect(second.calls).toEqual([]);
    expect(second.doc.status).toBe('completed');
    expect(second.inc).toMatchObject({ mode: 'delta', pairs: { toRun: 0, cached: 6 }, endpoints: { unchanged: 3 } });
    expect(second.side.reason).toContain('all 6 checks were served from completed earlier scans');
    // endpoint and site documents describe the surface
    const eps = await h.store.col('web_endpoints').find({ projectId: 'prj_inc', kind: 'endpoint' }).toArray();
    expect(eps.map((e: any) => e.input).sort()).toEqual(['/', '/api/orders', '/api/users']);
    expect(eps[0]).toMatchObject({ fingerprint: { stability: 'stable' }, removedAt: null });
    expect((await h.store.col('web_endpoints').findOne({ kind: 'site' })).fingerprint.infra.poweredBy).toBe('Express');
  });

  it('timestamps, request ids and changing dates do not count as changes', async () => {
    h.surface.pages['/'] = { body: `<html><p>Generated ${new Date().toISOString()}</p></html>` };
    await h.run();
    h.surface.pages['/'] = { body: `<html><p>Generated ${new Date(Date.now() + 60_000).toISOString()}</p></html>` };
    expect((await h.run()).calls).toEqual([]);
  });

  it('a changed endpoint re-runs only that input; a new route is scanned, a removed one reported', async () => {
    await h.run();
    h.surface.pages['/api/orders'] = { body: '{"orders":[],"debug":{"sql":"select"}}', headers: { 'content-type': 'application/json' } };
    const r = await h.run();
    expect(h.pairs(r.calls)).toEqual(T.map((t) => `${t}@/api/orders`));
    expect(r.inc.endpoints.changed).toEqual([{ input: '/api/orders', what: ['page structure'] }]);
    (h.svc as any).ctx.graph = () => ({ ...G, nodes: [G.nodes[1]!, { id: 'ep:GET /api/admin', kind: 'endpoint', label: '', hash: 'a', meta: { method: 'GET', path: '/api/admin' } }] });
    h.surface.pages['/api/admin'] = { body: 'admin' };
    const r2 = await h.run();
    // the root's sub-path probes can land on the new route too (its subtree code changed); /api/users is untouched
    expect(h.pairs(r2.calls)).toEqual([...T.map((t) => `${t}@/`), ...T.map((t) => `${t}@/api/admin`)].sort());
    expect(r2.inc.endpoints).toMatchObject({ added: ['/api/admin'], removed: ['/api/orders'], changed: [{ input: '/', what: ['code of routes below it'] }] });
    const removed = await h.store.col('web_endpoints').findOne({ input: '/api/orders' });
    expect(removed.removedAt).toBeInstanceOf(Date);
  });

  it('a site-wide change (new server header or a global header shift) re-runs the whole scope', async () => {
    await h.run();
    h.surface.global = { 'x-powered-by': 'Express', 'x-frame-options': 'DENY' };
    const r = await h.run();
    expect(h.pairs(r.calls)).toHaveLength(6);
    expect(r.inc.reasons.join(' ')).toContain('x-frame-options added');
    h.surface.global = { 'x-powered-by': 'Express', 'x-frame-options': 'DENY', server: 'nginx' };
    const r2 = await h.run();
    expect(r2.inc).toMatchObject({ mode: 'full', pairs: { toRun: 6 } });
  });

  it('findings are re-verified every time, so a fix is noticed on the very next scan', async () => {
    h.behaviour.match = (t, i) => t === 'workbench-debug-page' && i === '/api/users';
    await h.run();
    expect((await h.findings()).map((f: any) => f.status)).toEqual(['open']);
    const again = await h.run();
    expect(h.pairs(again.calls)).toEqual(['workbench-debug-page@/api/users']);
    expect(again.doc.counts).toMatchObject({ recurring: 1 });
    h.behaviour.match = () => false;
    const fixed = await h.run();
    expect(h.pairs(fixed.calls)).toEqual(['workbench-debug-page@/api/users']);
    expect(fixed.doc.counts).toMatchObject({ notCurrentlyObserved: 1 });
    expect((await h.findings())[0].status).toBe('not_currently_observed');
    // a fixed finding stays on the re-verification list: its page coming back changes no fingerprint
    expect(h.pairs((await h.run()).calls)).toEqual(['workbench-debug-page@/api/users']);
    h.behaviour.match = (t, i) => t === 'workbench-debug-page' && i === '/api/users';
    const back = await h.run();
    expect(back.doc.counts).toMatchObject({ regressions: 1 });
  });

  it('checks whose requests failed are not cached and run again next time', async () => {
    h.behaviour.errors = (t, i) => t === 'workbench-canary-header' && i === '/api/orders';
    const first = await h.run();
    expect(first.doc.status).toBe('completed');
    expect(first.inc.cache).toMatchObject({ cachedNegatives: 5, skippedForErrors: 1 });
    h.behaviour.errors = () => false;
    expect(h.pairs((await h.run()).calls)).toEqual(['workbench-canary-header@/api/orders']);
  });

  it('without -elog, an invocation with any request error caches no negatives', async () => {
    h = harness({ missingElog: true });
    h.behaviour.requestErrors = 3;
    const first = await h.run();
    expect(first.side.command).not.toContain('-elog');
    expect(first.inc.cache).toMatchObject({ cachedNegatives: 0, skippedForErrors: 6 });
    h.behaviour.requestErrors = 0;
    expect(h.pairs((await h.run()).calls)).toHaveLength(6);
    expect((await h.run()).calls).toEqual([]);
  });

  it('an incomplete invocation caches nothing and keeps earlier clean results', async () => {
    h.behaviour.stderr = '[INF] Skipped 127.0.0.1:4555 from target list as found unresponsive 30 times';
    const r = await h.run();
    expect(r.doc.status).toBe('incomplete');
    expect(r.inc.cache.cachedNegatives).toBe(0);
    h.behaviour.stderr = '';
    await h.run();
    h.behaviour.stderr = '[INF] Skipped 127.0.0.1:4555 from target list as found unresponsive 30 times';
    await h.run({ fullScan: true }); // inconclusive re-run
    h.behaviour.stderr = '';
    expect((await h.run()).calls).toEqual([]);
  });

  it('templates probing other (closed) ports of the host do not make the target scan incomplete', async () => {
    h.behaviour.stderr = '[INF] Skipped 127.0.0.1:9091 from target list as found unresponsive permanently: cause="port closed or filtered" address=127.0.0.1:9091';
    h.behaviour.errors = (t, i) => t === 'workbench-canary-header' && i === '/';
    const r = await h.run();
    expect(r.doc.status, r.side.reason ?? '').toBe('completed');
    expect(r.side.reason).toContain('other ports of this host; nuclei gave up on 127.0.0.1:9091');
    expect(r.inc.cache).toMatchObject({ cachedNegatives: 5, skippedForErrors: 1 }); // the failed probe is not cached
    h.behaviour.stderr = '[INF] Skipped 127.0.0.1:4555 from target list as found unresponsive 30 times\n' + h.behaviour.stderr;
    expect((await h.run({ fullScan: true })).doc.status).toBe('incomplete'); // the target itself still counts
  });

  it('reads coverage from the stderr stream, so a long scan whose tail lost the start is still complete', async () => {
    h.behaviour.tailLost = true;
    const r = await h.run();
    expect(r.doc.status, r.side.reason ?? '').toBe('completed');
    expect(r.side.templatesLoaded).toBe(2);
    expect(r.inc.cache.cachedNegatives).toBe(6);
  });

  it('a page whose structure changes on every request is never served from the cache', async () => {
    let n = 0;
    Object.defineProperty(h.surface.pages, '/api/users', { get: () => ({ body: n++ % 2 ? '<ul><li>a</li></ul>' : '<table></table>' }), enumerable: true, configurable: true });
    await h.run();
    const r = await h.run();
    expect(h.pairs(r.calls)).toEqual(T.map((t) => `${t}@/api/users`));
    expect(r.inc.endpoints.unstable).toEqual(['/api/users']);
  });

  it('expired results run again; a full scan ignores the cache and refreshes it', async () => {
    h = harness({ nuclei: { incremental: { ttlHours: { self: 0, subpath: 0, origin: 0 } } } });
    await h.run();
    expect(h.pairs((await h.run()).calls)).toHaveLength(6);
    h = harness();
    await h.run();
    const full = await h.run({ fullScan: true });
    expect(full.inc).toMatchObject({ mode: 'full', reasons: ['full scan requested: the cache was ignored and refreshed'], pairs: { toRun: 6 } });
    expect((await h.run()).calls).toEqual([]);
  });

  it('with incremental scanning disabled, every scan runs everything and no fingerprints are taken', async () => {
    h = harness({ nuclei: { incremental: { enabled: false } } });
    await h.run();
    const r = await h.run();
    expect(h.pairs(r.calls)).toHaveLength(6);
    expect(r.inc).toBeNull();
    expect(await h.store.col('web_endpoints').find({}).toArray()).toEqual([]);
  });
});
