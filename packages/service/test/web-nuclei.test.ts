// Nuclei web-scan integration: MOCKED tests. The nuclei process is replaced by a fake `exec` and MongoDB by the
// in-memory MemoryStore (test/helpers/memoryStore.ts). Real-tool and real-MongoDB coverage lives in
// web-nuclei.real.test.ts and web-nuclei.integration.test.ts. Fixture provenance: test/fixtures/web/README.md.
import { beforeEach, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ProjectConfigSchema } from '../src/config.js';
import type { Exec, ExecResult, Which } from '../src/security/types.js';
import { buildArgs, checkNuclei, effectiveSettings, flagsInHelp, mapNucleiSeverity, OPTIONAL_FLAGS, parseEngineVersion, parseNucleiJsonl, parseStatsLine, parseTemplatesVersion, PROFILE_TEMPLATES, readStderr, REQUIRED_FLAGS } from '../src/security/web/nuclei.js';
import { authorizeTarget, inScope, isLoopbackHost, normalizeEndpoint, type AuthorizedTarget } from '../src/security/web/target.js';
import { readTemplateMeta, selectTemplates, stageTemplates, vetTemplate } from '../src/security/web/templates.js';
import { redactCurl, redactExtracted, redactHttpDump } from '../src/security/web/redact.js';
import { correlate, routeRegex } from '../src/security/web/correlate.js';
import { graphEndpointPaths, isTechDetection, WebScanService, type SnapshotTargets } from '../src/security/web/service.js';
import type { Graph } from '../src/analyzer/types.js';
import { MemoryStore } from './helpers/memoryStore.js';
import { sleep } from '../src/util.js';

const FX = path.resolve(__dirname, 'fixtures/web');
const TEMPLATES = path.join(FX, 'templates');
const SYNTH = fs.readFileSync(path.join(FX, 'nuclei-output.synthetic.jsonl'), 'utf8');
const nucleiCfg = (n: Record<string, unknown> = {}) => ProjectConfigSchema.parse({ security: { nuclei: { templatesDir: TEMPLATES, templates: ['http'], ...n } } }).security.nuclei;
const policy = { methods: ['GET', 'HEAD', 'OPTIONS'], excludeTags: [], excludeIds: [] };
const res = (p: Partial<ExecResult>): ExecResult => ({ exitCode: 0, signal: null, stdout: '', stdoutBytes: 0, stdoutTruncated: false, stderrTail: '', timedOut: false, cancelled: false, spawnError: null, durationMs: 5, ...p });
const HELP = [...REQUIRED_FLAGS, ...OPTIONAL_FLAGS].map((f) => `   -${f}, -long-${f} string   description`).join('\n');
const target = (authorizeTarget('http://127.0.0.1:4555', []) as { ok: true; target: AuthorizedTarget }).target;

// ------------------------------------------------------------------ readiness

function fakeTool(opts: { installed?: boolean; versionOut?: string; help?: string; tv?: string } = {}) {
  const which: Which = (name, explicit) => (opts.installed === false ? null : explicit ?? `/fake/bin/${name}`);
  const exec: Exec = async (_b, args) => {
    if (args[0] === '-version') return res({ stderrTail: opts.versionOut ?? '[INF] Nuclei Engine Version: v3.11.1\n[INF] Nuclei Config Directory: /x' });
    if (args[0] === '-h') return res({ stdout: opts.help ?? HELP });
    if (args[0] === '-tv') return res({ stderrTail: opts.tv ?? `[INF] Public nuclei-templates version: v10.3.1 (${TEMPLATES})` });
    throw new Error(`unexpected ${args.join(' ')}`);
  };
  return { which, exec };
}

describe('nuclei readiness (mocked process)', () => {
  it('reports a missing executable with setup-relevant reasons', async () => {
    const { which, exec } = fakeTool({ installed: false });
    expect(await checkNuclei(nucleiCfg(), exec, which, os.tmpdir())).toMatchObject({ state: 'not_installed', reason: "'nuclei' was not found on PATH" });
    const explicit = await checkNuclei(nucleiCfg({ binary: '/nope/nuclei' }), exec, () => null, os.tmpdir());
    expect(explicit).toMatchObject({ state: 'not_installed', reason: 'configured path /nope/nuclei is not an executable file' });
  });

  it('detects the version from the log line on stderr and reads templates from -tv', async () => {
    const { which, exec } = fakeTool();
    const r = await checkNuclei(nucleiCfg({ templatesDir: undefined }), exec, which, os.tmpdir());
    expect(r).toMatchObject({ state: 'ready', version: '3.11.1', binary: '/fake/bin/nuclei', missingOptionalFlags: [] });
    expect(r.templates).toMatchObject({ state: 'ready', dir: TEMPLATES, source: 'nuclei', version: '10.3.1' });
  });

  it('is not functional when the version cannot be read or a required flag is missing', async () => {
    let t = fakeTool({ versionOut: 'garbage' });
    expect((await checkNuclei(nucleiCfg(), t.exec, t.which, os.tmpdir())).state).toBe('not_functional');
    t = fakeTool({ help: HELP.replace(/-dr, /, '-xx, ') });
    const r = await checkNuclei(nucleiCfg(), t.exec, t.which, os.tmpdir());
    expect(r).toMatchObject({ state: 'not_functional' });
    expect(r.reason).toContain('-dr');
  });

  it('reports optional flags the installed build lacks and leaves them out of the arguments', async () => {
    const t = fakeTool({ help: HELP.replace(/-rsr, /, '-zzz, ').replace(/-pd, /, '-qq, ') });
    const r = await checkNuclei(nucleiCfg(), t.exec, t.which, os.tmpdir());
    expect(r.missingOptionalFlags).toEqual(['rsr', 'pd']);
    const args = buildArgs(target, '/staged', nucleiCfg(), r.missingOptionalFlags);
    expect(args).not.toContain('-rsr');
    expect(args).not.toContain('-pd=false');
    expect(args).toContain('-cup=false');
  });

  it('reports missing and empty template directories', async () => {
    const t = fakeTool({ tv: '[INF] Public nuclei-templates version:  ()' });
    expect((await checkNuclei(nucleiCfg({ templatesDir: undefined }), t.exec, t.which, os.tmpdir())).templates).toMatchObject({ state: 'missing', reason: 'no template directory configured and nuclei did not report one' });
    expect((await checkNuclei(nucleiCfg({ templatesDir: '/does/not/exist' }), t.exec, t.which, os.tmpdir())).templates).toMatchObject({ state: 'missing' });
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'wb-empty-tpl-'));
    expect((await checkNuclei(nucleiCfg({ templatesDir: empty }), t.exec, t.which, os.tmpdir())).templates).toMatchObject({ state: 'empty' });
  });

  it('parses version strings and help output', () => {
    expect(parseEngineVersion('[INF] Nuclei Engine Version: v3.4.10')).toBe('3.4.10');
    expect(parseTemplatesVersion('[INF] Public nuclei-templates version: v10.2.7 (/home/u/nuclei-templates)')).toEqual({ version: '10.2.7', dir: '/home/u/nuclei-templates' });
    expect(flagsInHelp('   -u, -target string[]\n   -t, -templates string[]\n', ['u', 't', 'ni'])).toEqual(['ni']);
  });

  it('is disabled by configuration without running anything', async () => {
    const r = await checkNuclei(nucleiCfg({ enabled: false }), async () => { throw new Error('must not run'); }, () => '/x', os.tmpdir());
    expect(r.state).toBe('disabled');
  });
});

describe('nuclei arguments', () => {
  it('uses only documented flags with conservative defaults and no template download', () => {
    const args = buildArgs(target, '/staged/templates', nucleiCfg());
    expect(args.slice(0, 4)).toEqual(['-u', 'http://127.0.0.1:4555/', '-t', '/staged/templates']);
    for (const f of ['-jsonl', '-nc', '-duc', '-ni', '-dr', '-ot', '-pd=false', '-cup=false']) expect(args).toContain(f);
    const val = (f: string) => args[args.indexOf(f) + 1];
    expect([val('-rl'), val('-c'), val('-bs'), val('-timeout'), val('-retries'), val('-rsr')]).toEqual(['50', '10', '1', '5', '0', String(1024 * 1024)]);
    expect(args.join(' ')).toContain('-stats -sj -si 1');
    expect(val('-etags')).toContain('intrusive');
    for (const f of ['-ut', '-update-templates', '-code', '-headless', '-dast', '-file', '-fr', '-H', '-lfa']) expect(args).not.toContain(f);
    // every flag passed is in the verified list
    const used = args.filter((a) => a.startsWith('-')).map((a) => a.slice(1).split('=')[0]);
    expect(used.every((f) => [...REQUIRED_FLAGS, ...OPTIONAL_FLAGS].includes(f!))).toBe(true);
  });

  it('uses a slower default rate for non-loopback targets and a target list when given', () => {
    const remote = (authorizeTarget('https://staging.example.com', ['https://staging.example.com']) as any).target;
    const args = buildArgs(remote, '/s', nucleiCfg());
    expect(args[args.indexOf('-rl') + 1]).toBe('10');
    const listed = buildArgs(target, '/s', nucleiCfg(), [], undefined, '/tmp/targets.txt');
    expect(listed.slice(0, 2)).toEqual(['-l', '/tmp/targets.txt']);
    expect(listed).not.toContain('-u');
    expect(buildArgs(target, '/s', nucleiCfg(), ['l'], undefined, '/tmp/targets.txt').slice(0, 2)).toEqual(['-u', 'http://127.0.0.1:4555/']);
  });

  it('resolves profiles and per-profile timeouts', () => {
    expect(effectiveSettings(nucleiCfg({ templates: undefined }), true, 'quick')).toMatchObject({ profile: 'quick', templates: PROFILE_TEMPLATES.quick, rateLimit: 50, timeoutMs: 600_000 });
    expect(effectiveSettings(nucleiCfg({ templates: undefined }), false, 'full')).toMatchObject({ profile: 'full', templates: ['http'], rateLimit: 10, timeoutMs: 3_600_000 });
    expect(effectiveSettings(nucleiCfg({ templates: ['x'], rateLimit: 3 }), true, 'full')).toMatchObject({ profile: 'custom', templates: ['x'], rateLimit: 3 });
  });

  it('follows redirects only on the same host when configured', () => {
    const args = buildArgs(target, '/s', nucleiCfg({ redirects: 'same-host' }));
    expect(args).not.toContain('-dr');
    expect(args.join(' ')).toContain('-fhr -mr 3');
  });
});

// ------------------------------------------------------------------ output parsing + redaction

describe('nuclei JSONL parsing (synthetic output)', () => {
  const out = parseNucleiJsonl(SYNTH, target);
  const canary = out.observations.find((o) => o.templateId === 'workbench-canary-header')!;

  it('keeps template id, name, severity, matched URL, host, tags, evidence and classification', () => {
    expect(canary).toMatchObject({
      name: 'Workbench test canary header', severity: 'medium', originalSeverity: 'medium', tags: ['workbench-test', 'misconfig'], type: 'http',
      host: '127.0.0.1:4555', method: 'GET', endpoint: '/canary?token&x', extractorName: 'canary-version', extractedResults: ['1.2.3'], ip: '127.0.0.1',
      classification: { cve: [], cwe: ['cwe-200'], cvssScore: 5.3, cvssMetrics: 'CVSS:3.1/AV:N' }, references: ['https://example.org/ref'],
    });
    expect(canary.request).toContain('GET /canary');
    expect(canary.response).toContain('X-Workbench-Canary: exposed');
  });

  it('merges duplicate results, counts malformed lines, and drops out-of-scope results', () => {
    expect(canary.occurrences).toBe(2);
    expect(out.observations.map((o) => o.templateId).sort()).toEqual(['exposed-key', 'tech-detect', 'workbench-canary-header']);
    expect(out.malformed).toBe(2); // "{not json" and the event without template-id
    expect(out.outOfScope).toEqual([{ templateId: 'open-redirect-check', matchedAt: 'https://evil.example.com/landing' }]);
    expect(out.lines).toBe(7);
  });

  it('maps severities and keeps the original label', () => {
    expect(out.observations.find((o) => o.templateId === 'exposed-key')).toMatchObject({ severity: 'high', originalSeverity: 'critical' });
    expect(mapNucleiSeverity('INFO')).toBe('info');
    expect(mapNucleiSeverity('weird')).toBe('unknown');
    expect(mapNucleiSeverity(undefined)).toBe('unknown');
  });

  it('redacts credentials, cookies, tokens and found secrets before anything is stored', () => {
    const all = JSON.stringify(out);
    for (const secret of ['abc.def.ghi', 'SECRETSESSION123', 'NEWSECRET999', 'live_key_9f8e7d6c5b4a', 'hunter2', 'token=abc123', 'sk_live_51Habcdefghijklmnop', 'AKIAABCDEFGHIJKLMNOP', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIi']) {
      expect(all, secret).not.toContain(secret);
    }
    expect(canary.request).toContain('Authorization: ***');
    expect(canary.request).toContain('Cookie: ***');
    expect(canary.request).toContain('User-Agent: Mozilla/5.0');
    expect(canary.matchedAt).toBe('http://127.0.0.1:4555/canary?token=***&x=1');
    expect(canary.curlCommand).toContain("-H 'Authorization: ***'");
    expect(canary.curlCommand).toContain("-H 'Accept: */*'");
    expect(out.observations.find((o) => o.templateId === 'exposed-key')!.extractedResults).toEqual(['sk_***(27 chars)', '***aws-key']);
  });

  it('treats empty output as zero results and nuclei error events as tool errors', () => {
    expect(parseNucleiJsonl('', target)).toMatchObject({ observations: [], malformed: 0, lines: 0 });
    const e = parseNucleiJsonl(JSON.stringify({ 'template-id': 't', error: 'context deadline exceeded token=xyz' }), target);
    expect(e.observations).toEqual([]);
    expect(e.toolErrors[0]).toContain('token=***');
  });

  it('redaction helpers keep structure', () => {
    expect(redactHttpDump('POST /login HTTP/1.1\nX-CSRF-Token: abc\nContent-Type: application/json\n\n{"username":"a","password":"b"}'))
      .toBe('POST /login HTTP/1.1\nX-CSRF-Token: ***\nContent-Type: application/json\n\n{"username":"a","password":"b"}'.replace('"password":"b"', '"password":"***"'));
    expect(redactCurl("curl -u admin:pw 'http://h/?api_key=1'")).toBe("curl -u *** 'http://h/?api_key=***'");
    expect(redactExtracted(['nginx/1.25.3'], 'tech-detect tech')).toEqual(['nginx/1.25.3']);
    expect(redactExtracted(['hunter2'], 'exposed-password')).toEqual(['hun***(7 chars)']);
  });

  it('reads coverage facts from nuclei log lines', () => {
    expect(readStderr('[INF] Templates loaded for current scan: 12\n[WRN] Found 1 templates with syntax warning')).toMatchObject({ templatesLoaded: 12, hostSkipped: false, fatal: null, warnings: ['[WRN] Found 1 templates with syntax warning'] });
    expect(readStderr('[INF] Skipped 127.0.0.1:4555 from target list as found unresponsive 30 times').hostSkipped).toBe(true);
    expect(readStderr('[INF] Skipped [::1]:4555 from target list as found unresponsive 30 times\n[INF] Skipped 127.0.0.1:80 from target list as found unresponsive permanently').skippedHosts).toEqual(['::1:4555', '127.0.0.1:80']);
    expect(readStderr('[FTL] Could not run nuclei: no templates provided for scan').fatal).toContain('no templates provided');
    // statistics line exactly as printed by nuclei 3.11.1 with -stats -sj
    const real = '{"duration":"0:00:00","errors":"0","hosts":"2","matched":"2","percent":"100","requests":"4","rps":"14","startedAt":"2026-10-24T18:37:10.657906+05:30","templates":"2","total":"4"}';
    expect(parseStatsLine(real)).toEqual({ requests: 4, total: 4, percent: 100, matched: 2, errors: 0, rps: 14, duration: '0:00:00', hosts: 2, templates: 2 });
    expect(readStderr(`[INF] Current nuclei-templates version: v10.5.1 (unknown)\n[INF] Templates loaded for current scan: 2\n[INF] Targets loaded for current scan: 2\n${real}`)).toMatchObject({ templatesVersion: '10.5.1', targetsLoaded: 2, stats: { requests: 4 } });
    // seen with the real nuclei 3.11.1 under -duc: expected, not a scan error
    expect(readStderr('[ERR] Could not read nuclei-ignore file: open /x/.nuclei-ignore: no such file or directory')).toMatchObject({ errors: [], warnings: [expect.stringContaining('nuclei-ignore')] });
  });
});

// ------------------------------------------------------------------ target authorization

describe('target authorization and scope', () => {
  it('allows loopback targets and refuses everything else unless explicitly authorized', () => {
    for (const u of ['http://127.0.0.1:3000', 'http://localhost:8080/app', 'http://[::1]:3000', 'https://127.1.2.3']) expect(authorizeTarget(u, []).ok, u).toBe(true);
    const r = authorizeTarget('https://example.com', []);
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toContain('authorizedTargets');
    expect(authorizeTarget('http://192.168.1.10:3000', []).ok).toBe(false);
    expect(authorizeTarget('https://staging.example.com/', ['https://staging.example.com']).ok).toBe(true);
    expect(authorizeTarget('https://staging.example.com:8443/', ['https://staging.example.com']).ok).toBe(false); // different origin
  });

  it('rejects credentials, other schemes, unspecified addresses and junk', () => {
    expect(authorizeTarget('http://user:pw@127.0.0.1:3000', [])).toMatchObject({ ok: false });
    expect(authorizeTarget('file:///etc/passwd', [])).toMatchObject({ ok: false });
    expect(authorizeTarget('ftp://127.0.0.1', [])).toMatchObject({ ok: false });
    expect(authorizeTarget('http://0.0.0.0:3000', [])).toMatchObject({ ok: false });
    expect(authorizeTarget('not a url', [])).toMatchObject({ ok: false });
  });

  it('normalizes scope and endpoints', () => {
    const t = (authorizeTarget('http://LOCALHOST:3000/app/#frag', []) as any).target as AuthorizedTarget;
    expect(t).toMatchObject({ origin: 'http://localhost:3000', basePath: '/app/', scopeKey: 'url:http://localhost:3000/app', url: 'http://localhost:3000/app/' });
    expect(inScope('http://localhost:3000/x', t)).toBe(true);
    expect(inScope('http://localhost:3001/x', t)).toBe(false);
    expect(inScope('https://evil.example.com/', t)).toBe(false);
    expect(inScope('localhost:3000', t)).toBe(true);
    expect(normalizeEndpoint('http://h/a//b?z=1&a=2&a=3')).toBe('/a/b?a&z');
    expect(isLoopbackHost('::ffff:127.0.0.1')).toBe(true);
    expect(isLoopbackHost('127.example.com')).toBe(false);
  });
});

// ------------------------------------------------------------------ template vetting

describe('template vetting (content, not just tags)', () => {
  const unsafe = (f: string) => vetTemplate(fs.readFileSync(path.join(FX, 'unsafe', f), 'utf8'), policy);

  it('approves plain GET templates and reads their metadata', () => {
    const v = vetTemplate(fs.readFileSync(path.join(TEMPLATES, 'http/misconfiguration/workbench-canary-header.yaml'), 'utf8'), policy);
    expect(v).toMatchObject({ ok: true, meta: { id: 'workbench-canary-header', severity: 'medium', tags: ['workbench-test', 'misconfig'], methods: ['GET'] } });
  });

  it.each([
    ['oast.yaml', 'out-of-band'], ['post.yaml', 'sends POST'], ['raw-put.yaml', 'sends PUT'], ['bruteforce.yaml', 'payload lists'],
    ['intrusive-tag.yaml', 'tagged "intrusive"'], ['code.yaml', 'code protocol'], ['fuzz.yaml', 'fuzzing'],
  ])('rejects %s (%s)', (file, why) => {
    const v = unsafe(file);
    expect(v.ok).toBe(false);
    expect(v.reason).toContain(why);
  });

  it('allowing POST does not let payload brute force through', () => {
    expect(vetTemplate(fs.readFileSync(path.join(FX, 'unsafe/post.yaml'), 'utf8'), { ...policy, methods: ['GET', 'POST'] }).ok).toBe(true);
    expect(vetTemplate(fs.readFileSync(path.join(FX, 'unsafe/bruteforce.yaml'), 'utf8'), { ...policy, methods: ['GET', 'POST'] }).ok).toBe(false);
  });

  it('reads list-form tags and honours excluded ids and severities', () => {
    expect(readTemplateMeta(fs.readFileSync(path.join(FX, 'unsafe/intrusive-tag.yaml'), 'utf8')).tags).toEqual(['exposure', 'intrusive']);
    const t = fs.readFileSync(path.join(TEMPLATES, 'http/exposures/workbench-debug-page.yaml'), 'utf8');
    expect(vetTemplate(t, { ...policy, excludeIds: ['workbench-debug-page'] }).ok).toBe(false);
    expect(vetTemplate(t, { ...policy, severities: ['high'] }).reason).toContain('severity low');
  });

  it('selects from the local directory only, reports missing paths, and stages only approved templates', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wb-tpl-'));
    fs.cpSync(TEMPLATES, root, { recursive: true });
    fs.cpSync(path.join(FX, 'unsafe'), path.join(root, 'http/unsafe'), { recursive: true });
    const sel = selectTemplates(root, ['http', 'http/does-not-exist', '../../etc'], policy, 100);
    expect(sel.approved.map((a) => a.id).sort()).toEqual(['workbench-canary-header', 'workbench-debug-page']);
    expect(sel.rejected).toHaveLength(7);
    expect(sel.missing).toEqual(['http/does-not-exist', expect.stringMatching(/\.\.\/\.\.\/etc/)]);
    const staged = stageTemplates(sel, path.join(root, '..', `staged-${path.basename(root)}`));
    const copied: string[] = [];
    const walk = (d: string) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) e.isDirectory() ? walk(path.join(d, e.name)) : copied.push(e.name); };
    walk(staged);
    expect(copied.sort()).toEqual(['workbench-canary-header.yaml', 'workbench-debug-page.yaml']);
    expect(selectTemplates(root, ['http'], policy, 100).setHash).toBe(sel.setHash);
    expect(selectTemplates(root, ['http'], policy, 1)).toMatchObject({ truncated: true });
  });
});

// ------------------------------------------------------------------ graph correlation

const G: Graph = {
  provider: 't', stats: { files: 0, parsedFiles: 0, parseErrors: [], unresolvedCalls: 0, unsupportedFiles: 0 },
  nodes: [
    { id: 'ep:GET /api/orders/:id', kind: 'endpoint', label: 'GET /api/orders/:id', meta: { method: 'GET', path: '/api/orders/:id', mountResolved: true } },
    { id: 'ep:GET /api/orders/export', kind: 'endpoint', label: 'GET /api/orders/export', meta: { method: 'GET', path: '/api/orders/export', mountResolved: true } },
    { id: 'ep:GET /api/users/:id', kind: 'endpoint', label: 'GET /api/users/:id', meta: { method: 'GET', path: '/api/users/:id', mountResolved: true } },
    { id: 'ep:GET /api/users/:name', kind: 'endpoint', label: 'GET /api/users/:name', meta: { method: 'GET', path: '/api/users/:name', mountResolved: true } },
    { id: 'fn:src/routes/orders.js#getOrder', kind: 'function', label: 'getOrder', loc: { file: 'src/routes/orders.js', line: 12 }, meta: {} },
  ],
  edges: [{ id: 'e1', source: 'ep:GET /api/orders/:id', target: 'fn:src/routes/orders.js#getOrder', kind: 'route_to_handler', certainty: 'static', confidence: 1, derivation: 'x' }],
};

describe('graph correlation', () => {
  it('links a matched URL to the route and handler only when the graph supports it', () => {
    expect(correlate(G, 'GET', '/api/orders/42')).toMatchObject({ status: 'linked', endpointId: 'ep:GET /api/orders/:id', handlers: ['fn:src/routes/orders.js#getOrder'], handlerLocations: [{ file: 'src/routes/orders.js', line: 12 }] });
    expect(correlate(G, 'GET', '/api/orders/export?format')).toMatchObject({ status: 'linked', endpointId: 'ep:GET /api/orders/export' });
    expect(correlate(G, 'POST', '/api/orders/42').status).toBe('unlinked');
    expect(correlate(G, 'GET', '/js/app.js')).toMatchObject({ status: 'unlinked' });
    expect(correlate(G, 'GET', '/api/users/7')).toMatchObject({ status: 'unlinked', reason: expect.stringContaining('2 routes match') });
    expect(correlate(null, 'GET', '/api/orders/1').status).toBe('unlinked');
    expect(correlate(G, 'GET', '/app/api/orders/1', '/app/').status).toBe('linked');
    expect(routeRegex('/a/(\\d+)')).toBeNull();
  });
});

// ------------------------------------------------------------------ service lifecycle (fake nuclei + in-memory store)

type Behaviour = { stdout?: (url: string) => string; exitCode?: number; stderr?: string; timedOut?: boolean; hang?: boolean; loaded?: number | null; spawnError?: string };

function harness(opts: { installed?: boolean; nuclei?: Record<string, unknown>; reachable?: boolean; downAfterFirstProbe?: boolean; snapshots?: Partial<SnapshotTargets> & { failSide?: 'baseline' | 'candidate' } } = {}) {
  const store = new MemoryStore();
  const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wb-web-'));
  const behaviour: { next: Behaviour; calls: string[][]; lists: string[][] } = { next: {}, calls: [], lists: [] };
  const tool = fakeTool({ installed: opts.installed });
  const exec: Exec = async (bin, args, o) => {
    if (['-version', '-h', '-tv'].includes(args[0]!)) return tool.exec(bin, args, o);
    behaviour.calls.push(args);
    if (args[0] === '-ut') return res({ stderrTail: '[INF] Successfully installed nuclei-templates' });
    const b = behaviour.next;
    const url = args.includes('-l') ? fs.readFileSync(args[args.indexOf('-l') + 1]!, 'utf8').split('\n')[0]!.replace(/\/$/, '') : args[args.indexOf('-u') + 1]!.replace(/\/$/, '');
    behaviour.lists.push(args.includes('-l') ? fs.readFileSync(args[args.indexOf('-l') + 1]!, 'utf8').trim().split('\n') : [url]);
    const staged = args[args.indexOf('-t') + 1]!;
    const count = fs.readdirSync(staged, { recursive: true }).filter((f) => String(f).endsWith('.yaml')).length;
    if (b.hang) {
      await new Promise<void>((r) => { if (o.signal?.aborted) r(); o.signal?.addEventListener('abort', () => r(), { once: true }); });
      return res({ cancelled: true, exitCode: null, signal: 'SIGTERM' });
    }
    const stdout = b.stdout?.(url) ?? '';
    o.onStdout?.(stdout);
    const loaded = b.loaded === undefined ? count : b.loaded;
    return res({ stdout, exitCode: b.exitCode ?? 0, timedOut: !!b.timedOut, spawnError: b.spawnError ?? null, stderrTail: `${loaded === null ? '' : `[INF] Templates loaded for current scan: ${loaded}\n`}${b.stderr ?? ''}` });
  };
  let probes = 0;
  const fetchImpl = (async () => { probes++; if (opts.reachable === false || (opts.downAfterFirstProbe && probes > 1)) throw new Error('connect ECONNREFUSED'); return new Response('ok'); }) as unknown as typeof fetch;
  const started: string[] = [];
  const svc = new WebScanService({
    projectId: 'prj_test', projectDir, store: store as never, cfg: () => nucleiCfg(opts.nuclei), graph: () => G,
    graphVersion: () => 1, sourceHash: () => 'h',
    snapshotReadiness: () => ({ ok: true, reasons: [] }),
    prepareSnapshots: async () => ({
      baseline: { snapshotId: 'snap_base', contentHash: 'b' }, candidate: { snapshotId: 'snap_cur', contentHash: 'c' }, candidateGraph: G, notes: [], isStale: () => false,
      start: async (side) => {
        if (opts.snapshots?.failSide === side) throw Object.assign(new Error('start command exited early with code 1'), { output: 'boom' });
        const port = side === 'baseline' ? 41001 : 41002;
        started.push(side);
        return { url: `http://127.0.0.1:${port}`, port, log: () => `${side} log`, stop: async () => {}, cleanup: () => {} };
      },
      ...opts.snapshots,
    }),
    emit: () => {}, exec, which: tool.which, fetch: fetchImpl,
  });
  const wait = async () => { const end = Date.now() + 5000; while (svc.job && Date.now() < end) await sleep(10); };
  const run = async (b: Behaviour, req: Parameters<WebScanService['start']>[0] = { mode: 'url', url: 'http://127.0.0.1:4555' }) => {
    behaviour.next = b;
    const { runId } = await svc.start(req);
    await wait();
    return store.col('security_scan_runs').findOne({ _id: runId });
  };
  const findings = () => store.col('graph_findings').find({ source: 'web' }).toArray();
  return { svc, store, run, findings, behaviour, started, wait, projectDir };
}

const line = (templateId: string, url: string, p: string, severity = 'medium', extra: Record<string, unknown> = {}) =>
  JSON.stringify({ 'template-id': templateId, info: { name: templateId, severity, tags: ['workbench-test'] }, type: 'http', host: url, 'matched-at': `${url}${p}`, request: `GET ${p} HTTP/1.1\r\nHost: x\r\n\r\n`, 'matcher-status': true, timestamp: '2026-10-24T00:00:00Z', ...extra });
const both = (u: string) => [line('workbench-canary-header', u, '/canary'), line('workbench-debug-page', u, '/debug', 'low')].join('\n');
const canaryOnly = (u: string) => line('workbench-canary-header', u, '/canary');

describe('web scan lifecycle (fake nuclei, in-memory store)', () => {
  let h: ReturnType<typeof harness>;
  beforeEach(() => { h = harness(); });

  it('persists a completed scan, observations and open findings with evidence and run metadata', async () => {
    const run = await h.run({ stdout: both });
    expect(run).toMatchObject({ category: 'web_dast', tool: 'nuclei', mode: 'url', status: 'completed', toolVersion: '3.11.1', target: { origin: 'http://127.0.0.1:4555', scopeKey: 'url:http://127.0.0.1:4555/' } });
    expect(run.templateSet).toMatchObject({ approvedCount: 2, dir: fs.realpathSync(TEMPLATES) });
    expect(run.sides.target).toMatchObject({ status: 'completed', templatesLoaded: 2, findings: 2, bySeverity: { medium: 1, low: 1 } });
    expect(run.counts).toMatchObject({ total: 2, new: 2, recurring: 0 });
    expect(run.durationMs).toBeGreaterThanOrEqual(0);
    expect(run.comparison).toMatchObject({ comparable: false, reasons: ['no earlier completed scan of this target'] });
    const f = await h.findings();
    expect(f.map((x: any) => [x.web.templateId, x.status, x.severity]).sort()).toEqual([['workbench-canary-header', 'open', 'medium'], ['workbench-debug-page', 'open', 'low']]);
    expect(f[0]).toMatchObject({ classification: 'scanner_detected', confidence: 'scanner', web: { correlation: { status: 'unlinked' } }, labels: ['scanner_detected', 'unlinked_web_finding'] });
    expect((await h.store.col('security_observations').find({ runId: run._id }).toArray()).length).toBe(2);
    const report = fs.readFileSync(path.join(h.projectDir, run.sides.target.reportRef), 'utf8');
    expect(report.split('\n')).toHaveLength(2);
    expect(run.sides.target.reportSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(h.behaviour.calls[0]).toContain('-duc');
  });

  it('marks a finding absent only after a completed re-test that ran its template, then flags its return', async () => {
    const first = await h.run({ stdout: both });
    const second = await h.run({ stdout: canaryOnly });
    expect(second.status).toBe('completed');
    expect(second.comparison).toMatchObject({ comparable: true, against: { kind: 'previous_scan', runId: first._id } });
    expect(second.comparison.absent).toHaveLength(1);
    expect(second.comparison.recurring).toHaveLength(1);
    expect(second.counts).toMatchObject({ notCurrentlyObserved: 1, recurring: 1, new: 0 });
    const debug = (await h.findings()).find((x: any) => x.web.templateId === 'workbench-debug-page');
    expect(debug.status).toBe('not_currently_observed');
    const third = await h.run({ stdout: both });
    expect(third.counts).toMatchObject({ regressions: 1 });
    expect(third.comparison.new).toHaveLength(1);
    expect(third.comparison.returned).toEqual([debug._id]);
    const back = (await h.findings()).find((x: any) => x._id === debug._id);
    expect(back).toMatchObject({ status: 'open', potentialRegression: true });
    const recs = await h.store.col('verification_records').find({ findingId: debug._id }).toArray();
    expect(recs.map((r: any) => r.action)).toEqual(['observed', 'not_currently_observed', 'potential_regression']);
  });

  it('a zero-finding completed scan is a real result: counts are 0, earlier findings become not currently observed', async () => {
    await h.run({ stdout: both });
    const r = await h.run({ stdout: () => '' });
    expect(r.status).toBe('completed');
    expect(r.counts).toMatchObject({ total: 0, notCurrentlyObserved: 2 });
    expect(r.sides.target.findings).toBe(0);
  });

  it.each<[string, Behaviour, string, string]>([
    ['nuclei exits non-zero', { stdout: () => '', exitCode: 1, stderr: '[ERR] something broke' }, 'failed', 'exited with code 1'],
    ['nuclei reports a fatal error', { stdout: () => '', stderr: '[FTL] Could not run nuclei: no templates provided for scan' }, 'failed', 'no templates provided'],
    ['nuclei loads no templates', { stdout: () => '', loaded: 0 }, 'failed', 'loaded 0 templates'],
    ['nuclei cannot be spawned', { spawnError: 'EACCES' }, 'failed', 'EACCES'],
  ])('a failed scan (%s) changes no finding', async (_n, b, status, why) => {
    await h.run({ stdout: both });
    const r = await h.run(b);
    expect(r.status).toBe(status);
    expect(r.sides.target.reason).toContain(why);
    expect(r.counts).toBeNull();
    expect((await h.findings()).every((f: any) => f.status === 'open')).toBe(true);
  });

  it.each<[string, Behaviour, string]>([
    ['timed out', { stdout: canaryOnly, timedOut: true, exitCode: null as never }, 'did not finish'],
    ['host skipped as unresponsive', { stdout: canaryOnly, stderr: '[INF] Skipped 127.0.0.1:4555 from target list as found unresponsive 30 times' }, 'unresponsive'],
    ['fewer templates loaded than approved', { stdout: canaryOnly, loaded: 1 }, 'loaded 1 of 2'],
    ['template count not reported', { stdout: canaryOnly, loaded: null }, 'cannot be confirmed'],
  ])('an incomplete scan (%s) records what it saw but never marks findings absent', async (_n, b, why) => {
    await h.run({ stdout: both });
    const r = await h.run(b);
    expect(r.status).toBe('incomplete');
    expect(r.sides.target.reason).toContain(why);
    expect(r.counts).toMatchObject({ notCurrentlyObserved: 0, notRechecked: 1 });
    expect(r.comparison).toMatchObject({ comparable: false, absent: [] });
    expect((await h.findings()).every((f: any) => f.status === 'open')).toBe(true);
  });

  it('says plainly when the application stopped responding (crashed) during the scan', async () => {
    h = harness({ downAfterFirstProbe: true });
    const r = await h.run({ stdout: canaryOnly, stderr: '[INF] Skipped 127.0.0.1:4555 from target list as found unresponsive permanently: connection refused' });
    expect(r.status).toBe('incomplete');
    expect(r.sides.target.reason).toContain('the application stopped responding during the scan');
    expect(r.activity.some((a: any) => a.kind === 'error' && /no longer answers/.test(a.text))).toBe(true);
  });

  it('an unreachable target fails before nuclei runs', async () => {
    h = harness({ reachable: false });
    const r = await h.run({ stdout: both });
    expect(r.status).toBe('failed');
    expect(r.sides.target.reason).toContain('not a clean result');
    expect(h.behaviour.calls).toHaveLength(0);
  });

  it('cancellation stops the scan and records it as cancelled', async () => {
    h.behaviour.next = { hang: true };
    const { runId } = await h.svc.start({ mode: 'url', url: 'http://127.0.0.1:4555' });
    const end = Date.now() + 2000;
    while (!h.behaviour.calls.length && Date.now() < end) await sleep(5);
    expect(h.svc.cancel()).toBe(true);
    await h.wait();
    const r = await h.store.col('security_scan_runs').findOne({ _id: runId });
    expect(r).toMatchObject({ status: 'cancelled', sides: { target: { status: 'cancelled' } } });
    expect(await h.findings()).toEqual([]);
  });

  it('refuses unauthorized targets and concurrent scans', async () => {
    await expect(h.svc.start({ mode: 'url', url: 'https://example.com' })).rejects.toMatchObject({ status: 400 });
    h.behaviour.next = { hang: true };
    await h.svc.start({ mode: 'url', url: 'http://127.0.0.1:4555' });
    await expect(h.svc.start({ mode: 'url', url: 'http://127.0.0.1:4555' })).rejects.toMatchObject({ status: 409 });
    h.svc.cancel();
    await h.wait();
  });

  it('records an unavailable run (with setup steps) when nuclei is not installed, without scanning', async () => {
    h = harness({ installed: false });
    const { status, runId } = await h.svc.start({ mode: 'url', url: 'http://127.0.0.1:4555' });
    expect(status).toBe('unavailable');
    const r = await h.store.col('security_scan_runs').findOne({ _id: runId });
    expect(r).toMatchObject({ status: 'unavailable', error: expect.stringContaining('not installed') });
    expect(r.setup.join(' ')).toContain('never installs');
    expect(h.behaviour.calls).toHaveLength(0);
  });

  it('a changed template set makes scans not comparable', async () => {
    await h.run({ stdout: both });
    (h.svc as any).ctx.cfg = () => nucleiCfg({ excludeIds: ['workbench-debug-page'] });
    const r = await h.run({ stdout: canaryOnly });
    expect(r.comparison.comparable).toBe(false);
    expect(r.comparison.reasons[0]).toContain('template set differs');
    // the debug finding's template did not run, so it is not marked absent
    expect(r.counts).toMatchObject({ notCurrentlyObserved: 0, notRechecked: 1 });
  });

  it('scans the baseline and current snapshots and compares them within the run', async () => {
    h.behaviour.next = { stdout: (u) => (u.includes('41001') ? canaryOnly(u) : [line('workbench-canary-header', u, '/canary'), line('workbench-debug-page', u, '/debug', 'low')].join('\n')) };
    const { runId } = await h.svc.start({ mode: 'snapshots' });
    await h.wait();
    const r = await h.store.col('security_scan_runs').findOne({ _id: runId });
    expect(h.started).toEqual(['baseline', 'candidate']);
    expect(r).toMatchObject({ status: 'completed', mode: 'snapshots', target: { scopeKey: 'snapshots', baselineSnapshotId: 'snap_base', candidateSnapshotId: 'snap_cur' } });
    expect(r.sides.baseline).toMatchObject({ status: 'completed', findings: 1, url: 'http://127.0.0.1:41001/' });
    expect(r.sides.candidate).toMatchObject({ status: 'completed', findings: 2 });
    expect(r.comparison).toMatchObject({ comparable: true, against: { kind: 'baseline_snapshot' } });
    expect(r.comparison.new).toHaveLength(1);
    expect(r.comparison.recurring).toHaveLength(1);
    expect(r.comparison.absent).toHaveLength(0);
    // ephemeral ports do not split identities: the same template+endpoint on both sides is one finding
    const obs = await h.store.col('security_observations').find({ runId }).toArray();
    expect(new Set(obs.map((o: any) => o.findingId)).size).toBe(2);
    expect((await h.findings()).length).toBe(2); // lifecycle comes from the current side only
  });

  it('scans the root URL plus the app\'s own GET routes and records live activity', async () => {
    const r = await h.run({ stdout: both, stderr: '{"duration":"0:00:01","errors":"0","hosts":"2","matched":"2","percent":"100","requests":"8","rps":"8","templates":"2","total":"8"}\n' });
    expect(h.behaviour.lists[0]).toEqual(['http://127.0.0.1:4555/', 'http://127.0.0.1:4555/api/orders/export']);
    expect(r.target.endpoints).toEqual(['/api/orders/export']);
    expect(r.sides.target).toMatchObject({ inputs: ['/', '/api/orders/export'], stats: { requests: 8, percent: 100 } });
    expect(r.sides.target.command).toMatch(/^nuclei -l <targets.txt> -t <vetted-templates> -jsonl/);
    const kinds = r.activity.map((a: any) => a.kind);
    expect(kinds).toEqual(expect.arrayContaining(['phase', 'command', 'match', 'info']));
    expect(r.activity.filter((a: any) => a.kind === 'match').map((a: any) => a.templateId).sort()).toEqual(['workbench-canary-header', 'workbench-debug-page']);
  });

  it('a finding from a route that is no longer scanned is not marked absent, and the comparison says why', async () => {
    const fromRoute = (u: string) => JSON.stringify({ 'template-id': 'workbench-debug-page', info: { name: 'd', severity: 'low' }, host: u, url: `${u}/api/orders/export`, 'matched-at': `${u}/api/orders/export/debug`, request: 'GET /api/orders/export/debug HTTP/1.1\r\n\r\n' });
    await h.run({ stdout: (u) => [canaryOnly(u), fromRoute(u)].join('\n') });
    (h.svc as any).ctx.cfg = () => nucleiCfg({ includeGraphEndpoints: false });
    const r = await h.run({ stdout: canaryOnly });
    expect(r.counts).toMatchObject({ notCurrentlyObserved: 0, notRechecked: 1 });
    expect(r.comparison).toMatchObject({ comparable: false });
    expect(r.comparison.reasons.join(' ')).toContain('route list differs');
  });

  it('lists only parameter-free GET routes and recognises technology fingerprints', () => {
    expect(graphEndpointPaths([G, G], 10)).toEqual(['/api/orders/export']);
    expect(graphEndpointPaths([G], 0)).toEqual([]);
    expect(isTechDetection({ tags: ['tech', 'discovery'], templateId: 'tech-detect', severity: 'info' })).toBe(true);
    expect(isTechDetection({ tags: ['exposure'], templateId: 'git-config', severity: 'medium' })).toBe(false);
  });

  it('updates templates only on request, never during a scan, and reports the outcome', async () => {
    h.behaviour.next = { hang: true };
    await h.svc.start({ mode: 'url', url: 'http://127.0.0.1:4555' });
    await expect(h.svc.updateTemplates()).rejects.toMatchObject({ status: 409 });
    h.svc.cancel();
    await h.wait();
    await h.svc.updateTemplates();
    const end = Date.now() + 2000;
    while (h.svc.templateUpdate?.running && Date.now() < end) await sleep(5);
    expect(h.behaviour.calls.at(-1)?.slice(0, 2)).toEqual(['-ut', '-nc']);
    expect(h.svc.templateUpdate).toMatchObject({ running: false, ok: true });
  });

  it('a baseline that cannot start leaves the current scan usable but the comparison unavailable', async () => {
    h = harness({ snapshots: { failSide: 'baseline' } });
    h.behaviour.next = { stdout: canaryOnly };
    const { runId } = await h.svc.start({ mode: 'snapshots' });
    await h.wait();
    const r = await h.store.col('security_scan_runs').findOne({ _id: runId });
    expect(r.status).toBe('incomplete');
    expect(r.sides.baseline).toMatchObject({ status: 'failed', appLog: 'boom' });
    expect(r.comparison).toMatchObject({ comparable: false, reasons: ['baseline scan failed'] });
  });
});
