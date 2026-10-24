// Website comparison → Security changes UI. Components are rendered to static HTML with react-dom/server from
// hand-written API payloads shaped like the service's responses (no browser, no running service).
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { LiveScan, ReadinessBox, SecurityComparison, WebRunDetail } from '../src/views/WebSecurityPanel';
import { CompareView } from '../src/views/CompareView';
import type { Finding } from '../src/api';

const text = (html: string) => html.replace(/<[^>]+>/g, ' ').replace(/&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/\s+/g, ' ');

const readyOv = {
  readiness: { state: 'ready', version: '3.11.1', binary: '/opt/homebrew/bin/nuclei', reason: null, missingOptionalFlags: [], templates: { state: 'ready', dir: '/home/u/nuclei-templates', version: '10.3.1', reason: null } },
  templates: { approved: 412, rejected: 37, missing: [], truncated: false, rejectedByReason: [{ reason: 'uses payload lists (brute force / spraying)', count: 20 }] },
  usable: true, reasons: [], setup: [], configFile: null,
  targets: { snapshots: { ok: true, reasons: [] }, defaultTarget: 'http://127.0.0.1:3000', authorizedTargets: [] },
  settings: { rateLimit: 10, methods: ['GET', 'HEAD', 'OPTIONS'], redirects: 'none', timeoutMs: 600000 },
};

const finding = (id: string, sev: Finding['severity'], status: Finding['status'], linked: boolean, extra: Partial<Finding> = {}): Finding => ({
  _id: id, source: 'web', category: 'web_scanner', classification: 'scanner_detected', severity: sev, title: `${id} title`, explanation: [], nodes: [], edges: [], paths: [],
  locations: [], evidence: {}, suggestedNextStep: '', confidence: 'scanner', limitations: [], status,
  web: {
    scopeKey: 'url:http://127.0.0.1:3000/', mode: 'url', templateId: id, templatePath: null, templateName: null, tags: [], endpoint: '/x', matchedAt: 'http://127.0.0.1:3000/x', host: null, method: 'GET',
    matcherName: null, extractorName: null, originalSeverity: sev, classification: { cve: [], cwe: [], cvssScore: null, cvssMetrics: null },
    correlation: linked
      ? { status: 'linked', endpointId: 'ep:GET /api/orders/:id', handlers: ['fn:src/routes/orders.js#getOrder'], handlerLocations: [{ file: 'src/routes/orders.js', line: 12 }], reason: 'GET /api/orders/7 matches route GET /api/orders/:id.' }
      : { status: 'unlinked', endpointId: null, handlers: [], handlerLocations: [], reason: 'No route in the code graph matches GET /.env.' },
  },
  ...extra,
});
const obs = (fid: string, side: string, sev: string, tpl: string, url: string) => ({
  _id: `nob_${fid}_${side}`, findingId: fid, side, severity: sev, originalSeverity: sev === 'high' ? 'critical' : sev, templateId: tpl, name: `${tpl} name`, matchedAt: url,
  method: 'GET', host: '127.0.0.1:3000', tags: ['exposure'], occurrences: 1, extractedResults: [], classification: { cve: [], cwe: [], cvssScore: null },
  request: 'GET /.env HTTP/1.1\nHost: 127.0.0.1:3000\nCookie: ***', response: null, curlCommand: null, references: [],
});

const side = (p: Record<string, unknown> = {}) => ({ status: 'completed', phase: null, findings: 2, bySeverity: { high: 1, medium: 1 }, exitCode: 0, templatesLoaded: 412, durationMs: 8200, malformedLines: 0, outOfScope: [], toolErrors: [], warnings: [], reason: null, reportRef: 'websec/r/nuclei-target.redacted.jsonl', ...p });
const baseRun = {
  _id: 'web_run2', mode: 'url', status: 'completed', startedAt: new Date().toISOString(), durationMs: 8300, toolVersion: '3.11.1',
  target: { url: 'http://127.0.0.1:3000/', origin: 'http://127.0.0.1:3000', loopback: true }, templateSet: { approvedCount: 412, version: '10.3.1' },
  settings: { rateLimit: 10, methods: ['GET', 'HEAD', 'OPTIONS'], redirects: 'none' }, sides: { target: side() },
  comparison: { comparable: true, reasons: [], against: { kind: 'previous_scan', runId: 'web_run1', startedAt: new Date().toISOString() }, new: ['f_env'], recurring: ['f_ord'], absent: ['f_old'], returned: [] },
};
const findings = [finding('f_env', 'high', 'open', false), finding('f_ord', 'medium', 'open', true), finding('f_old', 'low', 'not_currently_observed', false)];
const observations = [obs('f_env', 'target', 'high', 'exposed-env', 'http://127.0.0.1:3000/.env'), obs('f_ord', 'target', 'medium', 'cors-misconfig', 'http://127.0.0.1:3000/api/orders/7')];

describe('readiness', () => {
  it('shows version, template directory and the vetted template set', () => {
    const t = text(renderToStaticMarkup(<ReadinessBox ov={readyOv} />));
    expect(t).toContain('v3.11.1');
    expect(t).toContain('/home/u/nuclei-templates');
    expect(t).toContain('412 approved · 37 excluded');
    expect(t).toContain('20 × uses payload lists');
  });

  it('explains why scanning is unavailable and how to set it up', () => {
    const ov = { ...readyOv, usable: false, templates: null, reasons: ["'nuclei' was not found on PATH"], setup: ['Install nuclei yourself (the workbench never installs it)'],
      readiness: { ...readyOv.readiness, state: 'not_installed', version: null, binary: null, reason: "'nuclei' was not found on PATH", templates: { state: 'unknown', reason: 'nuclei is not usable' } } };
    const t = text(renderToStaticMarkup(<ReadinessBox ov={ov} />));
    expect(t).toContain('Security scanning is unavailable');
    expect(t).toContain('not installed');
    expect(t).toContain('never installs');
  });
});

describe('scan results', () => {
  it('shows status, severity totals, the security comparison and a findings table with code links', () => {
    const t = text(renderToStaticMarkup(<WebRunDetail run={baseRun} observations={observations} findings={findings} projectId="p" />));
    expect(t).toContain('Completed');
    expect(t).toContain('nuclei 3.11.1');
    expect(t).toMatch(/1 New .*f_env title/);
    expect(t).toMatch(/1 Still present .*f_ord title/);
    expect(t).toMatch(/1 No longer observed .*f_old title/);
    expect(t).toContain('exposed-env');
    expect(t).toContain('http://127.0.0.1:3000/.env');
    expect(t).toContain('unlinked web finding');
    expect(t).toContain('GET /api/orders/:id');
    expect(t).toContain('severity not supplied');
    expect(t).toContain('A visual difference is not a vulnerability');
  });

  it('never shows "no longer observed" when the comparison is not valid', () => {
    const run = { ...baseRun, status: 'incomplete', sides: { target: side({ status: 'incomplete', reason: 'nuclei loaded 300 of 412 approved templates' }) },
      comparison: { ...baseRun.comparison, comparable: false, reasons: ['this scan is incomplete'], new: [], recurring: [], absent: [] } };
    const t = text(renderToStaticMarkup(<WebRunDetail run={run} observations={observations} findings={findings} projectId="p" />));
    expect(t).toContain('Incomplete');
    expect(t).toContain('Not a valid comparison: this scan is incomplete');
    expect(t).toContain('loaded 300 of 412');
    expect(t).not.toContain('No longer observed');
    expect(t).toContain('Returned (potential regression)');
  });

  it('a failed scan says it has no result rather than zero findings', () => {
    const run = { ...baseRun, status: 'failed', comparison: { ...baseRun.comparison, comparable: false, reasons: ['this scan is failed'], new: [], recurring: [], absent: [] },
      sides: { target: side({ status: 'failed', findings: null, bySeverity: null, reason: 'target did not answer before the scan (ECONNREFUSED). Nothing was scanned; this is not a clean result.' }) } };
    const t = text(renderToStaticMarkup(<WebRunDetail run={run} observations={[]} findings={[]} projectId="p" />));
    expect(t).toContain('Failed');
    expect(t).toContain('not a clean result');
    expect(t).toContain('That is not the same as no findings');
    expect(t).toContain('No severity totals');
  });

  it('shows live progress for each side of a running baseline-vs-current scan', () => {
    const run = { ...baseRun, _id: 'web_live', mode: 'snapshots', status: 'running', comparison: null, target: { baselineSnapshotId: 'snap_aaaaaaaaaaaa', candidateSnapshotId: 'snap_bbbbbbbbbbbb' },
      sides: { baseline: side({ findings: 1 }), candidate: side({ status: 'scanning', phase: 'running 412 templates', findings: null }) } };
    const t = text(renderToStaticMarkup(<WebRunDetail run={run} observations={[]} findings={[]} projectId="p" job={{ runId: 'web_live', findingsSoFar: 3 }} />));
    expect(t).toContain('Running');
    expect(t).toContain('Baseline app: completed');
    expect(t).toContain('Current app: scanning · running 412 templates · 3 results so far');
  });

  it('finding details show template id, matched URL, redacted evidence, the code link and scan history', () => {
    const t = text(renderToStaticMarkup(
      <WebRunDetail run={baseRun} observations={observations} findings={findings} projectId="p" selected="f_ord"
        history={[{ _id: 'v1', at: new Date().toISOString(), action: 'observed', securityRunId: 'web_run1', result: 'nuclei cors-misconfig' }]} />,
    ));
    expect(t).toContain('Template ID cors-misconfig');
    expect(t).toContain('GET http://127.0.0.1:3000/api/orders/7');
    expect(t).toContain('Cookie: ***');
    expect(t).toContain('src/routes/orders.js:12');
    expect(t).toContain('not proof that it is exploitable');
    expect(t).toContain('Scan history');
    expect(t).toContain('web_run1');
  });

  it('labels the snapshot comparison basis', () => {
    const t = text(renderToStaticMarkup(<SecurityComparison run={{ ...baseRun, mode: 'snapshots' }} byId={new Map(findings.map((f) => [f._id, f]))} />));
    expect(t).toContain('Compared with the baseline snapshot, scanned in the same run');
  });
});

describe('live scan and how the website was scanned', () => {
  it('shows nuclei progress and what it is doing right now', () => {
    const job = {
      runId: 'r', side: 'target', phase: 'running 4120 templates against 3 URL(s) at 50 req/s', profile: 'standard', startedAt: new Date().toISOString(), findingsSoFar: 2,
      progress: { requests: 5120, total: 12360, percent: 41, matched: 2, errors: 3, rps: 48, duration: '0:01:47', hosts: 3, templates: 4120 },
      activity: [
        { at: new Date().toISOString(), kind: 'command', text: 'nuclei -l <targets.txt> -t <vetted-templates> -jsonl -nc -duc -ni' },
        { at: new Date().toISOString(), kind: 'match', severity: 'medium', templateId: 'git-config', text: 'git-config matched http://127.0.0.1:3000/.git/config' },
      ],
    };
    const t = text(renderToStaticMarkup(<LiveScan job={job} />));
    expect(t).toContain('41%');
    expect(t).toContain('5,120 / 12,360 requests');
    expect(t).toContain('4120 templates × 3 URLs');
    expect(t).toContain('2 matched');
    expect(t).toContain('$ nuclei -l <targets.txt>');
    expect(t).toContain('git-config matched http://127.0.0.1:3000/.git/config');
  });

  it('lists technologies separately from vulnerabilities and shows the scanned URLs and command', () => {
    const tech = { ...obs('f_tech', 'target', 'info', 'tech-detect', 'http://127.0.0.1:3000/'), tags: ['tech', 'discovery'], matcherName: 'express', endpoint: '/' };
    const run = { ...baseRun, profile: 'standard', target: { ...baseRun.target, endpoints: ['/api/orders', '/api/users'] },
      sides: { target: side({ inputs: ['/', '/api/orders', '/api/users'], command: 'nuclei -l <targets.txt> -t <vetted-templates> -jsonl', stats: { requests: 9000, errors: 2, rps: 49, duration: '0:03:04' } }) } };
    const t = text(renderToStaticMarkup(<WebRunDetail run={run} observations={[...observations, tech]} findings={findings} projectId="p" />));
    expect(t).toContain('Vulnerabilities and misconfigurations (2)');
    expect(t).toMatch(/Detected technologies \(1\) .*express/);
    expect(t).toContain('/ /api/orders /api/users');
    expect(t).toContain('nuclei -l <targets.txt>');
    expect(t).toContain('9,000 sent · 2 errors');
    expect(t).toContain('standard profile');
  });
});

describe('Website comparison', () => {
  it('shows website changes and security changes side by side', () => {
    const status = {
      baseline: null, config: { run: null, runApproved: false }, verification: { ok: false, reasons: ['no baseline snapshot yet'] },
      browser: { job: null, queued: false }, store: { available: true }, security: { web: { job: null } },
    };
    const ctx = { projectId: 'p', status, graph: null, ticks: {}, selection: { nodeId: null, path: null }, select: () => {}, refreshStatus: () => {} };
    const html = renderToStaticMarkup(<CompareView ctx={ctx as never} />);
    const t = text(html);
    expect(html).toContain('class="compare-grid"');
    expect((html.match(/class="compare-col"/g) ?? []).length).toBe(2);
    expect(t).toContain('Website changes visual, DOM and behaviour');
    expect(t).toContain('Security changes vulnerability scan of the running website');
    expect(t).toContain('Checking nuclei');
    expect(t).toContain('Mark current files as baseline');
    expect(t).toContain('Compare current files with baseline');
  });
});
