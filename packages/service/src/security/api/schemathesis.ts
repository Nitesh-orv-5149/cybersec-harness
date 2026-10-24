// Schemathesis (https://schemathesis.readthedocs.io) adapter: command line and report reading.
// The tool writes two local files that this module reads:
//   run.json      `--report json`    summary: complete, stop_reason, operations tested/errored/skipped, errors
//   events.ndjson `--report ndjson`  event stream; each ScenarioFinished event carries a "recorder" with the
//                                    checks per generated case and the matching request/response.
// The exit code alone is not trusted (1 means failures were found, and also some run problems).
// Report shapes were taken from real Schemathesis 4.32.x runs (see test/fixtures/api).
import type { ProjectConfig } from '../../config.js';
import { mapLabel } from '../deps/severity.js';
import { redact } from '../../util.js';
import type { ScanObservation } from '../scan/types.js';

export type ApiConfig = ProjectConfig['security']['api'];

export const parseSchemathesisVersion = (s: string) => s.match(/version\s+(\d+\.\d+\.\d+\S*)/i)?.[1] ?? null;

export function schemathesisArgs(o: { schema: string; baseUrl: string; cfg: ApiConfig; runJson: string; ndjson: string }): string[] {
  const c = o.cfg;
  const args = [
    'run', o.schema, '--url', o.baseUrl,
    '--checks', c.checks.join(','),
    '--phases', c.phases.join(','),
    '--max-examples', String(c.maxExamples),
    '--request-timeout', String(c.requestTimeoutSec),
    '--workers', String(c.workers),
    '--generation-database', 'none',
    '--report', 'json,ndjson', '--report-json-path', o.runJson, '--report-ndjson-path', o.ndjson,
  ];
  for (const m of c.methods) args.push('--include-method', m);
  if (c.rateLimit) args.push('--rate-limit', c.rateLimit);
  if (c.seed !== undefined) args.push('--seed', String(c.seed));
  for (const [k, v] of Object.entries(c.headers)) args.push('-H', `${k}: ${v}`);
  return args;
}

/** For storage/display: header values removed. */
export function displayArgs(args: string[]): string[] {
  return args.map((a, i) => (args[i - 1] === '-H' ? `${a.split(':')[0]}: [redacted]` : a));
}

export interface RunSummary {
  version: string | null;
  complete: boolean;
  stopReason: string | null;
  operations: { total: number; selected: number; tested: number; errored: number; skipped: number };
  generated: number | null;
  errors: string[];
  phases: Record<string, string>;
  seed: string | null;
}

const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);

export function readRunSummary(text: string): RunSummary | { error: string } {
  let d: any;
  try { d = JSON.parse(text); } catch (e) { return { error: `run report is not valid JSON (${String((e as Error).message).slice(0, 100)})` }; }
  if (!d || typeof d !== 'object' || typeof d.operations !== 'object' || d.operations === null) return { error: 'run report has no "operations" section (unsupported Schemathesis version?)' };
  const phases: Record<string, string> = {};
  for (const [k, v] of Object.entries<any>(d.phases ?? {})) if (v && typeof v.status === 'string') phases[k] = v.status;
  return {
    version: typeof d.schemathesis_version === 'string' ? d.schemathesis_version : null,
    complete: d.complete === true,
    stopReason: typeof d.stop_reason === 'string' ? d.stop_reason : null,
    operations: { total: num(d.operations.total), selected: num(d.operations.selected), tested: num(d.operations.tested), errored: num(d.operations.errored), skipped: num(d.operations.skipped) },
    generated: typeof d.test_cases?.generated === 'number' ? d.test_cases.generated : null,
    errors: Array.isArray(d.errors) ? d.errors.map((e: unknown) => (typeof e === 'string' ? e : JSON.stringify(e)).slice(0, 500)) : [],
    phases,
    seed: d.seed === undefined || d.seed === null ? null : String(d.seed),
  };
}

function decodeBody(content: unknown): string | null {
  if (content === null || content === undefined) return null;
  if (typeof content === 'string') return content;
  if (typeof content === 'object' && typeof (content as any).$base64 === 'string') {
    try { return Buffer.from((content as any).$base64, 'base64').toString('utf8'); } catch { return null; }
  }
  return JSON.stringify(content);
}

const clip = (s: string | null, n = 2000) => (s === null ? null : s.length > n ? `${s.slice(0, n)}… [${s.length - n} more characters]` : s);

export interface EventsResult {
  observations: ScanObservation[];
  testedOperations: string[];
  scenarios: number;
  malformedLines: number;
}

/** Read the NDJSON event stream. One observation per (operation, check, failure code), with the first failing request as evidence. */
export function readEvents(text: string, o: { toolVersion: string | null; headerNames: string[] }): EventsResult {
  const byKey = new Map<string, ScanObservation & { count: number }>();
  const tested = new Set<string>();
  let scenarios = 0;
  let malformed = 0;
  const secretHeaders = new Set(['authorization', 'cookie', 'set-cookie', 'proxy-authorization', ...o.headerNames.map((h) => h.toLowerCase())]);
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    let ev: any;
    try { ev = JSON.parse(line); } catch { malformed++; continue; }
    const fin = ev?.ScenarioFinished;
    const rec = fin?.recorder;
    if (!rec || typeof rec.label !== 'string') continue;
    scenarios++;
    if (fin.status !== 'skip') tested.add(rec.label);
    for (const [caseId, checks] of Object.entries<any>(rec.checks ?? {})) {
      if (!Array.isArray(checks)) continue;
      for (const c of checks) {
        if (!c || c.status !== 'failure') continue;
        const f = c.failure_info?.failure ?? {};
        const operation: string = typeof f.operation === 'string' ? f.operation : rec.label;
        const code: string | null = typeof f.code === 'string' ? f.code : null;
        const key = `api|${operation}|${c.name}|${code ?? ''}`;
        const prev = byKey.get(key);
        if (prev) { prev.count++; (prev.evidence as any).occurrences = prev.count; continue; }
        const inter = rec.interactions?.[caseId];
        const req = inter?.request ?? null;
        const resp = inter?.response ?? null;
        const [method, ...pathParts] = operation.split(' ');
        let requestPath: string | null = null;
        if (req?.uri) { try { const u = new URL(req.uri); requestPath = u.pathname + u.search; } catch { requestPath = String(req.uri); } }
        const reqHeaders = Object.fromEntries(Object.entries<any>(req?.headers ?? {}).map(([k, v]) => [k, secretHeaders.has(k.toLowerCase()) ? '[redacted]' : Array.isArray(v) ? v.join(', ') : String(v)]));
        const respHeaders = Object.fromEntries(Object.entries<any>(resp?.headers ?? {}).filter(([k]) => ['content-type', 'content-length'].includes(k.toLowerCase())).map(([k, v]) => [k, Array.isArray(v) ? v.join(', ') : String(v)]));
        const title = `${f.title ?? c.name} on ${operation}`;
        byKey.set(key, {
          tool: 'schemathesis', toolVersion: o.toolVersion,
          ruleId: code ?? c.name, ruleName: f.title ?? null, title,
          message: f.message ? clip(redact(String(f.message)), 500) : null,
          severity: mapLabel(f.severity), originalSeverity: f.severity ?? null, confidence: null,
          cwe: [], references: code ? ['https://schemathesis.readthedocs.io/en/stable/'] : [],
          location: { operation, method, url: requestPath ?? pathParts.join(' ') },
          evidence: {
            check: c.name, failureCode: code, failureType: f.type ?? null, caseId,
            request: req ? { method: req.method, path: requestPath ? redact(requestPath) : null, headers: reqHeaders, body: clip(redact(decodeBody(req.body) ?? '') || null, 1000) } : null,
            response: resp ? { status: resp.status_code, headers: respHeaders, body: clip(redact(decodeBody(resp.content) ?? '') || null), elapsedSec: resp.elapsed ?? null } : null,
            generation: rec.cases?.[caseId]?.value?.meta?.generation?.mode ?? null,
            phase: fin.phase ?? null,
            occurrences: 1,
          },
          dedupeKey: key, ids: [c.name, ...(code ? [code] : [])], count: 1,
        });
      }
    }
  }
  return { observations: [...byKey.values()].map(({ count: _c, ...rest }) => rest), testedOperations: [...tested].sort(), scenarios, malformedLines: malformed };
}
