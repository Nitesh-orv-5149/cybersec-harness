// OSV.dev API adapter: no binary to install. Package names and versions from the lockfile are sent to
// https://api.osv.dev (querybatch), then each matched advisory record is fetched (GET /v1/vulns/{id}).
// Records are converted with the same parser as OSV-Scanner output, so both tools produce identical observations.
// Gated by security.allowNetwork. Any failed request fails the whole run: partial results are never reported as complete.
import type { DependencyScannerAdapter, DependencyTarget, ApiRunContext, ApiRunResult, ToolOutcome } from '../types.js';
import { parseOsvScanner } from './osvScanner.js';

const BASE = 'https://api.osv.dev';
const BATCH = 1000;
const MAX_PAGES = 10;
const MAX_RECORDS = 1500;
const MAX_BYTES = 16 * 1024 * 1024;
const API_VERSION = 'osv.dev API v1';

class ApiError extends Error {}

async function call(ctx: ApiRunContext, signal: AbortSignal, url: string, init?: RequestInit): Promise<unknown> {
  let res: Response;
  try { res = await ctx.fetch(url, { ...init, signal, headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': 'code-impact-workbench' } }); }
  catch (e) { throw new ApiError(`request to ${new URL(url).host} failed: ${(e as Error).message}`); }
  const text = await res.text();
  if (text.length > MAX_BYTES) throw new ApiError('response exceeded the size limit');
  if (!res.ok) throw new ApiError(`${new URL(url).host} answered HTTP ${res.status}: ${text.slice(0, 160).replace(/\s+/g, ' ')}`);
  try { return JSON.parse(text); } catch { throw new ApiError('response was not valid JSON'); }
}

export async function probeOsvApi(fetchFn: typeof fetch, timeoutMs = 8000): Promise<{ ok: true } | { ok: false; reason: string }> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    await call({ fetch: fetchFn, packages: [], lockVersions: new Map(), signal: undefined, timeoutMs }, ctl.signal, `${BASE}/v1/query`, {
      method: 'POST', body: JSON.stringify({ package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.21' }),
    });
    return { ok: true };
  } catch (e) { return { ok: false, reason: ctl.signal.aborted ? `api.osv.dev did not answer within ${timeoutMs / 1000}s` : (e as Error).message }; }
  finally { clearTimeout(t); }
}

async function run(target: DependencyTarget, ctx: ApiRunContext): Promise<ApiRunResult> {
  const started = Date.now();
  const ctl = new AbortController();
  let timedOut = false;
  let cancelled = false;
  const onAbort = () => { cancelled = true; ctl.abort(); };
  ctx.signal?.addEventListener('abort', onAbort, { once: true });
  const timer = setTimeout(() => { timedOut = true; ctl.abort(); }, ctx.timeoutMs);
  const done = (outcome: ToolOutcome, raw = ''): ApiRunResult => ({ outcome, raw, durationMs: Date.now() - started, timedOut, cancelled });
  try {
    const pkgs = [...new Map(ctx.packages.filter((p) => p.version).map((p) => [`${p.name}@${p.version}`, p])).values()];
    if (!pkgs.length) return done({ status: 'inconclusive', reason: 'no resolvable package versions were found in the lockfile to send', notes: [] });

    // 1. which advisories affect each package@version
    const ids: string[][] = pkgs.map(() => []);
    for (let off = 0; off < pkgs.length; off += BATCH) {
      const slice = pkgs.slice(off, off + BATCH);
      let pending = slice.map((_, i) => ({ i, token: undefined as string | undefined }));
      for (let page = 0; pending.length && page < MAX_PAGES; page++) {
        const body = { queries: pending.map(({ i, token }) => ({ package: { name: slice[i]!.name, ecosystem: 'npm' }, version: slice[i]!.version, ...(token ? { page_token: token } : {}) })) };
        const resp = (await call(ctx, ctl.signal, `${BASE}/v1/querybatch`, { method: 'POST', body: JSON.stringify(body) })) as { results?: { vulns?: { id: string }[]; next_page_token?: string }[] };
        if (!Array.isArray(resp.results) || resp.results.length !== pending.length) throw new ApiError('querybatch returned an unexpected number of results');
        const next: typeof pending = [];
        resp.results.forEach((r, k) => {
          const { i } = pending[k]!;
          for (const v of r.vulns ?? []) ids[off + i]!.push(v.id);
          if (r.next_page_token) next.push({ i, token: r.next_page_token });
        });
        pending = next;
      }
      if (pending.length) throw new ApiError(`advisory list for ${pending.length} package(s) was still paginated after ${MAX_PAGES} pages`);
    }

    // 2. full records for the matched advisory ids
    const unique = [...new Set(ids.flat())];
    if (unique.length > MAX_RECORDS) throw new ApiError(`${unique.length} distinct advisories matched; refusing to fetch more than ${MAX_RECORDS}`);
    const records = new Map<string, any>();
    let cursor = 0;
    await Promise.all(Array.from({ length: Math.min(8, unique.length) }, async () => {
      while (cursor < unique.length) {
        const id = unique[cursor++]!;
        records.set(id, await call(ctx, ctl.signal, `${BASE}/v1/vulns/${encodeURIComponent(id)}`));
      }
    }));

    // 3. same shape as `osv-scanner --format json`, so one parser handles both tools
    const report = {
      results: [{
        source: { path: target.lockfile, type: 'lockfile' },
        packages: pkgs.map((p, k) => ({
          package: { name: p.name, version: p.version, ecosystem: 'npm' },
          vulnerabilities: ids[k]!.map((id) => records.get(id)).filter((r) => r && !r.withdrawn),
        })).filter((p) => p.vulnerabilities.length),
      }],
    };
    const raw = JSON.stringify({ queriedPackages: pkgs.length, ...report });
    const parsed = parseOsvScanner(raw, { lockVersions: ctx.lockVersions, toolVersion: API_VERSION, sourceFile: target.lockfile });
    if (parsed.status !== 'completed') return done(parsed, raw);
    return done({
      status: 'completed',
      observations: parsed.observations.map((o) => ({ ...o, tool: 'osv-api' as const })),
      notes: [`Queried ${pkgs.length} package versions against api.osv.dev.`, ...parsed.notes.filter((n) => !n.startsWith('osv-scanner returned no'))],
    }, raw);
  } catch (e) {
    const reason = timedOut ? `timed out after ${Math.round(ctx.timeoutMs / 1000)}s; partial results discarded` : cancelled ? 'cancelled' : (e instanceof ApiError ? e.message : `unexpected error: ${(e as Error).message}`);
    return done({ status: 'failed', reason, notes: [] });
  } finally {
    clearTimeout(timer);
    ctx.signal?.removeEventListener('abort', onAbort);
  }
}

export const osvApiAdapter: DependencyScannerAdapter = {
  id: 'osv-api',
  displayName: 'OSV.dev (web API)',
  category: 'dependency_vulns',
  kind: 'api',
  outputFormat: 'OSV records from api.osv.dev (querybatch + vulns/{id})',
  executable: '',
  networkHosts: () => ['api.osv.dev'],
  supports: (t) => (t.ecosystem === 'npm' ? { ok: true } : { ok: false, reason: 'this adapter queries the npm ecosystem only' }),
  versionArgs: [],
  parseVersion: () => API_VERSION,
  buildArgs: () => [],
  interpret: () => ({ status: 'failed', reason: 'API adapter has no process output', notes: [] }),
  runApi: run,
  limitations: [
    'Nothing is installed: the service calls the public OSV.dev HTTPS API directly.',
    'Sends package names and versions (no source code) to api.osv.dev.',
    'Matches versions from the lockfile against OSV records; it does not check whether vulnerable code is called.',
    'Severity comes from the record\'s own label (GitHub-reviewed advisories have one); records without a label show as unknown.',
  ],
};
