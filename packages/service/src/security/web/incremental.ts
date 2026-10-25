// Incremental, state-aware nuclei scanning. A scan normally sends every vetted template to every input (the root URL
// plus up to maxGraphEndpoints routes), and nuclei is rate-limited, so its cost is templates × inputs requests.
// This module decides which (input, template) pairs actually need to run.
//
// A clean negative result is cached per pair together with a *context hash*: a hash of everything the template can
// observe, which depends on its reach (templates.ts):
//   self    — scan settings + site infrastructure + the input's own response (status, headers, normalized body) +
//             the code closure of the route that serves it;
//   subpath — scan settings + site infrastructure + the input's structure + its not-found response (status,
//             headers, body) + the code closure of every route at or below it (probes can land on child routes);
//   origin  — scan settings + site infrastructure + site headers + the root's not-found response; run only at '/'.
// A pair is served from the cache only when its entry is a clean negative, for the same template content, with
// the same context hash, and not expired. Everything else runs. Blast radius therefore follows from the hashes:
//   - a new or changed input re-runs everything on that input;
//   - a code change re-runs the routes whose closure contains it (and sub-path templates on their parents);
//   - a change of server / X-Powered-By / Via / CDN / technology markers / the root's catch-all behaviour changes
//     the infrastructure hash, which is part of every context: the whole scope is re-run;
//   - a global header shift changes every input's header signature: self and sub-path templates re-run everywhere.
// Every signal can only add work. Matches are never cached as "done": a pair that matched last time, or that has
// ever produced a finding in this scope (open, not currently observed, or any other status), is always re-run, so
// fixes are noticed on the next scan and so are regressions of fixed findings (a fixed page coming back changes
// nothing the fingerprints can see). Only pairs that have never matched are served from the cache.
import type { Store } from '../../store/mongo.js';
import type { Graph } from '../../analyzer/types.js';
import { GraphIndex } from '../../analyzer/query.js';
import { sha256, shortHash } from '../../util.js';
import type { NucleiConfig } from './nuclei.js';
import type { TemplateReach } from './templates.js';
import { diffSite, type EndpointFingerprint, type ResponseSig, type SiteFingerprint } from './fingerprint.js';

export type IncrementalConfig = NucleiConfig['incremental'];

export interface CacheEntry {
  /** template content hash */ s: string;
  /** context hash the result was obtained under */ c: string;
  r: 'no_match' | 'matched';
  at: Date;
  exp: Date;
  run: string;
}
export type CacheBucket = Record<string, CacheEntry>;

export interface PlanTemplate { id: string; sha: string; reach: TemplateReach }
export interface CodeHashes { self: string | null; subtree: string | null; routes: string[] }
export type Contexts = Partial<Record<TemplateReach, string>>;

export interface StoredEndpoint {
  input: string;
  fingerprint: { self: ResponseSig | null; notFound: ResponseSig | null; stability: string; code: string | null; subtreeCode: string | null } | null;
  removedAt?: Date | null;
}

export type PairReason = 'full' | 'uncacheable' | 'rerun_matched' | 'no_entry' | 'template_changed' | 'context_changed' | 'expired';

export interface ScanPlan {
  mode: 'full' | 'delta';
  reasons: string[];
  groups: { inputs: string[]; templateIds: string[] }[];
  contexts: Map<string, Contexts | null>;
  pairs: { applicable: number; toRun: number; cached: number; scheduled: number; naive: number; byReason: Partial<Record<PairReason, number>> };
  endpoints: { added: string[]; removed: string[]; changed: { input: string; what: string[] }[]; unchanged: number; unstable: string[]; unreachable: string[] };
  site: { infra: string[]; headers: string[] };
}

const H = (parts: unknown[]) => sha256(JSON.stringify(parts)).slice(0, 20);
const sig = (r: ResponseSig) => `${r.status}|${r.contentType}|${r.headerSig}|${r.bodySig}`;
export const SAFE_ID = /^[A-Za-z0-9][\w-]{0,200}$/;

/** Hash of the scan settings that change what a request sends or what nuclei can see in a response. */
export function scanContextHash(engineVersion: string | null, cfg: NucleiConfig): string {
  return H(['ctx/v1', engineVersion, cfg.redirects, [...cfg.methods].sort(), cfg.maxResponseBytes, cfg.requestTimeoutSec, cfg.retries, [...cfg.excludeTags].sort()]);
}

// ------------------------------------------------------------------ code blast radius

/**
 * Per input: a hash over the downstream closure (handlers, callees, middleware, sinks) of the routes serving it
 * ('self') and of every route at or below it ('subtree'). Routes whose mount could not be resolved may live under
 * any input, so they are part of every subtree. Null when the graph has no route for the input.
 */
export function codeHashes(graph: Graph | null, inputs: string[], methods: string[]): Map<string, CodeHashes> {
  const out = new Map<string, CodeHashes>();
  if (!graph) return out;
  const idx = new GraphIndex(graph);
  const allowed = new Set([...methods.map((m) => m.toUpperCase()), 'ALL']);
  const eps = graph.nodes.filter((n) => n.kind === 'endpoint' && allowed.has(String(n.meta.method ?? '').toUpperCase()));
  const pathOf = (p: unknown) => String(p ?? '').replace(/\/+$/, '') || '/';
  const unresolved = eps.filter((n) => n.meta.mountResolved === false);
  const closure = (ids: string[]) => {
    if (!ids.length) return null;
    const nodes = [...idx.downstream(ids).keys()].map((id) => `${id}@${idx.nodes.get(id)?.hash ?? ''}`).sort();
    return H(nodes);
  };
  for (const input of inputs) {
    const resolved = eps.filter((n) => n.meta.mountResolved !== false);
    const own = resolved.filter((n) => pathOf(n.meta.path) === input);
    const under = resolved.filter((n) => { const p = pathOf(n.meta.path); return p === input || p.startsWith(input === '/' ? '/' : `${input}/`); });
    const sub = [...under, ...unresolved];
    out.set(input, { self: closure(own.map((n) => n.id)), subtree: closure(sub.map((n) => n.id)), routes: sub.map((n) => `${String(n.meta.method).toUpperCase()} ${pathOf(n.meta.path)}`).sort() });
  }
  return out;
}

// ------------------------------------------------------------------ context hashes

/** Context hashes per reach for one input; null when nothing about it may be trusted (unreachable or unstable). */
export function contextsFor(scanCtx: string, site: SiteFingerprint | null, fp: EndpointFingerprint | undefined, code: CodeHashes | undefined, root: EndpointFingerprint | undefined): Contexts | null {
  if (!site || !fp?.ok || fp.stability === 'unstable' || !fp.self || !fp.notFound) return null;
  const c: Contexts = {
    self: H(['self', scanCtx, site.infraHash, sig(fp.self), code?.self ?? '-']),
    subpath: H(['subpath', scanCtx, site.infraHash, fp.self.status, fp.self.contentType, fp.self.skeletonSig, sig(fp.notFound), code?.subtree ?? '-']),
  };
  if (fp.input === '/' && root?.ok && root.stability !== 'unstable' && root.notFound) c.origin = H(['origin', scanCtx, site.infraHash, site.headersHash, sig(root.notFound)]);
  return c;
}

/** Deterministic per-template jitter (80–100 % of the TTL) so cached results do not all expire on the same scan. */
export function expiryFor(now: Date, ttlHours: number, templateId: string): Date {
  const frac = parseInt(shortHash(templateId, 8), 16) / 0xffffffff;
  return new Date(now.getTime() + ttlHours * 3600_000 * (0.8 + 0.2 * frac));
}

// ------------------------------------------------------------------ planning

export interface PlanArgs {
  inputs: string[];
  templates: PlanTemplate[];
  fingerprints: Map<string, EndpointFingerprint>;
  site: SiteFingerprint | null;
  prevSite: SiteFingerprint | null;
  prevEndpoints: Map<string, StoredEndpoint>;
  cache: Map<string, CacheBucket>;
  /** templateId -> inputs where it has produced a finding in this scope, whatever its status (always re-verified) */
  knownFindings: Map<string, Set<string>>;
  scanCtx: string;
  code: Map<string, CodeHashes>;
  now: Date;
  /** reason to run everything (forced full scan), or null */
  full: string | null;
  maxGroups: number;
}

/** Below this many extra (input, template) pairs, merging two invocations is cheaper than starting another nuclei. */
export const INVOCATION_OVERHEAD_PAIRS = 150;

export function planScan(a: PlanArgs): ScanPlan {
  const root = a.fingerprints.get('/');
  const contexts = new Map<string, Contexts | null>();
  for (const input of a.inputs) contexts.set(input, contextsFor(a.scanCtx, a.site, a.fingerprints.get(input), a.code.get(input), root));

  const siteDiff = a.site ? diffSite(a.prevSite, a.site) : { infra: [], headers: [] };
  const reasons: string[] = [];
  if (a.full) reasons.push(a.full);
  if (!a.prevSite && !a.full) reasons.push('first incremental scan of this target: nothing is cached yet');
  if (!a.site) reasons.push('the root URL could not be fingerprinted; nothing can be served from the cache');
  if (siteDiff.infra.length) reasons.push(`site-wide change (re-runs everything): ${siteDiff.infra.join('; ')}`);
  if (siteDiff.headers.length) reasons.push(`global header change (re-runs header-dependent checks on every input): ${siteDiff.headers.join('; ')}`);

  const byReason: Partial<Record<PairReason, number>> = {};
  const runSets = new Map<string, string[]>();
  let applicable = 0;
  let cached = 0;
  for (const input of a.inputs) {
    const ctx = contexts.get(input) ?? null;
    const bucket = a.cache.get(input) ?? {};
    const run: string[] = [];
    for (const t of a.templates) {
      if (t.reach === 'origin' && input !== '/') continue; // origin checks send the same requests from every input
      applicable++;
      const c = ctx?.[t.reach];
      const e = bucket[t.id];
      const known = a.knownFindings.get(t.id);
      let why: PairReason | null;
      if (a.full) why = 'full';
      else if (!c || !SAFE_ID.test(t.id)) why = 'uncacheable';
      else if (e?.r === 'matched' || (known && (t.reach === 'origin' ? known.size > 0 : known.has(input)))) why = 'rerun_matched';
      else if (!e) why = 'no_entry';
      else if (e.s !== t.sha) why = 'template_changed';
      else if (e.c !== c) why = 'context_changed';
      else if (new Date(e.exp).getTime() <= a.now.getTime()) why = 'expired';
      else why = null;
      if (why) { run.push(t.id); byReason[why] = (byReason[why] ?? 0) + 1; } else cached++;
    }
    if (run.length) runSets.set(input, run);
  }

  const groups = mergeGroups(runSets, a.maxGroups);
  const scheduled = groups.reduce((n, g) => n + g.inputs.length * g.templateIds.length, 0);
  return {
    mode: a.full || !a.prevSite || siteDiff.infra.length || !a.site ? 'full' : 'delta',
    reasons, groups, contexts,
    pairs: { applicable, toRun: applicable - cached, cached, scheduled, naive: a.inputs.length * a.templates.length, byReason },
    endpoints: diffEndpoints(a),
    site: siteDiff,
  };
}

function diffEndpoints(a: PlanArgs): ScanPlan['endpoints'] {
  const live = new Set(a.inputs);
  const added: string[] = [];
  const changed: { input: string; what: string[] }[] = [];
  const unstable: string[] = [];
  const unreachable: string[] = [];
  let unchanged = 0;
  for (const input of a.inputs) {
    const fp = a.fingerprints.get(input);
    if (!fp?.ok) { unreachable.push(input); continue; }
    if (fp.stability === 'unstable') unstable.push(input);
    const prev = a.prevEndpoints.get(input);
    if (!prev || prev.removedAt || !prev.fingerprint) { added.push(input); continue; }
    const p = prev.fingerprint;
    const code = a.code.get(input);
    const what: string[] = [];
    if (p.self?.status !== fp.self?.status) what.push(`status ${p.self?.status ?? '?'} → ${fp.self?.status ?? '?'}`);
    if (p.self?.headerSig !== fp.self?.headerSig) what.push('response headers');
    if (p.self?.skeletonSig !== fp.self?.skeletonSig) what.push('page structure');
    else if (p.self?.bodySig !== fp.self?.bodySig) what.push('content');
    if (p.notFound && fp.notFound && sig(p.notFound) !== sig(fp.notFound)) what.push('not-found behaviour below it');
    if ((p.code ?? null) !== (code?.self ?? null)) what.push('route code');
    else if ((p.subtreeCode ?? null) !== (code?.subtree ?? null)) what.push('code of routes below it');
    if (what.length) changed.push({ input, what }); else unchanged++;
  }
  const removed = [...a.prevEndpoints.values()].filter((e) => !e.removedAt && !live.has(e.input)).map((e) => e.input).sort();
  return { added, removed, changed, unchanged, unstable, unreachable };
}

/**
 * Turn per-input template lists into nuclei invocations (each runs all its templates against all its inputs).
 * Inputs with identical lists share an invocation; groups are then merged greedily by the fewest extra pairs while
 * there are more than maxGroups, or while a merge costs less than starting another process. Merging only ever adds
 * pairs, never drops one.
 */
export function mergeGroups(runSets: Map<string, string[]>, maxGroups: number): { inputs: string[]; templateIds: string[] }[] {
  const byKey = new Map<string, { inputs: string[]; ids: string[] }>();
  for (const [input, ids] of runSets) {
    const sorted = [...ids].sort();
    const k = sorted.join('\n');
    (byKey.get(k) ?? byKey.set(k, { inputs: [], ids: sorted }).get(k)!).inputs.push(input);
  }
  const universe = [...new Set([...byKey.values()].flatMap((g) => g.ids))].sort();
  const index = new Map(universe.map((id, i) => [id, i]));
  const words = Math.ceil(universe.length / 32) || 1;
  type G = { inputs: string[]; bits: Uint32Array; size: number };
  const popcount = (x: number) => { x -= (x >>> 1) & 0x55555555; x = (x & 0x33333333) + ((x >>> 2) & 0x33333333); return Math.imul((x + (x >>> 4)) & 0x0f0f0f0f, 0x01010101) >>> 24; };
  const groups: G[] = [...byKey.values()].map((g) => {
    const bits = new Uint32Array(words);
    for (const id of g.ids) { const i = index.get(id)!; bits[i >>> 5]! |= 1 << (i & 31); }
    return { inputs: g.inputs, bits, size: g.ids.length };
  });
  const unionSize = (x: G, y: G) => { let n = 0; for (let w = 0; w < words; w++) n += popcount((x.bits[w]! | y.bits[w]!) >>> 0); return n; };
  const extra = (x: G, y: G) => (x.inputs.length + y.inputs.length) * unionSize(x, y) - x.inputs.length * x.size - y.inputs.length * y.size;
  while (groups.length > 1) {
    let best = Infinity;
    let bi = 0;
    let bj = 1;
    for (let i = 0; i < groups.length; i++) for (let j = i + 1; j < groups.length; j++) {
      const e = extra(groups[i]!, groups[j]!);
      if (e < best) { best = e; bi = i; bj = j; }
    }
    if (groups.length <= maxGroups && best > INVOCATION_OVERHEAD_PAIRS) break;
    const x = groups[bi]!;
    const y = groups[bj]!;
    for (let w = 0; w < words; w++) x.bits[w] = (x.bits[w]! | y.bits[w]!) >>> 0;
    x.inputs.push(...y.inputs);
    x.size = 0;
    for (let w = 0; w < words; w++) x.size += popcount(x.bits[w]!);
    groups.splice(bj, 1);
  }
  return groups.map((g) => ({
    inputs: [...g.inputs].sort((p, q) => (p === '/' ? -1 : q === '/' ? 1 : p.localeCompare(q))),
    templateIds: universe.filter((_, i) => (g.bits[i >>> 5]! >>> (i & 31)) & 1),
  }));
}

// ------------------------------------------------------------------ result attribution

/** The scan input a request URL belongs to: the longest input that is the path or a prefix segment of it. */
export function inputOfUrl(url: string, inputs: string[], basePath = '/'): string {
  let p: string;
  try { p = new URL(url).pathname; } catch { p = url.split('?')[0] ?? '/'; }
  const base = basePath.replace(/\/+$/, '');
  if (base && (p === base || p.startsWith(`${base}/`))) p = p.slice(base.length) || '/';
  p = p.replace(/\/{2,}/g, '/');
  let best = '/';
  for (const i of inputs) if (i !== '/' && (p === i || p === `${i}/` || p.startsWith(`${i}/`)) && i.length > best.length) best = i;
  return best;
}

export const pairKey = (templateId: string, input: string) => `${templateId}\u0000${input}`;

// ------------------------------------------------------------------ persistence

export interface LoadedState {
  site: SiteFingerprint | null;
  endpoints: Map<string, StoredEndpoint & { changes?: unknown[]; firstSeenAt?: Date }>;
  cache: Map<string, CacheBucket>;
}

const docId = (projectId: string, scope: string, what: string) => `wst_${shortHash(`${projectId}|${scope}|${what}`, 24)}`;

/** Cache scope: one per URL target; per side in snapshot mode (baseline and current are different applications). */
export function cacheScope(scopeKey: string, side: string): string {
  return scopeKey === 'snapshots' ? `snapshots:${side}` : scopeKey;
}

export async function loadState(store: Store, projectId: string, scope: string): Promise<LoadedState> {
  const ep = store.col('web_endpoints');
  const docs = await ep.find({ projectId, scope }).toArray();
  const endpoints = new Map<string, StoredEndpoint & { changes?: unknown[]; firstSeenAt?: Date }>();
  let site: SiteFingerprint | null = null;
  for (const d of docs) {
    if (d.kind === 'site') site = d.fingerprint as SiteFingerprint;
    else if (d.kind === 'endpoint') endpoints.set(d.input as string, d as never);
  }
  const cache = new Map<string, CacheBucket>();
  for (const b of await store.col('web_scan_cache').find({ projectId, scope }).toArray()) cache.set(b.input as string, (b.entries ?? {}) as CacheBucket);
  return { site, endpoints, cache };
}

/** Every web finding the scope has produced, by template (any status): these pairs are always re-run. */
export async function knownFindingPairs(store: Store, projectId: string, scopeKey: string): Promise<Map<string, Set<string>>> {
  const out = new Map<string, Set<string>>();
  const docs = await store.col('graph_findings').find({ projectId, source: 'web', 'web.scopeKey': scopeKey }).toArray();
  for (const f of docs) {
    const t = f.web?.templateId as string | undefined;
    if (!t) continue;
    (out.get(t) ?? out.set(t, new Set()).get(t)!).add((f.web?.input as string | undefined) ?? '/');
  }
  return out;
}

export interface GroupOutcome {
  inputs: string[];
  templateIds: string[];
  /** nuclei finished this invocation cleanly: exit 0, every template loaded, host never skipped, output complete */
  completed: boolean;
  /** request errors can be attributed per pair (-elog was used) */
  errorsAttributed: boolean;
  /** request errors were reported in total (statistics), null when unknown */
  requestErrors: number | null;
  matched: Set<string>;
  errored: Set<string>;
}

/**
 * Write what this side learned. Negatives are cached only from a completed invocation, and only for pairs without
 * a request error — when errors cannot be attributed, an invocation with any request error caches no negatives.
 * Matches are recorded so that they are re-verified next time. A previous clean entry is never discarded because a
 * re-run was inconclusive: it stays valid for its own context and expiry.
 */
export async function recordResults(store: Store, a: {
  projectId: string; scope: string; runId: string; now: Date; ttl: IncrementalConfig['ttlHours'];
  templates: Map<string, PlanTemplate>; contexts: Map<string, Contexts | null>; groups: GroupOutcome[];
}): Promise<{ cachedNegatives: number; recordedMatches: number; skippedForErrors: number }> {
  const col = store.col('web_scan_cache');
  const maxTtl = Math.max(a.ttl.self, a.ttl.subpath, a.ttl.origin);
  const sets = new Map<string, Record<string, unknown>>();
  let cachedNegatives = 0;
  let recordedMatches = 0;
  let skippedForErrors = 0;
  for (const g of a.groups) {
    const cleanGroup = g.completed && (g.errorsAttributed || g.requestErrors === 0);
    for (const input of g.inputs) {
      const ctx = a.contexts.get(input) ?? null;
      const $set = sets.get(input) ?? sets.set(input, {}).get(input)!;
      for (const tid of g.templateIds) {
        const t = a.templates.get(tid);
        if (!t || !SAFE_ID.test(tid) || (t.reach === 'origin' && input !== '/')) continue;
        const k = pairKey(tid, input);
        const c = ctx?.[t.reach] ?? '';
        if (g.matched.has(k)) {
          $set[`entries.${tid}`] = { s: t.sha, c, r: 'matched', at: a.now, exp: expiryFor(a.now, a.ttl[t.reach], tid), run: a.runId };
          recordedMatches++;
        } else if (!g.completed || !c) continue;
        else if (!cleanGroup || g.errored.has(k)) skippedForErrors++;
        else {
          $set[`entries.${tid}`] = { s: t.sha, c, r: 'no_match', at: a.now, exp: expiryFor(a.now, a.ttl[t.reach], tid), run: a.runId };
          cachedNegatives++;
        }
      }
    }
  }
  for (const [input, $set] of sets) {
    if (!Object.keys($set).length) continue;
    await col.updateOne(
      { _id: docId(a.projectId, a.scope, input) as never },
      { $set: { ...$set, projectId: a.projectId, scope: a.scope, input, updatedAt: a.now, expiresAt: new Date(a.now.getTime() + maxTtl * 3600_000) } },
      { upsert: true },
    );
  }
  return { cachedNegatives, recordedMatches, skippedForErrors };
}

/** Persist the surface: one document per input (fingerprint, code hashes, routes below it, tech) and one for the site. */
export async function recordSurface(store: Store, a: {
  projectId: string; scope: string; runId: string; now: Date; plan: ScanPlan; prev: LoadedState;
  fingerprints: Map<string, EndpointFingerprint>; site: SiteFingerprint | null; code: Map<string, CodeHashes>; observedTech: Map<string, string[]>;
}) {
  const col = store.col('web_endpoints');
  const changedWhat = new Map(a.plan.endpoints.changed.map((c) => [c.input, c.what]));
  const added = new Set(a.plan.endpoints.added);
  for (const [input, fp] of a.fingerprints) {
    if (!fp.ok) continue;
    const prev = a.prev.endpoints.get(input);
    const code = a.code.get(input);
    const what = added.has(input) ? ['added'] : changedWhat.get(input);
    const changes = what ? [{ at: a.now, runId: a.runId, what }, ...((prev?.changes as unknown[] | undefined) ?? [])].slice(0, 20) : (prev?.changes ?? []);
    await col.updateOne({ _id: docId(a.projectId, a.scope, `ep|${input}`) as never }, {
      $set: {
        projectId: a.projectId, scope: a.scope, kind: 'endpoint', input, path: input,
        fingerprint: { self: fp.self, notFound: fp.notFound, stability: fp.stability, code: code?.self ?? null, subtreeCode: code?.subtree ?? null },
        volatileHeaders: fp.volatileHeaders, routesBelow: code?.routes ?? [], headerTech: fp.tech, observedTech: a.observedTech.get(input) ?? (prev as { observedTech?: string[] } | undefined)?.observedTech ?? [],
        lastSeenAt: a.now, lastScannedRunId: a.runId, removedAt: null, changes, ...(what ? { lastChangedAt: a.now } : {}),
      },
      $setOnInsert: { firstSeenAt: a.now },
    }, { upsert: true });
  }
  for (const input of a.plan.endpoints.removed) {
    await col.updateOne({ _id: docId(a.projectId, a.scope, `ep|${input}`) as never }, { $set: { removedAt: a.now, changes: [{ at: a.now, runId: a.runId, what: ['removed'] }, ...((a.prev.endpoints.get(input)?.changes as unknown[] | undefined) ?? [])].slice(0, 20) } });
  }
  if (a.site) {
    const what = [...a.plan.site.infra, ...a.plan.site.headers];
    await col.updateOne({ _id: docId(a.projectId, a.scope, 'site') as never }, {
      $set: { projectId: a.projectId, scope: a.scope, kind: 'site', fingerprint: a.site, lastSeenAt: a.now, lastScannedRunId: a.runId, ...(what.length || !a.prev.site ? { lastChangedAt: a.now } : {}) },
      $setOnInsert: { firstSeenAt: a.now },
    }, { upsert: true });
  }
}
