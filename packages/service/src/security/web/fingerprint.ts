// Change detection for incremental nuclei scans. Before nuclei runs, every scan input (the root URL and each graph
// route) is fetched twice, and so is a sub-path under it that cannot exist (the "not found" canary). The results
// are reduced to signatures that ignore per-request noise:
//  - status code;
//  - header signature: names of all headers, values only for headers that are not inherently volatile and that
//    were identical on both fetches (Set-Cookie: cookie names and attributes, never values);
//  - body signature: the body after normalizing timestamps, dates, UUIDs, long hex/base64 tokens, CSP/script
//    nonces, CSRF form values, the target origin (ephemeral ports) and the canary token;
//  - skeleton signature: structure only (HTML: tag and attribute names; JSON: key paths and value types).
// Stability decides what may be trusted: 'stable' (normalized bodies equal), 'volatile' (only the skeleton is
// equal; the skeleton stands in for the body), or 'unstable' (not even the skeleton repeats, or the status
// differs). Nothing for an unstable or unreachable input is ever served from the cache.
//
// The site fingerprint (from the root response) separates infrastructure (server, X-Powered-By, Via, CDN and
// technology markers) from global security headers and cookie attributes; any infrastructure change invalidates
// the whole scope.
import crypto from 'node:crypto';
import { sha256 } from '../../util.js';

export interface ResponseSig {
  status: number;
  contentType: string | null;
  headerSig: string;
  bodySig: string;
  skeletonSig: string;
}

export type Stability = 'stable' | 'volatile' | 'unstable';

export interface EndpointFingerprint {
  input: string;
  ok: boolean;
  error: string | null;
  stability: Stability;
  /** the input's own response; bodySig is the skeleton when the body is volatile */
  self: ResponseSig | null;
  /** response to `${input}/<random>` — what most sub-path templates actually hit */
  notFound: ResponseSig | null;
  /** headers whose values differed between the two fetches (recorded as names only) */
  volatileHeaders: string[];
  tech: string[];
}

export interface SiteFingerprint {
  infra: { server: string | null; poweredBy: string | null; via: string | null; cdn: string[]; tech: string[] };
  headers: Record<string, string>;
  cookies: string[];
  infraHash: string;
  headersHash: string;
}

const h = (s: string) => sha256(s).slice(0, 16);

/** Header values that change per response by nature; only their presence is part of the signature. */
const VOLATILE_HEADERS = new Set([
  'date', 'age', 'expires', 'last-modified', 'etag', 'content-length', 'x-request-id', 'x-correlation-id', 'x-trace-id', 'traceparent',
  'x-amzn-requestid', 'x-amz-cf-id', 'x-amz-cf-pop', 'cf-ray', 'x-runtime', 'server-timing', 'x-response-time', 'report-to', 'nel',
  'x-cache', 'x-cache-hits', 'x-served-by', 'x-timer', 'keep-alive', 'connection', 'transfer-encoding', 'x-vercel-id',
]);
/** Headers that describe site-wide policy; a change in any of them is a global header shift. */
export const SITE_HEADERS = [
  'strict-transport-security', 'content-security-policy', 'content-security-policy-report-only', 'x-frame-options', 'x-content-type-options',
  'referrer-policy', 'permissions-policy', 'cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy',
  'access-control-allow-origin', 'access-control-allow-credentials', 'x-xss-protection',
];
const CDN_MARKERS: [string, RegExp][] = [
  ['cloudflare', /^cf-ray$/], ['cloudfront', /^x-amz-cf-id$/], ['fastly', /^x-served-by$|^fastly-/], ['akamai', /^x-akamai-/],
  ['vercel', /^x-vercel-id$/], ['netlify', /^x-nf-request-id$/], ['varnish', /^x-varnish$/],
];
const COOKIE_TECH: [string, RegExp][] = [
  ['express-session', /^connect\.sid$/], ['php', /^PHPSESSID$/], ['java', /^JSESSIONID$/], ['asp.net', /^ASP\.NET_SessionId$|^\.AspNetCore\./],
  ['laravel', /^laravel_session$/], ['django', /^csrftoken$|^sessionid$/], ['rails', /^_session_id$|_rails_session$/],
];

const DYNAMIC: [RegExp, string][] = [
  [/\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?/g, '<ts>'],
  [/\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{1,2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT\b/g, '<date>'],
  [/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '<uuid>'],
  [/\bnonce=(["'])[^"']*\1/gi, 'nonce="<nonce>"'],
  [/'nonce-[^']+'/g, "'nonce-<nonce>'"],
  [/(<input\b[^>]*\bname=["'][^"']*(?:csrf|xsrf|authenticity_token|verificationtoken|_token)[^"']*["'][^>]*\bvalue=["'])[^"']*/gi, '$1<csrf>'],
  [/(<input\b[^>]*\bvalue=["'])[^"']*(["'][^>]*\bname=["'][^"']*(?:csrf|xsrf|authenticity_token|verificationtoken|_token)[^"']*["'])/gi, '$1<csrf>$2'],
  [/(<meta\b[^>]*\bname=["']csrf[-_]token["'][^>]*\bcontent=["'])[^"']*/gi, '$1<csrf>'],
  [/\b1\d{9}(?:\d{3})?\b/g, '<epoch>'],
  [/\b[0-9a-f]{16,}\b/gi, '<hex>'],
  [/[A-Za-z0-9+_-]{32,}={0,2}/g, '<token>'],
];

export function normalizeBody(body: string, opts: { origin?: string; canary?: string } = {}): string {
  let s = body;
  if (opts.origin) s = s.split(opts.origin).join('<origin>');
  if (opts.canary) s = s.split(opts.canary).join('<canary>');
  for (const [re, rep] of DYNAMIC) s = s.replace(re, rep);
  return s.replace(/\s+/g, ' ').trim();
}

const normValue = (v: string) => v.replace(/'nonce-[^']+'/g, "'nonce-<nonce>'").replace(/\s+/g, ' ').trim();

/** Set-Cookie → "name; attr; attr" with the value removed (attributes such as HttpOnly/Secure/SameSite matter). */
export function cookieShape(setCookie: string): string {
  const [pair, ...attrs] = setCookie.split(';');
  const name = (pair ?? '').split('=')[0]!.trim();
  const keep = attrs.map((a) => a.trim()).filter(Boolean).map((a) => {
    const [k, v] = a.split('=');
    const key = k!.trim().toLowerCase();
    return ['expires', 'max-age'].includes(key) ? key : v === undefined ? key : `${key}=${v.trim().toLowerCase()}`;
  }).sort();
  return [name, ...keep].join('; ');
}

/** Structure only. HTML: tag + sorted attribute names in document order. JSON: sorted key paths with value types. */
export function skeletonOf(body: string, contentType: string | null): string {
  const t = body.trimStart();
  if (/json/i.test(contentType ?? '') || /^[[{]/.test(t)) {
    try { return [...jsonShape(JSON.parse(t), '$', new Set<string>(), 0)].sort().join('\n'); } catch { /* not JSON */ }
  }
  if (/html|xml/i.test(contentType ?? '') || t.startsWith('<')) {
    const out: string[] = [];
    for (const m of body.matchAll(/<\s*(\/?)([a-zA-Z][\w:-]*)([^>]*)>/g)) {
      if (out.length >= 20_000) break;
      const attrs = [...m[3]!.matchAll(/([a-zA-Z_:][\w:.-]*)\s*(?==|\s|\/?$)/g)].map((a) => a[1]!.toLowerCase()).sort();
      out.push(`${m[1]}${m[2]!.toLowerCase()}${attrs.length ? `[${attrs.join(',')}]` : ''}`);
    }
    return out.join(' ');
  }
  return normalizeBody(body);
}

function jsonShape(v: unknown, p: string, out: Set<string>, depth: number): Set<string> {
  if (depth > 12 || out.size > 5000) return out;
  if (Array.isArray(v)) { out.add(`${p}:array`); for (const x of v.slice(0, 20)) jsonShape(x, `${p}[]`, out, depth + 1); }
  else if (v && typeof v === 'object') { out.add(`${p}:object`); for (const [k, x] of Object.entries(v)) jsonShape(x, `${p}.${k}`, out, depth + 1); }
  else out.add(`${p}:${v === null ? 'null' : typeof v}`);
  return out;
}

export interface RawResponse { status: number; headers: [string, string][]; body: string }

/** Header signature over two fetches of the same URL: values that differ between them count as names only. */
export function headerSignature(a: RawResponse, b: RawResponse | null): { sig: string; volatile: string[] } {
  const group = (r: RawResponse) => {
    const m = new Map<string, string[]>();
    for (const [k, v] of r.headers) { const key = k.toLowerCase(); (m.get(key) ?? m.set(key, []).get(key)!).push(key === 'set-cookie' ? cookieShape(v) : normValue(v)); }
    for (const v of m.values()) v.sort();
    return m;
  };
  const ga = group(a);
  const gb = b ? group(b) : ga;
  const volatile: string[] = [];
  const parts: string[] = [];
  for (const name of [...new Set([...ga.keys(), ...gb.keys()])].sort()) {
    const va = (ga.get(name) ?? []).join('\n');
    const vb = (gb.get(name) ?? []).join('\n');
    if (VOLATILE_HEADERS.has(name)) { parts.push(name); continue; }
    if (va !== vb) { volatile.push(name); parts.push(name); continue; }
    parts.push(`${name}: ${va}`);
  }
  return { sig: h(parts.join('\n')), volatile };
}

function contentTypeOf(r: RawResponse): string | null {
  return r.headers.find(([k]) => k.toLowerCase() === 'content-type')?.[1]?.split(';')[0]!.trim().toLowerCase() ?? null;
}

/** Signatures from two fetches. Returns the stability verdict and the signature that may be trusted. */
export function compareFetches(a: RawResponse, b: RawResponse, opts: { origin?: string; canaries?: [string, string] }): { sig: ResponseSig; stability: Stability; volatileHeaders: string[] } {
  const ct = contentTypeOf(a);
  const bodyA = normalizeBody(a.body, { origin: opts.origin, canary: opts.canaries?.[0] });
  const bodyB = normalizeBody(b.body, { origin: opts.origin, canary: opts.canaries?.[1] });
  const skA = h(skeletonOf(opts.canaries ? a.body.split(opts.canaries[0]).join('<canary>') : a.body, ct));
  const skB = h(skeletonOf(opts.canaries ? b.body.split(opts.canaries[1]).join('<canary>') : b.body, contentTypeOf(b)));
  const hs = headerSignature(a, b);
  let stability: Stability;
  if (a.status !== b.status || ct !== contentTypeOf(b)) stability = 'unstable';
  else if (bodyA === bodyB) stability = 'stable';
  else if (skA === skB) stability = 'volatile';
  else stability = 'unstable';
  const bodySig = stability === 'stable' ? h(bodyA) : `skel:${skA}`;
  return { sig: { status: a.status, contentType: ct, headerSig: hs.sig, bodySig, skeletonSig: skA }, stability, volatileHeaders: hs.volatile };
}

function techOf(r: RawResponse): string[] {
  const t = new Set<string>();
  for (const [k, v] of r.headers) {
    const key = k.toLowerCase();
    if (key === 'x-powered-by') t.add(v.trim().toLowerCase());
    if (key === 'server') t.add(v.trim().toLowerCase().split(/[\s/]/)[0]!);
    if (key === 'set-cookie') { const name = v.split('=')[0]!.trim(); for (const [tech, re] of COOKIE_TECH) if (re.test(name)) t.add(tech); }
  }
  return [...t].filter(Boolean).sort();
}

export function siteFingerprint(root: RawResponse, rootNotFound: ResponseSig | null): SiteFingerprint {
  const hdr = (n: string) => root.headers.find(([k]) => k.toLowerCase() === n)?.[1]?.trim() ?? null;
  const names = root.headers.map(([k]) => k.toLowerCase());
  const cdn = CDN_MARKERS.filter(([, re]) => names.some((n) => re.test(n))).map(([c]) => c).sort();
  const infra = { server: hdr('server'), poweredBy: hdr('x-powered-by'), via: hdr('via'), cdn, tech: techOf(root) };
  const headers: Record<string, string> = {};
  for (const n of SITE_HEADERS) { const v = hdr(n); if (v !== null) headers[n] = normValue(v); }
  const cookies = root.headers.filter(([k]) => k.toLowerCase() === 'set-cookie').map(([, v]) => cookieShape(v)).sort();
  // The root's not-found behaviour (catch-all SPA vs. plain 404) decides what most probes see: infrastructure.
  const nf = rootNotFound ? `${rootNotFound.status}|${rootNotFound.contentType}|${rootNotFound.bodySig}` : 'unknown';
  return { infra, headers, cookies, infraHash: h(JSON.stringify([infra, nf])), headersHash: h(JSON.stringify([headers, cookies])) };
}

/** Human-readable differences between two site fingerprints (empty when equal). */
export function diffSite(prev: SiteFingerprint | null, cur: SiteFingerprint): { infra: string[]; headers: string[] } {
  if (!prev) return { infra: [], headers: [] };
  const infra: string[] = [];
  const headers: string[] = [];
  for (const k of ['server', 'poweredBy', 'via'] as const) if (prev.infra[k] !== cur.infra[k]) infra.push(`${k}: ${prev.infra[k] ?? '(none)'} → ${cur.infra[k] ?? '(none)'}`);
  if (prev.infra.cdn.join() !== cur.infra.cdn.join()) infra.push(`CDN: ${prev.infra.cdn.join(', ') || '(none)'} → ${cur.infra.cdn.join(', ') || '(none)'}`);
  if (prev.infra.tech.join() !== cur.infra.tech.join()) infra.push(`technology: ${prev.infra.tech.join(', ') || '(none)'} → ${cur.infra.tech.join(', ') || '(none)'}`);
  if (!infra.length && prev.infraHash !== cur.infraHash) infra.push('the root URL answers unknown paths differently (not-found / catch-all behaviour changed)');
  for (const n of new Set([...Object.keys(prev.headers), ...Object.keys(cur.headers)])) if (prev.headers[n] !== cur.headers[n]) headers.push(`${n} ${prev.headers[n] === undefined ? 'added' : cur.headers[n] === undefined ? 'removed' : 'changed'}`);
  if (prev.cookies.join('\n') !== cur.cookies.join('\n')) headers.push('cookie names or attributes changed');
  return { infra, headers };
}

export interface FetchOptions { fetchImpl: typeof fetch; timeoutMs: number; maxBytes: number; throttle?: () => Promise<void> }

/** Spaces request starts at least 1000/rate ms apart across all callers (the scan's own requests-per-second budget). */
export function throttle(ratePerSecond: number): () => Promise<void> {
  const gap = 1000 / Math.max(1, ratePerSecond);
  let nextAt = 0;
  return async () => {
    const now = Date.now();
    const at = Math.max(now, nextAt);
    nextAt = at + gap;
    if (at > now) await new Promise((r) => setTimeout(r, at - now));
  };
}

export async function fetchRaw(url: string, o: FetchOptions): Promise<RawResponse> {
  await o.throttle?.();
  const res = await o.fetchImpl(url, { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(o.timeoutMs) });
  const headers: [string, string][] = [];
  res.headers.forEach((v, k) => { if (k.toLowerCase() !== 'set-cookie') headers.push([k, v]); });
  for (const c of res.headers.getSetCookie?.() ?? []) headers.push(['set-cookie', c]);
  let body = '';
  if (res.body) {
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let bytes = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      body += dec.decode(value, { stream: true });
      if (bytes >= o.maxBytes) { await reader.cancel().catch(() => {}); break; }
    }
  }
  return { status: res.status, headers, body };
}

const joinPath = (base: string, input: string, tail = '') => `${base.replace(/\/+$/, '')}${input === '/' ? '' : input}${tail ? `/${tail}` : input === '/' ? '/' : ''}`;

/** Fingerprint one input: two fetches of the URL, two fetches of two different non-existent sub-paths. */
export async function fingerprintEndpoint(base: string, input: string, origin: string, o: FetchOptions): Promise<EndpointFingerprint & { rootRaw?: RawResponse }> {
  const canaries: [string, string] = [`wb-nf-${crypto.randomBytes(6).toString('hex')}`, `wb-nf-${crypto.randomBytes(6).toString('hex')}`];
  try {
    const a = await fetchRaw(joinPath(base, input), o);
    const b = await fetchRaw(joinPath(base, input), o);
    const na = await fetchRaw(joinPath(base, input, canaries[0]), o);
    const nb = await fetchRaw(joinPath(base, input, canaries[1]), o);
    const self = compareFetches(a, b, { origin });
    const nf = compareFetches(na, nb, { origin, canaries });
    const stability: Stability = self.stability === 'unstable' || nf.stability === 'unstable' ? 'unstable' : self.stability === 'volatile' || nf.stability === 'volatile' ? 'volatile' : 'stable';
    return { input, ok: true, error: null, stability, self: self.sig, notFound: nf.sig, volatileHeaders: [...new Set([...self.volatileHeaders, ...nf.volatileHeaders])].sort(), tech: techOf(a), ...(input === '/' ? { rootRaw: a } : {}) };
  } catch (e) {
    return { input, ok: false, error: String((e as Error).message ?? e).slice(0, 300), stability: 'unstable', self: null, notFound: null, volatileHeaders: [], tech: [] };
  }
}

/** Fingerprint all inputs with bounded concurrency. The root input ('/') also yields the site fingerprint. */
export async function fingerprintInputs(base: string, origin: string, inputs: string[], o: FetchOptions & { concurrency: number; signal?: AbortSignal }): Promise<{ endpoints: Map<string, EndpointFingerprint>; site: SiteFingerprint | null; requests: number }> {
  const endpoints = new Map<string, EndpointFingerprint>();
  let site: SiteFingerprint | null = null;
  const queue = [...inputs];
  const worker = async () => {
    for (let next = queue.shift(); next !== undefined; next = queue.shift()) {
      if (o.signal?.aborted) return;
      const fp = await fingerprintEndpoint(base, next, origin, o);
      if (fp.rootRaw) { site = siteFingerprint(fp.rootRaw, fp.notFound); delete fp.rootRaw; }
      endpoints.set(next, fp);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(o.concurrency, inputs.length)) }, worker));
  return { endpoints, site, requests: [...endpoints.values()].length * 4 };
}
