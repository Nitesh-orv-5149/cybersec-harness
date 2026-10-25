// Target authorization for active web scanning. A URL may be scanned only when it is loopback (the developer's
// own running app, or a workbench-started copy) or its exact origin is listed in security.nuclei.authorizedTargets.
// Anything else is refused before a single request is sent.
import net from 'node:net';

export interface AuthorizedTarget {
  url: string;          // normalized URL handed to nuclei (no credentials, no fragment)
  origin: string;       // scheme://host:port with an explicit port
  host: string;         // hostname as written (lower-case, IPv6 without brackets)
  loopback: boolean;
  basePath: string;     // path of the URL ('/' when none)
  /** stable identity of what was scanned; findings are only compared within the same scope */
  scopeKey: string;
}

export type TargetCheck = { ok: true; target: AuthorizedTarget } | { ok: false; reason: string };

export function isLoopbackHost(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, '').toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (net.isIPv4(h)) return h.startsWith('127.');
  if (net.isIPv6(h)) return h === '::1' || h === '0:0:0:0:0:0:0:1' || /^::ffff:127\./.test(h);
  return false;
}

export function originOf(u: URL): string {
  const port = u.port || (u.protocol === 'https:' ? '443' : '80');
  return `${u.protocol}//${u.hostname.toLowerCase()}:${port}`;
}

export function authorizeTarget(raw: string, authorizedOrigins: string[]): TargetCheck {
  let u: URL;
  try { u = new URL(raw.trim()); } catch { return { ok: false, reason: 'not a valid absolute URL' }; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return { ok: false, reason: `scheme ${u.protocol} is not allowed (http and https only)` };
  if (u.username || u.password) return { ok: false, reason: 'URLs with embedded credentials are not accepted; credentials would be stored with the scan' };
  if (!u.hostname) return { ok: false, reason: 'URL has no host' };
  if (u.hostname === '0.0.0.0' || u.hostname === '[::]') return { ok: false, reason: 'unspecified address; use 127.0.0.1 or localhost' };
  u.hash = '';
  const origin = originOf(u);
  const loopback = isLoopbackHost(u.hostname);
  const allowed = new Set(authorizedOrigins.map((a) => { try { return originOf(new URL(a)); } catch { return null; } }).filter(Boolean) as string[]);
  if (!loopback && !allowed.has(origin)) {
    return { ok: false, reason: `${origin} is not loopback and not listed in security.nuclei.authorizedTargets. Only scan systems you are explicitly authorized to test.` };
  }
  const basePath = u.pathname || '/';
  return {
    ok: true,
    target: { url: u.toString(), origin, host: u.hostname.replace(/^\[|\]$/g, '').toLowerCase(), loopback, basePath, scopeKey: `url:${origin}${basePath.replace(/\/+$/, '') || '/'}` },
  };
}

/** Is a URL reported by the scanner inside the authorized origin? (Redirect or template escape check.) */
export function inScope(reported: string, target: AuthorizedTarget): boolean {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(reported)) {
    try { return originOf(new URL(reported)) === target.origin; } catch { return false; }
  }
  {
    // host:port style values (non-URL) — compare host and port
    const m = reported.match(/^\[?([^\]/]+?)\]?(?::(\d+))?$/);
    if (!m) return false;
    const t = new URL(target.origin);
    return m[1]!.toLowerCase() === target.host && (!m[2] || m[2] === t.port);
  }
}

/** Endpoint identity used in finding fingerprints: path + sorted query parameter names (values dropped). */
export function normalizeEndpoint(reported: string): string {
  if (!/^https?:\/\//i.test(reported)) return reported.trim();
  try {
    const u = new URL(reported);
    const keys = [...new Set([...u.searchParams.keys()])].sort();
    const path = u.pathname.replace(/\/{2,}/g, '/') || '/';
    return keys.length ? `${path}?${keys.join('&')}` : path;
  } catch {
    return reported.trim();
  }
}

/** Liveness pre-flight: one GET without following redirects. An unreachable target is a failed scan, never "0 findings". */
export async function probeTarget(url: string, timeoutMs: number, fetchImpl: typeof fetch = fetch): Promise<{ ok: boolean; status: number | null; reason: string | null }> {
  try {
    const res = await fetchImpl(url, { method: 'GET', redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
    await res.body?.cancel().catch(() => {});
    return { ok: true, status: res.status, reason: null };
  } catch (e) {
    return { ok: false, status: null, reason: String((e as Error).message ?? e) };
  }
}
